#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth_logic.py — логика авторизации LoginApp/BaseApp для локального
BigWorld-эмулятора (offline, версия клиента ~0.6.5 / совместимо с 1.23 wire).

Назначение: оффлайн-запуск СОБСТВЕННОГО сервера на localhost, чтобы старый
клиент с уже мёртвыми официальными серверами получил валидный LoginSuccess +
LoginRedirect и перешёл на BaseApp. Никакого взаимодействия с живым сервисом.

Содержит:
  - encode_var32 / decode_var32   — Variable32 длины элементов (wg-toolkit совместимо)
  - BlowfishLesta                 — нестандартный PCBC режим Lesta (IV=0)
  - LoginRedirect (dataclass)     — IP(4B) + Port(2B LE) + Key(4B)
  - LoginSuccess (dataclass)      — inner-структура, шифруется Blowfish
  - BigWorldPacketBuilder         — авто-длины элементов + checksum + prefix
  - generate_full_auth_packet()   — LoginSuccess + LoginRedirect в один поток
  - BaseAppHandshake              — конечный автомат SYN -> ACK на BaseApp

Все «неуверенные» места (endianness, наличие salt, формат redirect) вынесены
в параметры — это первое, что перебирают при подгонке под конкретный клиент.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from Crypto.Cipher import Blowfish as _BF


# ════════════════════════════════════════════════════════════════════
#  Константы протокола
# ════════════════════════════════════════════════════════════════════
FLAG_HAS_REQUESTS   = 0x0001   # в пакете есть reply/request-элементы
FLAG_HAS_PIGGYBACKS = 0x0002
FLAG_IS_ON_CHANNEL  = 0x0008   # есть seq_num/last_reliable в footer (BaseApp/CellApp)
FLAG_HAS_CHECKSUM   = 0x0100   # в footer есть XOR-checksum

# Element ID (message id внутри element-области)
MSG_LOGIN_SUCCESS  = 0x01
MSG_LOGIN_FAILURE  = 0x02
MSG_LOGIN_REDIRECT = 0x03


# ════════════════════════════════════════════════════════════════════
#  Variable32 — длина элемента переменной разрядности
#    0..=0x7F          -> 1 байт
#    0x80..=0x3FFF     -> 2 байта  (0x80 | val>>7, val & 0x7F)
#    0x4000..=0x1FFFFF -> 3 байта
#    >= 0x200000       -> 1 + 4 байта (0xE0, uint32 LE)
# ════════════════════════════════════════════════════════════════════
def encode_var32(val: int) -> bytes:
    if val < 0:
        raise ValueError("var32 не может быть отрицательным")
    if val <= 0x7F:
        return bytes([val])
    elif val <= 0x3FFF:
        return bytes([0x80 | (val >> 7), val & 0x7F])
    elif val <= 0x1FFFFF:
        return bytes([0xC0 | (val >> 14), (val >> 7) & 0x7F, val & 0x7F])
    else:
        return bytes([0xE0]) + struct.pack("<I", val)


def decode_var32(buf: bytes, off: int = 0) -> tuple[int, int]:
    """Возвращает (значение, новый_offset). Обратная к encode_var32 — для самотеста."""
    b0 = buf[off]
    if b0 <= 0x7F:
        return b0, off + 1
    if (b0 & 0xE0) == 0x80:          # 2 байта
        return ((b0 & 0x7F) << 7) | buf[off + 1], off + 2
    if (b0 & 0xE0) == 0xC0:          # 3 байта
        return ((b0 & 0x1F) << 14) | (buf[off + 1] << 7) | buf[off + 2], off + 3
    if b0 == 0xE0:                   # 1 + 4 байта
        return struct.unpack_from("<I", buf, off + 1)[0], off + 5
    raise ValueError(f"невалидный var32 префикс: 0x{b0:02X}")


# ════════════════════════════════════════════════════════════════════
#  Checksum / prefix (совместимо с server_stub.build_bw_packet)
# ════════════════════════════════════════════════════════════════════
def xor_checksum(data: bytes) -> int:
    """XOR по полным 4-байтовым словам, хвост игнорируется."""
    cs = 0
    for i in range(0, len(data) - len(data) % 4, 4):
        cs ^= struct.unpack_from("<I", data, i)[0]
    return cs & 0xFFFFFFFF


def prefix_hash(body: bytes) -> int:
    """Нелинейный hash первых 8 байт body (BigWorld packet prefix)."""
    b = body[:8].ljust(8, b"\x00")
    p0 = struct.unpack_from("<I", b, 0)[0]
    p1 = struct.unpack_from("<I", b, 4)[0]
    a = (p0 + p1) & 0xFFFFFFFF
    b2 = (a << 13) & 0xFFFFFFFF
    c = (b2 ^ a) >> 17
    d = c ^ b2 ^ a ^ (((c ^ b2 ^ a) << 5) & 0xFFFFFFFF)
    return d & 0xFFFFFFFF


# ════════════════════════════════════════════════════════════════════
#  Blowfish · Lesta PCBC:  C[i] = E(P[i] ⊕ P[i-1] ⊕ C[i-1]), IV = 0
# ════════════════════════════════════════════════════════════════════
class BlowfishLesta:
    def __init__(self, key: bytes):
        self._ecb = _BF.new(key, _BF.MODE_ECB)
        self._prev_pt = b"\x00" * 8
        self._prev_ct = b"\x00" * 8

    def reset(self) -> "BlowfishLesta":
        self._prev_pt = b"\x00" * 8
        self._prev_ct = b"\x00" * 8
        return self

    def encrypt(self, data: bytes) -> bytes:
        # FIX #4: режим wg-toolkit BlowfishWriter — C[i] = E(P[i] ⊕ P[i-1]),
        #         P[-1] = 0. Обратная связь ТОЛЬКО по открытому тексту.
        #         Раньше было E(P[i] ⊕ P[i-1] ⊕ C[i-1]) — лишний C[i-1].
        out = bytearray()
        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            xored = bytes(a ^ b for a, b in zip(block, self._prev_pt))
            ct = self._ecb.encrypt(xored)
            out += ct
            self._prev_pt = block
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        # Обратная операция: P[i] = D(C[i]) ⊕ P[i-1], P[-1] = 0.
        out = bytearray()
        for i in range(0, len(data), 8):
            ct = data[i:i + 8]
            dec = self._ecb.decrypt(ct)
            pt = bytes(a ^ b for a, b in zip(dec, self._prev_pt))
            out += pt
            self._prev_pt = pt
        return bytes(out)


def derive_bf_key(session: str) -> bytes:
    """32 hex-символа -> 16 байт ключа; иначе первые 16 ASCII, добитые нулями."""
    if len(session) == 32:
        try:
            return bytes.fromhex(session)
        except ValueError:
            pass
    return session[:16].encode().ljust(16, b"\x00")


# ════════════════════════════════════════════════════════════════════
#  Структуры данных
# ════════════════════════════════════════════════════════════════════
@dataclass
class LoginRedirect:
    """
    LoginRedirect — куда клиент идёт после успешного логина.

      IP   : 4 байта  (адрес BaseApp, network byte order через inet_aton)
      Port : 2 байта  little-endian
      Key  : 4 байта  little-endian  (login key / session handle для BaseApp)

    Endianness порта/ключа — параметры: если конкретный клиент не принимает,
    переверни big=True (это первое, что стоит перебрать).
    """
    ip: str
    port: int
    key: int
    element_id: int = MSG_LOGIN_REDIRECT
    port_big_endian: bool = False
    key_big_endian: bool = False

    def pack_payload(self) -> bytes:
        out = bytearray()
        out += socket.inet_aton(self.ip)                                  # IP  4B
        out += struct.pack(">H" if self.port_big_endian else "<H", self.port)  # Port 2B
        out += struct.pack(">I" if self.key_big_endian else "<I", self.key)    # Key  4B
        return bytes(out)

    @classmethod
    def unpack_payload(cls, buf: bytes, port_big=False, key_big=False) -> "LoginRedirect":
        ip = socket.inet_ntoa(buf[0:4])
        port = struct.unpack_from(">H" if port_big else "<H", buf, 4)[0]
        key = struct.unpack_from(">I" if key_big else "<I", buf, 6)[0]
        return cls(ip=ip, port=port, key=key,
                   port_big_endian=port_big, key_big_endian=key_big)


@dataclass
class LoginSuccess:
    """
    Inner-тело LoginSuccess (до шифрования Blowfish).

      IP       : 4B big-endian   (адрес BaseApp)
      Port     : 2B big-endian
      Salt     : 2B little-endian
      LoginKey : 4B little-endian
      [msg]    : опциональная packed-строка

    Финальный payload элемента = b'\\x01' + Blowfish_PCBC(pad8(inner)).
    """
    baseapp_ip: str
    baseapp_port: int
    login_key: int = 0x00000001
    salt: int = 0
    server_msg: str = ""

    def pack_inner(self) -> bytes:
        # FIX #3: убран 2-байтный salt. Запись = Addr(IP4 BE + Port2 BE) + Key(u32 LE).
        #         Лишний salt сдвигал и портил login_key при чтении клиентом.
        inner = bytearray()
        inner += socket.inet_aton(self.baseapp_ip)       # IP   4B BE
        inner += struct.pack(">H", self.baseapp_port)     # Port 2B BE
        inner += struct.pack("<I", self.login_key)        # Key  4B LE
        if self.server_msg:
            inner += _pack_string(self.server_msg.encode())
        return bytes(inner)

    def pack_payload(self, session_key: str, encrypt: bool = True,
                     bf_key: bytes | None = None) -> bytes:
        """
        bf_key: если задан — используется НАПРЯМУЮ как ключ Blowfish (16 байт,
        тот самый blowfish_key, что клиент прислал в RSA-блобе LoginRequest).
        Если None — fallback: ключ выводится из session-строки (старое поведение,
        работает только если клиент в самом деле взял ключ из session).
        """
        inner = self.pack_inner()
        if not encrypt:
            return bytes([MSG_LOGIN_SUCCESS]) + inner
        pad = (8 - len(inner) % 8) % 8
        padded = inner + b"\x00" * pad
        key = bf_key if bf_key else derive_bf_key(session_key)
        ct = BlowfishLesta(key).encrypt(padded)
        return bytes([MSG_LOGIN_SUCCESS]) + ct


def _pack_string(s: bytes) -> bytes:
    n = len(s)
    if n < 0xFF:
        return bytes([n]) + s
    return b"\xFF" + struct.pack("<I", n) + s


# ════════════════════════════════════════════════════════════════════
#  BigWorldPacketBuilder — авто-подсчёт длин, checksum, prefix
# ════════════════════════════════════════════════════════════════════
class BigWorldPacketBuilder:
    """
    Накапливает элементы и собирает финальный UDP-пакет:

        [prefix:4][flags:2][ elements... ][last_rel:4][seq:4]?[checksum:4]

    last_rel/seq присутствуют ТОЛЬКО когда on_channel=True (BaseApp/CellApp).
    Длины элементов считаются автоматически.

    Два способа добавить элемент:
      - add_reply(request_id, payload): настоящий BigWorld reply-элемент
            0xFF + var32(len(req_id+payload)) + req_id + payload
        (так передаются LoginSuccess/LoginFailure — это ответ на request клиента)
      - add_fixed_element(msg_id, payload): простой элемент
            msg_id(1) + uint16_LE(len) + payload
        (формат из твоей таблицы: ID + Length 2-bytes LE + Payload)
    """

    def __init__(self, on_channel: bool = False, seq_num: int = 0, last_rel: int = 0):
        self._elements = bytearray()
        self._flags = FLAG_HAS_CHECKSUM
        self.on_channel = on_channel
        self.seq_num = seq_num
        self.last_rel = last_rel

    # ── reply-элемент (LoginSuccess / LoginFailure) ────────────────
    def add_reply(self, request_id: int, payload: bytes) -> "BigWorldPacketBuilder":
        # FIX #1: длина reply-элемента — простой 4-байтовый LE u32 (в wg-toolkit
        #         "Variable32" для Reply == plain u32 LE), а НЕ упакованный var32.
        #         Раньше 0x15 вместо 15 00 00 00 → клиент читал мусорную длину.
        # FIX #2: reply ≠ request, флаг HAS_REQUESTS НЕ ставим (иначе клиент ждёт
        #         несуществующий request-footer и отбрасывает пакет).
        content = struct.pack("<I", request_id) + payload
        self._elements += b"\xFF" + struct.pack("<I", len(content)) + content
        return self

    # ── простой элемент: ID + len16_LE + payload (LoginRedirect) ───
    def add_fixed_element(self, msg_id: int, payload: bytes) -> "BigWorldPacketBuilder":
        if len(payload) > 0xFFFF:
            raise ValueError("payload > 65535: используй add_reply/var32")
        self._elements += bytes([msg_id]) + struct.pack("<H", len(payload)) + payload
        return self

    # ── элемент с var32-длиной (если клиент ждёт var32 и для redirect) ─
    def add_var_element(self, msg_id: int, payload: bytes) -> "BigWorldPacketBuilder":
        self._elements += bytes([msg_id]) + encode_var32(len(payload)) + payload
        return self

    def set_extra_flags(self, flags: int) -> "BigWorldPacketBuilder":
        self._flags |= flags
        return self

    def build(self, with_checksum: bool = True, prefix_mode: str = "hash") -> bytes:
        """
        with_checksum: добавлять ли flag 0x0100 и 4-байтовый XOR-checksum в хвост.
                       Клиент этой сборки шлёт connectionless БЕЗ checksum —
                       пробуй with_checksum=False, чтобы зеркалить его фрейм.
        prefix_mode:   'hash' — наш нелинейный prefix_hash (догадка)
                       'zero' — 4 нулевых байта (если префикс не валидируется)
        """
        flags = self._flags
        if not with_checksum:
            flags &= ~FLAG_HAS_CHECKSUM
        if self.on_channel:
            flags |= FLAG_IS_ON_CHANNEL

        body = bytearray()
        body += struct.pack("<H", flags)
        body += self._elements
        if self.on_channel:
            body += struct.pack("<I", self.last_rel)
            body += struct.pack("<I", self.seq_num)
        if with_checksum:
            body += struct.pack("<I", xor_checksum(bytes(body)))   # footer: checksum

        if prefix_mode == "zero":
            prefix = 0
        else:
            prefix = prefix_hash(bytes(body))
        return struct.pack("<I", prefix) + bytes(body)


# ════════════════════════════════════════════════════════════════════
#  Главная функция: LoginSuccess + LoginRedirect в один поток
# ════════════════════════════════════════════════════════════════════
def generate_full_auth_packet(
    req_id: int,
    session_key: str,
    *,
    baseapp_ip: str = "127.0.0.1",
    baseapp_port: int = 20017,
    login_key: int = 0x00000001,
    server_msg: str = "",
    encrypt_success: bool = True,
    redirect_as_var32: bool = False,
    redirect_port_big: bool = False,
    redirect_key_big: bool = False,
    bf_key: bytes | None = None,
) -> bytes:
    """
    Собирает единый ответ LoginApp:
        элемент 1: LoginSuccess  (reply-элемент, status 0x01, Blowfish inner)
        элемент 2: LoginRedirect (0x03, IP+Port+Key)

    Клиент повторяет LoginRequest с тем же req_id, пока не распарсит этот
    пакет; req_id обязан совпадать с присланным клиентом.
    """
    success = LoginSuccess(
        baseapp_ip=baseapp_ip,
        baseapp_port=baseapp_port,
        login_key=login_key,
        server_msg=server_msg,
    )
    redirect = LoginRedirect(
        ip=baseapp_ip,
        port=baseapp_port,
        key=login_key,
        port_big_endian=redirect_port_big,
        key_big_endian=redirect_key_big,
    )

    b = BigWorldPacketBuilder(on_channel=False)
    b.add_reply(req_id, success.pack_payload(session_key, encrypt=encrypt_success, bf_key=bf_key))
    if redirect_as_var32:
        b.add_var_element(redirect.element_id, redirect.pack_payload())
    else:
        b.add_fixed_element(redirect.element_id, redirect.pack_payload())
    return b.build()


# ════════════════════════════════════════════════════════════════════
#  Раздельные пакеты: LoginSuccess отдельно, LoginRedirect отдельно
#  (для эксперимента «разнести во времени», как советует фидбэк клиента)
# ════════════════════════════════════════════════════════════════════
def generate_login_success_packet(
    req_id: int,
    session_key: str,
    *,
    baseapp_ip: str = "127.0.0.1",
    baseapp_port: int = 20017,
    login_key: int = 0x00000001,
    server_msg: str = "",
    encrypt_success: bool = True,
    with_checksum: bool = True,
    prefix_mode: str = "hash",
    bf_key: bytes | None = None,
) -> bytes:
    """
    ТОЛЬКО LoginSuccess — один reply-элемент. В стоковом BigWorld адрес
    BaseApp (IP+Port+Key) УЖЕ внутри зашифрованного inner, отдельный 0x03
    не нужен. Это рекомендуемый первый тест.

    with_checksum / prefix_mode — управление обёрткой пакета (см. build()).
    """
    success = LoginSuccess(
        baseapp_ip=baseapp_ip, baseapp_port=baseapp_port,
        login_key=login_key, server_msg=server_msg,
    )
    return (
        BigWorldPacketBuilder(on_channel=False)
        .add_reply(req_id, success.pack_payload(session_key, encrypt=encrypt_success, bf_key=bf_key))
        .build(with_checksum=with_checksum, prefix_mode=prefix_mode)
    )


# Набор вариантов ОБЁРТКИ фрейма — перебираем по retry-попыткам клиента.
# (with_checksum, prefix_mode, encrypt) + человекочитаемое описание.
FRAME_VARIANTS = [
    (True,  "hash", True,  "A: checksum + prefix_hash + encrypted (текущий)"),
    (False, "hash", True,  "B: NO checksum + prefix_hash + encrypted (зеркало клиента)"),
    (False, "zero", True,  "C: NO checksum + prefix=0 + encrypted"),
    (True,  "zero", True,  "D: checksum + prefix=0 + encrypted"),
    (False, "hash", False, "E: NO checksum + prefix_hash + RAW (без Blowfish)"),
]


def generate_login_redirect_packet(
    req_id: int,
    *,
    baseapp_ip: str = "127.0.0.1",
    baseapp_port: int = 20017,
    login_key: int = 0x00000001,
    as_reply: bool = False,
    as_var32: bool = False,
    port_big: bool = False,
    key_big: bool = False,
) -> bytes:
    """
    ТОЛЬКО LoginRedirect — отдельным пакетом (если решишь слать вторым).
      as_reply=True  -> завернуть как reply-элемент (0xFF + req_id)
      иначе          -> элемент 0x03 (fixed16 или var32)
    """
    redirect = LoginRedirect(
        ip=baseapp_ip, port=baseapp_port, key=login_key,
        port_big_endian=port_big, key_big_endian=key_big,
    )
    payload = redirect.pack_payload()
    b = BigWorldPacketBuilder(on_channel=False)
    if as_reply:
        b.add_reply(req_id, bytes([redirect.element_id]) + payload)
    elif as_var32:
        b.add_var_element(redirect.element_id, payload)
    else:
        b.add_fixed_element(redirect.element_id, payload)
    return b.build()


# ════════════════════════════════════════════════════════════════════
#  BaseApp SYN -> ACK handshake (конечный автомат на одного клиента)
# ════════════════════════════════════════════════════════════════════
def generate_baseapp_login_reply(
    reply_id: int,
    *,
    session_key: int = 0x00000001,
    payload: bytes | None = None,
    with_checksum: bool = True,
    prefix_mode: str = "hash",
) -> bytes:
    """
    Ответ BaseApp на baseAppLogin-request (off-channel reply, как у LoginApp).
    По умолчанию payload = uint32 sessionKey. Если клиент ждёт другое — меняй
    payload (варианты: b"" пустой / b"\\x00" статус / uint32 ключ).
    reply_id ОБЯЗАН совпадать с присланным клиентом (у baseAppLogin он на смещ. 7).
    """
    if payload is None:
        payload = struct.pack("<I", session_key)
    return (
        BigWorldPacketBuilder(on_channel=False)
        .add_reply(reply_id, payload)
        .build(with_checksum=with_checksum, prefix_mode=prefix_mode)
    )



class BaseAppHandshake:
    """
    Состояние хендшейка одного клиента на BaseApp.

      step 0 (SYN):  первый пакет от клиента после redirect.
                     Отвечаем ACK + prerequisites reply (пустой список, reason=0).
      step >=1:      обычные channel-ACK (подтверждаем reliable seq клиента).

    Каждый исходящий пакет канальный (on_channel=True) и нумеруется server_seq.
    """

    def __init__(self):
        self.server_seq = 0
        self.step = 0

    def _next_seq(self) -> int:
        s = self.server_seq
        self.server_seq += 1
        return s

    def build_ack(self, client_seq: int) -> bytes:
        """Пустой канальный ACK."""
        return (
            BigWorldPacketBuilder(on_channel=True, seq_num=self._next_seq(), last_rel=client_seq)
            .build()
        )

    def build_prereq_reply(self, request_id: int, client_seq: int) -> bytes:
        """Ответ на EntityCreationRequest: prereq_count=0, reason=0 (OK)."""
        payload = bytes([0x00, 0x00])  # [prereq_count=0][reason=0]
        return (
            BigWorldPacketBuilder(on_channel=True, seq_num=self._next_seq(), last_rel=client_seq)
            .add_reply(request_id, payload)
            .build()
        )

    def handle(self, request_id: int, client_seq: int) -> bytes:
        """Принять входящий пакет клиента, вернуть байты ответа."""
        if self.step == 0:
            self.step = 1
            return self.build_prereq_reply(request_id, client_seq)
        return self.build_ack(client_seq)


# ════════════════════════════════════════════════════════════════════
#  Декодер собственного пакета — для самотеста / отладки
# ════════════════════════════════════════════════════════════════════
def decode_auth_packet(pkt: bytes, session_key: str | None = None) -> dict:
    """Разбирает пакет, собранный generate_full_auth_packet. Проверяет checksum."""
    out: dict = {"elements": []}
    out["prefix"] = struct.unpack_from("<I", pkt, 0)[0]
    body = pkt[4:]
    out["flags"] = struct.unpack_from("<H", body, 0)[0]

    stored_cs = struct.unpack_from("<I", body, len(body) - 4)[0]
    calc_cs = xor_checksum(body[:len(body) - 4])
    out["checksum_ok"] = (stored_cs == calc_cs)

    off = 2
    elem_area_end = len(body) - 4  # без checksum (on_channel здесь False)
    while off < elem_area_end:
        tag = body[off]
        if tag == 0xFF:  # reply-элемент
            # FIX #1: длина reply — 4-байтовый LE u32 (не var32).
            ln = struct.unpack_from("<I", body, off + 1)[0]
            off += 5
            content = body[off:off + ln]
            off += ln
            req_id = struct.unpack_from("<I", content, 0)[0]
            payload = content[4:]
            elem = {"type": "reply", "request_id": req_id,
                    "status": payload[0] if payload else None}
            if session_key and payload and payload[0] == MSG_LOGIN_SUCCESS:
                ct = payload[1:]
                if len(ct) % 8 == 0:
                    inner = BlowfishLesta(derive_bf_key(session_key)).decrypt(ct)
                    elem["decrypted_ip"] = socket.inet_ntoa(inner[0:4])
                    elem["decrypted_port"] = struct.unpack_from(">H", inner, 4)[0]
                    # FIX #3: salt убран → login_key теперь на смещении 6 (4+2), не 8.
                    elem["decrypted_key"] = struct.unpack_from("<I", inner, 6)[0]
            out["elements"].append(elem)
        else:  # простой элемент ID + len16 + payload
            msg_id = tag
            ln = struct.unpack_from("<H", body, off + 1)[0]
            payload = body[off + 3:off + 3 + ln]
            off += 3 + ln
            elem = {"type": "fixed", "msg_id": msg_id, "len": ln}
            if msg_id == MSG_LOGIN_REDIRECT and len(payload) >= 10:
                r = LoginRedirect.unpack_payload(payload)
                elem.update({"redirect_ip": r.ip, "redirect_port": r.port,
                             "redirect_key": r.key})
            out["elements"].append(elem)
    return out


# ════════════════════════════════════════════════════════════════════
#  Самотест
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    SESSION = "00112233445566778899aabbccddeeff"  # 32 hex -> 16-байт ключ
    REQ_ID = 0xA1B2C3D4

    pkt = generate_full_auth_packet(
        REQ_ID, SESSION,
        baseapp_ip="127.0.0.1", baseapp_port=20017, login_key=0xCAFEBABE,
    )
    print(f"full auth packet ({len(pkt)} B):")
    print(pkt.hex(" "))
    print()

    dec = decode_auth_packet(pkt, session_key=SESSION)
    print("decoded:")
    print(f"  prefix      = 0x{dec['prefix']:08X}")
    print(f"  flags       = 0x{dec['flags']:04X}")
    print(f"  checksum_ok = {dec['checksum_ok']}")
    for i, e in enumerate(dec["elements"]):
        print(f"  element[{i}] = {e}")

    # Проверки
    assert dec["checksum_ok"], "checksum mismatch!"
    succ = dec["elements"][0]
    assert succ["request_id"] == REQ_ID, "req_id mismatch!"
    assert succ["status"] == MSG_LOGIN_SUCCESS
    assert succ["decrypted_ip"] == "127.0.0.1"
    assert succ["decrypted_port"] == 20017
    assert succ["decrypted_key"] == 0xCAFEBABE
    redir = dec["elements"][1]
    assert redir["msg_id"] == MSG_LOGIN_REDIRECT
    assert redir["redirect_ip"] == "127.0.0.1"
    assert redir["redirect_port"] == 20017
    assert redir["redirect_key"] == 0xCAFEBABE
    print("\n[OK] roundtrip самотест пройден — пакет внутренне консистентен.")

    # Демонстрация BaseApp SYN -> ACK
    print("\nBaseApp handshake:")
    hs = BaseAppHandshake()
    syn_reply = hs.handle(request_id=REQ_ID, client_seq=0)
    print(f"  SYN -> prereq reply ({len(syn_reply)} B): {syn_reply.hex(' ')}")
    ack = hs.handle(request_id=0, client_seq=1)
    print(f"  data -> ACK ({len(ack)} B):           {ack.hex(' ')}")
