#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║   BigWorld LoginApp + BaseApp stub  ·  WoT/Mir Tankov 1.23     ║
║   Full rewrite · всё исправлено на основе wg-toolkit-rs анализа ║
╠══════════════════════════════════════════════════════════════════╣
║  ИСПРАВЛЕНЫ БАГИ:                                                ║
║  #1 Element length: FIXED uint32 → Variable32 (wg-toolkit-rs)  ║
║  #2 Payload: нет prereqs как строк, правильный binary формат   ║
║  #3 Variable32 алгоритм: (val>>7) а не (val>>8)                ║
║  #4 Footer: seq_num=0, last_reliable=0 (LoginApp stateless)    ║
║  #5 Все payload варианты покрыты (с/без prereqs, с/без msg)    ║
║  #6 BaseApp stub: правильный EntityDetails reply               ║
║  #7 RequestID offset: исправлено извлечение из пакета (offset 8)║
╠══════════════════════════════════════════════════════════════════╣
║  Структура LOGIN SUCCESS пакета (server → client):              ║
║  [prefix:4][flags:2][0xFF:1][var32(len):1-4][req_id:4]         ║
║  [0x01:status][BF_PCBC( inner )][checksum:4]                   ║
║                                                                  ║
║  inner = IP:4BE + Port:2BE + Salt:2LE + LoginKey:4LE           ║
║          + [optional: prereq_count:1 + reason:1]                ║
╚══════════════════════════════════════════════════════════════════╝
"""

import socket
import struct
import os
import sys
import time
import json
import traceback
import threading

from pathlib import Path
from src.manager import DefManager
from handlers.baseapp_handler import BaseAppHandler

sys.stdout.reconfigure(line_buffering=True)

HOST       = '0.0.0.0'
LOGIN_PORT = 20014
BASE_PORT  = 20017
BASEAPP_IP = '127.0.0.1'

PRIVKEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server_privkey.pem')
LOG_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

from Crypto.PublicKey import RSA
from Crypto.Cipher   import PKCS1_OAEP
from Crypto.Cipher   import Blowfish as BF_ECB
from Crypto.Hash     import SHA1

# Инициализация парсера
app_root = Path(__file__).resolve().parent
def_manager = DefManager(app_root)
def_manager.load() # Это та самая функция, которая выводит [DEF] ... - is found
print(f"[OK] DefManager готов: {len(def_manager)} сущностей в реестре")

handler = BaseAppHandler(def_manager=def_manager)

# ── Entity System ──
try:
    from entity_addon import EntitySystemAddon
    ENTITY_ADDON = True
    print('[OK] EntitySystemAddon загружен')
except ImportError:
    ENTITY_ADDON = False
    print('[WARN] EntitySystemAddon не загружен (опционально)')

# ── Логика авторизации вынесена в auth_logic.py (тот же каталог) ──
from auth_logic import (
    generate_full_auth_packet,
    generate_login_success_packet,
    generate_login_redirect_packet,
    generate_baseapp_login_reply,
    BaseAppHandshake,
    FRAME_VARIANTS,
)

# ── Тумблеры эксперимента (крути их, чтобы подобрать формат под клиент) ──
SEND_SEPARATE_REDIRECT = False   # True = слать LoginRedirect вторым пакетом
REDIRECT_DELAY_SEC     = 0.08    # задержка перед redirect (клиенту на расшифровку)
ENCRYPT_SUCCESS        = True    # False = LoginSuccess без Blowfish (диагностика)
LOGIN_KEY              = 0x00000001  # sessionKey-поле внутри LoginReplyRecord

# Источник Blowfish-ключа для шифрования LoginSuccess:
# Источник Blowfish-ключа для шифрования LoginSuccess:
#   'blob'     — ПРАВИЛЬНО: 16-байтовый blowfish_key, распарсенный из RSA-блоба
#                (поле после username+password). ДЕФОЛТ.
#   'session'  — ключ = bytes.fromhex(session) из JSON (оказалось НЕВЕРНО)
#   'first16'/'prejson'/'postjson' — сырые срезы блоба (диагностика)
# ⚠ Клиент шифрует свой blowfish_key ТВОИМ public-ключом (loginapp_wot.pubkey).
BF_KEY_SOURCE          = 'blob'

# ───────────────────────────────────────────────────────────────
#  RSA
# ───────────────────────────────────────────────────────────────
PRIVATE_KEY = None
try:
    with open(PRIVKEY_PATH, 'r') as f:
        PRIVATE_KEY = RSA.importKey(f.read())
    print('[OK] RSA private key loaded')
except Exception as e:
    print(f'[WARN] RSA key not loaded: {e}')

RSA_BLOCK_SIZE = 256

# FIX #5: reply_id (request correlation id) читается со смещения 9, не 8.
# Раскладка login-request элемента: prefix(4)+flags(2)+msg_id(1)+len16(2)+reply_id(4)
#   = байты 0..5 заголовок, 6 msg_id, 7..8 длина (Variable16), 9..12 reply_id.
# ⚠ Сверь с СВОИМ дампом: если login использует другую ElementLength,
#   подвинь это значение (частые варианты: 7 для Fixed, 9 для Variable16).
REPLY_ID_OFFSET = 9

# На BaseApp baseAppLogin reply_id лежит со смещения 7 (фиксированный элемент,
# без inline-длины). Если клиент не матчит reply — попробуй 9.
BASEAPP_REPLYID_OFFSET = 7

# ───────────────────────────────────────────────────────────────
#  BigWorld пакетные флаги
# ───────────────────────────────────────────────────────────────
FLAG_HAS_REQUESTS   = 0x0001   # в пакете есть request-элементы
FLAG_HAS_PIGGYBACKS = 0x0002
FLAG_HAS_CHECKSUM   = 0x0100   # в footer есть XOR checksum

# ───────────────────────────────────────────────────────────────
#  Blowfish  ·  Lesta PCBC:  C[i] = E(P[i] ⊕ P[i-1] ⊕ C[i-1])
#  IV = 0,0,…,0  (нулевой вектор)
# ───────────────────────────────────────────────────────────────
class BlowfishLesta:
    """
    Нестандартный PCBC режим Lesta:
        C[0] = ECB(P[0])
        C[i] = ECB(P[i] ⊕ P[i-1] ⊕ C[i-1])
    """
    def __init__(self, key: bytes):
        self._ecb        = BF_ECB.new(key, BF_ECB.MODE_ECB)
        self._prev_pt    = b'\x00' * 8
        self._prev_ct    = b'\x00' * 8

    def encrypt(self, data: bytes) -> bytes:
        # FIX #4: режим wg-toolkit — C[i] = E(P[i] ⊕ P[i-1]), P[-1]=0.
        out = b''
        for i in range(0, len(data), 8):
            block  = data[i:i+8]
            xored  = bytes(a ^ b for a, b in zip(block, self._prev_pt))
            ct     = self._ecb.encrypt(xored)
            out   += ct
            self._prev_pt = block
        return out

    def decrypt(self, data: bytes) -> bytes:
        # P[i] = D(C[i]) ⊕ P[i-1], P[-1]=0.
        out = b''
        for i in range(0, len(data), 8):
            ct    = data[i:i+8]
            dec   = self._ecb.decrypt(ct)
            pt    = bytes(a ^ b for a, b in zip(dec, self._prev_pt))
            out  += pt
            self._prev_pt = pt
        return out


# ───────────────────────────────────────────────────────────────
#  Variable32 (wg-toolkit-rs bundle.rs реализация)
#  val 0..=0x7F        → 1 байт
#  val 0x80..=0x3FFF   → 2 байта  (0x80 | val>>7, val&0x7F)
#  val 0x4000..=0x1FFFFF → 3 байта
#  val ≥ 0x200000      → 1+4 байта (0xE0 + uint32 LE)
# ───────────────────────────────────────────────────────────────
def encode_var32(val: int) -> bytes:
    if val <= 0x7F:
        return bytes([val])
    elif val <= 0x3FFF:
        return bytes([0x80 | (val >> 7), val & 0x7F])
    elif val <= 0x1FFFFF:
        return bytes([0xC0 | (val >> 14), (val >> 7) & 0x7F, val & 0x7F])
    else:
        return bytes([0xE0]) + struct.pack('<I', val)


def pack_string(s: bytes) -> bytes:
    """BigWorld packed string: len<255 → [len:1], иначе [0xFF][len:4LE]"""
    n = len(s)
    if n < 0xFF:
        return bytes([n]) + s
    return b'\xFF' + struct.pack('<I', n) + s


# ───────────────────────────────────────────────────────────────
#  BigWorld packet builders
# ───────────────────────────────────────────────────────────────
def _prefix_hash(body: bytes) -> int:
    """Префикс = нелинейный hash первых 8 байт body."""
    b  = body[:8].ljust(8, b'\x00')
    p0 = struct.unpack_from('<I', b, 0)[0]
    p1 = struct.unpack_from('<I', b, 4)[0]
    a  = (p0 + p1)      & 0xFFFFFFFF
    b2 = (a << 13)       & 0xFFFFFFFF
    c  = (b2 ^ a) >> 17
    d  = c ^ b2 ^ a ^ (((c ^ b2 ^ a) << 5) & 0xFFFFFFFF)
    return d & 0xFFFFFFFF


def _xor_cs(data: bytes) -> int:
    """XOR checksum: только полные 4-байтовые слова (хвост игнорируется)."""
    cs = 0
    for i in range(0, len(data) - len(data) % 4, 4):
        cs ^= struct.unpack_from('<I', data, i)[0]
    return cs


def build_reply_element(request_id: int, payload: bytes) -> bytes:
    """
    Reply element (wg-toolkit-rs bundle.rs):
      [0xFF : 1B]
      [var32(len(req_id+payload)) : 1-4B]
      [request_id : 4B LE]
      [payload]
    """
    # FIX #1: длина reply — 4-байтовый LE u32 (wg-toolkit), не упакованный var32.
    content = struct.pack('<I', request_id) + payload
    return b'\xFF' + struct.pack('<I', len(content)) + content


def build_bw_packet(
    elements: bytes,
    is_on_channel: bool = False,
    seq_num: int = 0,
    last_rel: int = 0,
    extra_flags: int = 0,
) -> bytes:
    """
    Собирает BigWorld UDP пакет.
    Если is_on_channel = False, seq_num и last_rel НЕ добавляются в footer.
    """
    FLAG_HAS_CHECKSUM  = 0x0100
    FLAG_IS_ON_CHANNEL = 0x0008  # Указывает клиенту, что нужно читать seq_num и last_rel

    flags = FLAG_HAS_CHECKSUM | extra_flags
    if is_on_channel:
        flags |= FLAG_IS_ON_CHANNEL

    body = bytearray()
    body += struct.pack('<H', flags)    # flags
    body += elements                   # element area

    # Добавляем seq-номера только если пакет канальный (BaseApp/CellApp)
    if is_on_channel:
        body += struct.pack('<I', last_rel)
        body += struct.pack('<I', seq_num)

    cs = _xor_cs(bytes(body))
    body += struct.pack('<I', cs)       # footer: checksum

    prefix = _prefix_hash(bytes(body))
    return struct.pack('<I', prefix) + bytes(body)


# ───────────────────────────────────────────────────────────────
#  LOGIN SUCCESS payload
# ───────────────────────────────────────────────────────────────
def _bf_key(session: str) -> bytes:
    if len(session) == 32:
        try:
            return bytes.fromhex(session)
        except ValueError:
            pass
    return session[:16].encode().ljust(16, b'\x00')


def build_login_success_payload(session: str, login_key: int = 0x00000001,
                                 server_msg: str = '') -> bytes:
    """
    Правильная структура LOGIN SUCCESS inner (по wg-toolkit-rs):

        IP      : 4B  big-endian   (127.0.0.1 → 7f 00 00 01)
        Port    : 2B  big-endian   (20017 → 4e 31)
        Salt    : 2B  little-endian (0 → 00 00)
        LoginKey: 4B  little-endian

    Опционально (если сервер присылает строку):
        server_msg: pack_string(msg)

    Без поля prereqs — prereqs это ответ BaseApp, не LoginApp!

    Всё шифруется Blowfish PCBC (Lesta mode), padded к кратному 8.
    Перед шифротекстом идёт байт-статус 0x01 (LOGIN_SUCCESS).
    """
    inner = bytearray()
    inner += socket.inet_aton(BASEAPP_IP)          # IP  4B BE
    inner += struct.pack('>H', BASE_PORT)           # Port 2B BE
    # FIX #3: salt убран — Addr(IP4+Port2) + Key(u32).
    inner += struct.pack('<I', login_key)            # Key  4B LE
    if server_msg:
        inner += pack_string(server_msg.encode())

    raw     = bytes(inner)
    pad     = (8 - len(raw) % 8) % 8
    padded  = raw + b'\x00' * pad

    key = _bf_key(session)
    ct  = BlowfishLesta(key).encrypt(padded)

    return b'\x01' + ct


# ───────────────────────────────────────────────────────────────
#  Набор payload вариантов — чтобы перебрать при повторных попытках
# ───────────────────────────────────────────────────────────────
def _make_variants(session: str):
    return [
        # (описание, payload_bytes)
        ("V1 standard: IP+Port+Salt+Key, no msg",
         build_login_success_payload(session, login_key=0x00000001, server_msg='')),

        ("V2 key=0",
         build_login_success_payload(session, login_key=0x00000000, server_msg='')),

        ("V3 key=DEADBEEF",
         build_login_success_payload(session, login_key=0xDEADBEEF, server_msg='')),

        ("V4 with server_msg='offline'",
         build_login_success_payload(session, login_key=0x00000001, server_msg='offline')),

        ("V5 no Blowfish (raw inner)",
         _raw_payload(session)),

        ("V6 key=CAFEBABE, msg='ok'",
         build_login_success_payload(session, login_key=0xCAFEBABE, server_msg='ok')),
    ]


def _raw_payload(session: str) -> bytes:
    """Без шифрования — для диагностики."""
    inner = bytearray()
    inner += socket.inet_aton(BASEAPP_IP)
    inner += struct.pack('>H', BASE_PORT)
    inner += struct.pack('<I', 0x00000001)   # FIX #3: без salt
    return b'\x01' + bytes(inner)


# ───────────────────────────────────────────────────────────────
#  RSA брутфорс (фиксированные offsets 20 и 276 — быстро)
# ───────────────────────────────────────────────────────────────
_KNOWN_RSA_OFFSETS = (20, 276)   # подтверждено из логов

def rsa_decrypt_login(packet: bytes) -> dict | None:
    """
    Расшифровывает два RSA-блока логина и парсит JSON.
    Быстрый путь: фиксированные offsets 20+276.
    Запасной: полный брутфорс.
    """
    if not PRIVATE_KEY:
        return None
    oaep = PKCS1_OAEP.new(PRIVATE_KEY, hashAlgo=SHA1, label=b'')

    # Быстрый путь
    raw = b''
    for off in _KNOWN_RSA_OFFSETS:
        if off + RSA_BLOCK_SIZE <= len(packet):
            try:
                raw += oaep.decrypt(packet[off:off+RSA_BLOCK_SIZE])
            except Exception:
                raw = b''
                break
    if not raw:
        # Брутфорс
        blocks = []
        for off in range(0, len(packet) - RSA_BLOCK_SIZE + 1):
            try:
                dec = oaep.decrypt(packet[off:off+RSA_BLOCK_SIZE])
                nz  = sum(1 for b in dec if b != 0)
                if nz > 15:
                    blocks.append((nz, off, dec))
            except Exception:
                pass
        blocks.sort(reverse=True)
        for _, _, dec in blocks[:2]:
            raw += dec

    js_raw = raw.decode('ascii', errors='replace')
    js = js_raw.find('{')
    je = -1
    if js >= 0:
        depth = 0
        for i in range(js, len(js_raw)):
            if js_raw[i] == '{':
                depth += 1
            elif js_raw[i] == '}':
                depth -= 1
                if depth == 0:
                    je = i
                    break
    if js >= 0 and je > js:
        try:
            parsed = json.loads(js_raw[js:je+1])
        except Exception:
            return None
        # FIX (blowfish_key): кладём сырые расшифрованные байты и кандидатов на
        # симметричный ключ. В wg-toolkit blowfish_key пишется ПЕРЕД телом логина,
        # поэтому самый вероятный кандидат — первые 16 байт raw. Второй кандидат —
        # 16 байт, идущих прямо перед JSON. Оба логируем, чтобы ты сверил с дампом.
        parsed['__raw_hex__']   = raw.hex()
        parsed['__bf_first16__'] = raw[:16].hex()
        pre = raw[:js] if js >= 0 else b''
        parsed['__bf_prejson__'] = pre[-16:].hex() if len(pre) >= 16 else pre.hex()
        post = raw[je+1:] if je >= 0 else b''
        parsed['__bf_postjson__'] = post[:16].hex()
        # НАСТОЯЩИЙ ключ: BigWorld LoginRequest = flag(1) + username(pstr) +
        # password(pstr) + blowfish_key(pblob, 16B). Парсим length-prefixed поля.
        parsed['__bf_blob__'] = _extract_blowfish_blob(raw)
        return parsed
    return None


def _read_pstr(buf: bytes, i: int):
    """BigWorld packed string/blob: [len:1] либо [0xFF][len:4LE], затем bytes."""
    L = buf[i]; i += 1
    if L == 0xFF:
        L = struct.unpack_from('<I', buf, i)[0]; i += 4
    return buf[i:i+L], i + L


def _extract_blowfish_blob(raw: bytes) -> str:
    """raw = flag(1) + username(pstr) + password(pstr) + blowfish_key(pblob)."""
    try:
        i = 1                       # пропускаем flag-байт (0x01)
        _user, i = _read_pstr(raw, i)   # username (JSON)
        _pwd,  i = _read_pstr(raw, i)   # password
        key,   i = _read_pstr(raw, i)   # blowfish key (16 байт)
        return key.hex()
    except Exception:
        return ''


# ───────────────────────────────────────────────────────────────
#  Вспомогательные парсеры входящего пакета
# ───────────────────────────────────────────────────────────────
def _parse_incoming(packet: bytes) -> dict:
    """Разбираем входящий клиентский пакет."""
    info = {
        'prefix': 0, 'flags': 0,
        'elem_id': -1, 'request_id': 0, 'client_seq': 0,
    }
    if len(packet) < 6:
        return info
    info['prefix'] = struct.unpack_from('<I', packet, 0)[0]
    info['flags']  = struct.unpack_from('<H', packet, 4)[0]
    if len(packet) > 6:
        info['elem_id'] = packet[6]

    # request_id: извлекаем со смещения REPLY_ID_OFFSET (см. FIX #5).
    if len(packet) >= REPLY_ID_OFFSET + 4:
        info['request_id'] = struct.unpack_from('<I', packet, REPLY_ID_OFFSET)[0]

    # client_seq из footer (только если HAS_REQUESTS и нет HAS_CHECKSUM у клиента)
    # Клиент: flags=0x0001 (HAS_REQUESTS), нет checksum
    # Footer клиента (с конца): first_request_offset (2B) — только это!
    # seq_num/last_rel отсутствуют в Login пакетах (connectionless)
    info['client_seq'] = 0   # LoginApp stateless, seq не нужен

    return info


# ───────────────────────────────────────────────────────────────
#  LoginApp  (UDP 20014)
# ───────────────────────────────────────────────────────────────
class LoginApp:

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, LOGIN_PORT))
        self.sock.settimeout(0.5)

        self._log_path    = os.path.join(LOG_DIR, 'loginapp.log')
        self._login_count = 0
        self._server_seq  = 0
        self._sessions    = {}   # addr → {'session', 'variant', variants[]}

        print(f'[LOGIN] Listening  UDP {HOST}:{LOGIN_PORT}')

    # ── log ──────────────────────────────────────────────────
    def _log(self, msg: str, addr=None, level: str = 'INFO'):
        tag  = f'[{addr[0]}:{addr[1]}]' if addr else ''
        line = f'[{level}]{tag} {msg}'
        print(f'[LOGIN] {line}')
        try:
            with open(self._log_path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception:
            pass

    # ── main loop ────────────────────────────────────────────
    def run(self):
        with open(self._log_path, 'w', encoding='utf-8') as f:
            f.write(f'=== Started {time.strftime("%Y-%m-%d %H:%M:%S")} ===\n')
        self._log('Server started')
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._dispatch(data, addr)
            except socket.timeout:
                continue
            except Exception:
                traceback.print_exc()

    # ── dispatch ─────────────────────────────────────────────
    def _dispatch(self, data: bytes, addr):
        # ── Дамп ПОЛНОГО входящего пакета (для крекинга prefix-алгоритма) ──
        # Пишем prefix отдельно от тела: prefix(hex) | full_packet(hex) | len
        try:
            prefix = data[:4].hex()
            with open(os.path.join(LOG_DIR, 'client_packets.hex'), 'a', encoding='utf-8') as f:
                f.write(f'{prefix} | {data.hex()} | {len(data)}\n')
        except Exception:
            pass

        # Маленький пакет = ping/probe
        if len(data) <= 64:
            self._handle_ping(data, addr)
            return

        self._handle_login(data, addr)

    # ── ping ─────────────────────────────────────────────────
    def _handle_ping(self, data: bytes, addr):
        # Клиент шлёт 16-байтовые probe пакеты
        num    = data[11] if len(data) > 11 else 0
        # NB: ping (16B) — другая раскладка, чем login. Если pong не матчится,
        #     попробуй REPLY_ID_OFFSET (9) вместо 8.
        req_id = struct.unpack_from('<I', data, 8)[0] if len(data) >= 12 else 0
        
        # Pong: reply element с payload [0x02, 0x01, num]
        ping_pl = bytes([0x02, 0x01, num & 0xFF])
        elem    = build_reply_element(req_id, ping_pl)
        pkt = build_bw_packet(elem, is_on_channel=False)
        self._server_seq += 1
        self.sock.sendto(pkt, addr)
        self._log(f'<< ping {len(data)}B >> pong', addr)

    # ── login ────────────────────────────────────────────────
    def _handle_login(self, data: bytes, addr):
        self._login_count += 1
        info = _parse_incoming(data)
        self._log(
            f'<< Login #{self._login_count} {len(data)}B '
            f'flags=0x{info["flags"]:04X} req_id={info["request_id"]}',
            addr
        )
        self._log(f'   hex={data[:24].hex(" ")}', addr)

        # RSA + JSON
        login_data = rsa_decrypt_login(data)
        if login_data is None:
            self._log('   RSA/JSON parse FAILED', addr, 'WARN')
            return

        session = login_data.get('session', '')
        login   = login_data.get('login',   '?')
        self._log(f'   login={login}  session={session[:8]}…{session[-8:]}', addr)

        # Кандидаты на реальный blowfish_key из RSA-блоба (сверь с дампом!)
        bf_first16 = login_data.get('__bf_first16__', '')
        bf_prejson = login_data.get('__bf_prejson__', '')
        bf_postjson = login_data.get('__bf_postjson__', '')
        bf_blob     = login_data.get('__bf_blob__', '')
        raw_hex     = login_data.get('__raw_hex__', '')
        self._log(f'   bf_key BLOB (parsed) ={bf_blob}', addr)
        self._log(f'   bf_key cand: session={session}', addr)
        self._log(f'   bf_key cand: first16={bf_first16} prejson={bf_prejson} postjson={bf_postjson}', addr)
        if   BF_KEY_SOURCE == 'blob'     and bf_blob:
            bf_key = bytes.fromhex(bf_blob)
        elif BF_KEY_SOURCE == 'first16'  and bf_first16:
            bf_key = bytes.fromhex(bf_first16)
        elif BF_KEY_SOURCE == 'prejson'  and bf_prejson:
            bf_key = bytes.fromhex(bf_prejson)
        elif BF_KEY_SOURCE == 'postjson' and bf_postjson:
            bf_key = bytes.fromhex(bf_postjson)
        else:
            bf_key = None   # 'session': derive_bf_key(session) внутри генератора

        # Кешируем варианты для этого addr
        key = addr
        if key not in self._sessions or self._sessions[key]['session'] != session:
            self._sessions[key] = {
                'session':  session,
                'variants': _make_variants(session),
                'vi':       0,
            }
        s = self._sessions[key]
        vi    = s['vi'] % len(s['variants'])
        desc, payload = s['variants'][vi]
        s['vi'] += 1

        req_id = info['request_id']

        # ── ШАГ 1: LoginSuccess, перебор ВАРИАНТОВ ФРЕЙМА по retry ───
        # Клиент ретраит Login #N — используем это как стенд: на каждую
        # попытку шлём следующий вариант обёртки. По логу увидим, на каком
        # (если на каком-то) клиент перестанет ретраить.
        # Frame-вариант A (checksum+prefix_hash+encrypted) ПОДТВЕРЖДЁН логом:
        # клиент дошёл до stage=1, значит обёртка верная. Пинуем его, чтобы все
        # retry слали один и тот же корректный фрейм (а не перебор вариантов).
        fi = 0
        wc, pmode, enc, fdesc = FRAME_VARIANTS[fi]
        success_pkt = generate_login_success_packet(
            req_id, session,
            baseapp_ip=BASEAPP_IP,
            baseapp_port=BASE_PORT,
            login_key=LOGIN_KEY,
            encrypt_success=enc,
            with_checksum=wc,
            prefix_mode=pmode,
            bf_key=bf_key,
        )
        self._server_seq += 1
        self._log(f'   >> LoginSuccess [{fdesc}] {len(success_pkt)}B', addr)
        self._log(f'      success hex = {success_pkt.hex(" ")}', addr)
        self.sock.sendto(success_pkt, addr)

        # ── ШАГ 2 (опц.): LoginRedirect отдельным пакетом ────────────
        if SEND_SEPARATE_REDIRECT:
            time.sleep(REDIRECT_DELAY_SEC)   # клиенту время на расшифровку
            redirect_pkt = generate_login_redirect_packet(
                req_id,
                baseapp_ip=BASEAPP_IP,
                baseapp_port=BASE_PORT,
                login_key=LOGIN_KEY,
            )
            self._server_seq += 1
            self._log(f'   >> LoginRedirect {len(redirect_pkt)}B  (+{int(REDIRECT_DELAY_SEC*1000)}ms)', addr)
            self._log(f'      redirect hex = {redirect_pkt.hex(" ")}', addr)
            self.sock.sendto(redirect_pkt, addr)


# ───────────────────────────────────────────────────────────────
#  BaseApp stub  (UDP 20017)
#  Клиент подключается сюда ПОСЛЕ успешного LoginApp.
#  Нам нужно ответить на initial handshake чтобы C++ создал
#  Account entity через onBecomePlayer.
# ───────────────────────────────────────────────────────────────
class BaseAppStub:

    def __init__(self, def_manager):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, BASE_PORT))
        self.sock.settimeout(0.5)
        self._log_path  = os.path.join(LOG_DIR, 'baseapp.log')
        self._seq       = 0
        self._clients   = {}  # addr → BaseAppHandshake (SYN→ACK автомат)
        self.handler = BaseAppHandler(def_manager=def_manager)
        
        # Entity System
        if ENTITY_ADDON:
            self.entity_system = EntitySystemAddon()
            self.entity_system.initialize()
        print(f'[BASE]  Listening  UDP {HOST}:{BASE_PORT}')

    def _log(self, msg: str, addr=None, level: str = 'INFO'):
        tag  = f'[{addr[0]}:{addr[1]}]' if addr else ''
        line = f'[{level}]{tag} {msg}'
        print(f'[BASE]  {line}')
        try:
            with open(self._log_path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception:
            pass

    def run(self):
        with open(self._log_path, 'w', encoding='utf-8') as f:
            f.write(f'=== Started {time.strftime("%Y-%m-%d %H:%M:%S")} ===\n')
        self._log('BaseApp stub started')
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._dispatch(data, addr)
            except socket.timeout:
                continue
            except Exception:
                traceback.print_exc()

    def _dispatch(self, data: bytes, addr):
        self._log(f'<< Recv {len(data)}B hex={data[:32].hex(" ")}', addr)

        flags = struct.unpack_from('<H', data, 4)[0] if len(data) >= 6 else 0

        hs = self._clients.get(addr)
        if hs is None:
            hs = BaseAppHandshake()
            self._clients[addr] = hs

        # Проверяем наличие флага HAS_REQUESTS (0x0001)
        if (flags & 0x0001) and len(data) >= 11: # BASEAPP_REPLYID_OFFSET обычно 7
            
            # --- ВЫЗЫВАЕМ ТВОЙ ХЕНДЛЕР ---
            reply, info = self.handler.handle_baseapp_login(data, addr)
            
            if reply:
                self._log(f'>> baseAppLogin REPLY ({len(reply)}B) '
                          f'hex={reply.hex(" ")}', addr)
                self.sock.sendto(reply, addr)
            
            # Если нужно — сохраняем данные сессии в hs или self._clients[addr]
            # hs.session_info = info 
            
        else:
            # маленький/без-request пакет → пустой канальный ACK
            reply = hs.build_ack(0)
            self._log(f'>> ACK ({len(reply)}B)', addr)
            self.sock.sendto(reply, addr)

    def _send_ack(self, addr, req_id: int, client_seq: int):
        """Пустой ACK — подтверждаем что пакет получен."""
        pkt = build_bw_packet(b'', is_on_channel=True, seq_num=self._seq, last_rel=client_seq)
        self._seq += 1
        self.sock.sendto(pkt, addr)
        self._log(f'>> ACK ({len(pkt)}B)', addr)

    def _send_prereq_reply(self, addr, req_id: int, client_seq: int):
        """
        Ответ на prerequisite запрос клиента.
        Структура: [prereq_count:1][str0...strN][reason:1]
        prereq_count=0 → нет prerequisites, reason=0 → OK.
        """
        prereq_payload = bytearray()
        prereq_payload.append(0)   # prereq_count = 0  (пустой список)
        prereq_payload.append(0)   # reason = 0 (success)

        elem = build_reply_element(req_id, bytes(prereq_payload))
        pkt = build_bw_packet(elem, is_on_channel=True, seq_num=self._seq, last_rel=client_seq)
        self._seq += 1
        self.sock.sendto(pkt, addr)
        self._log(f'>> PrereqReply ({len(pkt)}B) req_id={req_id} hex={pkt.hex(" ")}', addr)


# ───────────────────────────────────────────────────────────────
#  Точка входа
# ───────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────
# Точка входа
# ───────────────────────────────────────────────────────────────
def main():
    print()
    print('╔' + '═' * 58 + '╗')
    print('║  WoT/Mir Tankov 1.23 · BigWorld LoginApp+BaseApp stub   ║')
    print('║  Fixed: Variable32 element len · correct payload fmt    ║')
    print('╚' + '═' * 58 + '╝')
    print()

    # 1. Инициализация DefManager (парсер данных)
    print('[SYSTEM] Loading .def files...')
    def_manager = DefManager(root_path='.')
    def_manager.load()  # Загружаем структуры данных
    print(f'[SYSTEM] DefManager loaded with {len(def_manager)} entities')

    # 2. Инициализация BaseAppStub с передачей def_manager
    # Теперь конструктор BaseAppStub принимает наш def_manager
    base_stub = BaseAppStub(def_manager=def_manager)
    
    # 3. Запуск BaseApp в отдельном потоке
    base_thread = threading.Thread(target=base_stub.run, daemon=True, name='BaseApp')
    base_thread.start()

    # 4. Запуск LoginApp (блокирующий вызов)
    login_app = LoginApp()
    login_app.run() 


if __name__ == '__main__':
    main()
