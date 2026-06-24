#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
account_properties.py — receiveProperties через AccountEditor.def

КАК ЭТО РАБОТАЕТ:
  Account.py клиента имеет метод receiveProperties(self, data).
  Сервер вызывает его через Entity Method Call элемент.

  Структура элемента (server→client, on-channel):
    [element_id : 1B]   — первый "exposed" client method index
                          в BigWorld = 0x0C + method_index_in_Account_exposed_list
                          receiveProperties = первый метод AccountEditor → index=0
                          Если не реагирует — пробуй 0x0C, 0x0D, 0x10, 0x28
    [var16 len  : 1-3B] — Variable16(len(entity_id + sub_id + pickle))
    [entity_id  : 4B LE]
    [sub_id     : 1B]   — индекс метода внутри entity (0)
    [pickle     : NB]   — cPickle.dumps(payload, protocol=2)

  Кадруется в build_bw_packet(is_on_channel=True) как обычный element.

КЛЮЧЕВОЙ ФАКТ: данные stats+inventory+serverSettings можно передавать
  ДВУМЯ путями одновременно:
  1. Через initial_server_settings в createBasePlayer (уже делаем).
  2. Через этот отдельный вызов receiveProperties (добавляем).
  Клиент примет тот что распарсит первым — безопасно слать оба.
"""

import json
import os
import pickle
import struct
import time

# ── Настройки ──────────────────────────────────────────────────────────────

_HERE    = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(_HERE, 'database.json')

# element_id для entity method call.
# BigWorld client iface (server→client) после системных элементов:
#   0x00 AUTHENTICATE  0x04 RESET_ENTITIES  0x05 CREATE_BASE_PLAYER
#   0x06 CREATE_CELL_PLAYER  0x0B CREATE_ENTITY
# Entity exposed methods начинаются с 0x0C.
# receiveProperties = первый exposed метод → element_id = 0x0C.
# Если клиент не реагирует: попробуй 0x0D, 0x10, 0x28.
ENTITY_METHOD_BASE  = 0x0C
RECV_PROPS_SUB_ID   = 0     # позиция receiveProperties в exposed list Account.def


# ── Утилиты ────────────────────────────────────────────────────────────────

def _load_db(path: str = DB_PATH) -> dict:
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def _var16(val: int) -> bytes:
    """BigWorld Variable16: <128 → 1B, иначе 2B."""
    if val < 0x80:
        return bytes([val])
    return bytes([0x80 | (val >> 8), val & 0xFF])


def _build_payload(db: dict) -> dict:
    """
    Словарь для receiveProperties.
    Клиент читает: stats (золото/кредиты/опыт/слоты),
    vehiclesData (инвентарь), serverSettings (флаги/урлы).
    """
    py   = db.get('PYTHON', {})
    st   = py.get('stats', {})
    inv  = py.get('inventory', {})
    ss   = py.get('serverSettings', {})

    return {
        # Финансы
        'gold':      st.get('gold',    999999),
        'credits':   st.get('credits', 999999999),
        'freeXP':    st.get('freeXP',  999999),
        'slots':     st.get('slots',   10),
        'berths':    st.get('berths',  20),
        'clanInfo':  st.get('clanInfo',  ['', '', 0, 0, 0]),
        'accLvlInfo': st.get('accLvlInfo', [0, 0, 0]),

        # Инвентарь (ключи — int compactDescr)
        'vehiclesData': {int(k): v for k, v in inv.get('vehicles', {}).items()},

        # Настройки сервера — всё что есть
        **{k: v for k, v in ss.items() if not k.startswith('_')},
    }


# ── Главная функция ─────────────────────────────────────────────────────────

def build_receive_properties_element(
    entity_id: int,
    db_path:   str = DB_PATH,
    sub_id:    int = RECV_PROPS_SUB_ID,
) -> tuple[bytes, dict]:
    """
    Строит bytes element для receiveProperties (готов к передаче в build_bw_packet).

    Возвращает (element_bytes, debug_dict).
    """
    db      = _load_db(db_path)
    payload = _build_payload(db)
    pkl     = pickle.dumps(payload, protocol=2)  # protocol=2 — Python 2.7 совместимый

    element_id = ENTITY_METHOD_BASE + sub_id     # 0x0C для sub_id=0

    # inner = entity_id(4B LE) + sub_id(1B) + pickle
    inner = struct.pack('<I', entity_id) + bytes([sub_id]) + pkl

    elem  = bytes([element_id]) + _var16(len(inner)) + inner

    dbg = {
        'element_id': element_id,
        'sub_id':     sub_id,
        'entity_id':  entity_id,
        'pkl_len':    len(pkl),
        'total':      len(elem),
        'gold':       payload.get('gold'),
        'vehicles':   list(payload.get('vehiclesData', {}).keys()),
    }
    return elem, dbg


def send_receive_properties(
    sock,
    addr,
    entity_id:         int,
    prefix_offset:     int,
    seq_num:           int,
    build_bw_packet_fn,          # build_bw_packet из server_stub.py
    last_rel:          int = 0,
    db_path:           str = DB_PATH,
    log_fn             = None,
) -> int:
    """
    Строит и отправляет receiveProperties клиенту.
    Возвращает новый seq_num.
    """
    elem, dbg = build_receive_properties_element(entity_id, db_path)

    pkt = build_bw_packet_fn(
        elem,
        is_on_channel  = True,
        seq_num        = seq_num,
        last_rel       = last_rel,
        prefix_offset  = prefix_offset,
    )
    sock.sendto(pkt, addr)

    if log_fn:
        log_fn(
            f'>> receiveProperties ({len(pkt)}B) '
            f'elem_id=0x{dbg["element_id"]:02X} sub_id={dbg["sub_id"]} '
            f'entity={dbg["entity_id"]} pkl={dbg["pkl_len"]}B '
            f'gold={dbg["gold"]} vehicles={dbg["vehicles"]}',
            addr
        )
    return seq_num + 1