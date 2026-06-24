# 🎮 WoT 1.23 Offline Emulator — PROJECT STATE

**Дата:** 2026-06-24 (обновлено Sai)
**Статус:** 🟡 BaseApp: применён FIX #6 (prefix_offset), ждём прогон №6
**Версия клиента:** 1.23.0.6
**Реальный путь запуска у юзера:** C:\Users\fsociety\Desktop\unpack\server\
**Рабочая копия (правит Sai):** C:\server\  → юзер копирует файлы к себе

---

## ✅ ТЕКУЩЕЕ СОСТОЯНИЕ

- **LoginApp (:20014)** — 100% работает. Клиент логинится, `BigWorld.connect returned OK`.
- **BaseApp (:20017)** — канал почти встал. Клиент доходит до BaseApp, lobby-движок
  грузится (lobby.swf, LoginSpace), шкала подключения заполняется.
- **Блокер до FIX #6:** клиент дропал ВСЕ ответы BaseApp →
  `LOGIN_REJECTED_NO_BASEAPP_RESPONSE` (таймаут 40с).

---

## 🔧 ФИКСЫ, ВНЕСЁННЫЕ СЕГОДНЯ (server_stub.py)

1. **Убран брут-форс 9 вариантов** → один детерминированный SessionKey(0x01)-reply
   по эталону wg-toolkit (theorzr/wg-toolkit-rs, base/element.rs).
2. **Офсеты парсинга входящего LoginKey:** `elt_id = data[6]` (был 12),
   `request_id = data[7]` (был 6). Framing: prefix(4) flags(2)@4 msgid@6 replyID@7.
3. **Подключён _send_player_bootstrap** после SessionKey (CreateBasePlayer /
   receiveProperties / showGUI), один раз на addr, помечается только при успехе.
4. **Импорт build_receive_properties_element** из account_properties (был NameError).
5. **Импорт build_show_gui_payload** из show_gui на верхний уровень (был NameError).
6. **★ ГЛАВНЫЙ: prefix_offset исходящих = client_offset** (был 0).
   - `ch.prefix_offset = client_offset` сохраняется в _dispatch
   - SessionKey reply: prefix_offset=client_offset
   - _send_on_channel: prefix_offset=ch.prefix_offset
   Причина: клиент использует НЕнулевой per-connection offset (выдан при логине,
   восстанавливается через _recover_prefix_offset). С offset=0 клиент считал
   другой ожидаемый prefix и дропал пакеты. Симптом совпал с docstring _prefix_hash.

---

## ⏭️ СЛЕДУЮЩИЙ ШАГ — прогон №6

Запустить сервер+клиент, прислать серверный `logs/baseapp.log`. Маркеры успеха:
- Клиент ПЕРЕСТАЁТ слать LoginKey (elt_id=0x00), присылает on-channel (ACK/др. elt_id).
- В клиенте лобби открывается (золото/серебро, карусель танков) вместо NO_BASEAPP_RESPONSE.

Если FIX #6 не сработал (клиент всё ещё дропает):
- Проверить НАПРАВЛЕНИЕ offset (server→client RX vs client→server TX могут отличаться).
- Проверить формулу _prefix_hash против wg-toolkit packet.rs::update_prefix.
- Последний кандидат: Blowfish-шифрование канала (но входящие LoginKey — plaintext,
  так что шифрование скорее НЕ нужно на этой стадии).

Если FIX #6 сработал → Фаза 2: TickSync, корректный CreateBasePlayer/receiveProperties,
PropertyUpdate (золото/серебро через account_properties.py + database.json).

---

## 🔑 ПОЛЕЗНЫЕ ФАКТЫ

- Blowfish-ключ (из loginapp.log, parsed blob): 954b19d4427e94e5b957ac9845f3e46f
- LoginApp выдаёт login_key=0x00000001, но клиент в BaseApp шлёт login_key=0
  (для оффлайна это ок, валидация не нужна).
- Эталон протокола: github.com/theorzr/wg-toolkit-rs
  (wg-toolkit/src/net/app/base/{element,mod}.rs, login/element.rs).
- LoginKey(0x00) Fixed(7): login_key u32 + attempt u8 + unk u16.
- Ответ = SessionKey(0x01) Fixed(4): session_key u32, как REPLY (reply_id=request_id).
- Серверные логи: C:\server\logs\ (baseapp.log, baseapp_packets.hex = сырые входящие).
- Клиентский лог: python.log клиента (WorldOfTanks), показывает stage/status.
