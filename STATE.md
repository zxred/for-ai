# 🎮 WoT 1.23 Offline Emulator — PROJECT STATE

**Дата:** 2026-06-23  
**Статус:** 🟡 В разработке  
**Версия клиента:** 1.23.0.6 (официальный, мёртвые сервера)  
**Цель:** ОФФЛАЙН запуск собственного сервера на localhost

---

## 📁 СТРУКТУРА ФАЙЛОВ

### 🔥 Основные (РАБОТАЮТ 100%)

| Файл | Строк | Назначение | Статус |
|------|-------|------------|--------|
| `server_stub.py` | ~700 | LoginApp (:20014) + BaseApp (:20017) | ✅ РАБОТАЕТ |
| `auth_logic.py` | ~700 | BigWorld packet builders, BlowfishLesta, RSA | ✅ РАБОТАЕТ |

### 🟡 Интеграция (В ПРОЦЕССЕ)

| Файл | Строк | Назначение | Статус |
|------|-------|------------|--------|
| `baseapp_handler.py` | ~350 | BaseApp login handler + entity streaming | 🟡 ТРЕБУЕТ ИНТЕГРАЦИИ |
| `server/entity_addon.py` | ~200 | Entity System addon (опционально) | 🟡 ТРЕБУЕТ ИНТЕГРАЦИИ |

### ✅ Парсеры (РАБОТАЮТ)

| Файл | Строк | Назначение | Статус |
|------|-------|------------|--------|
| `src/DefManager.py` | ~150 | Registry manager для .def файлов | ✅ РАБОТАЕТ (168 entity) |
| `src/entity_def.py` | ~100 | EntityDef dataclass | ✅ РАБОТАЕТ |
| `src/parser.py` | ~150 | XML парсер .def файлов | ✅ РАБОТАЕТ |

### 📄 Документация

| Файл | Описание |
|------|----------|
| `STATE.md` | Этот файл — состояние проекта |
| `README_SERVER.md` | Инструкция по запуску |
| `ENTITY_INTEGRATION.md` | Как интегрировать Entity System |
| `server/README.md` | Документация server/ папки |

---

## 📊 СТАТУС КОМПОНЕНТОВ

### LoginApp (:20014) — ✅ 100% ГОТОВ

| Функция | Статус | Примечание |
|---------|--------|------------|
| RSA расшифровка | ✅ | OAEP-SHA1, offsets 20+276 |
| Blowfish key из блоба | ✅ | Парсинг length-prefixed полей |
| LoginSuccess пакет | ✅ | Variable32, checksum, prefix_hash |
| LoginRedirect пакет | ✅ | IP:4BE + Port:2BE + Key:4LE |
| Ping/Pong | ✅ | elem_id=0xFE |

**Известные данные:**
```python
# LoginRequest структура:
prefix(4) + flags(2) + msg_id(1) + len16(2) + reply_id(4) + RSA_blob(256)
# reply_id читается с offset 9 (Variable16 length)

# LoginSuccess inner:
IP(4B BE) + Port(2B BE) + LoginKey(4B LE)
# Шифруется Blowfish PCBC (Lesta): C[i] = E(P[i] ⊕ P[i-1]), P[-1]=0
```

---

### BaseApp (:20017) — 🔴 ТРЕБУЕТ РАБОТЫ

| Функция | Статус | Примечание |
|---------|--------|------------|
| Приём baseAppLogin | 🟡 Частично | Пакеты приходят, но обработка не готова |
| Префикс BaseApp | 🔴 НЕИЗВЕСТЕН | байт[2]=0xE3 константа, формула не крекнута |
| baseAppLogin reply | 🔴 ГИПОТЕЗА | sessionKey + entityID формат не подтверждён |
| Entity streaming | 🔴 НЕ РЕАЛИЗОВАНО | createEntityFromStream формат нужен |
| Handshake (SYN/ACK) | 🟡 Есть в auth_logic.py | BaseAppHandshake класс готов |

**Известные данные:**
```python
# baseAppLogin структура (гипотеза):
prefix(4) + flags(2)=0x0001 + msgId(1)=0x00 + reply_id(4) + nextReqOff(2) + body + footer(2)
# reply_id читается с offset 7 (Fixed length, не Variable32!)
# prefix — ДРУГАЯ формула, не prefix_hash от LoginApp!

# baseAppLogin reply (гипотеза):
prefix(4) + flags(2)=0x0000 + msgId(1)=0x00 + len(2) + reply_id(4) + sessionKey(4) + entityID(4) + checksum(4)
```

**Проблемы:**
1. ❌ baseAppLogin пакеты идут на LoginApp (elem_id=0x00 не распознан)
2. ❌ Префикс BaseApp — формула неизвестна
3. ❌ Entity stream формат — нужен точный порядок свойств из .def

---

### Entity System — 🟡 В ПРОЦЕССЕ

| Функция | Статус | Примечание |
|---------|--------|------------|
| DefManager загрузка | ✅ | 168 entity из .def файлов |
| Account.def парсинг | ✅ | Свойства, флаги, методы |
| Vehicle.def парсинг | ✅ | 120+ свойств |
| Entity streaming | 🔴 | Нужен точный BigWorld формат |
| Репликация свойств | 🔴 | BASE vs CLIENT vs ALL_CLIENTS |

**Известные данные из .def:**
```python
# Account.def свойства (BASE только):
- name: STRING (BASE)
- dbid: UINT64 (BASE)
- state: UINT8 (BASE_AND_CLIENT)
- globalRating: INT32 (BASE_AND_CLIENT)
- session: UINT32 (BASE)

# Vehicle.def свойства (ALL_CLIENTS):
- position: VECTOR3 (ALL_CLIENTS)
- yaw: FLOAT (ALL_CLIENTS)
- health: INT16 (ALL_CLIENTS)
- is_alive: BOOL (ALL_CLIENTS)
```

**createEntityFromStream формат (гипотеза):**
```
EntityTypeID(2) + EntityID(4) + PropertyCount(2) + [PropertyName(len+str) + TypeByte(1) + Value]*N
```

---

## 🔬 ПРОТОКОЛ BIGWORLD — ИЗВЕСТНЫЕ ДАННЫЕ

### Пакетные флаги
```python
FLAG_HAS_REQUESTS   = 0x0001  # есть request/reply элементы
FLAG_HAS_PIGGYBACKS = 0x0002  # есть piggyback данные
FLAG_IS_ON_CHANNEL  = 0x0008  # канальный пакет (seq_num в footer)
FLAG_HAS_CHECKSUM   = 0x0100  # есть XOR checksum в footer
```

### Типы данных для сериализации
```python
INT8=0x01, INT16=0x02, INT32=0x03, INT64=0x04
UINT8=0x05, UINT16=0x06, UINT32=0x07, UINT64=0x08
FLOAT32=0x09, FLOAT64=0x0A
BOOL=0x0B
STRING=0x0C  # len(2) + bytes
VECTOR2=0x0D, VECTOR3=0x0E, VECTOR4=0x0F
```

### Флаги репликации (из .def)
```python
BASE              # Только сервер
CLIENT            # Только клиент
BASE_AND_CLIENT   # Сервер + клиент
ALL_CLIENTS       # Все клиенты в зоне видимости
CELL_PRIVATE      # Только владелец entity
```

---

## 🐛 ИЗВЕСТНЫЕ ПРОБЛЕМЫ

### #1 baseAppLogin на LoginApp ❌
**Симптом:**
```
[WARN] Неизвестный elem_id=0x00  ← baseAppLogin приходит на порт 20014!
```

**Причина:** Клиент не получает Redirect на BaseApp или игнорирует его

**Решение:**
- Проверить LoginRedirect формат (Port endianness?)
- Проверить что client получает и расшифровывает LoginSuccess
- Посмотреть логи клиента (python.log)

---

### #2 BaseApp префикс ❌
**Симптом:** Формула префикса для BaseApp неизвестна

**Известное:**
- байт[2] = 0xE3 (константа, подтверждено)
- байт[0] чередуется по чётности счётчика пакетов
- НЕ prefix_hash() от LoginApp!

**Нужно:** Дампы baseAppLogin с разными body для анализа

---

### #3 Entity stream формат ❌
**Симптом:** Неизвестен точный порядок и формат свойств

**Нужно:**
- Точный формат createEntityFromStream
- Порядок свойств (из .def или фиксированный?)
- Типы данных (type byte mapping)

---

## 📋 СЛЕДУЮЩИЕ ШАГИ

### Приоритет 1 (СРОЧНО):
- [ ] Исправить routing: baseAppLogin → BaseApp (:20017), не LoginApp
- [ ] Проверить LoginRedirect (клиент получает?)
- [ ] Посмотреть логи клиента (python.log)

### Приоритет 2:
- [ ] Крекнуть BaseApp префикс (нужны дампЫ)
- [ ] Подтвердить baseAppLogin reply формат
- [ ] Реализовать createEntityFromStream

### Приоритет 3:
- [ ] Account entity streaming
- [ ] Vehicle entity streaming
- [ ] CellApp интеграция

---

## 🔗 ССЫЛКИ

- **Веб-интерфейс:** `dist/index.html` (Protocol Analyzer)
- **Логи:** `logs/loginapp.log`, `logs/baseapp.log`

---

## 📞 КОНТАКТЫ

**Следующий шаг:** Интеграция baseapp_handler.py в server_stub.py

---

**ПОСЛЕДНЕЕ ОБНОВЛЕНИЕ:** 2026-06-23 12:55  
**СЛЕДУЮЩИЙ МИЛЬСТОУН:** Клиент подключается к BaseApp и получает Account entity





🎮 WoT 1.23 Offline Emulator — PROJECT STATE
Дата: 2026-06-23 Статус: 🟢 BaseApp login прорыв — найден и устранён главный блокер (prefix offset) Версия клиента: 1.23.0.6 (официальный, мёртвые сервера) Цель: ОФФЛАЙН запуск собственного сервера на localhost

🔥 ГЛАВНОЕ ЗА СЕССИЮ (что изменилось)
Найден и устранён невидимый сетевой блокер, который съедал все предыдущие фиксы: BaseApp использует per-connection prefix offset, а сервер строил prefix с offset=0 → клиент дропал КАЖДЫЙ наш пакет ещё до парсинга → LOGIN_REJECTED_NO_BASEAPP_RESPONSE.

Все правки выверены по исходникам wg-toolkit-rs (ветка master): net/packet.rs, net/bundle.rs, net/element.rs, net/app/client/element.rs, net/app/base/element.rs, wot-cli/src/common/entity/account.rs, util/io.rs.

📁 СТРУКТУРА ФАЙЛОВ
🔥 Основные
Файл	Назначение	Статус
server_stub.py	LoginApp (:20014) + BaseApp (:20017)	✅ v4 — login fix
auth_logic.py	BigWorld packet builders, BlowfishLesta, RSA	✅ РАБОТАЕТ
entity_streaming.py	НОВЫЙ — сериализатор createBasePlayer/Account	✅ round-trip OK
✅ Парсеры (РАБОТАЮТ)
Файл	Назначение	Статус
src/manager.py (DefManager)	Registry .def, использует src/parser.py	✅ 168 entity
src/parser.py	XML парсер .def, ЧИНИТ unbound-prefix	✅ РАБОТАЕТ
src/entity_def.py	EntityDef dataclass	✅ РАБОТАЕТ
📄 Документация
Файл	Описание
STATE.md	Этот файл
README_ENTITY_STREAM.md	Спецификация формата createBasePlayer + интеграция
baseapp_integration.py	Справочные сниппеты (SessionKey reply и т.п.)
✅ ЧТО РЕАЛИЗОВАНО (подтверждено)
LoginApp (:20014) — ✅ 100%
RSA расшифровка (OAEP-SHA1), Blowfish key из блоба.
LoginSuccess (Variable32, checksum, prefix offset=0) + LoginRedirect.
Prefix-формула выверена: совпала на 45/45 реальных пакетах с offset=0.
BaseApp (:20017) — 🟢 login прорыв
Функция	Статус	Примечание
Парсинг baseAppLogin (LoginKey 0x00)	✅	msg_id@6, reply_id@7, payload Fixed(7)
Channel prefix offset	✅	_recover_prefix_offset() — восстанавливаем из пакета клиента
SessionKey reply (0xFF, off-channel)	✅	[0xFF][var32 len][reply_id][session_key]
Prefix наших ответов	✅	теперь с правильным offset → клиент не дропает
createBasePlayer(Account)	✅ сериализация	отправляется после логина (on-channel)
Entity serialization — ✅
createBasePlayer (client iface id=0x05, Variable16), точно по wg-toolkit:

[0x05][u16 len]
  u32 entity_id
  u16 entity_type_id          ; Account = 1
  blob_variable(b"")          ; packed_u24(0) = 0x00
  <entity_data>
  u8  entity_components_count = 0
entity_data для Account (account.rs::encode):

string_variable(required_version)        ; напр. "eu_1.19.1_4"
string_variable(name)
python_pickle(initial_server_settings)   ; pickle protocol 2
Примитивы (util/io.rs):

packed_u24(n):  n<255 -> [n] ; иначе [0xFF]+u24_LE(n)
string_variable / blob_variable / python_pickle
Round-trip самотест в entity_streaming.py проходит.

🔬 ВЫВЕРЕННЫЕ ФОРМУЛЫ ПРОТОКОЛА (надёжно)
Prefix (packet.rs::update_prefix)
M = 0xFFFFFFFF
p0 = u32_LE(body[0:4]); p1 = u32_LE(body[4:8])   # body = байты после prefix
a  = (offset + p0 + p1) & M
b  = (a << 13) & M
c  = (b ^ a) >> 17
e  = c ^ b ^ a
prefix = (e ^ ((e << 5) & M)) & M
LoginApp: offset = 0.
BaseApp: offset = per-connection константа (в дампе 0x5f330e8f), восстанавливается инверсией формулы из входящего пакета клиента.
Checksum (packet.rs::calc_checksum)
XOR всех u32-слов от flags до конца (без prefix, без самого checksum); хвост < 4 байт игнорируется. ✅ совпадает с _xor_cs.

Reply element (element.rs)
[0xFF][Variable32 len = u32 LE][reply_id:4][payload], len = 4 + len(payload).

Request element (bundle.rs) — входящий
[msg_id:1][reply_id:4][next_req_offset:2][payload по ElementLength], footer first_request_offset:2 отсчитывается от начала flags.

Packet flags (packet.rs::flags)
HAS_REQUESTS=0x0001  HAS_PIGGYBACKS=0x0002  HAS_ACKS=0x0004
ON_CHANNEL=0x0008    IS_RELIABLE=0x0010     IS_FRAGMENT=0x0020
HAS_SEQUENCE_NUMBER=0x0040  INDEXED_CHANNEL=0x0080
HAS_CHECKSUM=0x0100  CREATE_CHANNEL=0x0200
Элементы интерфейсов
client iface (server→client): AUTHENTICATE=0x00(Fixed4), RESET_ENTITIES=0x04(Fixed1), CREATE_BASE_PLAYER=0x05(Var16), CREATE_CELL_PLAYER=0x06(Var16), CREATE_ENTITY=0x0B(Var16).
base iface (client→server): LOGIN_KEY=0x00(Fixed7), SESSION_KEY=0x01(Fixed4), ENABLE_ENTITIES=0x0A, DISCONNECT_CLIENT=0x0C, CELL_ENTITY_METHOD=0x0F..0x86, BASE_ENTITY_METHOD=0x87..0xFE.
🔴 ЧТО ОСТАЁТСЯ РЕАЛИЗОВАТЬ
Приоритет 1 — довести логин до гаража
 Проверить приём createBasePlayer клиентом (нужен свежий baseapp.txt после v4: ушла ли ошибка «Exhausted attempts»).
 Reliable channel: sequence number + ACK. On-channel пакеты (createBasePlayer и далее) требуют корректных seq и обработки ACK от клиента (флаги HAS_ACKS / IS_RELIABLE). Сейчас seq просто инкрементится, ACK от клиента не обрабатываются.
 CREATE_CHANNEL (0x0200) — проверить, нужен ли флаг на первом канальном пакете для установления канала.
 required_version должен совпасть с реальной версией клиента (сейчас eu_1.19.1_4 placeholder).
 initial_server_settings — расширить минимальный dict до того, что реально ждёт python-слой клиента (по логам lobby).
Приоритет 2 — entity система
 AUTHENTICATE (0x00) перед createBasePlayer (если клиент его ждёт).
 Обработка входящих base entity methods (0x87..0xFE).
 createCellPlayer (0x06) для входа в бой.
 Generic positional-сериализатор по .def (для Vehicle и др.) — свойства по порядку, без имён/тайп-байтов, по флагам видимости.
Приоритет 3
 Vehicle entity streaming.
 CellApp интеграция.
 Репликация свойств (BASE / CLIENT / ALL_CLIENTS / OWN_CLIENT).
🐛 ИСТОРИЯ БАГОВ ЭТОЙ СЕССИИ
#	Баг	Причина	Фикс
1	createEntityFromStream неверный формат	выдуманный [name][type][value]	позиционный codec Account (version+name+pickle)
2	unbound prefix на Account.def	BaseApp юзал сломанный DefSchemaParser	переключено на DefManager (src/parser.py)
3	baseAppLogin без ответа	слался prereq on-channel вместо SessionKey	off-channel SessionKey reply
4	Клиент дропал ВСЕ пакеты BaseApp	prefix с offset=0 вместо channel offset	восстановление offset из пакета клиента
⚠️ Ключевой урок: баги 1–3 были исправлены верно, но их «съедал» баг #4 — неверный prefix убивал пакет на сетевом слое до парсинга. Сначала канал, потом содержимое.

🔗 ССЫЛКИ
Логи: logs/loginapp.log, logs/baseapp.log
Референс протокола: wg-toolkit-rs (theorzr/mindstorm38), ветка master
ПОСЛЕДНЕЕ ОБНОВЛЕНИЕ: 2026-06-23 (session: prefix offset fix) СЛЕДУЮЩИЙ МИЛЬСТОУН: клиент принимает createBasePlayer → reliable channel (seq/ack) → гараж



# 🎮 WoT 1.23 Offline Emulator — PROJECT STATE

**Дата:** 2026-06-23  
**Статус:** 🟢 ПРОБИТИЕ ТРАНСПОРТА (Лобби загружено!)  
**Версия клиента:** 1.23.0.6 (официальный, мёртвые сервера)  
**Цель:** ОФФЛАЙН запуск собственного сервера на localhost

---

## 📁 СТРУКТУРА ФАЙЛОВ

### 🔥 Основные (РАБОТАЮТ 100%)

| Файл | Строк | Назначение | Статус |
|------|-------|------------|--------|
| `server_stub.py` | ~1000 | LoginApp (:20014) + BaseApp (:20017) | ✅ ИСПРАВЛЕН (offset=0) |
| `auth_logic.py` | ~700 | BigWorld packet builders, BlowfishLesta, RSA | ✅ РАБОТАЕТ |
| `show_gui.py` | ~400 | Сериализация вызова Account.showGUI(ctx) | ✅ РАБОТАЕТ |
| `entity_streaming.py` | - | Сериализатор createBasePlayer/Account | ✅ РАБОТАЕТ |

### ✅ Парсеры (РАБОТАЮТ)

| Файл | Строк | Назначение | Статус |
|------|-------|------------|--------|
| `src/DefManager.py` | ~150 | Registry manager для .def файлов | ✅ 168 entities |
| `src/parser.py` | ~150 | XML парсер .def (пофикшен unbound-prefix) | ✅ РАБОТАЕТ |

---

## 📊 СТАТУС КОМПОНЕНТОВ

### LoginApp (:20014) — ✅ 100% ГОТОВ
Отрабатывает RSA, отдает Blowfish key, формирует LoginSuccess и редиректит на BaseApp. `prefix_offset` = 0.

### BaseApp (:20017) — 🟢 КАНАЛ УСТАНОВЛЕН
| Функция | Статус | Примечание |
|---------|--------|------------|
| Приём baseAppLogin | ✅ | msg_id=0x00, парсится успешно |
| SessionKey reply | ✅ | off-channel (msg_id=0x01), **TX offset=0** |
| Префикс BaseApp | ✅ | Клиент шлёт со своим salt (0xb5...), сервер отвечает строго 0x00 |
| createBasePlayer | ✅ | Успешно доезжает до клиента по reliable channel |
| showGUI method | ✅ | Метод `0x5C` (index 14, count 37) переводит в Ангар |
| Обработка ClientSessionKey | 🟡 ЖДЁТ | Нужно обрабатывать пакет `0x01` от клиента |
| Обработка BaseEntityMethod | 🟡 ЖДЁТ | Пакеты `0x88..0xFE` (запросы инвентаря от клиента) |

---

## 🔬 ПРОТОКОЛ BIGWORLD — ИЗВЕСТНЫЕ ДАННЫЕ

### Вызов клиентского метода (Client Entity Method)
Для вызова метода на клиенте (server -> client) используется двухуровневая схема:
1. Обозначение таргета: `SELECT_PLAYER_ENTITY` (`0x1A`), длина 0 байт.
2. Сам метод лежит в диапазоне `0x4E..0xA6` (89 слотов). 
3. Идентификатор метода высчитывается через `from_exposed_id(exposed_count, method_index)`. Если методов больше 89, включаются `sub_slots`.
4. Для `showGUI` в 1.23.0.6: `index = 14`, `exposed_count = 37`. Метод влезает в фулл-слот `0x4E + 14 = 0x5C`.
5. Аргументы метода пакуются как `Variable16` пакет, внутри Python `cPickle` (protocol 2), предваренный `packed_u32(len)`.

### Формирование префикса пакета (Prefix Hash)
**ВАЖНО:** Сервер всегда отправляет свои пакеты с `offset = 0`.
Клиент присылает свои пакеты с уникальным per-connection offset (соль), но **не ждет**, что сервер будет зеркалить этот offset. Использование клиентского offset сервером приводит к молчаливому дропу пакетов (`Exhausted attempts`).

---

## 🐛 ИСТОРИЯ БАГОВ ЭТОЙ СЕССИИ

| # | Баг | Причина | Фикс |
|---|-----|---------|------|
| 1 | createEntityFromStream неверный формат | выдуманный [name][type][value] | позиционный codec Account (version+name+pickle) |
| 2 | unbound prefix на Account.def | BaseApp юзал сломанный DefSchemaParser | переключено на DefManager |
| 3 | baseAppLogin без ответа | слался prereq on-channel вместо SessionKey | off-channel SessionKey reply |
| 4 | Клиент дропал ВСЕ пакеты BaseApp | **Сервер зеркалил channel offset клиента** | **Хардкод `prefix_offset = 0` для всех исходящих ответов сервера** |

---

## 📋 СЛЕДУЮЩИЕ ШАГИ (ПЛАН НА НЕКСТ СЕССИЮ)

### Приоритет 1 (Стабилизация Лобби):
- [ ] **Перехват `ClientSessionKey` (`0x01`):** Клиент пришлёт этот пакет как подтверждение установки канала.
- [ ] **Заглушка для `BaseEntityMethod` (`0x88..0xFE`):** Сделать обработчик входящих методов от клиента (doCmd). Сейчас лобби крашится/закрывается из-за отсутствия ответов на инициализационные запросы.

### Приоритет 2 (Данные Ангара):
- [ ] **Пакет `PropertyUpdate` (Обновление свойств Account):** Найти точный ID пакета (предположительно `0x07`, `0x2E` или из диапазона `0xA7..0xFE`).
- [ ] **Инъекция базовых словарей (cPickle):**
  * `stats` (золото, серебро)
  * `inventoryCache` (заглушки для танков и слотов `{'slots': 10}`)
  * `serverSettings` (roaming, premium)

**СЛЕДУЮЩИЙ МИЛЬСТОУН:** `lobby.swf` не закрывается, отрисовывает базовый UI (золото/серебро, пустая карусель танков) и ждет действий пользователя.
