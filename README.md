# automotive-protocol-re

**ZCode-плагин для реверс-инжиниринга автомобильных диагностических и протоколов программирования ЭБУ** — от снятия «глубокого» лога с чужой программы до собственной, проверенной на живом блоке реализации протокола.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![ZCode plugin](https://img.shields.io/badge/ZCode-plugin-4B6EF5.svg)](#установка)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](#скрипты)

Изначально собран под практический кейс: **BMW BMS46 / DS2 / WinKFP / EDIABAS** (снятие сессии флешинга, разбор, реплика, прошивка чужого образа на стенде). Обобщён на весь класс задач «снять обмен с одной программы → разобрать → реализовать в другой»: KWP2000/KWP FAST, ISO 9141-2, KWP1281, UDS/ISO-TP/DoIP, TP2.0, J2534, J1850/CCD/SCI/MUT.

---

## Возможности

- **Глубокие логи**: логгер FTDI (D2XX через ctypes — без pip-зависимостей; VCP через pyserial; TCP — против симулятора), эхо-логика K-line, канонический формат лога (text + JSONL).
- **Перехват чужого ПО**: Frida-хуки COM и `ftd2xx.dll`, прокси-DLL для `FTD2XX.DLL`, прокси SAE J2534, рецепты USBPcap/Bus Hound/логического анализатора, штатные трассы EDIABAS.
- **Анализ**: нарезка кадров (DS2/KWP/по паузам/по строкам), автоподбор чексумм и CRC по корпусу логов, майнинг каталогов телеграмм из EXE, методика «от лога до спецификации».
- **Справочник**: DS2 (wire-verified таблица команд и полный flash-конвейер), EDIABAS (BEST/SGBD/трассы/API), KWP2000/ISO 14230 (5-baud и fast init), ISO 9141-2, KWP1281/KW71/TP2.0, UDS/ISO-TP/DoIP, J1850/CCD/SCI/MUT/ALDL, J2534 + шаблон спецификации протокола.
- **Реплика протокола**: транспорт-абстракция, строгий ACK, идемпотентные ретраи, «мёртвые окна», симулятор ЭБУ для офлайн-тестов, wire-верификация и recovery.

---

## Состав плагина

### Скиллы

| Скилл | Для чего |
|---|---|
| [`diag-protocol-re`](skills/diag-protocol-re/SKILL.md) | Главный маршрут: 8 фаз (опознание → захват → декод → спецификация → реплика → wire-верификация → recovery). Точка входа для любой задачи реверса. |
| [`deep-log-capture`](skills/deep-log-capture/SKILL.md) | Логгеры и перехват: FTDI D2XX/VCP, Frida, прокси `FTD2XX.DLL` и J2534, USB, анализаторы; канон формата лога. |
| [`log-analysis`](skills/log-analysis/SKILL.md) | Декодирование: framing, чексуммы/CRC, майнинг телеграмм, корреляция UI↔обмен, тайминги, сессионная машина. |
| [`protocol-reference`](skills/protocol-reference/SKILL.md) | Справочник протоколов с обязательными статусами достоверности (wire-verified / code-grounded / hypothesis). |
| [`protocol-replica-build`](skills/protocol-replica-build/SKILL.md) | Реализация: архитектура, строгий ACK, гейты безопасности, приёмка, восстановление. |

### Скрипты

| Скрипт | Что делает | Зависимости | Self-test |
|---|---|---|---|
| [`deep-log-capture/scripts/ftdi_kline_logger.py`](skills/deep-log-capture/scripts/ftdi_kline_logger.py) | Активный логгер/зонд: D2XX (ctypes), VCP, TCP; эхо; probe DS2; лестница скоростей; реплей «золотой трассы» | stdlib; опц. pyserial | `--selftest` |
| [`deep-log-capture/scripts/frida-serial-hook.js`](skills/deep-log-capture/scripts/frida-serial-hook.js) + [`frida-launch.py`](skills/deep-log-capture/scripts/frida-launch.py) | Перехват COM (`ReadFile/WriteFile`) и `ftd2xx.dll` (Frida 17-совместимо) | frida (опц.) | `--selftest` |
| [`deep-log-capture/scripts/ftd2xx_proxy/`](skills/deep-log-capture/scripts/ftd2xx_proxy/) | Прокси-`FTD2XX.DLL` с логом вызовов и байт (C + `.def` + `build.bat`) | MSVC/MinGW | — |
| [`deep-log-capture/scripts/j2534_proxy/`](skills/deep-log-capture/scripts/j2534_proxy/) | Прокси J2534 Pass-Thru с дампами `PASSTHRU_MSG` (C + `.def` + `build.bat`) | MSVC x86 | — |
| [`log-analysis/scripts/telegram_parse.py`](skills/log-analysis/scripts/telegram_parse.py) | Нарезка логов: диалекты (канон/Frida/EDIABAS), framing `ds2|kwp|gap:MS|line`, проверка CKS | stdlib | `--selftest` |
| [`log-analysis/scripts/checksum_solver.py`](skills/log-analysis/scripts/checksum_solver.py) | Автоподбор чексуммы/CRC (XOR/сумма/CRC8/CRC16) по корпусу кадров | stdlib | `--selftest` |
| [`log-analysis/scripts/mine_telegrams.py`](skills/log-analysis/scripts/mine_telegrams.py) | Поиск литеральных каталогов телеграмм в EXE/бинарях (`[addr][len][payload][cks]`) | stdlib | `--selftest` |
| [`protocol-replica-build/scripts/ds2_ecu_sim.py`](skills/protocol-replica-build/scripts/ds2_ecu_sim.py) | Симулятор ЭБУ DS2 по TCP (ident, чтения, авторизации, «мёртвое окно», busy-статусы) | stdlib | `--selftest` |

### Справочники (`skills/*/references/`)

- **Протоколы**: [`ds2-bmw.md`](skills/protocol-reference/references/ds2-bmw.md) (wire-verified), [`ediabas.md`](skills/protocol-reference/references/ediabas.md), [`kwp2000-iso14230.md`](skills/protocol-reference/references/kwp2000-iso14230.md), [`iso9141-2.md`](skills/protocol-reference/references/iso9141-2.md), [`kwp1281-kw71.md`](skills/protocol-reference/references/kwp1281-kw71.md), [`uds-isotp-doip.md`](skills/protocol-reference/references/uds-isotp-doip.md), [`legacy-buses.md`](skills/protocol-reference/references/legacy-buses.md), [`j2534.md`](skills/protocol-reference/references/j2534.md), [`TEMPLATE-protocol.md`](skills/protocol-reference/references/TEMPLATE-protocol.md)
- **Логи**: [`log-format.md`](skills/deep-log-capture/references/log-format.md), [`ftdi-d2xx.md`](skills/deep-log-capture/references/ftdi-d2xx.md), [`capture-layers.md`](skills/deep-log-capture/references/capture-layers.md)
- **Методика и плейбук**: [`methodology.md`](skills/log-analysis/references/methodology.md), [`playbook-bms46.md`](skills/protocol-replica-build/references/playbook-bms46.md)

---

## Установка

### Вариант 1 — как GitHub-маркетплейс

В репозитории есть корневой `marketplace.json`, поэтому его можно добавить в ZCode как источник каталога:

1. **Plugin Marketplace → Add → Add Plugin Marketplace**.
2. Указать репозиторий: `Ydjin1984/automotive-protocol-re`.
3. **Personal → automotive-protocol-re → Install**.

### Вариант 2 — локальный каталог

Склонировать репозиторий и добавить путь к его корню (или к каталогу, где лежит `marketplace.json`) как локальный маркетплейс; затем Install.

### Вариант 3 — вручную, только скиллы

Скопировать каталоги из `skills/` в `~/.agents/skills/` (или `<проект>/.zcode/skills/`) — скиллы подхватятся без плагина; скрипты/справочники продолжат работать по относительным путям внутри скиллов.

---

## Быстрый старт

```bash
# 1) Свой DS2-зонд через FT232 (или против симулятора — без железа)
python skills/protocol-replica-build/scripts/ds2_ecu_sim.py --port 5555          # терминал A
python skills/deep-log-capture/scripts/ftdi_kline_logger.py --tcp 127.0.0.1:5555 --probe-ds2

python skills/deep-log-capture/scripts/ftdi_kline_logger.py \
    --serial A1B2C3D4 --baud 9600 --parity even --latency 1 --ladder 125000,19200,9600 --probe-ds2

# 2) Разбор лога
python skills/log-analysis/scripts/telegram_parse.py --file capture.log --framing ds2 --json frames.json
python skills/log-analysis/scripts/checksum_solver.py --file capture.log

# 3) Майнинг каталога телеграмм из EXE
python skills/log-analysis/scripts/mine_telegrams.py --file app.exe --addr 0x12 --cluster

# 4) Перехват чужой программы
frida -f "C:\\path\\app.exe" -l skills/deep-log-capture/scripts/frida-serial-hook.js -o capture-live.log
```

---

## Принципы

1. **Сначала лог, потом теории.** Каждое утверждение спецификации помечается: `wire-verified` (подтверждено на живом ЭБУ), `code-grounded` (из кода/трасс ПО), `hypothesis`.
2. **Стенд — да, машина — только с явного разрешения.** Бэкап до любой записи, известный путь восстановления.
3. **Read-only first.** Запись/стирание — отдельные гейты (стёртая область → полный цикл) с подтверждением владельца.
4. **Строгий ACK.** Все операции записи во flash — идемпотентные ретраи, проверка «своего» ответа и жёсткий ABORT при неопределённости.

## Статус проверки

| Что | Статус |
|---|---|
| Python-скрипты (self-тесты, синтетические векторы, сквозной тест логгер↔симулятор по TCP) | ✅ проверено |
| Структурная валидация плагина (манифест, frontmatter, ссылки) | ✅ проверено |
| Frida-хук (синтаксис, Frida 17 API) | ✅ статически; на живом процессе не гонялся |
| C-прокси (`ftd2xx_proxy`, `j2534_proxy`) | ⚠️ код и `.def` готовы; сборка не выполнялась |
| Железные пути (реальный FT232, ЭБУ, стенд) | ⚠️ вне репозитория: на вашем стенде |

## Структура

```
automotive-protocol-re/
├── .zcode-plugin/plugin.json     # манифест ZCode-плагина
├── marketplace.json              # каталог (репо = маркетплейс из одного плагина)
├── icon.png                      # иконка (раздаётся через jsDelivr)
├── skills/
│   ├── diag-protocol-re/         # главный маршрут
│   ├── deep-log-capture/         # логгеры/перехват + references + scripts
│   ├── log-analysis/             # анализ + references + scripts
│   ├── protocol-reference/       # справочник протоколов + шаблон
│   └── protocol-replica-build/   # реплика + плейбук + симулятор
├── LICENSE
└── README.md
```

## Лицензия

MIT — см. [LICENSE](LICENSE). Автор: `lex66`.

---

## English summary

**automotive-protocol-re** is a ZCode plugin for reverse-engineering automotive diagnostic and ECU programming protocols: deep log capture (FTDI D2XX/VCP via ctypes, Frida hooks for COM/`ftd2xx.dll`, `FTD2XX.DLL` and SAE J2534 logging proxies, USB capture), log decoding (frame splitting, checksum/CRC recovery across a corpus, telegram-catalog mining from executables), a protocol reference (BMW DS2 — wire-verified, EDIABAS, KWP2000/ISO 14230 5-baud and fast init, ISO 9141-2, KWP1281/KW71/TP2.0, UDS/ISO-TP/DoIP, J1850/CCD/SCI/MUT, J2534), and a replica-building playbook (strict ACKs, idempotent retries, ECU simulator, wire acceptance, recovery). Every specification claim is labeled `wire-verified`, `code-grounded` or `hypothesis`.
