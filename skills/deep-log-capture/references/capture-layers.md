# Слои перехвата: Frida, прокси-DLL, J2534, USB, анализаторы

## 1. Сравнение слоёв

| Уровень | Что видно | Точность времени | Инструменты |
|---|---|---|---|
| Шина (аналог/логика) | сырые края, 5-baud init, коллизии | нс–мкс | Saleae/sigrok/Hantek, MCU-сниффер |
| USB (URB/bulk) | байты + 2-байтный FTDI-статус | мкс | USBPcap+Wireshark, Bus Hound |
| Драйвер D2XX | байты, настройки порта, rc | мс (latency) | прокси FTD2XX.DLL, Frida |
| ОС VCP | ReadFile/WriteFile, параметры DCB | мс | Frida, com0com, Eltima/HHD |
| Устройство J2534 | PASSTHRU_MSG (µs-таймстамп в структуре) | мкс (поле Timestamp) | прокси J2534, Fulcrum-подобные shim |
| Приложение EDIABAS | джобы + телеграммы INPUT/OUTPUT | мс (метки `#@`) | штатные трассы ifh.trc/api.trc |

Правило: чем ниже уровень, тем «сырее» и надёжнее лог, но тем дороже анализ. Для «снять с программы» начинай сверху (трассы), для «понять физику» — снизу (анализатор).

## 2. Frida (хуки API Windows)

Минимум для COM-порта:

```bash
frida-trace -i "CreateFileW" -i "ReadFile" -i "WriteFile" -i "DeviceIoControl" -i "SetCommState" -i "ClearCommError" target.exe
```
Затем фильтровать по хендлу `\\.\COMx` из `CreateFileW`. Наш готовый скрипт: `../scripts/frida-serial-hook.js` (хукает COM-хендлы + `ftd2xx.dll`, если загружен).

Подводные камни:
- Реализация `CreateFileW/ReadFile/WriteFile` на современных Windows — в **kernelbase.dll**, а kernel32 — форвардер. Хукать надо то, что реально вызывается (обычно оба).
- **Overlapped I/O**: буфер валиден только по завершении операции — логируй в `onLeave`/по событию, иначе мусор и `access violation` при чтении out-параметров. Чтение out-длин оборачивай в try/catch, длину дампа ограничивай (≤4096).
- Frida 17: `Module.getExportByName(name)` удалён → `Process.getModuleByName(n).getExportByName(fn)` или `Module.getGlobalExportByName(fn)`.
- Ловушки в `send()` vs `console.log` (не мостится в frida-python 17) — используй `send()` и хост-обработчик.
- Если модуль (`ftd2xx.dll`) грузится позже — `Process.attachModuleObserver` или polling каждые ~400 мс.

## 3. Прокси-DLL (общая техника)

Схема: оригинальная DLL переименовывается (`X_orig.dll`), на её место кладётся наша с тем же именем и **всеми** экспортами. Обёрнутые функции логируют и вызывают оригинал; необёрнутые — форвардятся через `.def` (`FT_XXX=FTD2XX_orig.FT_XXX`).

Шаги:
```bat
dumpbin /exports ftd2xx.dll > exports.txt   :: полный список + ординалы (некоторые клиенты грузят по ординалу!)
:: собрать прокси (наш C + .def), положить рядом с EXE целевой программы
:: оригинал переименовать в ftd2xx_orig.dll
```
Нюансы: битность строго как у процесса (J2534-ПО и флешеры почти всегда **32-бит**); DLL search order (каталог EXE → System32) — надёжнее держать прокси рядом с EXE; форвардинг в .def даёт прозрачность без кода, но логирование требует обёртки.
Генераторы-шаблоны: `dllproxy` (PyPI), kevinalmansa/DLL_Wrapper, flangvik/SharpDllProxy.

Готовые реализации в плагине:
- `../scripts/ftd2xx_proxy/` — для FTDI D2XX (формат лога совпадает с Frida-логгером).
- `../scripts/j2534_proxy/` — для J2534 Pass-Thru.

## 4. J2534 Pass-Thru — специфика

- API-функции: `PassThruOpen/Close/Connect/Disconnect/ReadMsgs/WriteMsgs/StartPeriodicMsg/StopPeriodicMsg/StartMsgFilter/StopMsgFilter/SetProgrammingVoltage/ReadVersion/GetLastError/Ioctl`.
- `PASSTHRU_MSG` (packed): `ProtocolID, RxStatus, TxFlags, Timestamp(µs, 32 бита → wrap ~71.6 мин), DataSize, ExtraDataIndex, Data[4128]`.
- ProtocolID: 1=J1850VPW, 2=J1850PWM, 3=ISO9141, 4=ISO14230, 5=CAN, 6=ISO15765, 7=SCI_A_ENGINE, 8=SCI_A_TRANS, 9=SCI_B_ENGINE, 10=SCI_B_TRANS.
- `IoctlID`: 4 = **FIVE_BAUD_INIT** (InputPtr = SBYTE_ARRAY с адресом, OutputPtr = key bytes; SET_CONFIG FIVE_BAUD_MOD=0x22 управляет инверсией), 5 = **FAST_INIT**. Это аппаратный 5-baud — то, чего не умеет FTDI напрямую.
- `SET_CONFIG` (SELECT) параметры: DATA_RATE=0x01, LOOPBACK=0x03, NODE_ADDRESS=0x04, NETWORK_LINE=0x05, P1_MIN/MAX=0x06/07, P2_MIN/MAX=0x08/09, P3_MIN/MAX=0x0A/0B, P4_MIN/MAX=0x0C/0D, W1..W5=0x0E..0x12, TIDLE=0x13, TINIL=0x14, TWUP=0x15, PARITY=0x16, BIT_SAMPLE_POINT=0x17, SYNC_JUMP_WIDTH=0x18, W0=0x19, T1_MAX..T5_MAX=0x1A..1E, ISO15765_BS=0x1F, ISO15765_STMIN=0x20, DATA_BITS=0x21, FIVE_BAUD_MOD=0x22, BS_TX=0x23, STMIN_TX=0x24, ISO15765_WFT_MAX=0x25, CAN_MIXED_FORMAT=0x8000.
- Где брать DLL устройства: реестр `HKLM\SOFTWARE\WOW6432Node\PassThruSupport.04.04\<Vendor>` → `Function Library` (путь к vendor-DLL), `Name`, `Vendor`, `Config Application`.
- Как внедрить логгер: (а) подменить значение `Function Library` на прокси-DLL, (б) выбрать устройство-«shim» в настройках OE-приложения, (в) слинковать shim в приложение.
- Версии: J2534-1 04.04 (эталон J1699-3 тестов), 05.00 (2022); J2534-2 — расширения (SW-CAN, GM UART, J1939, TP2.0, CAN FD и т.д.).

Открытые проекты-аналоги (изучать/брать идеи): MEAT-Inc/Fulcrum (shim + импорт/реплей логов), joeyoravec/j2534-logger (`ptshim32.dll`, логирование всех PassThru*), diamondman/J2534-PassThru-Logger, kinetekautomotive/etc (драйвер+over-IP+logger), python-обвязки keenanlaws/python-j2534-interface (32-битный Python!), shamtam/PyJ2534, emdzej/j2534 (TS, примеры `canlogger`/`klogger` для Tactrix OpenPort 2.0 — он же FTDI).

## 5. USB-уровень

- **USBPcap + Wireshark**: `USBPcapCMD.exe -d \\.\USBPcap2 -o - | Wireshark.exe -k -i -`. Диссектор FTDI (`ftdi-ft`, Wireshark ≥3.2.0) понимает 2-байтный заголовок bulk-IN (modem status + line status: parity/framing/break/overrun). Автопривязка по VID 0x0403 (PID 0x6001/0x6010/0x6011/0x6014/0x6015); кастомные VID/PID — «Decode As…».
- Готовый «включи и получи pcapng»: stephenkingston/serial-capture (вырезает FTDI-заголовок).
- **Bus Hound** (perisoft) — GUI-монитор USB с декодом фаз, удобен для коротких сессий.
- Ограничения USBPcap: не видит bus states/PID, неполный USB 3.0; захват идёт только пока порт открыт приложением.

## 6. Виртуальные порты и готовые снифферы COM

| Инструмент | Тип | Замечания |
|---|---|---|
| com0com + hub4com | виртуальная пара портов | бесплатно, подписанные драйверы; реальный порт «раздаётся» наблюдателю |
| Eltima Serial Port Monitor | kernel/API | платный, умеет пассивный перехват открытого порта |
| HHD Device Monitoring Studio / Free Serial Port Monitor | kernel/USB | DMS — мощный, платный; Free SPM — старый x86 |
| AGG Advanced Serial Port Monitor | spy-режим | платный |
| ENLYZE PortSniffer | KMDF-драйвер | open-source, x64, CLI, требует Test Mode |
| API Monitor (rohitab) | API-хуки | x64, ReadFile/WriteFile/DeviceIoControl; давно без обновлений |
| Portmon (Sysinternals) | kernel filter | **не работает на x64** (32-битный драйвер) — только x86/VM |

## 7. Логические анализаторы (физика)

- **Два канала минимум**: K-линия (через делитель 2 резистора; idle 12В → 3.3/5В) и RX-выход трансивера. Тогда эхо и ответ видны раздельно.
- Saleae Logic 2: штатного K-line/ISO9141 анализатора нет; фазу данных смотри Async Serial 8N1 @10400, 5-baud init — по фронтам вручную (200 мс/бит). Тестовые записи K-line: iwanders/OBD9141 (`logic/`).
- sigrok/PulseView: декодеры CAN/CAN-FD/LIN/UART/J1850-VPW; KWP2000/ISO9141 — нет, писать Python-декодер.
- Hantek 4032L поддержан в sigrok; 6022BE/6254BD — OpenHantek6022/официальное ПО (6254BD в sigrok не поддержан).
- CAN-логи: candleLight/gs_usb + socketcan → `candump -L` (Wireshark открывает нативно), Cangaroo (Windows, WinUSB), python-can (`can.Logger` → .log/.asc/.blf/.csv), Vector ASC/BLF форматы (vector_blf — эталон реверса).

## 8. Что не сработало/чего нет (не тратить время)

- Готового open-source «FTDI D2XX K-line логгер с 5-baud» не существует — ближайшее MCU-реализации (OBD9141, KLineKWP1281Lib).
- Frida к USB «напрямую» неприменима (хуки юзермода не видят URB).
- Публичных эталонных pcap J2534-сессий нет — только текстовые shim-логи (Fulcrum `.shimLog`, joeyoravec UTF-8) и примеры PASSTHRU_MSG в спецификации.
