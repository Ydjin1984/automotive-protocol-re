# UDS (ISO 14229) / ISO-TP (ISO 15765-2) / DoIP (ISO 13400)

Современный стек диагностики и программирования: CAN (500k, часто CAN FD) → ISO-TP → UDS; либо Ethernet → DoIP → UDS. BMW F/G-серии (D-CAN/ENET), VAG MQB, Mercedes, все новые ЭБУ.

## 1. ISO-TP (ISO 15765-2) — транспорт поверх CAN

PCI (старший ниббл первого байта):
- `0` **SingleFrame**: длина в мл. ниббле (≤7 байт данных). CAN FD: escape `0x00` + длина во втором байте.
- `1` **FirstFrame**: 12-битная длина 0x008..0xFFF (до 4095 байт).
- `2` **ConsecutiveFrame**: мл. ниббл — sequence number 1..15 (заворот на 0).
- `3` **FlowControl**: FS (`0` CTS / `1` WAIT / `2` OVFLW), BS (число кадров до следующего FC; 0 = без ограничения), STmin (0x00–0x7F мс; 0xF1–0xF9 = 100..900 мкс).

Адресация: обычная 11-бит (`7E0`/`7E8` для OBD), расширенная (29-бит + адресный байт), и «normal addressing with padding` (добивка 0xCC/0x00 — типично у BMW/VAG).

## 2. UDS (ISO 14229-1)

Сервисы: `0x10` DiagnosticSessionControl, `0x11` ECUReset, `0x14` ClearDiagnosticInformation, `0x19` ReadDTCInformation, `0x22` ReadDataByIdentifier, `0x23` ReadMemoryByAddress, `0x24` ReadScalingDataByIdentifier, `0x27` SecurityAccess, `0x28` CommunicationControl, `0x29` Authentication, `0x2A` ReadDataByPeriodicIdentifier, `0x2C` DynamicallyDefineDataIdentifier, `0x2E` WriteDataByIdentifier, `0x2F` InputOutputControlByIdentifier, `0x31` RoutineControl (start/stop/results), `0x34` RequestDownload, `0x35` RequestUpload, `0x36` TransferData, `0x37` RequestTransferExit, `0x38` RequestFileTransfer, `0x3D` WriteMemoryByAddress, `0x3E` TesterPresent, `0x84` SecuredDataTransmission, `0x85` ControlDTCSetting, `0x86` ResponseOnEvent, `0x87` LinkControl.

- Сессии: `0x01` default, `0x02` programming, `0x03` extended, `0x04` safetySystem. Suppress-positive-response — бит7 субфункции (кроме сервисов без субфункции, напр. 0x22).
- SecurityAccess: level = субфункция; нечётная (0x01,0x03,0x05…) = requestSeed, чётная (0x02,0x04…)= sendKey. Seed→key обычно OEM-специфичен (алгоритм в прошивке).
- Позитивный ответ = SID+0x40; негативный = `7F <SID> <NRC>`.

**NRC**: 0x10 generalReject, 0x11 serviceNotSupported, 0x12 subFunctionNotSupported, 0x13 incorrectMessageLength, 0x14 responseTooLong, 0x21 busyRepeatRequest, 0x22 conditionsNotCorrect, 0x24 requestSequenceError, 0x25 noResponseFromSubnet, 0x26 failurePreventsExecution, 0x31 requestOutOfRange, 0x33 securityAccessDenied, 0x34 authenticationRequired, 0x35 invalidKey, 0x36 exceedNumberOfAttempts, 0x37 requiredTimeDelayNotExpired, 0x70 uploadDownloadNotAccepted, 0x71 transferDataSuspended, 0x72 generalProgrammingFailure, 0x73 wrongBlockSequenceCounter, **0x78 requestCorrectlyReceived-ResponsePending** (ждать!), 0x7E/0x7F not supported in active session.

## 3. Классическая последовательность программирования (flash) UDS

```
10 03 (extended)            → 50 03          ; или сразу 10 02 (programming) → 50 02 (+ P2/P2*)
28 03 03 (отключить обычный обмен) → 68 03  ; опционально
85 02 (DTC off)             → C5 02          ; опционально
27 01 (seed)                → 67 01 <seed>
27 02 <key>                 → 67 02          ; проверка алгоритма
34 <addr/len format>        → 74 <maxBlock>  ; RequestDownload (формат = compression/encryption + addr len + size len)
36 <seq> <data> …           → 76 <seq>       ; TransferData (seq инкремент!)
37                          → 77
31 01 FF00/FF01/FF02 (erase/check/apply) → 71 …   ; OEM-специфичные routine
11 01 (reset)               → 51 01
```
Практические правила: ждать `78` сколько нужно (P2* = 5 с и больше); следить за последовательностью `36` (неверный seq → 0x73); проверять maxNumberOfBlockLength из `74`.

## 4. DoIP (ISO 13400)

- **Порт 13400** UDP (дискавери) и TCP (данные); TLS 3496.
- Типы сообщений: `0x0000` generic header NACK, `0x0001` Vehicle Identification Request (UDP, без payload), `0x0002` VIR with EID, `0x0003` VIR with VIN, `0x0004` Vehicle Announcement/VIR response, `0x0005` Routing Activation Request, `0x0006` Routing Activation Response, `0x0007/0x0008` Alive Check req/resp, `0x4001`–`0x4004` entity status/power mode, `0x8001` Diagnostic Message, `0x8002` diag ACK, `0x8003` diag NACK.
- Routing Activation: SA (2 байта) + activation type (1) + ISO reserved (4 = 0) + OEM (4); ответ: SA тестера + SA DoIP-узла + код (0x10 = успешно активировано, 0x11 = будет активировано) + reserved (4) + OEM (4). Без активации диагностические сообщения не проходят.
- BMW ENET: статические адреса (тестер 169.254.0.1/…, блоки 169.254.x.x), диагностический порт 6801 у EDIABAS-INTERFACE (см. `ediabas.md`).

## 5. Логирование и реверс

- CAN: candleLight/gs_usb + `candump -L`, Cangaroo/Wireshark, python-can; логи `.asc/.blf/.log` — форматы описаны в `deep-log-capture/references/capture-layers.md`.
- DoIP: Wireshark (tcp/udp 13400), либо прокси на loopback; для EDIABAS-мира — ENET-трассы.
- Реверс seed/key: снять несколько пар seed→key (разными запросами), искать линейную/табличную зависимость; для современных блоков — только дизасм прошивки.

## Источники

- Wikipedia UDS/ISO 15765-2/ISO 13400; udsoncan.readthedocs.io; scapy contrib/automotive/doip.py; ISO 14229-1 тексты сервисов.
