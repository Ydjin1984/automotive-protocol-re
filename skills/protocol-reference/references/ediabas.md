# EDIABAS (BMW) — установка, концепции, трассы, API

«EDIABAS» — это не проводной протокол, а зонтичная платформа BMW: концепции обмена (ADS, DS1, DS2, BMW-FAST, ISO 9141, KWP2000, D-CAN, ENET) + язык описания ЭБУ и джобов (SGBD/BIP) + интерфейсные драйверы (IFH) + API. «Протокол EDIABAS» в обиходе = конкретная концепция (обычно DS2/BMW-FAST) + штатные трассы этой платформы — самый дешёвый способ снять байтовый лог чужого ПО.

Ниже — по факту установки `C:\EDIABAS` (7.3.0) + `C:\EC-APPS\NFS` (WinKFP 5.2.9/5.3.1) + `C:\EC-APPS\INPA` (5.06).

## 1. Карта установки

```
C:\EDIABAS\
  Bin\      — ebas32.dll, api32.dll/api64.dll, apital32.exe (tall-API), Tool32.exe, IFHSRV32.exe, NET\APINET32.DLL, Log\, Server\ (flash-данные), Utils\ (CIC/NBT/SWID), EDIABAS.INI, OBD.INI
  Api\      — SDK: WIN32\Api.h, Apidll.h, Apicalls.c, *.lib (VC), Api.bas/vb (VB), WIN64\, JAVA\, EXCEL\
  Ecu\      — 1970 × .prg (SGBD) + 495 × .grp (адресные), включая bms46ds0.prg
  TRACE\    — куда пишутся трассы: api.trc, ifh.trc (+ ручные копии *old.trc)
  Doku\     — EDIABAS-DE/EN.chm, IFH.pdf, IFHSTD.pdf, FAQ.pdf, Release.pdf, INI.pdf
  HELP\     — B2BMW.chm, B2RUNTIM.chm (язык SGBD/BIP)
  Hardware\ — OBD\ (драйверы FTDI/Prolific, OBD_DOKU.pdf), ENET\ (ZGW_SEARCH.exe), CAN\, FUNK\, OPPS\
  Sim\      — OBD.sim, EDIC.sim, OMITEC.sim (симуляция интерфейсов)
C:\EC-APPS\NFS\BIN\Winkfpt.ini   — WinKFP: API_TRACE=1, IFH_TRACE=1, [HW-Interface] маппинг железа
C:\EC-APPS\INPA\                  — INPA 5.06: BIN, CFGDAT (меню), SGDAT (2039 ipo/prg)
```

## 2. Ключевые конфиги

**C:\EDIABAS\BIN\EDIABAS.INI** (рабочие строки; ниже в файле — полная документация ключей):

```ini
[Configuration]
Interface        = STD:OBD          ; ADS | EDIC | EDICC | STD:OBD | STD:CAN | STD:FUNK | STD:OMITEC |
                                    ; REMOTE[:name] | RPLUS[:name] | ENET | PROXY:<Interface>
EcuPath          = C:\EDIABAS\ECU
TracePath        = C:\EDIABAS\TRACE
TraceSize        = 262144
ApiTrace         = 1                ; 0=off 1=user 2=+timestamp 3=+PID 4=func 5=+ts 6=+ts+timing 7=+ts+timing+PID 8=debug
IfhTrace         = 1                ; 0=off 1=user 2=+interface 3=+interface+timestamp
; IfhnTrace      = 0                ; сетевой IFH-trace
TraceBuffering   = 0                ; 0 = закрывать файл после дампа (лог «живьём»)
TraceHistory     = 0
TraceSync        = 1
; TraceWriter    = <FilePathName>   ; можно указать СВОЙ writer-DLL — точка внедрения кастомного логгера
UBattHandling    = 0
IgnitionHandling = 0
RetryComm        = 1
```

**OBD.INI** (для `Interface=STD:OBD`, USB-K+DCAN):

```ini
[OBD]
Port=Com6
Hardware=USB          ; драйвер FTD2XX
RETRY=ON
```

Прочие интерфейсы: `XEdicC.ini` (тайминги CAN для EDICC), `Rplus.ini` (ICOM по TCP), `REMOTE.INI` (OPPS, порты 6801 OBD / 6802 MOST), `[XEthernet]` в EDIABAS.INI (ENET, ControlPort 6811/DiagnosticPort 6801). WinKFP выбирает железо через `[HW-Interface]` (K-Line/OBD=`STD:OBD`, K-Line/ADS=`ADS`, Ethernet/ENET=`ENET`, CAN/Vector=`STD:CAN`…).

## 3. Как снять трассу (рецепт)

1. Выставить `ApiTrace`/`IfhTrace` (для реверса полезно `IfhTrace=3`, `ApiTrace=5` — с интерфейсом и метками времени).
2. Отработать сценарий в INPA/WinKFP/Tool32.
3. Забрать `C:\EDIABAS\TRACE\ifh.trc` (байтовый обмен) и `api.trc` (входы/результаты джобов).
4. Для конвертации — `C:\EDIABAS\BIN\traceXML.exe` + `xtract.xsd`.

**Формат ifh.trc** (по реальному файлу): ASCII/CRLF; заголовок сессии `#'<дата>;!<id>h;V7.3.0;#`; разделители `#@<мс от старта>;P<pid>h;#`; строки интерфейса `_STD      INPUT: …` / `_STD      OUTPUT: …` (hex, 16 байт на строку) / `_STD      ERROR: NO ERROR`; примитивы `SENDECUTEL` и т.п. **INPUT — то, что вернул интерфейс; OUTPUT — то, что отдано в интерфейс**; запрос в INPUT идёт без финального CKS, ответ в OUTPUT — полный.

**Формат api.trc**: блоки `Initialization` (`"STD:OBD"`), `Job` (имя SGBD, имя джоба, аргумент, байты), `Results` (поля `JOB_STATUS`, `*_ANZAHL`, `*_ADRESSE` и т.д.). Полезно для понимания, какие джобы делает программа и с какими параметрами.

## 4. Программный вызов джобов (для экспериментов и реплея)

- Интерактивно: `Tool32.exe` (открыть .prg, выбрать джоб, задать аргументы; LASTFILE содержит 07FLASH.PRG и др.).
- Автоматически: `printf 'i\nj bms46ds0 ident\nr\ne\nq\n' | apital32.exe` — «tall»-тестер API (пишет трассу в TRACE).
- Свой код: `C:\EDIABAS\Api\WIN32\Api.h` + `api32.dll` (экспорты `__apiInit, __apiJob, __apiJobData, __apiResultText/Binary/Int/…, __apiErrorText, __apiSetConfig/__apiGetConfig, __apiTrace …`). Есть обёртки для VB, VC6..2010, .NET (`BIN\NET\…\APINET32.DLL`), Java (`Api\JAVA\CascadeEdiabas.jar`).
- Тест-файлы с вызовами джобов и параметрами протокола: `C:\EDIABAS\Ecu\13_Ediabas-Testfiles\*.tst`, формат `N|SGBD|JOB|ARG|PARA`, где PARA может задавать протокол: `DIAGNOSEPROTOKOLL_SETZEN||BMW-FAST;0x12`.
- Симуляция без железа: `Simulation = 1` + `C:\EDIABAS\Sim\OBD.sim` (таблицы REQUEST/RESPONSE).

## 5. SGBD/BEST и концепции

- SGBD (`Ecu\*.prg`) — скомпилированные скрипты ЭБУ (язык BIP/BEST; документация `HELP\B2BMW.chm`, `B2RUNTIM.chm`). Внутри — джобы (`ident`, `aif_lesen`, `fs_lesen`, `FS_LOESCHEN`, `STATUS_*`, `STEUERN_*`, `FLASH_SCHREIBEN`, …), тексты ошибок, таблицы.
- Концепции обмена выбираются параметром протокола и/или именем SGBD: **ADS** (старый ADS-интерфейс), **DS1**, **DS2** (K-line 9600 8E1 — см. `ds2-bmw.md`), **BMW-FAST** (KWP2000-подобный, 5-baud/fast init), **ISO9141** (Concept 2), **KWP2000**, **D-CAN** (CAN + ISO-TP), **ENET** (Ethernet, DoIP-подобный), **MOST** (FUNK/OPPS). В PDX/.pid и документации встречаются номера концепций (Concept 1/2/3).
- Полезный ориентир: имена SGBD содержат протокол: `ms410ds0`, `mss54ds0`, `bms46ds0`, `alc_ds2.prg`, `00SWTDS2.PRG` (DS2-семейство).

## 6. EDIABAS в роли «штатного логгера» (сравнение с внешним перехватом)

| Способ | Что даёт | Ограничения |
|---|---|---|
| ifh.trc | байтовый обмен INPUT/OUTPUT + мс-метки | нет явных «кто начал», CKS в INPUT отсутствует |
| api.trc | джобы + аргументы + результаты | не байтовый уровень |
| Frida-хук COM/D2XX | байты + параметры порта + rc | нужен запуск программы под Frida |
| Прокси FTD2XX.DLL | байты + ВСЕ настройки чипа | 32/64-бит, рядом с EXE |
| Логический анализатор | физика, тайминги, эхо | дорогой анализ |

Для WinKFP-сессий EDIABAS-трассы достаточно для 95% задач; для «дешёвого» 5-baud init и тонких таймингов нужен анализатор.

## 7. Типовые задачи и где смотреть

- «Программа не стирает/не пишет» → сравнить её ifh.trc с эталонной (у BMS46: отсутствие BMW-авторизации перед `07 0F`).
- «Надо воспроизвести сессию» → выгрузить ifh.trc, превратить в «золотую трассу» TX-строк (см. `log-analysis`), реплей на стенде.
- «Надо понять джоб» → api.trc покажет имя джоба и аргументы; SGBD-тексты — `B2BMW.chm`.
- Восстановление после неудачного флеша: тем же WinKFP (полная сессия) — задокументировано в `protocol-replica-build/references/playbook-bms46.md`.
