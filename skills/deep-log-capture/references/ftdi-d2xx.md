# FTDI (FT232R / FT2232H / FT232H) для логов K-line: D2XX, скорости, тайминги, электрика

## 1. D2XX или VCP?

- **D2XX** — прямой доступ к чипу, полный контроль (latency, bit-bang, purge, события). Нужен для глубоких логов и K-line. Несовместим с VCP в один момент времени.
- **VCP** — виртуальный COM-порт (FTDIPORT/FTDIBUS драйверы). Удобно (любой терминал, pyserial), но: latency по умолчанию 16 мс, нет bit-bang, нет 5 бод.
- Переключение D2XX↔VCP у FT232R — **переподключение USB** (у H-чипов — EEPROM/драйверные опции).

## 2. Минимальный набор вызовов для логгера

```c
FT_Open(iDev, &h);                       // или FT_OpenEx(serial, FT_OPEN_BY_SERIAL_NUMBER=1, &h)
FT_ResetDevice(h);
FT_SetTimeouts(h, 1000, 1000);           // мс; 0 = бесконечно
FT_SetLatencyTimer(h, 1);                // 1..255 мс, дефолт 16
FT_SetBaudRate(h, 9600);                 // или FT_SetDivisor(h, D)
FT_SetDataCharacteristics(h, FT_BITS_8=8, FT_STOP_BITS_1=0, FT_PARITY_EVEN=2);
FT_SetFlowControl(h, 0, 0, 0);           // OFF
FT_Purge(h, FT_PURGE_RX=1 | FT_PURGE_TX=2);
FT_Read(h, buf, want, &got);  FT_Write(h, buf, n, &written);
FT_GetQueueStatus(h, &rxBytes);          // опрос очереди (legacy, но надёжен)
FT_GetStatus(h, &rxQ, &txQ, &eventDword); // + события
FT_GetDriverVersion/FT_GetLibraryVersion(&v); // есть ли DLL вообще + версия в шапку лога
FT_SetBitMode(h, mask, mode);            // bit-bang (см. §6)
FT_CreateDeviceInfoList/FT_GetDeviceInfoList // инвентаризация: Type, ID, LocId, SerialNumber[16], Description[64]
```
Полный справочник — D2XX Programmer's Guide (FT_000071). Для логгера правильный порядок: open → reset → timeouts → latency → baud → characteristics → flow off → purge (именно в этом порядке настраивает эталонный транспорт в кодовой базе проекта).

**Открывать по серийнику, а не по индексу** — индексы «плывут» при hot-plug.

## 3. Нестандартные скорости (K-line: 10400, 125000, 7812.5)

База FT232R: 48 МГц / 16 = **3 МГц**; делитель `D = 3e6 / baud`, дробная часть с шагом 1/8, целая 2…16384; диапазон 183 бод … 3 Мбод, допуск ±3%. Драйвер сам округляет.

| baud | D (3 МГц) | факт | ошибка | где встречается |
|---|---|---|---|---|
| 9600 | 312.5 | 9600 | 0% | DS2 (BMW), K-line |
| 10400 | 288.4615→288.5 | 10398.6 | −0.013% | ISO 9141-2, ISO 14230 |
| 19200 | 156.25 | 19200 | 0% | DS2 (лестница скоростей) |
| 125000 | 24 | 125000 | 0% | DS2 (верхняя ступень) |
| 7812.5 | 384.0 | 7812.5 | 0% | Chrysler SCI/CCD |

Если `FT_SetBaudRate` вернул `FT_INVALID_BAUD_RATE (7)` — считай делитель сам и `FT_SetDivisor`. Для VCP нестандартные скорости включаются «алиасингом» таблицы в `FTDIPORT.INF` (AN_120).

H-чипы (FT2232H/FT4232H/FT232H): опора 120 МГц, до 12 Мбод, точность ещё выше.

## 4. Latency timer и точность таймстемпов

- Дефолт 16 мс — при низких скоростях данные висят в чипе до заполнения буфера (до ~1 с!). Для логов ставь **1 мс**.
- Цена 1 мс: каждые 1 мс приходит 2-байтный статусный заголовок bulk-пакета даже на молчащей линии (учитывай в парсере; полезно для контроля живости линии).
- Ещё уменьшают: `FT_SetUSBParameters(h, 64, 64)` (или 4096/16384 — компромисс с пропускной), выключить event-символ.
- Для VCP: Device Manager → порт → Advanced → Latency Timer; реестр `...\Device Parameters\LatencyTimer`.
- Итоговая точность метки времени = момент выхода `FT_Read` + latency + USB-фрейм (1 мс). Аппаратных таймстампов у FTDI нет — для пауз <5 мс (P1/P4 в KWP2000) используй логический анализатор, а в отчётах помечай метод измерения.

## 5. Полудуплекс K-line и эхо

K-line — один провод: TX тянет линию вниз (open-collector), RX читает ту же линию. **Эхо неизбежно**, если в адаптере нет аппаратного отключения. Алгоритм подавления (эталон — из рабочего проекта):

```
write(tx)
wait up to echo_timeout_ms (обычно 300):
  chunk = read(...)               // окнами ≤80 мс
  сравнить побайтно с tx
  первое несовпадение → это уже ОТВЕТ: всё, начиная с него, — данные (pushed back)
  полное совпадение     → echo discarded
  прочитано 0 байт      → адаптер БЕЗ эха (переставить режим!)
```
Не полагайся на `FT_Purge` сразу после записи — байты могут быть ещё в USB-pipe; purge полезен до сессии/между обменами. При пассивном слушании держи TX в idle.

## 6. Bit-bang и 5-baud init

- UART 5 бод не умеет (минимум 183 бода) — только ручное дёрганье пинов: `FT_SetBitMode(h, mask, 0x01)` (async bit-bang), далее `FT_Write` по одному байту на состояние. **“If no new data is written, the pins hold the last value written”** — паузы задаёт хост.
- Ловушка: при входе в bit-bang выходы стартуют в LOW (K-line idle — ВЫСОКИЙ). Приём: сначала пины как вход, `FT_Write(0xFF)`, затем переключить в выход.
- Точность 200 мс/бит на Windows: `Sleep()` ~15.6 мс гранулярность → `timeBeginPeriod(1)` + busy-wait. Практика: VCP-подход даёт 20–35 мс и <50% успеха init; D2XX ~25 мс и >95%.
- Снимок линии: `FT_GetBitMode` (round-trip ~1 мс) — для чтения 10.4 кбод НЕ годится; после init возвращайся в UART (`SetBitMode(0,0)` → characteristics → baud).
- Для стабильного 5-baud init **делегируй адаптеру**: J2534 `PassThruIoctl(FIVE_BAUD_INIT)`, ELM327/STN (внутренний init), MCU-фронтенд. FTDI оставляй на данные и пассивный лог.

## 7. Python

| Библиотека | База | Плюсы | Минусы |
|---|---|---|---|
| `ftd2xx` (pip) | официальная D2XX DLL | все FT_* 1:1 с гайдом, события | Windows-центрично |
| `pyftdi` | libusb (без vendor-драйвера) | до 12 Мбод, MPSSE/GPIO, кросс-платформенно | Windows «unofficial», теряет стабильность на длинных прогонах |
| `pylibftdi` | libftdi (ctypes) | простой API, `BitBangDevice` | нет событий |
| `pyserial` | VCP COM | тривиально | latency 16 мс, нет bit-bang/5 бод |

Наш `scripts/ftdi_kline_logger.py` использует `ftd2xx` (если установлен), иначе `pyserial`, и умеет всё вышеописанное.

## 8. Электрика K-line (адаптер)

- Трансиверы: **L9637D** (ST; 1 RX, 2 LO, 3 VCC 5В, 4 TX, 5 GND, 6 K, 7 VS 12В, 8 LI), **MC33290** (NXP), **SI9241A** (Vishay) — однопроводные ISO 9141 интерфейсы, 5В логика, шина к VBAT, подтяжки 510 Ом (K→+12В) и 1 кОм в цепях TX/RX по application-circuit из даташита.
- Дискретная классика (2 транзистора, KKL409.1-стиль) — работает, но известна пробоями и «залипшим эхо»; для стенда предпочитай L9637D.
- L-line (если нужен 5-baud адрес) — отдельный каскад; приём L через CTS/пин FTDI.
- Идле K-line = +12В. UART idle = high → каскад должен быть open-collector с правильной полярностью (либо внешний инвертор; у части FTDI-чипов инверсия — через EEPROM-опции).
- Защита: TVS/диоды по K, последовательный резистор, фильтр по VS. Немаловажно: **общая масса** тестера и ЭБУ на столе.

## 9. Источники (для углубления)

- D2XX Programmer's Guide FT_000071; AN232B-05 (Baud Rates); AN232B-04 (Data Throughput, Latency); AN_232R-01 (Bit-Bang); AN_373 (USB Bit-Bang).
- `pyftdi` (eblot/pyftdi), `pylibftdi`, `ftd2xx` (PyPI), pyserial.
- MCU-эталоны протокола: iwanders/OBD9141 (ISO9141/5-baud, Saleae-записи в `logic/`), domnulvlad/KLineKWP1281Lib, GeonPi/kw1281.
