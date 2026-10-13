# ftd2xx_proxy — логирующая прокси-DLL для FTD2XX.DLL

Перехватывает обмен чужой программы с FTDI-адаптером на уровне драйвера D2XX (глубже COM-порта, видно все настройки чипа).

## Как это работает

```
Целевая программа  →  FTD2XX.dll (НАША прокси, рядом с EXE)
                          ├─ обёрнутые FT_* → лог + вызов оригинала
                          └─ остальные      → форвардинг в FTD2XX_orig.dll
                                                      (переименованный оригинал)
```

## Шаги установки

1. Собрать: `build.bat` (MSVC, из Developer Command Prompt; битность — как у целевого процесса).
   - MinGW-вариант: `gcc -shared -O2 -o FTD2XX.dll ftd2xx_proxy.c ftd2xx_proxy.def -luser32`
2. Оригинал: скопировать `C:\Windows\System32\FTD2XX.DLL` рядом с EXE программы под именем **`FTD2XX_orig.dll`** (или задать путь переменной `FTD2XX_ORIG`).
3. Собранный `FTD2XX.dll` положить **рядом с EXE** целевой программы (каталог EXE — первый в DLL search order). Не подменяй системный файл в System32!
4. Один запуск программы = один `ftd2xx-log-<дата>-<время>.log` рядом с EXE.

## Чек-лист беды «ничего не логируется / программа не видит адаптер»

- [ ] Битность прокси = битности процесса (флешеры и J2534-ПО обычно **32-бит** → собери x86).
- [ ] Реально загрузилась НАША DLL: в логе при старте есть `# ftd2xx_proxy attached`. Если нет — проверь search order (EXE рядом?) и что DLL не заблокирована антивирусом.
- [ ] Оригинал найден: в логе `# original loaded: ...`. Если `LoadLibrary` не удался — поправь имя/путь.
- [ ] Полнота экспортов: `dumpbin /exports FTD2XX.DLL` (оригинал) → все имена должны быть в `.def` (обёрнутые — как `FT_X=Proxy_FT_X`, остальные — форвардинг). Для импорта по ординалам добавь `@N`.
- [ ] 64-битное приложение — 64-битная сборка (`call "C:\Program Files\Microsoft Visual Studio\...\vcvars64.bat"`).

## Что попадёт в лог

- `TX/RX` байты (`FT_Write`/`FT_Read`) с длинами и hex;
- настройки линии: `FT_SetBaudRate`, `FT_SetDataCharacteristics`, `FT_SetTimeouts`, `FT_SetLatencyTimer`, `FT_SetFlowControl`, `FT_SetBitMode`, `FT_ResetDevice`, `FT_Purge`;
- открытие/закрытие устройства и загрузка/отгрузка прокси.

Формат совместим с `log-analysis/scripts/telegram_parse.py` (`--format auto`).

## Если вместо прокси можно обойтись

- Программа ходит через COM-порт (VCP) → проще `frida-serial-hook.js` или `frida-launch.py`.
- Доступен запуск с Frida → хуки `ftd2xx.dll` уже есть в `frida-serial-hook.js`.

## Ограничение

Логируется только то, что программа вызывает через D2XX. Обмен внутри чипа (USB-уровень, 5-baud init, сделанный самим адаптером) виден только через USBPcap + Wireshark.
