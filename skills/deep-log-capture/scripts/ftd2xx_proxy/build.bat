@echo off
rem Сборка логирующей прокси FTD2XX.DLL (MSVC x86 или x64 — под целевое приложение).
rem Из каталога с Visual Studio Developer Command Prompt:
rem   build.bat          (x86 по умолчанию; для x64 запусти из x64-шелла)
rem Результат: FTD2XX.dll рядом со скриптом.

cl /nologo /LD /O2 /W3 /D_CRT_SECURE_NO_WARNINGS ftd2xx_proxy.c /link /DEF:ftd2xx_proxy.def /OUT:FTD2XX.dll user32.lib
if errorlevel 1 (
  echo.
  echo [ОШИБКА] Сборка не удалась. Проверь, что запущено из Developer Command Prompt (cl.exe в PATH).
  exit /b 1
)
echo.
echo Готово: FTD2XX.dll
echo Дальше:
echo   1) найди оригинал (обычно C:\Windows\System32\FTD2XX.DLL) и положи рядом с целевым EXE как FTD2XX_orig.dll
echo   2) положи собранный FTD2XX.dll РЯДОМ С EXE целевой программы (DLL search order: каталог exe - первый)
echo   3) запусти программу и отработай сценарий; лог появится как ftd2xx-log-*.log рядом с EXE
