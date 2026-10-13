@echo off
rem Сборка логирующей J2534-прокси. ВАЖНО: 32-битная (x86) — под J2534-приложения.
rem Запускать из "x86 Native Tools Command Prompt for VS" (или vcvars32.bat).
rem Результат: J2534.dll (переименуй в имя vendor-DLL, например op20pt32.dll — см. README).

cl /nologo /LD /O2 /W3 /D_CRT_SECURE_NO_WARNINGS j2534_proxy.c /link /DEF:j2534_proxy.def /OUT:j2534_proxy.dll advapi32.lib
if errorlevel 1 (
  echo.
  echo [ОШИБКА] Сборка не удалась. Нужен x86 Developer Command Prompt (cl.exe в PATH).
  exit /b 1
)
echo.
echo Готово: j2534_proxy.dll
echo Дальше:
echo   1) посмотри реестр: HKLM\SOFTWARE\WOW6432Node\PassThruSupport.04.04\<Vendor>\Function Library
echo   2) скопируй vendor-DLL в надежное место (например C:\j2534real\vendor.dll)
echo   3) положи прокси рядом с EXE программы ПОД ИМЕНЕМ, которое грузит ПО (часто имя vendor-DLL),
echo      или подмени значение "Function Library" на путь к прокси
echo   4) создай j2534_proxy.ini рядом с прокси:  RealDll=C:\j2534real\vendor.dll
echo   5) отработай сценарий; лог: j2534-log-*.log рядом с EXE
