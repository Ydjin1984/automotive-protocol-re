/*
 * ftd2xx_proxy.c — логирующая прокси-DLL для FTD2XX.DLL (32/64-бит).
 *
 * Идея: оригинал переименовывается в FTD2XX_orig.dll, на его место кладётся эта DLL.
 * Обёрнутые функции (см. ниже) логируют вызов и вызывают оригинал; остальные экспорты
 * форвардятся на оригинал через .def (FT_XXX=FTD2XX_orig.FT_XXX).
 *
 * Формат лога (совместим с frida-serial-hook.js и telegram_parse.py):
 *   [+2.850s] TX ftd2xx FT_Write rc=0 len=4 n=4 : 12 04 00 16
 *   [+3.041s] RX ftd2xx FT_Read rc=0 want=2 n=2 : 12 2E
 *   [+0.001s] ftd2xx FT_SetBaudRate baud=9600 rc=0
 *
 * Сборка: см. build.bat (MSVC) или README.md (MinGW).
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

typedef unsigned long FT_STATUS;
typedef void* FT_HANDLE;

#define FT_OK 0

static HMODULE        g_orig = NULL;
static FILE*          g_log  = NULL;
static CRITICAL_SECTION g_cs;
static DWORD          g_t0   = 0;
static char           g_orig_path[MAX_PATH] = "FTD2XX_orig.dll";

/* ------------------------------------------------------------------ утилиты */

static void proxy_init_paths(void)
{
    char exe[MAX_PATH] = {0};
    char* p;
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    p = strrchr(exe, '\\');
    if (p) *(p + 1) = 0; else exe[0] = 0;

    /* оригинал ищем: переменная окружения -> рядом с exe -> рядом с нашей DLL */
    {
        char env[MAX_PATH] = {0};
        DWORD n = GetEnvironmentVariableA("FTD2XX_ORIG", env, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            strncpy(g_orig_path, env, MAX_PATH - 1);
            return;
        }
    }
    if (exe[0]) {
        char cand[MAX_PATH];
        snprintf(cand, MAX_PATH, "%sFTD2XX_orig.dll", exe);
        if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
            strncpy(g_orig_path, cand, MAX_PATH - 1);
            return;
        }
        snprintf(cand, MAX_PATH, "%sftd2xx_orig.dll", exe);
        if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
            strncpy(g_orig_path, cand, MAX_PATH - 1);
            return;
        }
    }
}

static void proxy_open_log(void)
{
    char exe[MAX_PATH] = {0};
    char* p; char path[MAX_PATH];
    SYSTEMTIME st;
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    p = strrchr(exe, '\\');
    if (p) *(p + 1) = 0; else exe[0] = 0;
    GetLocalTime(&st);
    snprintf(path, MAX_PATH, "%sftd2xx-log-%04d%02d%02d-%02d%02d%02d.log",
             exe, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    g_log = fopen(path, "a");
    if (g_log) {
        fprintf(g_log, "# ftd2xx_proxy log v1\n# time=%04d-%02d-%02d %02d:%02d:%02d pid=%lu\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                (unsigned long)GetCurrentProcessId());
        fflush(g_log);
    }
}

static void logline(const char* fmt, ...)
{
    va_list ap;
    EnterCriticalSection(&g_cs);
    if (g_log) {
        fprintf(g_log, "[+%.3fs] ", (GetTickCount() - g_t0) / 1000.0);
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fprintf(g_log, "\n");
        fflush(g_log);
    }
    LeaveCriticalSection(&g_cs);
}

static void log_hex(const char* prefix, const unsigned char* b, ULONG n)
{
    char buf[3 * 4096 + 1];
    ULONG i = 0, max = (n > 4096) ? 4096 : n;
    buf[0] = 0;
    for (; i < max; i++) {
        char t[4];
        snprintf(t, 4, "%02X ", b[i]);
        strcat(buf, t);
    }
    logline("%s%s", prefix, buf);
}

static FARPROC orig(const char* name)
{
    if (!g_orig) {
        proxy_init_paths();
        g_orig = LoadLibraryA(g_orig_path);
        if (!g_orig) {
            logline("# ОШИБКА: не загрузилась %s (переименуй оригинал!)", g_orig_path);
            return NULL;
        }
        logline("# original loaded: %s", g_orig_path);
    }
    return GetProcAddress(g_orig, name);
}

/* ------------------------------------------------------------------ обёртки */

FT_STATUS Proxy_FT_Open(int deviceNumber, FT_HANDLE* pHandle)
{
    typedef FT_STATUS (WINAPI *fn_t)(int, FT_HANDLE*);
    fn_t f = (fn_t)orig("FT_Open");
    FT_STATUS rc = f ? f(deviceNumber, pHandle) : 1;
    logline("ftd2xx FT_Open idx=%d rc=%lu handle=%p", deviceNumber, rc, pHandle ? *pHandle : NULL);
    return rc;
}

FT_STATUS Proxy_FT_OpenEx(void* arg, DWORD flags, FT_HANDLE* pHandle)
{
    typedef FT_STATUS (WINAPI *fn_t)(void*, DWORD, FT_HANDLE*);
    fn_t f = (fn_t)orig("FT_OpenEx");
    FT_STATUS rc = f ? f(arg, flags, pHandle) : 1;
    logline("ftd2xx FT_OpenEx arg=%s flags=%lu rc=%lu", (const char*)arg, flags, rc);
    return rc;
}

FT_STATUS Proxy_FT_Close(FT_HANDLE h)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE);
    fn_t f = (fn_t)orig("FT_Close");
    FT_STATUS rc = f ? f(h) : 1;
    logline("ftd2xx FT_Close rc=%lu", rc);
    return rc;
}

FT_STATUS Proxy_FT_Write(FT_HANDLE h, void* buf, DWORD n, DWORD* written)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, void*, DWORD, DWORD*);
    fn_t f = (fn_t)orig("FT_Write");
    FT_STATUS rc = f ? f(h, buf, n, written) : 1;
    {
        DWORD got = written ? *written : 0;
        char pfx[64];
        snprintf(pfx, 64, "TX ftd2xx FT_Write rc=%lu len=%lu n=%lu : ", rc, n, got);
        log_hex(pfx, (const unsigned char*)buf, n);
    }
    return rc;
}

FT_STATUS Proxy_FT_Read(FT_HANDLE h, void* buf, DWORD n, DWORD* got)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, void*, DWORD, DWORD*);
    fn_t f = (fn_t)orig("FT_Read");
    FT_STATUS rc = f ? f(h, buf, n, got) : 1;
    {
        DWORD have = got ? *got : 0;
        if (rc == FT_OK && have > 0) {
            char pfx[64];
            snprintf(pfx, 64, "RX ftd2xx FT_Read rc=%lu want=%lu n=%lu : ", rc, n, have);
            log_hex(pfx, (const unsigned char*)buf, have);
        } else {
            logline("RX ftd2xx FT_Read rc=%lu want=%lu n=%lu", rc, n, have);
        }
    }
    return rc;
}

FT_STATUS Proxy_FT_SetBaudRate(FT_HANDLE h, DWORD baud)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, DWORD);
    fn_t f = (fn_t)orig("FT_SetBaudRate");
    FT_STATUS rc = f ? f(h, baud) : 1;
    logline("ftd2xx FT_SetBaudRate baud=%lu rc=%lu", baud, rc);
    return rc;
}

FT_STATUS Proxy_FT_SetDataCharacteristics(FT_HANDLE h, BYTE bits, BYTE stop, BYTE parity)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, BYTE, BYTE, BYTE);
    fn_t f = (fn_t)orig("FT_SetDataCharacteristics");
    FT_STATUS rc = f ? f(h, bits, stop, parity) : 1;
    logline("ftd2xx FT_SetDataCharacteristics bits=%u stop=%u parity=%u rc=%lu", bits, stop, parity, rc);
    return rc;
}

FT_STATUS Proxy_FT_SetTimeouts(FT_HANDLE h, DWORD rd, DWORD wr)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, DWORD, DWORD);
    fn_t f = (fn_t)orig("FT_SetTimeouts");
    FT_STATUS rc = f ? f(h, rd, wr) : 1;
    logline("ftd2xx FT_SetTimeouts rd=%lu wr=%lu rc=%lu", rd, wr, rc);
    return rc;
}

FT_STATUS Proxy_FT_SetLatencyTimer(FT_HANDLE h, BYTE ms)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, BYTE);
    fn_t f = (fn_t)orig("FT_SetLatencyTimer");
    FT_STATUS rc = f ? f(h, ms) : 1;
    logline("ftd2xx FT_SetLatencyTimer ms=%u rc=%lu (важно для таймингов!)", ms, rc);
    return rc;
}

FT_STATUS Proxy_FT_SetFlowControl(FT_HANDLE h, WORD fc, BYTE xon, BYTE xoff)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, WORD, BYTE, BYTE);
    fn_t f = (fn_t)orig("FT_SetFlowControl");
    FT_STATUS rc = f ? f(h, fc, xon, xoff) : 1;
    logline("ftd2xx FT_SetFlowControl fc=0x%04X rc=%lu", fc, rc);
    return rc;
}

FT_STATUS Proxy_FT_Purge(FT_HANDLE h, DWORD mask)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, DWORD);
    fn_t f = (fn_t)orig("FT_Purge");
    FT_STATUS rc = f ? f(h, mask) : 1;
    logline("ftd2xx FT_Purge mask=%lu rc=%lu", mask, rc);
    return rc;
}

FT_STATUS Proxy_FT_ResetDevice(FT_HANDLE h)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE);
    fn_t f = (fn_t)orig("FT_ResetDevice");
    FT_STATUS rc = f ? f(h) : 1;
    logline("ftd2xx FT_ResetDevice rc=%lu", rc);
    return rc;
}

FT_STATUS Proxy_FT_SetBitMode(FT_HANDLE h, BYTE mask, BYTE mode)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, BYTE, BYTE);
    fn_t f = (fn_t)orig("FT_SetBitMode");
    FT_STATUS rc = f ? f(h, mask, mode) : 1;
    logline("ftd2xx FT_SetBitMode mask=0x%02X mode=0x%02X rc=%lu", mask, mode, rc);
    return rc;
}

FT_STATUS Proxy_FT_GetQueueStatus(FT_HANDLE h, DWORD* q)
{
    typedef FT_STATUS (WINAPI *fn_t)(FT_HANDLE, DWORD*);
    fn_t f = (fn_t)orig("FT_GetQueueStatus");
    FT_STATUS rc = f ? f(h, q) : 1;
    /* очередь опрашивается часто — логируем только непустую */
    if (rc == FT_OK && q && *q > 0)
        logline("ftd2xx FT_GetQueueStatus rx=%lu", *q);
    return rc;
}

/* ------------------------------------------------------------------ DllMain */

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        DisableThreadLibraryCalls(inst);
        g_t0 = GetTickCount();
        proxy_open_log();
        logline("# ftd2xx_proxy attached (pid=%lu)", (unsigned long)GetCurrentProcessId());
    } else if (reason == DLL_PROCESS_DETACH) {
        logline("# ftd2xx_proxy detached");
        if (g_log) fclose(g_log);
        if (g_orig) FreeLibrary(g_orig);
        DeleteCriticalSection(&g_cs);
    }
    return TRUE;
}
