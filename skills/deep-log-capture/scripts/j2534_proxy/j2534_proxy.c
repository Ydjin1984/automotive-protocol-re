/*
 * j2534_proxy.c — логирующая прокси-DLL для SAE J2534 Pass-Thru (32-бит!).
 *
 * Идея: в реестре (HKLM\SOFTWARE\WOW6432Node\PassThruSupport.04.04\<Vendor>) значение
 * "Function Library" указывает на vendor-DLL. Подменяем путь на нашу прокси-DLL —
 * всё ПО (ODIS, Techstream, флешеры) продолжает работать, а мы получаем полный лог
 * вызовов PassThru* и дампы PASSTHRU_MSG.
 *
 * Реальную DLL прокси находит:
 *   1) переменная окружения J2534_REAL_DLL;
 *   2) первый подходящий <vendor> в реестре (кроме нашей DLL);
 *   3) файл j2534_proxy.ini рядом с DLL:  RealDll=C:\...\vendor.dll
 *
 * Сборка: см. build.bat. Обязательно 32-битная (J2534-приложения 32-битные).
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define J2534_CALL __stdcall

typedef long J2534_STATUS;
typedef unsigned long ULONG_;

#pragma pack(push, 1)
typedef struct {
    ULONG_ ProtocolID;
    ULONG_ RxStatus;
    ULONG_ TxFlags;
    ULONG_ Timestamp;      /* микросекунды (32 бита) */
    ULONG_ DataSize;
    ULONG_ ExtraDataIndex;
    unsigned char Data[4128];
} PASSTHRU_MSG;
#pragma pack(pop)

static HMODULE g_orig = NULL;
static FILE*   g_log = NULL;
static CRITICAL_SECTION g_cs;
static DWORD   g_t0 = 0;

static const char* proto_name(ULONG_ p)
{
    switch (p) {
    case 1: return "J1850VPW"; case 2: return "J1850PWM"; case 3: return "ISO9141";
    case 4: return "ISO14230"; case 5: return "CAN"; case 6: return "ISO15765";
    case 7: return "SCI_A_ENGINE"; case 8: return "SCI_A_TRANS";
    case 9: return "SCI_B_ENGINE"; case 10: return "SCI_B_TRANS";
    default: return "?";
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

static void log_msg(const char* dir, const PASSTHRU_MSG* m)
{
    char hex[3 * 512 + 1];
    ULONG_ i, n;
    if (!m) return;
    n = m->DataSize > 512 ? 512 : m->DataSize;
    hex[0] = 0;
    for (i = 0; i < n; i++) {
        char t[4];
        snprintf(t, 4, "%02X ", m->Data[i]);
        strcat(hex, t);
    }
    logline("%s proto=%s(%lu) flags=0x%lX rxstat=0x%lX ts=%lu len=%lu : %s",
            dir, proto_name(m->ProtocolID), m->ProtocolID, m->TxFlags, m->RxStatus,
            m->Timestamp, m->DataSize, hex);
}

static char g_log_path[MAX_PATH];

static void find_real_dll(void)
{
    char env[MAX_PATH] = {0}, ini[MAX_PATH] = {0};
    char* p;

    if (GetEnvironmentVariableA("J2534_REAL_DLL", env, MAX_PATH) > 0) { strncpy(g_log_path, env, MAX_PATH - 1); g_log_path[MAX_PATH-1]=0; return; }

    GetModuleFileNameA(NULL, ini, MAX_PATH);
    p = strrchr(ini, '\\'); if (p) *(p + 1) = 0;
    strncat(ini, "j2534_proxy.ini", MAX_PATH - strlen(ini) - 1);

    {
        FILE* f = fopen(ini, "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f)) {
                if (_strnicmp(line, "RealDll=", 8) == 0) {
                    char* v = line + 8;
                    char* e = strpbrk(v, "\r\n");
                    if (e) *e = 0;
                    strncpy(g_log_path, v, MAX_PATH - 1);
                    g_log_path[MAX_PATH - 1] = 0;
                    fclose(f);
                    return;
                }
            }
            fclose(f);
        }
    }

    /* реестр: первый vendor, чья Function Library не наша */
    {
        HKEY root, key;
        char sub[256];
        DWORD i = 0, len;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\PassThruSupport.04.04",
                          0, KEY_READ, &root) == ERROR_SUCCESS) {
            while (RegEnumKeyA(root, i++, sub, sizeof(sub)) == ERROR_SUCCESS) {
                if (RegOpenKeyExA(root, sub, 0, KEY_READ, &key) == ERROR_SUCCESS) {
                    char dll[MAX_PATH] = {0};
                    len = sizeof(dll);
                    if (RegQueryValueExA(key, "Function Library", NULL, NULL, (LPBYTE)dll, &len) == ERROR_SUCCESS) {
                        if (dll[0] && !strstr(dll, "j2534_proxy")) {
                            strncpy(g_log_path, dll, MAX_PATH - 1);
                            RegCloseKey(key);
                            RegCloseKey(root);
                            return;
                        }
                    }
                    RegCloseKey(key);
                }
            }
            RegCloseKey(root);
        }
    }
}

static FARPROC orig(const char* name)
{
    if (!g_orig) {
        find_real_dll();
        if (!g_log_path[0]) { logline("# ОШИБКА: реальная J2534 DLL не найдена (J2534_REAL_DLL / j2534_proxy.ini / реестр)"); return NULL; }
        g_orig = LoadLibraryA(g_log_path);
        if (!g_orig) { logline("# ОШИБКА: LoadLibrary(%s) failed %lu", g_log_path, GetLastError()); return NULL; }
        logline("# original J2534 loaded: %s", g_log_path);
    }
    return GetProcAddress(g_orig, name);
}

/* ------------------------------------------------------------------ API */

J2534_STATUS J2534_CALL Proxy_PassThruOpen(void* pName, ULONG_* pDeviceID)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(void*, ULONG_*);
    fn_t f = (fn_t)orig("PassThruOpen");
    J2534_STATUS rc = f ? f(pName, pDeviceID) : 1;
    logline("J2534 PassThruOpen(%s) rc=%ld deviceID=%lu", pName ? (char*)pName : "", rc, pDeviceID ? *pDeviceID : 0);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruClose(ULONG_ id)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_);
    fn_t f = (fn_t)orig("PassThruClose");
    J2534_STATUS rc = f ? f(id) : 1;
    logline("J2534 PassThruClose(%lu) rc=%ld", id, rc);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruConnect(ULONG_ dev, ULONG_ proto, ULONG_ flags, ULONG_ baud, ULONG_* pChan)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, ULONG_, ULONG_, ULONG_, ULONG_*);
    fn_t f = (fn_t)orig("PassThruConnect");
    J2534_STATUS rc = f ? f(dev, proto, flags, baud, pChan) : 1;
    logline("J2534 PassThruConnect proto=%s(%lu) flags=0x%lX baud=%lu rc=%ld chan=%lu",
            proto_name(proto), proto, flags, baud, rc, pChan ? *pChan : 0);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruDisconnect(ULONG_ ch)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_);
    fn_t f = (fn_t)orig("PassThruDisconnect");
    J2534_STATUS rc = f ? f(ch) : 1;
    logline("J2534 PassThruDisconnect(%lu) rc=%ld", ch, rc);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruReadMsgs(ULONG_ ch, PASSTHRU_MSG* msgs, ULONG_* num, ULONG_ tmo)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, PASSTHRU_MSG*, ULONG_*, ULONG_);
    fn_t f = (fn_t)orig("PassThruReadMsgs");
    J2534_STATUS rc = f ? f(ch, msgs, num, tmo) : 1;
    if (rc == 0 && num && *num > 0 && msgs) {
        ULONG_ i; char pfx[64];
        for (i = 0; i < *num && i < 8; i++) {
            snprintf(pfx, 64, "J2534 RX ch=%lu #%lu", ch, i);
            log_msg(pfx, &msgs[i]);
        }
    }
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruWriteMsgs(ULONG_ ch, const PASSTHRU_MSG* msgs, ULONG_* num, ULONG_ tmo)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, const PASSTHRU_MSG*, ULONG_*, ULONG_);
    fn_t f = (fn_t)orig("PassThruWriteMsgs");
    if (num && *num > 0 && msgs) {
        ULONG_ i; char pfx[64];
        for (i = 0; i < *num && i < 8; i++) {
            snprintf(pfx, 64, "J2534 TX ch=%lu #%lu", ch, i);
            log_msg(pfx, &msgs[i]);
        }
    }
    { J2534_STATUS rc = f ? f(ch, msgs, num, tmo) : 1; return rc; }
}

J2534_STATUS J2534_CALL Proxy_PassThruStartPeriodicMsg(ULONG_ ch, const PASSTHRU_MSG* m, ULONG_* id, ULONG_ dt)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, const PASSTHRU_MSG*, ULONG_*, ULONG_);
    fn_t f = (fn_t)orig("PassThruStartPeriodicMsg");
    log_msg("J2534 PERIODIC", m);
    { J2534_STATUS rc = f ? f(ch, m, id, dt) : 1; logline("J2534 PassThruStartPeriodicMsg interval=%lu rc=%ld", dt, rc); return rc; }
}

J2534_STATUS J2534_CALL Proxy_PassThruStopPeriodicMsg(ULONG_ ch, ULONG_ id)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, ULONG_);
    fn_t f = (fn_t)orig("PassThruStopPeriodicMsg");
    J2534_STATUS rc = f ? f(ch, id) : 1;
    logline("J2534 PassThruStopPeriodicMsg id=%lu rc=%ld", id, rc);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruStartMsgFilter(ULONG_ ch, ULONG_ type, const PASSTHRU_MSG* mask,
                                                     const PASSTHRU_MSG* pattern, const PASSTHRU_MSG* flow, ULONG_* fid)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, ULONG_, const PASSTHRU_MSG*, const PASSTHRU_MSG*, const PASSTHRU_MSG*, ULONG_*);
    fn_t f = (fn_t)orig("PassThruStartMsgFilter");
    J2534_STATUS rc = f ? f(ch, type, mask, pattern, flow, fid) : 1;
    logline("J2534 PassThruStartMsgFilter ch=%lu type=%lu rc=%ld", ch, type, rc);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruStopMsgFilter(ULONG_ ch, ULONG_ id)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, ULONG_);
    fn_t f = (fn_t)orig("PassThruStopMsgFilter");
    J2534_STATUS rc = f ? f(ch, id) : 1;
    logline("J2534 PassThruStopMsgFilter id=%lu rc=%ld", id, rc);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruSetProgrammingVoltage(ULONG_ dev, ULONG_ pin, ULONG_ v)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, ULONG_, ULONG_);
    fn_t f = (fn_t)orig("PassThruSetProgrammingVoltage");
    J2534_STATUS rc = f ? f(dev, pin, v) : 1;
    logline("J2534 PassThruSetProgrammingVoltage pin=%lu voltage=%lu rc=%ld", pin, v, rc);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruReadVersion(ULONG_ dev, char* api, char* dll, char* fw)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, char*, char*, char*);
    fn_t f = (fn_t)orig("PassThruReadVersion");
    J2534_STATUS rc = f ? f(dev, api, dll, fw) : 1;
    logline("J2534 PassThruReadVersion api=%s dll=%s fw=%s rc=%ld",
            api ? api : "", dll ? dll : "", fw ? fw : "", rc);
    return rc;
}

J2534_STATUS J2534_CALL Proxy_PassThruGetLastError(char* desc)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(char*);
    fn_t f = (fn_t)orig("PassThruGetLastError");
    J2534_STATUS rc = f ? f(desc) : 1;
    if (rc != 0 || (desc && desc[0]))
        logline("J2534 PassThruGetLastError rc=%ld desc=%s", rc, desc ? desc : "");
    return rc;
}

/* IoctlID: 4 = FIVE_BAUD_INIT (Input = адрес), 5 = FAST_INIT */
J2534_STATUS J2534_CALL Proxy_PassThruIoctl(ULONG_ ch, ULONG_ id, const void* in, void* out)
{
    typedef J2534_STATUS (J2534_CALL *fn_t)(ULONG_, ULONG_, const void*, void*);
    fn_t f = (fn_t)orig("PassThruIoctl");
    J2534_STATUS rc = f ? f(ch, id, in, out) : 1;
    logline("J2534 PassThruIoctl ch=%lu id=%lu%s rc=%ld", ch, id,
            (id == 4) ? " (FIVE_BAUD_INIT)" : (id == 5 ? " (FAST_INIT)" : ""), rc);
    return rc;
}

/* ------------------------------------------------------------------ DllMain */

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        char exe[MAX_PATH] = {0}, path[MAX_PATH];
        char* p;
        SYSTEMTIME st;
        InitializeCriticalSection(&g_cs);
        DisableThreadLibraryCalls(inst);
        g_t0 = GetTickCount();
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        p = strrchr(exe, '\\'); if (p) *(p + 1) = 0; else exe[0] = 0;
        GetLocalTime(&st);
        snprintf(path, MAX_PATH, "%sj2534-log-%04d%02d%02d-%02d%02d%02d.log",
                 exe, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        g_log = fopen(path, "a");
        logline("# j2534_proxy attached (pid=%lu)", (unsigned long)GetCurrentProcessId());
    } else if (reason == DLL_PROCESS_DETACH) {
        logline("# j2534_proxy detached");
        if (g_log) fclose(g_log);
        if (g_orig) FreeLibrary(g_orig);
        DeleteCriticalSection(&g_cs);
    }
    return TRUE;
}
