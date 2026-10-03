#include "zeta_tlsint.h"
#include "MinHook.h"

#include <windows.h>
#include <sspi.h>
#include <cstdio>

// ============================================================================
// TLS 明文截获 — hook secur32/sspicli!EncryptMessage / DecryptMessage
// 明文写入共享 Ring → ZETA.exe 统一消费判定。
// ============================================================================

namespace {

volatile unsigned long long g_captureCount = 0;
bool g_installed = false;
int g_lastError = 0;
int g_lastMhStatus = 0;

// Ring 句柄 (lazy open)
HANDLE g_ringMap = NULL;
ZETA_TLSINT_RING* g_ring = NULL;

// SSPI 原型
using pfnEncryptMessage = SECURITY_STATUS(SEC_ENTRY*)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
using pfnDecryptMessage = SECURITY_STATUS(SEC_ENTRY*)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);

pfnEncryptMessage g_OrigEncrypt = nullptr;
pfnDecryptMessage g_OrigDecrypt = nullptr;

// EncryptMessage/DecryptMessage 可能由 secur32 转发到 sspicli; 手动解析真实实现地址
void* ResolveProc(const char* name) {
    const wchar_t* mods[] = { L"secur32.dll", L"sspicli.dll" };
    for (const wchar_t* mod : mods) {
        HMODULE h = LoadLibraryW(mod);
        if (h) {
            FARPROC p = GetProcAddress(h, name);
            if (p) return (void*)p;
        }
    }
    return nullptr;
}

void EnsureRing() {
    if (g_ring) return;
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                  (DWORD)sizeof(ZETA_TLSINT_RING), ZETA_TLSINT_RING_NAME);
    if (!h) h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, ZETA_TLSINT_RING_NAME);
    if (!h) return;
    ZETA_TLSINT_RING* r = (ZETA_TLSINT_RING*)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0,
                                                           sizeof(ZETA_TLSINT_RING));
    if (!r) { CloseHandle(h); return; }
    g_ringMap = h;
    g_ring = r;
}

void ReportSample(int sendDir, const unsigned char* data, unsigned long len) {
    if (!data || len == 0) return;
    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&g_captureCount));

    EnsureRing();
    if (!g_ring) return;

    // 分配槽: 写 seq, 槽满覆盖旧样本 (Ring 溢出丢样本, 可接受)
    LONG seq = InterlockedIncrement(&g_ring->nextSeq);
    ZETA_TLSINT_RING_SLOT* s = &g_ring->slots[seq % ZETA_TLSINT_RING_SLOTS];
    ULONG n = (len > ZETA_TLSINT_RING_BODY) ? ZETA_TLSINT_RING_BODY : len;
    s->pid = (LONG)GetCurrentProcessId();
    s->dir = sendDir;
    s->len = n;
    memcpy(s->data, data, n);
    InterlockedExchange(&s->seq, seq);   // seq 最后写 = 发布
}

void Capture(SecBufferDesc* msg, int sendDir) {
    if (!msg || !msg->pBuffers || msg->cBuffers == 0) return;
    for (ULONG i = 0; i < msg->cBuffers; i++) {
        const SecBuffer& b = msg->pBuffers[i];
        if (b.BufferType == SECBUFFER_DATA && b.pvBuffer && b.cbBuffer > 0) {
            ReportSample(sendDir, static_cast<const unsigned char*>(b.pvBuffer), b.cbBuffer);
            break;
        }
    }
}

SECURITY_STATUS SEC_ENTRY Hooked_EncryptMessage(PCtxtHandle ctx, ULONG qop,
                                                PSecBufferDesc msg, ULONG seq) {
    Capture(msg, 1);  // 明文在原始加密前
    return g_OrigEncrypt(ctx, qop, msg, seq);
}

SECURITY_STATUS SEC_ENTRY Hooked_DecryptMessage(PCtxtHandle ctx, PSecBufferDesc msg,
                                                ULONG seq, PULONG pqop) {
    SECURITY_STATUS st = g_OrigDecrypt(ctx, msg, seq, pqop);
    if (st == SEC_E_OK) Capture(msg, 0);  // 解密后 DATA buffer 为明文
    return st;
}

DWORD WINAPI InstallWorker(LPVOID) {
    ZetaTlsInt_Install();
    return 0;
}

}  // namespace

extern "C" {

ZETA_TLSINT_API void* ZetaTlsInt_RingOpen(void) {
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                  (DWORD)sizeof(ZETA_TLSINT_RING), ZETA_TLSINT_RING_NAME);
    if (!h) h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, ZETA_TLSINT_RING_NAME);
    return h;
}

ZETA_TLSINT_API void* ZetaTlsInt_RingMap(HANDLE hMap) {
    if (!hMap) return NULL;
    return MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ZETA_TLSINT_RING));
}

ZETA_TLSINT_API void ZetaTlsInt_RingWrite(void* ring, int dir,
                                          const unsigned char* data, unsigned long len) {
    ZETA_TLSINT_RING* r = (ZETA_TLSINT_RING*)ring;
    if (!r || !data || len == 0) return;
    LONG seq = InterlockedIncrement(&r->nextSeq);
    ZETA_TLSINT_RING_SLOT* s = &r->slots[seq % ZETA_TLSINT_RING_SLOTS];
    ULONG n = (len > ZETA_TLSINT_RING_BODY) ? ZETA_TLSINT_RING_BODY : len;
    s->pid = (LONG)GetCurrentProcessId();
    s->dir = dir;
    s->len = n;
    memcpy(s->data, data, n);
    InterlockedExchange(&s->seq, seq);
}

ZETA_TLSINT_API unsigned long long ZetaTlsInt_GetCaptureCount(void) {
    return g_captureCount;
}

ZETA_TLSINT_API int ZetaTlsInt_GetLastError(void) {
    return g_lastError;
}

ZETA_TLSINT_API int ZetaTlsInt_GetLastMhStatus(void) {
    return g_lastMhStatus;
}

ZETA_TLSINT_API int ZetaTlsInt_Install(void) {
    if (g_installed) return 0;

    g_lastError = 0;
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) { g_lastError = 1; g_lastMhStatus = s; return -1; }

    void* encAddr = ResolveProc("EncryptMessage");
    if (!encAddr) { g_lastError = 2; g_lastMhStatus = -1; return -2; }
    s = MH_CreateHook(encAddr, reinterpret_cast<LPVOID>(&Hooked_EncryptMessage),
                      reinterpret_cast<LPVOID*>(&g_OrigEncrypt));
    if (s != MH_OK) { g_lastError = 2; g_lastMhStatus = s; return -2; }

    void* decAddr = ResolveProc("DecryptMessage");
    if (!decAddr) { g_lastError = 3; g_lastMhStatus = -1; return -3; }
    s = MH_CreateHook(decAddr, reinterpret_cast<LPVOID>(&Hooked_DecryptMessage),
                      reinterpret_cast<LPVOID*>(&g_OrigDecrypt));
    if (s != MH_OK) { g_lastError = 3; g_lastMhStatus = s; return -3; }

    MH_EnableHook(MH_ALL_HOOKS);
    g_installed = true;
    return 0;
}

ZETA_TLSINT_API int ZetaTlsInt_Uninstall(void) {
    if (!g_installed) return 0;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_installed = false;
    return 0;
}

}  // extern "C"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // 注入即生效: 后台线程安装 (避免 DllMain 中 LoadLibrary 触发 loader lock)
        HANDLE t = CreateThread(NULL, 0, InstallWorker, NULL, 0, NULL);
        if (t) CloseHandle(t);
    } else if (reason == DLL_PROCESS_DETACH) {
        ZetaTlsInt_Uninstall();
        if (g_ring) UnmapViewOfFile(g_ring);
        if (g_ringMap) CloseHandle(g_ringMap);
        g_ring = NULL;
        g_ringMap = NULL;
    }
    return TRUE;
}
