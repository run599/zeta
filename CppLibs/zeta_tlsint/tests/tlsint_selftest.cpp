// zeta_tlsint 自测: 安装 hook 后发起 HTTPS GET, 从共享 Ring 读回截获的明文
#include "zeta_tlsint.h"
#include <winhttp.h>
#include <cstdio>

#pragma comment(lib, "winhttp.lib")

typedef int(__stdcall* pfnInstall)(void);
typedef int(__stdcall* pfnUninstall)(void);
typedef unsigned long long(__stdcall* pfnCount)(void);
typedef HANDLE(__stdcall* pfnRingOpen)(void);
typedef void*(__stdcall* pfnRingMap)(HANDLE);
typedef int(__stdcall* pfnErr)(void);

static void DumpSample(const ZETA_TLSINT_RING_SLOT* s) {
    if (!s || s->seq <= 0) return;
    printf("[ring] seq=%ld dir=%s pid=%ld len=%lu head=",
           s->seq, s->dir ? "OUT" : "IN ", s->pid, s->len);
    unsigned long show = s->len < 60 ? s->len : 60;
    for (unsigned long i = 0; i < show; i++) {
        unsigned char c = s->data[i];
        printf("%c", (c >= 32 && c < 127) ? c : '.');
    }
    printf("\n");
}

int main() {
    HMODULE m = LoadLibraryW(L"ZETA_TlsInt.dll");
    if (!m) { printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }
    auto install  = (pfnInstall)GetProcAddress(m, "ZetaTlsInt_Install");
    auto uninst   = (pfnUninstall)GetProcAddress(m, "ZetaTlsInt_Uninstall");
    auto count    = (pfnCount)GetProcAddress(m, "ZetaTlsInt_GetCaptureCount");
    auto ringOpen = (pfnRingOpen)GetProcAddress(m, "ZetaTlsInt_RingOpen");
    auto ringMap  = (pfnRingMap)GetProcAddress(m, "ZetaTlsInt_RingMap");
    auto lasterr  = (pfnErr)GetProcAddress(m, "ZetaTlsInt_GetLastError");
    auto lastmh   = (pfnErr)GetProcAddress(m, "ZetaTlsInt_GetLastMhStatus");
    if (!install || !uninst || !count || !ringOpen || !ringMap) { printf("GetProcAddress failed\n"); return 2; }

    // DllMain ATTACH 已自动启动安装线程; 等待 hook 就绪 (若 install 返回
    // ALREADY_CREATED 等非零也属正常)
    Sleep(400);
    printf("[selftest] waiting auto-install... capture=%llu\n", count());

    // HTTPS GET → 触发 EncryptMessage(外发) / DecryptMessage(入站)
    HINTERNET sess = WinHttpOpen(L"zeta_tlsint_selftest/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET conn = sess ? WinHttpConnect(sess, L"www.example.com", INTERNET_DEFAULT_HTTPS_PORT, 0) : NULL;
    if (conn) {
        HINTERNET req = WinHttpOpenRequest(conn, L"GET", L"/", NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (req) {
            if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                WinHttpReceiveResponse(req, NULL);
                BYTE buf[4096]; DWORD got = 0;
                while (WinHttpReadData(req, buf, sizeof(buf), &got) && got > 0) {}
            }
            WinHttpCloseHandle(req);
        }
        WinHttpCloseHandle(conn);
    }
    if (sess) WinHttpCloseHandle(sess);

    Sleep(300);  // 等 hook 写入 Ring
    printf("[selftest] capture count = %llu\n", count());

    // 读回 Ring 样本 (DLL 自身已建 Ring)
    HANDLE hMap = ringOpen();
    ZETA_TLSINT_RING* ring = (ZETA_TLSINT_RING*)ringMap(hMap);
    if (ring) {
        LONG lastSeq = 0;
        int printed = 0;
        // 扫 3 遍模拟消费推进, 打印最新样本
        for (int pass = 0; pass < 2 && printed < 6; pass++) {
            LONG maxSeq = lastSeq;
            for (int i = 0; i < ZETA_TLSINT_RING_SLOTS; i++) {
                LONG s = ring->slots[i].seq;
                if (s > lastSeq && s > maxSeq) maxSeq = s;
            }
            for (int i = 0; i < ZETA_TLSINT_RING_SLOTS && printed < 6; i++) {
                if (ring->slots[i].seq > lastSeq && ring->slots[i].seq <= maxSeq) {
                    DumpSample(&ring->slots[i]);
                    printed++;
                }
            }
            lastSeq = maxSeq;
            Sleep(50);
        }
        printf("[selftest] ring samples printed=%d\n", printed);
    } else {
        printf("[selftest] ring open failed\n");
    }
    if (hMap) CloseHandle(hMap);

    uninst();
    FreeLibrary(m);
    printf("[selftest] done\n");
    return 0;
}
