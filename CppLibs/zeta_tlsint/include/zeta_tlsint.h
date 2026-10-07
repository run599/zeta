#ifndef ZETA_TLSINT_H
#define ZETA_TLSINT_H

// ============================================================================
// zeta_tlsint.dll — TLS 明文截获 (进程内 hook SSPI EncryptMessage/DecryptMessage)
//
// 目的: 防勒索数据外传 / 恶意信息外传 (DLP) / C2 通信内容检测。
//   网络驱动只能看到 TLS 密文; 本 DLL 注入受监控进程后, 在 TLS 加解密发生点
//   (EncryptMessage / DecryptMessage) 截获明文, 写入共享 Ring, 由 ZETA.exe
//   统一消费并做中央规则判定。
//
// 用法:
//   1) 目标进程加载本 DLL → DllMain ATTACH 自动启动安装线程 (注入即生效)
//   2) 明文样本写入共享 Ring: \BaseNamedObjects\ZETA_TlsInt_Ring (Session 级)
//   3) ZETA.exe 打开同一 Ring 消费 → 规则扫描 → 告警
//   4) 显式 ZetaTlsInt_Install()/Uninstall() 亦可用于受控加载 (自测)
// ============================================================================

#include <windows.h>

#ifdef ZETA_TLSINT_EXPORTS
#define ZETA_TLSINT_API __declspec(dllexport)
#else
#define ZETA_TLSINT_API __declspec(dllimport)
#endif

// ── 共享 Ring (跨进程明文回传, 供 ZETA.exe 统一判定) ──────────────
#define ZETA_TLSINT_RING_NAME  L"ZETA_TlsInt_Ring"   // Session 级命名对象
#define ZETA_TLSINT_RING_SLOTS 128
#define ZETA_TLSINT_RING_BODY  (64 * 1024)           // 单包明文上限

typedef struct _ZETA_TLSINT_RING_SLOT {
    volatile LONG seq;        // 写入序号 (>0 有效); 消费者按最大 seq 推进
    volatile LONG pid;        // 发送进程
    int dir;                  // 1=外发 0=入站
    ULONG len;                // 明文有效长度
    BYTE  data[ZETA_TLSINT_RING_BODY];
} ZETA_TLSINT_RING_SLOT;

typedef struct _ZETA_TLSINT_RING {
    volatile LONG nextSeq;    // 下一写入序号
    volatile LONG head;       // 消费者已处理序号
    ZETA_TLSINT_RING_SLOT slots[ZETA_TLSINT_RING_SLOTS];
} ZETA_TLSINT_RING;

extern "C" {

// 安装 / 卸载 hook (当前进程内; 幂等)
ZETA_TLSINT_API int ZetaTlsInt_Install(void);
ZETA_TLSINT_API int ZetaTlsInt_Uninstall(void);

// 打开/创建共享 Ring (DLL 侧写样本; 宿主侧读)
ZETA_TLSINT_API void* ZetaTlsInt_RingOpen(void);       // 返回 HANDLE(mapping), 失败 NULL
ZETA_TLSINT_API void* ZetaTlsInt_RingMap(HANDLE hMap); // 返回 ZETA_TLSINT_RING* (失败 NULL)
ZETA_TLSINT_API void  ZetaTlsInt_RingWrite(void* ring, int dir,
                                           const unsigned char* data, unsigned long len);

// 诊断
ZETA_TLSINT_API unsigned long long ZetaTlsInt_GetCaptureCount(void);
ZETA_TLSINT_API int ZetaTlsInt_GetLastError(void);
ZETA_TLSINT_API int ZetaTlsInt_GetLastMhStatus(void);
// 环不可达诊断: 0 = 环可用; 非 0 = EnsureRing 建/开环失败时的 GetLastError()
// (5=ACCESS_DENIED 多为权限/掩码不匹配; 2=FILE_NOT_FOUND 多为环尚未被创建)
ZETA_TLSINT_API unsigned long ZetaTlsInt_GetRingError(void);

}

#endif // ZETA_TLSINT_H
