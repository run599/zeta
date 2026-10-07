#ifndef ZETA_TLSINT_HOST_H
#define ZETA_TLSINT_HOST_H

// ============================================================================
// zeta_tlsint 宿主侧（M2-3）：注入器 + 环消费/中央判定
//
//   注入器  : 由 ZETA.exe 的 7006 进程创建回调驱动 → 过滤目标 → CreateRemoteThread(LoadLibraryW)
//   消费端  : 后台线程读共享 Ring（\BaseNamedObjects\ZETA_TlsInt_Ring，128 槽 × 64KB）→ 规则判定 → 告警
//
// 设计约束：
//   - 本模块**不链接** ZETA_TlsInt.dll（否则 ZETA.exe 启动即需该 DLL）。环的布局/名字
//     直接复用 zeta_tlsint 的公共头，避免两份定义漂移。
//   - 环若由本模块（ZETA.exe，提权）先创建，必须用与 DLL **完全相同的 SDDL**，
//     否则非提权的目标进程写不进环 ⇒ DLP 静默失效（见验证报告 §6）。SDDL 常量见 tlsint_host.cpp。
//   - 默认编译为**静态库**（ZETA.exe 内嵌）；若改成 DLL，定义 ZETA_TLSINT_HOST_EXPORTS 即可。
// ============================================================================

#include <windows.h>

#ifdef ZETA_TLSINT_HOST_EXPORTS
#define TLSINT_HOST_API __declspec(dllexport)
#else
#define TLSINT_HOST_API
#endif

// 日志回调：level 1=INFO 2=WARN 3=HIGH
typedef void (__stdcall *TlsIntLogFn)(int level, const wchar_t* msg);
// 告警回调（供接入行为引擎评分/拦截；与日志分离，便于后续把告警变成主动处置）
typedef void (__stdcall *TlsIntAlertFn)(int severity, unsigned long pid, int ruleId,
                                        const wchar_t* ruleName, const wchar_t* detail);

extern "C" {

// 启动宿主：初始化注入器 + 启动环消费线程。dllPath = ZETA_TlsInt.dll 完整路径。幂等。
// 返回 0 成功；-1 dllPath 为空或文件不存在。
TLSINT_HOST_API int  __stdcall TlsIntHost_Start(const wchar_t* dllPath);
TLSINT_HOST_API void __stdcall TlsIntHost_Stop(void);

// 由 7006 进程创建事件调用。内部完成过滤 + 注入（不阻塞调用线程，注入在工作线程做）。
TLSINT_HOST_API void __stdcall TlsIntHost_OnProcessCreate(unsigned long pid,
                                                          const wchar_t* imagePath);

// 直接把 DLL 注入指定 PID（**跳过过滤**，供自测/手工处置用）。返回 0 成功。
TLSINT_HOST_API int  __stdcall TlsIntHost_InjectPid(unsigned long pid);

// 目标过滤判定（可单测）。返回 1 = 允许注入；0 = 拒绝（why 给出原因）。
TLSINT_HOST_API int  __stdcall TlsIntHost_IsEligible(unsigned long pid,
                                                     const wchar_t* imagePath,
                                                     wchar_t* why, int whyCch);

// 确保环存在（不存在则以本模块的 SDDL 创建）。返回 0 成功。供自测与 SDDL 一致性校验。
TLSINT_HOST_API int  __stdcall TlsIntHost_EnsureRing(void);

// ── 启动时扫荡既有进程（补 7006 覆盖不到的盲区）────────────────────────────
// 7006 只能看到"启动后新建"的进程；ZETA 启动前就开着的浏览器/IM/Office 永远不被注入，
// 而这恰恰是 DLP 最该看的目标（实机实测：215 个有路径的进程中 86 个合格，
// 其中含 12×msedge、13×msedgewebview2、9×QQ —— 全部是启动前就在跑的）。
// nameSubstr: NULL/空 = 扫荡全部合格进程；非空 = 只扫进程名含该子串者（自测用，便于外科式验证）。
// 返回入队数量；-1 宿主未启动；-2 枚举失败。
TLSINT_HOST_API int  __stdcall TlsIntHost_SweepExisting(const wchar_t* nameSubstr);
// 自动扫荡开关（默认开；Start 后延时若干秒执行一次）。返回旧值。
TLSINT_HOST_API int  __stdcall TlsIntHost_SetSweepEnabled(int enable);
TLSINT_HOST_API int  __stdcall TlsIntHost_GetSweepEnabled(void);
TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetSweptCount(void);

TLSINT_HOST_API void __stdcall TlsIntHost_SetLogFn(TlsIntLogFn fn);
TLSINT_HOST_API void __stdcall TlsIntHost_SetAlertFn(TlsIntAlertFn fn);

// 诊断计数
TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetInjectedCount(void);
TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetSkippedCount(void);
TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetInjectFailCount(void);
TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetConsumedCount(void);
TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetAlertCount(void);
TLSINT_HOST_API int __stdcall TlsIntHost_GetRingError(void);   // 0 = 环可用

} // extern "C"

// ── 规则判定（纯函数，便于单测）────────────────────────────────────────────
// dir: 1=外发(请求明文) 0=入站(响应明文)
struct TlsIntFinding {
    int            ruleId;
    const wchar_t* ruleName;
    int            severity;      // 1=INFO 2=WARN 3=HIGH
    wchar_t        detail[256];
};

// 返回命中数（写入 out[0..maxOut-1]）
int TlsIntDetect_Analyze(int dir, const unsigned char* data, unsigned long len,
                         TlsIntFinding* out, int maxOut);

#endif // ZETA_TLSINT_HOST_H
