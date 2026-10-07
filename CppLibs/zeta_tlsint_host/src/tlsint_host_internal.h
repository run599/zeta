#ifndef ZETA_TLSINT_HOST_INTERNAL_H
#define ZETA_TLSINT_HOST_INTERNAL_H

// 宿主模块内部共享（不对外）。避免在 extern "C" 函数体内声明 C++ 函数
// —— 那会被 linkage specification 带成 C 链接，与 tlsint_host.cpp 的 C++ 定义名字不匹配。
#include <string>

namespace tlsint_host {

// 由 TlsIntHost_Start 写入的 DLL 完整路径
std::wstring& DllPath();

// 注入（带尝试预算）。
//   fast=true  : 单次尝试 + 短等待 —— 用于**已就绪的既有进程**（扫荡）。它们没有
//                "7006 时刻地址空间未就绪"的问题，重试纯属浪费；而"对既有进程也重试"
//                正是扫荡变慢、高价值目标（浏览器/IM）排不上队的直接原因。
//   fast=false : 退避重试 —— 用于 7006 刚创建、地址空间可能未就绪的进程。
int InjectPidWithBudget(unsigned long pid, bool fast);

// 统一日志出口（默认 OutputDebugStringW；ZETA.exe 通过 SetLogFn 接管）
void Log(int level, const wchar_t* fmt, ...);
void ReportAlert(int severity, unsigned long pid, int ruleId,
                 const wchar_t* ruleName, const wchar_t* detail);

} // namespace tlsint_host

#endif // ZETA_TLSINT_HOST_INTERNAL_H
