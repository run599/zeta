#pragma once
#include <Windows.h>
#include <string>
#include <vector>

// ============================================================================
// ByovdBlacklist —— 已知易受攻击驱动 (BYOVD) 黑名单
//
// 【为什么需要它】ZETA 原有的 BYOVD 防线只有两条, 各有盲区:
//   ① ProtectFile.cpp 的"无签名进程写 .sys → 直接拒绝": 挡不住由【已签名】
//      程序释放的驱动, 也挡不住事先就落在盘上、之后才被加载的驱动。
//   ② 状态机规则 byovd_unsigned_loads_driver: 同样以"进程无签名"为前提。
//   所以只要驱动文件通过任何受信任路径落地, 前两条都不会响。
//
// 【本模块提供两条独立检测通道】
//
//   通道 A —— 文件内容哈希比对  MatchFileHash()
//     驱动被改名、换路径、扔进 %TEMP% 都无效: 内容哈希不变。
//     这一点正是它相对"按文件名/路径判"的价值 —— 样本 E:\远控\cs 就是把驱动
//     解码后写成 %TEMP%\<随机16进制>.sys 再 NtLoadDriver 的。
//     接入点: 驱动加载事件 7010、可疑模块上报 7014。
//
//   通道 B —— 设备对象存活探测  ProbeLoadedDevices()
//     已知易受攻击驱动会创建固定的设备对象名(如 \\.\HP_WKS_SWTOOLS_DRIVER),
//     这个名字是驱动内部硬编码的, 攻击者改不了(改了就收不到自己的 IOCTL)。
//     尝试打开该设备: 打得开 = 该漏洞驱动此刻正在本机运行。
//     接入点: ZETA 启动时 + 自保护失效事件(7012)时。
//     代价极低(一次 CreateFileW, 不做任何 IOCTL), 且完全不依赖攻击者的落地路径,
//     也不依赖 ZETA 的 7010/7014 事件是否还能送达(回调被摘时事件本身就没了)。
//
// 【哈希来源与可信度】LOLDrivers (loldrivers.io) 收录的样本, 每条都记了来源
//   与收录日期, 便于日后核对是否已被厂商更新/吊销。表当前只有 1 条【经查证】
//   的条目 —— 宁少勿假, 不要凭记忆往里填哈希。
// ============================================================================

struct ByovdEntry {
    const char*    name;       // 驱动名 (人类可读, 纯 ASCII 以免日志编码歧义)
    const char*    sha256;     // 小写十六进制, 64 字符
    const wchar_t* devicePath; // 设备对象路径; 该驱动不创建具名设备时为 nullptr
    const char*    source;     // 来源 / 收录信息 (纯 ASCII)
};

namespace ByovdBlacklist {

// 通道 A: 计算 path 的 SHA256 并比对黑名单。
// 命中返回 true 并填充 outEntry (指向静态表项, 生命周期 = 进程)。
// 计算失败(文件不存在/打不开/读错)返回 false —— 静默返回, 因为这是"尽力检测"
// 路径, 不该因为一个读不到的文件就污染日志。
bool MatchFileHash(const std::wstring& path, const ByovdEntry** outEntry);

// 通道 B: 逐个尝试打开黑名单里已知的设备对象, 返回【存在】的那些(即正在运行)。
// 返回项是人可读的设备路径(访问被拒时会带标注 —— 设备存在但拒绝访问同样算"在")。
// 全程无副作用: 只 CreateFileW + CloseHandle, 不发任何 IOCTL。
std::vector<std::wstring> ProbeLoadedDevices();

// 黑名单条目数 (供启动日志显示当前覆盖度)
size_t EntryCount();

// 计算 SHA256 → 小写十六进制; 失败返回空串。
std::string Sha256Hex(const std::wstring& path);

// NT 风格路径 → Win32 路径。CreateFileW 打不开 \SystemRoot\... 与 \??\... ,
// 而 7010/7014 事件里的驱动路径正是这两种形态(来自内核的 FullPathName)。
//   \SystemRoot\System32\x.sys  →  C:\Windows\System32\x.sys
//   \??\C:\temp\x.sys           →  C:\temp\x.sys
// 其它形态(如 \Device\HarddiskVolume3\...)原样返回, 由调用方自行决定。
std::wstring NormalizeToWin32Path(const std::wstring& in);

} // namespace ByovdBlacklist
