#pragma once

// ============================================================
// ZETA 事件码契约 (P2-4c 统一)
//
// 驱动 → 用户态 消息码的【唯一定义源】。
// 所有工程 (驱动 DriverCommon.h / main.cpp / behavior_engine / driver_comm)
// 必须引用本头文件, 禁止在别处使用裸数字。
//
// 契约注释格式: 语义 → 产生源 (驱动回调) → 消费方 (main.cpp / behavior_engine)
// ============================================================

// ── 文件防护 (2000 系) ──
#define ZETA_MSG_FILE_PROTECT        2001  // 文件保护拦截 (PE 释放/重命名/删除/安全描述) → main 弹窗 + BE 评分
#define ZETA_MSG_HIDDEN_PE           2002  // 隐藏 PE 文件创建 → main 终止+隔离 (不入 BE)
#define ZETA_MSG_LEARN_PATH          2011  // 学习模式: 受保护路径事件 → main 仅记录
#define ZETA_MSG_LEARN_HIDDEN        2012  // 学习模式: 隐藏文件事件 → main 仅记录

// ── 注册表防护 (3000 系) ──
#define ZETA_MSG_REG_PROTECT         3001  // 注册表保护拦截 → main 弹窗 + BE 评分
#define ZETA_MSG_REG_BAM             3002  // BAM 注册表访问拦截 → main 记录 + 联动

// ── 磁盘/卷防护 (4000 系) ──
#define ZETA_MSG_DISK_WRITE          4001  // 磁盘底层写拦截 (ProtectBoot 格式化/擦写) → main 弹窗 + BE
#define ZETA_MSG_VOLUME_DISMOUNT     4002  // 卷卸载/锁卷拦截 (ProtectFile) → main 弹窗 + BE
#define ZETA_MSG_DISK_WRITE_ALERT    4003  // 磁盘擦写监控告警 (ProtectFile, 仅监控) → main 记录 + BE

// ── 勒索信号 (5000 系) ──
#define ZETA_MSG_RANSOM_FIRST_WRITE  5002  // 勒索首写检查命中 → main 联动 + BE 评分
#define ZETA_MSG_RANSOM_ENTROPY_WRITE 5003 // 勒索高熵/高频写 → main 联动 + BE 评分
#define ZETA_MSG_RANSOM_HONEY_TOUCH  5004  // 蜜罐文件触碰 → BE 强信号
// 注意: 5001(旧勒索行为) 已废弃 — 驱动从未产生, 死链已清除。

// ── 注入/银狐 (6000 系) ──
#define ZETA_MSG_CODE_INJECT         6001  // 代码注入/可疑 DLL 加载/LOLBin → main 弹窗 + BE
#define ZETA_MSG_SILVERFOX_SIGNATURE 6002  // 银狐签名不一致 → main 联动 + BE
#define ZETA_MSG_SILVERFOX_RELEASES  6003  // 银狐 PE 释放超量 → main 弹窗 + BE
#define ZETA_MSG_APC_INJECT          6010  // APC 注入拦截 → main 弹窗 + BE
#define ZETA_MSG_THREAD_CREATE_INJECT 6015 // 远程线程注入 (NtCreateThreadEx) → main 弹窗
#define ZETA_MSG_WRITE_MEM_INJECT    6016  // 跨进程写内存 (NtWriteVirtualMemory) → main 弹窗
#define ZETA_MSG_UNMAP_VIEW          6017  // 跨进程解映射 (NtUnmapViewOfSection) → BE 镂空链信号
                                          // 进程镂空前置"清空"动作: unmap+write+thread 组合 = 确定恶意
#define ZETA_MSG_WRITE_MEM_PE        6018  // 跨进程写入 MZ 头 (PE 注入/镂空载荷) → BE +30
#define ZETA_MSG_WRITE_MEM_SHELLCODE 6019  // 跨进程写入 shellcode 特征 (0xFC 48 83) → 驱动拒绝 + BE +50
#define ZETA_MSG_SYSCALL_SPOOF       6020  // P4: 用户 RIP 非 ntdll → 疑似间接/内联 syscall (观察) → BE +30

// ── 血统/日志/进程 (7000 系) ──
#define ZETA_MSG_LOG                 7000  // 驱动日志 → main 仅显示
#define ZETA_MSG_LINEAGE_ALERT       7001  // 血统追踪告警 → main 静默 + BE
#define ZETA_MSG_RANSOM_HEADER_ALERT 7002  // 勒索确认-进程已挂起 → main 弹窗决策 (ALLOW/DENY 回传)
#define ZETA_MSG_LINEAGE_FALLBACK    7004  // 血统回退 (保留定义, 当前无产生源)
#define ZETA_MSG_LEARNING_LOG        7005  // 学习模式活动日志 → main 记录
#define ZETA_MSG_PROCESS_CREATE      7006  // 进程创建 → main 记录+扫描 + BE
#define ZETA_MSG_PROCESS_EXIT        7007  // 进程退出 → main 记录
#define ZETA_MSG_THREAD_CREATE       7008  // 线程创建 (含远程线程标记 ,R) → BE 评分
#define ZETA_MSG_THREAD_EXIT         7009  // 线程退出 (保留定义, 主流程无 case)
#define ZETA_MSG_IMAGE_LOAD          7010  // 驱动加载 (.sys) → main 记录 + BE (BYOVD)
// 7011: 内核句柄访问受保护对象 —— 内核态打开不受 Ob 访问检查约束, 拦不住;
//       但绝不能静默放行(那等于给恶意驱动/BYOVD 一条无痕通道)。
//       见 ProtectProcess.cpp ReportKernelHandleAccess。
#define ZETA_MSG_KERNEL_HANDLE_ALERT 7011

// ── 自保护完整性 (7012 系, 2026-10-02 新增) ──
// 背景(2026-10-02 对抗分析, 样本 E:\远控\cs): 对手持有任意内核写时, "阻止篡改"做不到。
// 正确姿态是【及时检测 → 归因 → 反制】。判据改用【功能探针】而非结构偏移:
// 主动发起一次必然经过该回调的操作, 观察回调是否仍被调用 —— 于是对
// "清零回调项字段 / ObUnRegisterCallbacks / 替换函数指针 / 改 Operations 位"
// 等一切手法表现统一, 且不依赖任何 build 相关偏移。
#define ZETA_MSG_SELF_INTEGRITY_FAIL  7012  // 自保护组件探针连续>=3轮未命中 → main 弹窗 + BE 最高分
#define ZETA_MSG_KERNEL_TAMPER_SUSPECT 7013 // 探针失效后触发模块比对的次数 → main 记录 + BE
#define ZETA_MSG_ROGUE_DRIVER_LOADED  7014  // 模块比对定位到的可疑驱动路径 → main 签名判定 + 隔离候选

// 注意: 7003(勒索实验) 已废弃 — 曾错报高熵写, 已迁 5003, 消费清理完毕。
//
// ⚠ 2026-09-30 SSDT 退役后的孤儿码 (保留定义, 但已无产生源):
//   6010 APC_INJECT / 6015 THREAD_CREATE_INJECT / 6016 WRITE_MEM_INJECT /
//   6017 UNMAP_VIEW / 6018 WRITE_MEM_PE / 6019 WRITE_MEM_SHELLCODE / 6020 SYSCALL_SPOOF
//   —— 全部由 ApcHook.cpp / InjectHook.cpp 的 SSDT 重定向产生; ZETA_ENABLE_SSDT=0 后
//      这两个文件整文件空编, 故这些码不会再出现。
//   **能力未丢**: 它们拦的条件(NtCreateThreadEx 需 PROCESS_CREATE_THREAD、
//      NtQueueApcThread 需 THREAD_SET_CONTEXT)已被 ProtectProcess 的 Ob 回调在
//      **句柄层提前剥位**, 覆盖所有操作而非仅两个 syscall。详见 ProtectProcess.cpp。

// ── 网络事件 (8000 系, NetFilter 独立 ring buffer, 不进行为引擎) ──
#define ZETA_MSG_NET_SOCKET_CREATE   8001  // socket 创建 → netFilterEventLoop 展示
#define ZETA_MSG_NET_SOCKET_SEND     8002  // send 数据 → netFilterEventLoop 展示
#define ZETA_MSG_NET_SOCKET_CONNECT  8003  // connect → netFilterEventLoop 弹窗
