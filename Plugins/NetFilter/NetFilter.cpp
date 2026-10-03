#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>

#define ZETA_NET_TAG    'teN'
#define NET_RING_SIZE   2048
#define NET_EVENT_MAX   512

// M1-6: IP 黑名单持久化注册表位置 (服务 Parameters 键)
#define NET_BLOCK_REG_PATH  L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ZETA_NetFilter\\Parameters"
#define NET_BLOCK_REG_VALUE L"BlockedIps"

#define CTRL_NAME   L"\\Device\\ZETA_NetMon"
#define CTRL_LINK   L"\\??\\ZETA_NetMon"

// 仅附加 \\Device\\Afd (现代 socket 只走 afd, 不走 \\Device\\Tcp/Udp)
#define DEV_AFD     1

// 事件类型
#define EVT_SOCKET  8001  // socket 创建 (IRP_MJ_CREATE)
#define EVT_SEND    8002  // send() 数据
#define EVT_CONNECT 8003  // connect() 目标地址
#define EVT_RECV    8004  // recv() 请求 (含缓冲区大小)
#define EVT_BIND    8005  // bind() 本地地址
#define EVT_AGG     8010  // P1: 驱动侧聚合摘要 (socket/send/recv 的按 PID 累计量)
#define EVT_SEND_DIAG 8092 // P1 诊断: SEND 输入原始字节抓样 (布局待验证)
// ── 可观测性 / 诊断 ────────────────────────────────────────────────────────
// CONNECT 输入解析失败上报。历史问题: CONNECT 分支用 `if (cl) RingPush(...)` 上报,
// 解析不出来时 cl==0 → 事件、计数、日志全部没有, 于是"网络硬拦截已经失效"这件事
// 在现场完全不可见。现在解析失败必须留痕, 并附带原始输入头部, 便于反推
// AFD_CONNECT_INFO 在具体 Windows build 上的真实布局。
//   Data 布局: [0..1]=判定出的 cl(LE) | [2..3]=InputBufferLength(LE) | [4..]=输入前 N 字节
#define EVT_CONNECT_PARSEFAIL  8091
#define NET_DIAG_RAW_MAX       64

// =============================================================================
// AFD IOCTL 码 (从 afd.sys 逆向获取, AfdIoctlTable)
// 编码规则: CTL_CODE(0x12, Func, METHOD_NEITHER, FILE_ANY_ACCESS)
// =============================================================================
#define IOCTL_AFD_BIND              0x00012003  // Func=0x01  bind()
#define IOCTL_AFD_CONNECT           0x00012007  // Func=0x03  connect()
#define IOCTL_AFD_START_LISTEN      0x0001200B  // Func=0x05  listen()
#define IOCTL_AFD_ACCEPT            0x00012010  // Func=0x08  accept()
#define IOCTL_AFD_RECEIVE           0x00012017  // Func=0x0B  recv()
#define IOCTL_AFD_RECEIVE_DATAGRAM  0x0001201B  // Func=0x0C  recvfrom()
#define IOCTL_AFD_SEND              0x0001201F  // Func=0x0D  send()
#define IOCTL_AFD_SEND_DATAGRAM     0x00012023  // Func=0x0E  sendto()

// 注意: TA_ADDRESS / TRANSPORT_ADDRESS / WSABUF 等类型已在 WDK 头文件中定义,
//       这里不用同名类型以免冲突.  AFD 的 METHOD_NEITHER 输入数据直接按字节偏移读取.

// CONNECT 输入 (IOCTL_AFD_CONNECT=0x12007) —— 2026-09-29 由真实字节反推修正
//   Win10 22H2/19045 实测: 一次连 127.0.0.1:18080, InputBufferLength = 52 = 0x34
//   +0x00..+0x17  其他字段 (+0x10 处是一个内核时间戳类的值)
//   +0x18 AddressType    2 字节 USHORT = TDI_ADDRESS_TYPE_*
//   +0x1A AddressData[]  可变, 字节紧包无对齐:
//        TDI_ADDRESS_TYPE_IP   (2) : sin_port(2) + in_addr(4) + sin_zero[8]     = 16 → 总 0x2A
//        TDI_ADDRESS_TYPE_IPV6 (23): sin6_port(2)+flowinfo(4)+addr[16]+scope(4) = 26 → 总 0x34
//   自校验: 0x1A + 26 = 0x34 = 52, 与实测 InputBufferLength 完全吻合。
//   历史坑(已修): 旧实现假设 AddressLength@0x28 / AddressData@0x2C —— 本 build 上该处
//   恒读 0, 于是 cl==0, 拦截判定与事件上报双双被跳过; 且它只认 AF_INET, 而应用经双栈
//   socket 连 IPv4 字面量时地址是 IPv4 映射的 IPv6(::ffff:a.b.c.d)。两个原因叠加,
//   造成"网络硬拦截静默失效"这么久都没被发现。
// ⚠ 2026-09-30 实测补充: 同一台机器上 AFD CONNECT 的输入存在**两种布局**, 必须都认。
//   L1 (长, ilen 典型 52=0x34): AddressType@+0x18, 地址数据@+0x1A
//                              TDI_ADDRESS_TYPE_IPV6: 0x1A + 26 = 0x34 ✓
//   L2 (短, ilen 典型 28=0x1C): AddressType@+0x0C, 地址数据@+0x0E
//                              TDI_ADDRESS_TYPE_IP:   0x0E + 2 + 4 + 8 = 0x1C ✓
//   实测 L2 样本 (ilen=28):
//     00 1D 21 11 00 00 00 00 A4 13 00 00 | 02 00 | 1F 91 | 65 5B 16 D5 | 00 00 00 00
//     +0x0C AddressType=2(IP)   +0x0E sin_port=0x1F91(8081)   +0x10 in_addr=101.91.22.213
//     另一条同布局 → 183.47.103.43:36688
//   危害: 旧实现只认 L1 → L2 那一半 connect 解析不出 → 既不产生事件也**不参与黑名单拦截**,
//         即"网络硬拦截"对这部分流量完全失效(2026-09-30 由 8091 事件显形)。
//   判别式(重要): 不用长度猜布局, 而是看"该候选偏移处取到的 USHORT 是否 ∈ {2,23}"。
//     L2 缓冲在 +0x18 处取到的是 sin_zero 里的 0x0000, 天然落到 L2 分支;
//     且一旦某候选的类型合法就不再试另一候选 —— 绝不能用错布局读出"假 IP"去比黑名单
//     (那比解析失败更危险)。
#define ZTA_CONNECT_L1_TYPE_OFFSET  0x18   // 长布局 AddressType
#define ZTA_CONNECT_L1_ADDR_OFFSET  0x1A   // 长布局 地址数据起点
#define ZTA_CONNECT_L2_TYPE_OFFSET  0x0C   // 短布局 AddressType
#define ZTA_CONNECT_L2_ADDR_OFFSET  0x0E   // 短布局 地址数据起点
#define TDI_ADDRESS_TYPE_IP         2      // 目标为 AF_INET
#define TDI_ADDRESS_TYPE_IPV6       23     // 目标为 AF_INET6 (含 IPv4 映射形态)
#define AFD_IPV4_MAPPED_PREFIX_LEN  12     // ::ffff:a.b.c.d 的前缀长度

// SEND 输入 (IOCTL_AFD_SEND=0x1201F):
//   +0x00 BufferArray  (WSABUF* 用户态指针)  8 字节
//   +0x08 BufferCount  4 字节
//   +0x0C AfdFlags     4 字节
//   +0x10 TdiFlags     4 字节
// WSABUF: +0x00 len(4字节), +0x08 buf(8字节用户态指针)
#define ZTA_SEND_BUFARRAY_OFFSET    0x00
#define ZTA_SEND_BUFCOUNT_OFFSET    0x08
#define ZTA_WSABUF_LEN_OFFSET       0x00
#define ZTA_WSABUF_BUF_OFFSET       0x08
#define ZTA_WSABUF_SIZE             0x10   // 16 字节 (4+4pad+8 on x64 kernel)

// BIND 输入 (IOCTL_AFD_BIND=0x12003):
//   +0x00 taAddressCount  4 字节
//   +0x04 AddressLength   2 字节
//   +0x06 AddressType     2 字节
//   +0x08 AddressData[]   可变
#define ZTA_BIND_ADDR_OFFSET        0x04

// =============================================================================
// 网络事件 ring buffer (不变)
// =============================================================================
typedef struct _NET_EVENT {
    LONGLONG  Ts;                    // +0
    ULONG     Pid;                   // +8
    ULONG     Code;                  // +12
    USHORT    Len;                   // +16  实际写入 Data 的字节数 (<= NET_EVENT_MAX)
    USHORT    Reserved;              // +18  显式填充, 保证 TrueLen 4 字节对齐
    ULONG     TrueLen;               // +20  事件相关**真实**量值, 语义随 Code:
                                     //        EVT_AGG : 本事件聚合了多少条原始事件
                                     //        SEND/RECV(若将来恢复逐条): 真实字节数
                                     //        其余 : 同 Len
                                     //      历史 bug: SEND 曾把 Len 本身夹到 512,
                                     //      于是 >512 的发送在用户态恒显示 512, 字节量不可用。
    UCHAR     Data[NET_EVENT_MAX];   // +24
} NET_EVENT, *PNET_EVENT;

// ⚠ 加 TrueLen 后 sizeof 仍是 536(吃掉了原来尾部 6 字节填充), 所以**只断言 sizeof
//   会漏掉 Data 偏移 18→24 的变化** —— 必须连 offsetof 一起断言, 否则用户态按旧偏移
//   读 Data 会读出垃圾且毫无报错。
C_ASSERT(sizeof(NET_EVENT) == 536);
C_ASSERT(FIELD_OFFSET(NET_EVENT, Len)     == 16);
C_ASSERT(FIELD_OFFSET(NET_EVENT, TrueLen) == 20);
C_ASSERT(FIELD_OFFSET(NET_EVENT, Data)    == 24);

typedef struct _NET_RING {
    volatile LONG Head, Tail;
    NET_EVENT E[NET_RING_SIZE];
} NET_RING, *PNET_RING;

typedef struct _FILTER_EXT {
    PDEVICE_OBJECT Self;
    PDEVICE_OBJECT Low;
    UCHAR          Type;
    BOOLEAN        Att;
    LIST_ENTRY     Le;
} FILTER_EXT, *PFILTER_EXT;

static PDEVICE_OBJECT   g_Ctrl = NULL;
static LIST_ENTRY       g_List;
static KSPIN_LOCK       g_Lock, g_RLock;
static volatile PNET_RING g_Ring = NULL;  // volatile: Unload 置 NULL 后 Dispatch 不再访问
static BOOLEAN          g_Unload = FALSE;
static UNICODE_STRING   g_Link;
static BOOLEAN          g_LinkOk = FALSE;
static IO_REMOVE_LOCK   g_RemoveLock;
// RemoveLock 使用约定 (历史蓝屏根因, 必须严格遵守):
//   1) acquire / release / ReleaseAndWait 必须传同一个非 NULL 的稳定 Tag,
//      这里统一用 IoDriverObject. 传 NULL 或每处不一致会命中 nt 的
//      "bad release tag" 校验分支 (VfRemLockReportBadReleaseAndWaitTag);
//   2) IoReleaseRemoveLockAndWait 只能释放一次配对引用, 且必须在
//      IoInitializeRemoveLock 之后调用, 否则计数会变成负数.
static BOOLEAN          g_LockInited = FALSE;
PDRIVER_OBJECT IoDriverObject = NULL;

// ── 待删除设备对象 (Detach 后延迟删除) ──────────────────────────────────────
// ⚠ 这不是可选优化, 是必须的:
//   过滤设备对象 (AttachOne 给 \Device\Afd 创建的那个) 若不删除, 驱动对象就
//   带着一个未释放的引用, IoDeleteDriver 无法完成 → 本驱动镜像段永久驻留内核
//   → .sys 文件被锁死 → 此后 DriveEntry 每次加载都失败, SCM 报 error 2
//   (文件找不到), 表现为 ZETA_NetFilter 只在重启后第一次能启动, 之后永远
//   "not available", 网络信息流彻底断掉.
//   修前 DetachAll 把设备指针收进局部数组 pending[] 出作用域就丢了,
//   从未调用 IoDeleteDevice —— 这就是那个 bug.
//   对照: ZETA_DiskFilter.c 的 g_DyingDevices/DeleteDyingDevices 是正确写法,
//   所以 DiskFilter 反复载/停几十次仍然干净.
#define NET_MAX_DYING_DEVICES 64
static PDEVICE_OBJECT   g_DyingDevices[NET_MAX_DYING_DEVICES];
static ULONG            g_DyingCount = 0;

// =============================================================================
// P1-状态机/网络硬拦截: 目标 IP 黑名单 (C2/恶意服务器阻断)
// 用户态通过 IOCTL_BLOCK_IP 下发, AFD CONNECT 命中则拒绝连接
// =============================================================================
#define NET_BLOCK_IP_MAX  128
#define NET_BLOCK_PORT_MAX 64

typedef struct _NET_BLOCK_IP {
    UCHAR  Addr[4];    // IPv4 (网络字节序)
    USHORT Port;       // 0 = 全部端口
} NET_BLOCK_IP;

static NET_BLOCK_IP  g_BlockList[NET_BLOCK_IP_MAX];
static ULONG         g_BlockCount = 0;
static KSPIN_LOCK    g_BlockLock;

// =============================================================================
// M1-6: IP 黑名单持久化 (注册表 Parameters\BlockedIps, REG_BINARY)
// 格式: ULONG count (主机序) + count × NET_BLOCK_IP (6 字节)
// 仅 PASSIVE_LEVEL 可调用 (Zw* 要求); DispatchControl 的 IOCTL 在 PASSIVE 到达。
// =============================================================================
static NTSTATUS NetBlockPersist_Save(void) {
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

    ULONG count;
    KIRQL x;
    KeAcquireSpinLock(&g_BlockLock, &x);
    count = g_BlockCount;
    ULONG blobSize = sizeof(ULONG) + count * sizeof(NET_BLOCK_IP);
    PVOID blob = ExAllocatePool2(POOL_FLAG_PAGED, blobSize, ZETA_NET_TAG);
    if (!blob) { KeReleaseSpinLock(&g_BlockLock, x); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlCopyMemory(blob, &count, sizeof(ULONG));
    if (count) RtlCopyMemory((PUCHAR)blob + sizeof(ULONG), g_BlockList, count * sizeof(NET_BLOCK_IP));
    KeReleaseSpinLock(&g_BlockLock, x);

    UNICODE_STRING keyPath; RtlInitUnicodeString(&keyPath, NET_BLOCK_REG_PATH);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey = NULL;
    NTSTATUS st = ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (NT_SUCCESS(st)) {
        UNICODE_STRING vName; RtlInitUnicodeString(&vName, NET_BLOCK_REG_VALUE);
        if (count > 0) {
            st = ZwSetValueKey(hKey, &vName, 0, REG_BINARY, blob, blobSize);
        } else {
            st = ZwDeleteValueKey(hKey, &vName);   // 清空 → 删除值
            if (st == STATUS_OBJECT_NAME_NOT_FOUND) st = STATUS_SUCCESS;
        }
        ZwClose(hKey);
    }
    ExFreePool(blob);
    return st;
}

static VOID NetBlockPersist_Load(void) {
    UNICODE_STRING keyPath; RtlInitUnicodeString(&keyPath, NET_BLOCK_REG_PATH);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey = NULL;
    if (!NT_SUCCESS(ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa))) return;

    UNICODE_STRING vName; RtlInitUnicodeString(&vName, NET_BLOCK_REG_VALUE);
    ULONG size = 0;
    NTSTATUS st = ZwQueryValueKey(hKey, &vName, KeyValuePartialInformation, NULL, 0, &size);
    if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
        PKEY_VALUE_PARTIAL_INFORMATION kv =
            (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, size, ZETA_NET_TAG);
        if (kv) {
            if (NT_SUCCESS(ZwQueryValueKey(hKey, &vName, KeyValuePartialInformation, kv, size, &size)) &&
                kv->Type == REG_BINARY && kv->DataLength > sizeof(ULONG)) {
                ULONG count = *(PULONG)kv->Data;
                ULONG avail = (kv->DataLength - sizeof(ULONG)) / sizeof(NET_BLOCK_IP);
                if (count > avail) count = avail;
                if (count > NET_BLOCK_IP_MAX) count = NET_BLOCK_IP_MAX;
                KIRQL x;
                KeAcquireSpinLock(&g_BlockLock, &x);
                if (count > 0) {
                    RtlCopyMemory(g_BlockList, (PUCHAR)kv->Data + sizeof(ULONG),
                                  count * sizeof(NET_BLOCK_IP));
                }
                g_BlockCount = count;
                KeReleaseSpinLock(&g_BlockLock, x);
                DbgPrint("ZETA_NET: restored %lu blocked IPs from registry\n", count);
            }
            ExFreePool(kv);
        }
    }
    ZwClose(hKey);
}

// =============================================================================
// RingPush - 不变
// =============================================================================
// =============================================================================
// P1 驱动侧聚合 (2026-09-30)
//
// 背景: 实测 socket 占全部网络事件 11.7%、send 占 86.6%, 而事件环只有 2048 槽
//   (FIFO 满则覆盖最旧)。高频事件既会把 connect 这类高价值事件顶出环, 又让用户态
//   日志被淹没。且 send 的 Len 被 RingPush 夹到 512, 字节量本就不可用。
// 做法: socket/send/recv 不再逐条进环, 改为按 PID 在这里累加(字节用 64 位真实值),
//   由 GET_EVENT 在环空时**惰性 flush** 成 EVT_AGG 事件 —— 复用用户态已有的轮询节奏,
//   不需要新增内核定时器。
//
// ⚠ 代价(必须写明): send 事件原本把前 512 字节**有效载荷**拷进环(ProbeForRead+拷贝
//   wbBuf)。现在不再拷贝 —— 用户态此前只用 Len、从未消费过载荷, 所以当前零损失;
//   但若要恢复内容检测(P2), 必须重新设计成"受门控的低频采样"或直接在内核内做匹配,
//   绝不能退回逐条上报(会再次顶掉事件环)。同时不再触碰 wbBuf 也减少了在
//   高 IRQL 下访问用户态内存的风险面。
// =============================================================================
#define NET_AGG_MAX_PID   64
#define NET_AGG_FLUSH_MS  2000

typedef struct _NET_AGG {
    ULONG         Pid;
    ULONG         Sockets, Sends, Recvs;
    ULONGLONG     SendBytes, RecvBytes;   // 真实字节(64 位, 不截断)
    LARGE_INTEGER LastSeen;
} NET_AGG;

typedef struct _NET_AGG_DATA {            // EVT_AGG 的 Data 载荷
    ULONG     Pid;
    ULONG     Sockets, Sends, Recvs;
    ULONGLONG SendBytes, RecvBytes;
    ULONG     IntervalMs;
    ULONG     RingDrops;                  // 累计被环溢出丢掉的事件数(可见性)
} NET_AGG_DATA;

static NET_AGG       g_Agg[NET_AGG_MAX_PID];
static ULONG         g_AggCount = 0;
static KSPIN_LOCK    g_AggLock;
static LARGE_INTEGER g_AggLastFlush = {0};
static volatile LONG g_RingDrops = 0;    // 环满被覆盖的事件数(累计)

// 从 AFD SEND 类输入里取出真实发送字节数。
// 布局已由 8092 抓样确证, 且 **AFD_SEND 与 AFD_SEND_DATAGRAM 完全相同**:
//   +0x00 BufferArray (用户态指针, 8B) | +0x08 BufferCount (4B)
//   条目 AFD_WSABUF = { ULONG len; ULONG pad; PVOID buf; } 共 16B, len 在 +0x00
//   实测 len = 35/38/46/181/248/828/1067/3316 均合理, buf 均为合法用户地址。
// ⚠ 历史坑: SEND_DATAGRAM 曾被当成"内联 WSABUF", 直接拿 +0x00 当长度 —— 那里放的
//   其实是指针, 于是读出指针低半部分 ⇒ 汇总出现 60 秒 28 GB、单进程 27.8 GB/分 的
//   荒谬值。旧代码在同一位置也读错, 只是被 NET_EVENT_MAX 夹到 512 掩盖了整版。
static ULONGLONG AfdSendBytes(PUCHAR in, ULONG ilen) {
    ULONGLONG total = 0;
    ULONG bufCount, bi;
    void* bufArray;
    if (!in || ilen < ZTA_SEND_BUFCOUNT_OFFSET + sizeof(ULONG)) return 0;
    bufCount = *(PULONG)(in + ZTA_SEND_BUFCOUNT_OFFSET);
    bufArray = *(void**)(in + ZTA_SEND_BUFARRAY_OFFSET);
    if (!bufArray || bufCount == 0) return 0;
    if (bufCount > 64) bufCount = 64;          // 上限, 防异常输入
    ProbeForRead(bufArray, (SIZE_T)bufCount * ZTA_WSABUF_SIZE, 1);
    for (bi = 0; bi < bufCount; bi++) {
        ULONG wl = 0;
        RtlCopyMemory(&wl, (PUCHAR)bufArray + (SIZE_T)bi * ZTA_WSABUF_SIZE, sizeof(ULONG));
        total += wl;
    }
    return total;
}

// 前置声明 (SendDiagDump 定义在 RingPush 之前; 默认实参只在下面定义处给一次)
static void RingPush(ULONG Code, ULONG Pid, const void* Data, USHORT Len, ULONG TrueLen);

// ⚠ 全局最多抓 16 条, 避免刷环。SEND 输入的真实布局尚未验证:
//   首次尝试"累加全部 WSABUF 长度"得到 60 秒 28 GB 的荒谬值(单进程 27.8 GB/分),
//   说明读出来的不是长度(疑似把指针低半部分当成长度)。旧实现只读第一个 dword 且被
//   NET_EVENT_MAX 夹到 512, **错误被 clamp 掩盖了整整一版**。
//   故先按 CONNECT 那套方法抓真实字节反推布局, 期间字节计数一律置 0 —— 绝不往
//   日志/统计里写已知有问题的数。
static void SendDiagDump(ULONG pid, PUCHAR in, ULONG ilen) {
    static LONG s_diagCount = 0;
    // 固定布局 (用户态按同一偏移解析):
    //   [0..1]  hdrLen   实际写入的输入头字节数
    //   [2..3]  ilen     InputBufferLength
    //   [4..5]  bufLen   实际读到的 BufferArray 内容字节数 (0 = 指针无效/未尝试)
    //   [6..7]  bufCount 输入头 +0x08 处的 BufferCount
    //   [8..39] 输入头原始 32 字节
    //   [40..87] BufferArray 指向内容的 48 字节   <-- 本次新增, 用于判定条目字段顺序
    UCHAR b[8 + 32 + 48];
    ULONG hdrLen, bufLen = 0, bufCount = 0;
    void* arr = NULL;

    if (!in || !ilen) return;
    if (InterlockedIncrement(&s_diagCount) > 16) return;

    RtlZeroMemory(b, sizeof(b));
    hdrLen = (ilen < 32) ? ilen : 32;
    ProbeForRead(in, hdrLen, 1);
    RtlCopyMemory(b + 8, in, hdrLen);

    if (ilen >= ZTA_SEND_BUFCOUNT_OFFSET + sizeof(ULONG)) {
        bufCount = *(PULONG)(in + ZTA_SEND_BUFCOUNT_OFFSET);
        arr = *(void**)(in + ZTA_SEND_BUFARRAY_OFFSET);
        if (arr && bufCount > 0 && bufCount <= 64) {
            bufLen = (ULONG)((SIZE_T)bufCount * ZTA_WSABUF_SIZE);
            if (bufLen > 48) bufLen = 48;
            // 单独一层 __try: 指针无效时只丢这段, 不能把整条诊断事件一起吞掉
            __try {
                ProbeForRead(arr, bufLen, 1);
                RtlCopyMemory(b + 40, arr, bufLen);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                bufLen = 0;
            }
        }
    }

    b[0] = (UCHAR)(hdrLen & 0xFF);  b[1] = (UCHAR)((hdrLen >> 8) & 0xFF);
    b[2] = (UCHAR)(ilen & 0xFF);    b[3] = (UCHAR)((ilen >> 8) & 0xFF);
    b[4] = (UCHAR)(bufLen & 0xFF);  b[5] = (UCHAR)((bufLen >> 8) & 0xFF);
    b[6] = (UCHAR)(bufCount & 0xFF); b[7] = (UCHAR)((bufCount >> 8) & 0xFF);
    RingPush(EVT_SEND_DIAG, pid, b, (USHORT)sizeof(b), 0);
}

// kind: 0=socket 1=send 2=recv
static void NetAggAdd(ULONG Pid, int kind, ULONGLONG bytes) {
    KIRQL x; KeAcquireSpinLock(&g_AggLock, &x);
    ULONG i;
    for (i = 0; i < g_AggCount; i++) if (g_Agg[i].Pid == Pid) break;
    if (i == g_AggCount) {
        if (g_AggCount < NET_AGG_MAX_PID) {
            i = g_AggCount++;
            RtlZeroMemory(&g_Agg[i], sizeof(g_Agg[i]));
            g_Agg[i].Pid = Pid;
        } else {
            // 表满: 淘汰最久未活动的槽。绝不用"满表即不再插入"那种写法 ——
            // 那会让新进程永远不被统计且毫无迹象(用户态 32 槽节流表就踩过这个坑)。
            ULONG oldest = 0;
            for (ULONG k = 1; k < g_AggCount; k++)
                if (g_Agg[k].LastSeen.QuadPart < g_Agg[oldest].LastSeen.QuadPart) oldest = k;
            RtlZeroMemory(&g_Agg[oldest], sizeof(g_Agg[oldest]));
            g_Agg[oldest].Pid = Pid;
            i = oldest;
        }
    }
    KeQuerySystemTime(&g_Agg[i].LastSeen);
    switch (kind) {
    case 0: g_Agg[i].Sockets++; break;
    case 1: g_Agg[i].Sends++; g_Agg[i].SendBytes += bytes; break;
    case 2: g_Agg[i].Recvs++; g_Agg[i].RecvBytes += bytes; break;
    default: break;
    }
    KeReleaseSpinLock(&g_AggLock, x);
}

static void RingPush(ULONG Code, ULONG Pid, const void* Data, USHORT Len, ULONG TrueLen = 0) {
    if (!g_Ring) return;
    KIRQL x; KeAcquireSpinLock(&g_RLock, &x);
    LONG h = g_Ring->Head, n = (h + 1) & (NET_RING_SIZE - 1);
    if (n == g_Ring->Tail) {
        g_Ring->Tail = (g_Ring->Tail + 1) & (NET_RING_SIZE - 1);
        InterlockedIncrement(&g_RingDrops);   // 丢证据必须可计数
    }
    PNET_EVENT e = &g_Ring->E[h];
    KeQuerySystemTime((PLARGE_INTEGER)&e->Ts);
    e->Pid = Pid; e->Code = Code;
    e->Len = (Len > NET_EVENT_MAX) ? NET_EVENT_MAX : Len;
    e->TrueLen = TrueLen ? TrueLen : e->Len;
    if (Data && e->Len) RtlCopyMemory(e->Data, Data, e->Len);
    MemoryBarrier(); g_Ring->Head = n;
    KeReleaseSpinLock(&g_RLock, x);
}

// 到点就把聚合表 flush 成 EVT_AGG(每 PID 一条)。在 GET_EVENT 环空时调用。
static void NetAggFlushIfDue(void) {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    if (g_AggLastFlush.QuadPart == 0) { g_AggLastFlush = now; return; }
    if ((now.QuadPart - g_AggLastFlush.QuadPart) < (LONGLONG)NET_AGG_FLUSH_MS * 10000) return;
    g_AggLastFlush = now;

    KIRQL x; KeAcquireSpinLock(&g_AggLock, &x);
    for (ULONG i = 0; i < g_AggCount; i++) {
        NET_AGG* a = &g_Agg[i];
        ULONG cnt = a->Sockets + a->Sends + a->Recvs;
        if (!cnt) continue;
        NET_AGG_DATA d;
        d.Pid = a->Pid;
        d.Sockets = a->Sockets; d.Sends = a->Sends; d.Recvs = a->Recvs;
        d.SendBytes = a->SendBytes; d.RecvBytes = a->RecvBytes;
        d.IntervalMs = NET_AGG_FLUSH_MS;
        d.RingDrops = (ULONG)InterlockedCompareExchange(&g_RingDrops, 0, 0);
        RingPush(EVT_AGG, a->Pid, &d, (USHORT)sizeof(d), cnt);
        a->Sockets = 0; a->Sends = 0; a->Recvs = 0;
        a->SendBytes = 0; a->RecvBytes = 0;
    }
    KeReleaseSpinLock(&g_AggLock, x);
}

C_ASSERT(sizeof(NET_AGG_DATA) == 40);                       // 两端 ABI 必须一致
C_ASSERT(FIELD_OFFSET(NET_AGG_DATA, SendBytes)  == 16);
C_ASSERT(FIELD_OFFSET(NET_AGG_DATA, RecvBytes)  == 24);
C_ASSERT(FIELD_OFFSET(NET_AGG_DATA, IntervalMs) == 32);
C_ASSERT(FIELD_OFFSET(NET_AGG_DATA, RingDrops)  == 36);

#define IOCTL_GET_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_OUT_DIRECT,FILE_READ_DATA)
// P1-状态机: 添加目标 IP 黑名单 (输入 6 字节: IPv4[4] + Port[2], Port=0 表示全部端口)
#define IOCTL_BLOCK_IP  CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)
// P1-状态机: 清空黑名单
#define IOCTL_CLEAR_BLOCK CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_WRITE_DATA)

// =============================================================================
// DispatchControl - 控制设备 IRP 处理 (不变)
// =============================================================================
static NTSTATUS DispatchControl(PDEVICE_OBJECT Dev, PIRP Irp) {
    UNREFERENCED_PARAMETER(Dev);
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
    UCHAR mj = s->MajorFunction;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    // 卸载中 / 拿不到 RemoveLock: 直接失败, 避免访问已释放资源
    if (g_Unload || !NT_SUCCESS(IoAcquireRemoveLock(&g_RemoveLock, IoDriverObject))) {
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    do {
        if (mj == IRP_MJ_CREATE || mj == IRP_MJ_CLOSE) {
            status = STATUS_SUCCESS;
            break;
        }

        if (mj == IRP_MJ_DEVICE_CONTROL && s->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_EVENT) {
            void* ob = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
            ULONG ol = s->Parameters.DeviceIoControl.OutputBufferLength;
            if (ob && ol >= sizeof(NET_EVENT) && g_Ring) {
                KIRQL x; KeAcquireSpinLock(&g_RLock, &x);
                if (g_Ring->Head != g_Ring->Tail) {
                    LONG t = g_Ring->Tail;
                    ULONG c = (ol < sizeof(NET_EVENT)) ? ol : sizeof(NET_EVENT);
                    RtlCopyMemory(ob, &g_Ring->E[t], c);
                    g_Ring->Tail = (t + 1) & (NET_RING_SIZE - 1);
                    status = STATUS_SUCCESS;
                    Irp->IoStatus.Information = c;
                } else {
                    KeReleaseSpinLock(&g_RLock, x);
                    // P1: 环空时惰性 flush 驱动侧聚合 (复用用户态已有轮询节奏, 无需内核定时器)。
                    // flush 刚压入的 EVT_AGG 本次不返回, 下次轮询(10ms 级)即可取到。
                    NetAggFlushIfDue();
                    status = STATUS_NO_MORE_ENTRIES;
                    break;
                }
                KeReleaseSpinLock(&g_RLock, x);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        // P1-状态机: 添加 IP 黑名单 (输入 6 字节: IPv4[4] + Port[2])
        if (mj == IRP_MJ_DEVICE_CONTROL && s->Parameters.DeviceIoControl.IoControlCode == IOCTL_BLOCK_IP) {
            if (s->Parameters.DeviceIoControl.InputBufferLength >= 6 && Irp->AssociatedIrp.SystemBuffer) {
                PUCHAR in = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
                BOOLEAN added = FALSE;
                KIRQL x; KeAcquireSpinLock(&g_BlockLock, &x);
                // 去重: 相同 IP+Port 不重复添加
                BOOLEAN dup = FALSE;
                USHORT newPort = (USHORT)(in[4] | (in[5] << 8));
                for (ULONG di = 0; di < g_BlockCount; di++) {
                    if (g_BlockList[di].Addr[0] == in[0] && g_BlockList[di].Addr[1] == in[1] &&
                        g_BlockList[di].Addr[2] == in[2] && g_BlockList[di].Addr[3] == in[3] &&
                        g_BlockList[di].Port == newPort) { dup = TRUE; break; }
                }
                if (!dup && g_BlockCount < NET_BLOCK_IP_MAX) {
                    g_BlockList[g_BlockCount].Addr[0] = in[0];
                    g_BlockList[g_BlockCount].Addr[1] = in[1];
                    g_BlockList[g_BlockCount].Addr[2] = in[2];
                    g_BlockList[g_BlockCount].Addr[3] = in[3];
                    g_BlockList[g_BlockCount].Port = newPort;
                    g_BlockCount++;
                    added = TRUE;
                    DbgPrint("ZETA_NET: blocked IP %u.%u.%u.%u:%u (total=%lu)\n",
                        in[0], in[1], in[2], in[3], g_BlockList[g_BlockCount-1].Port, g_BlockCount);
                }
                KeReleaseSpinLock(&g_BlockLock, x);
                // M1-6: 持久化 (PASSIVE_LEVEL 下 IOCTL 到达)
                if (added) NetBlockPersist_Save();
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        // P1-状态机: 清空黑名单
        if (mj == IRP_MJ_DEVICE_CONTROL && s->Parameters.DeviceIoControl.IoControlCode == IOCTL_CLEAR_BLOCK) {
            KIRQL x; KeAcquireSpinLock(&g_BlockLock, &x);
            g_BlockCount = 0;
            KeReleaseSpinLock(&g_BlockLock, x);
            DbgPrint("ZETA_NET: block list cleared\n");
            NetBlockPersist_Save();  // M1-6: 同步删除注册表值
            status = STATUS_SUCCESS;
            break;
        }
    } while (FALSE);

    Irp->IoStatus.Status = status;
    IoReleaseRemoveLock(&g_RemoveLock, IoDriverObject);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// =============================================================================
// ParseAfdConnectAddrAt — 按指定偏移解析 (供双布局候选复用)
//   typeOff : AddressType 偏移      addrOff : 地址数据起点(sin_port / sin6_port)偏移
// =============================================================================
static BOOLEAN ParseAfdConnectAddrAt(PUCHAR buf, ULONG len, ULONG typeOff, ULONG addrOff,
                                     UCHAR ipOut[4], USHORT* portOut)
{
    USHORT type, portNet;
    PUCHAR addr;

    if (len < typeOff + sizeof(USHORT) || len < addrOff + sizeof(USHORT)) return FALSE;

    type    = *(PUSHORT)(buf + typeOff);
    portNet = *(PUSHORT)(buf + addrOff);
    addr    = buf + addrOff;
    *portOut = (USHORT)((portNet >> 8) | (portNet << 8));   // 网络序 → 主机序

    if (type == TDI_ADDRESS_TYPE_IP) {
        /* sin_port(2) + in_addr(4) + sin_zero[8] */
        if (len < addrOff + 2 + 4) return FALSE;
        RtlCopyMemory(ipOut, addr + 2, 4);
        return TRUE;
    }

    if (type == TDI_ADDRESS_TYPE_IPV6) {
        /* sin6_port(2) + flowinfo(4) + addr[16] + scope(4) */
        UCHAR* a;
        BOOLEAN v4mapped = TRUE;
        ULONG   i;
        if (len < addrOff + 2 + 4 + 16) return FALSE;
        a = addr + 2 + 4;                                   // sin6_addr
        for (i = 0; i < AFD_IPV4_MAPPED_PREFIX_LEN; i++) {
            UCHAR want = (UCHAR)((i == 10 || i == 11) ? 0xFF : 0x00);
            if (a[i] != want) { v4mapped = FALSE; break; }
        }
        if (!v4mapped) return FALSE;                        // 纯 IPv6: 本轮不比对(待办)
        RtlCopyMemory(ipOut, a + 12, 4);                     // ::ffff:a.b.c.d → a.b.c.d
        return TRUE;
    }

    return FALSE;
}

// =============================================================================
// ParseAfdConnectAddr — 从 AFD CONNECT 输入(内核侧拷贝)解析出目标 IPv4 + 端口
//
// 布局见文件头 ZTA_CONNECT_L1_*/L2_* 注释 —— 本机实测**两套布局并存**, 两者都试。
// 刻意只在内核拷贝(buf)上解析, 不碰用户态指针。
// 返回 TRUE  = 解析出 IPv4 目标(ipOut 主机序 4 字节, portOut 主机序)
// 返回 FALSE = 两套布局都不成立 / 纯 IPv6 目标(暂不参与 IPv4 黑名单比对)
// =============================================================================
static BOOLEAN ParseAfdConnectAddr(PUCHAR buf, ULONG len, UCHAR ipOut[4], USHORT* portOut)
{
    USHORT t;

    if (!buf) return FALSE;

    // 候选 1: 长布局 L1 (历史已验证形态)
    if (len >= ZTA_CONNECT_L1_TYPE_OFFSET + sizeof(USHORT)) {
        t = *(PUSHORT)(buf + ZTA_CONNECT_L1_TYPE_OFFSET);
        if (t == TDI_ADDRESS_TYPE_IP || t == TDI_ADDRESS_TYPE_IPV6)
            return ParseAfdConnectAddrAt(buf, len, ZTA_CONNECT_L1_TYPE_OFFSET,
                                         ZTA_CONNECT_L1_ADDR_OFFSET, ipOut, portOut);
    }

    // 候选 2: 短布局 L2 (2026-09-30 实测发现, ilen 典型 28)
    if (len >= ZTA_CONNECT_L2_TYPE_OFFSET + sizeof(USHORT)) {
        t = *(PUSHORT)(buf + ZTA_CONNECT_L2_TYPE_OFFSET);
        if (t == TDI_ADDRESS_TYPE_IP || t == TDI_ADDRESS_TYPE_IPV6)
            return ParseAfdConnectAddrAt(buf, len, ZTA_CONNECT_L2_TYPE_OFFSET,
                                         ZTA_CONNECT_L2_ADDR_OFFSET, ipOut, portOut);
    }

    return FALSE;
}

// =============================================================================
// DispatchFilter - AFD 设备过滤器 IRP 处理
//
// ⚠ IRQL 注意事项:
//   - Type3InputBuffer 是用户态指针 (METHOD_NEITHER)
//   - 在 DISPATCH_LEVEL (RingPush spinlock 内) 不能访问用户态内存
//   - 所以必须先在 PASSIVE_LEVEL (spinlock 外) 读取数据到内核缓冲区,
//     然后再调用 RingPush 写入共享 ring
// =============================================================================
static NTSTATUS DispatchFilter(PDEVICE_OBJECT Dev, PIRP Irp) {
    PFILTER_EXT ext = (PFILTER_EXT)Dev->DeviceExtension;

    // 卸载中: 所有新 IRP 直接跳过, 不需要 RemoveLock
    if (g_Unload || !ext->Att || !ext->Low) {
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    // 获取 RemoveLock — 阻止 Unload 直到所有 IRP 完成
    NTSTATUS lockSt = IoAcquireRemoveLock(&g_RemoveLock, IoDriverObject);
    if (!NT_SUCCESS(lockSt)) {
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    __try {
        PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
        UCHAR mj = s->MajorFunction;
        ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

        if (mj == IRP_MJ_CREATE) {
            // 没有 spinlock, 直接调用
            // P1: socket 创建是基数型事件(实测占 11.7%), 改驱动侧累加, 不逐条进环
            NetAggAdd(pid, 0, 0);
            goto done;
        }

        if (mj == IRP_MJ_DEVICE_CONTROL) {
            ULONG ioctl = s->Parameters.DeviceIoControl.IoControlCode;
            PUCHAR in = (PUCHAR)s->Parameters.DeviceIoControl.Type3InputBuffer;
            ULONG  ilen = s->Parameters.DeviceIoControl.InputBufferLength;

            // ⚠ 先在 PASSIVE_LEVEL 检查并读取用户态数据
            UCHAR cb[NET_EVENT_MAX];
            USHORT cl = 0;
            // 原始输入头部: 仅 CONNECT 分支填充, 用于解析失败时上报
            UCHAR  rawBuf[NET_DIAG_RAW_MAX];
            USHORT rawLen = 0;

            switch (ioctl) {

            case IOCTL_AFD_CONNECT: {
                UCHAR  ip[4] = {0,0,0,0};
                USHORT port  = 0;
                /* 先取原始输入头部: 解析失败时要靠它反推 AFD_CONNECT_INFO 的真实布局 */
                if (in && ilen > 0) {
                    rawLen = (USHORT)((ilen < NET_DIAG_RAW_MAX) ? ilen : NET_DIAG_RAW_MAX);
                    ProbeForRead(in, rawLen, 1);
                    RtlCopyMemory(rawBuf, in, rawLen);
                }

                /* 解析目标地址(在内核拷贝上做, 不碰用户态指针) */
                if (ParseAfdConnectAddr(rawBuf, rawLen, ip, &port)) {
                    /* 事件仍按 SOCKADDR_IN(AF_INET) 形态上报 8 字节, 用户态解析口径不变:
                       [0-1]family(小端=2) [2-3]port(网络序) [4-7]IPv4 */
                    cb[0] = 2; cb[1] = 0;
                    cb[2] = (UCHAR)((port >> 8) & 0xFF);
                    cb[3] = (UCHAR)(port & 0xFF);
                    RtlCopyMemory(cb + 4, ip, 4);
                    cl = 8;

                    // P1-状态机/网络硬拦截: 目标 IP 黑名单 (C2/恶意服务器阻断)
                    {
                        KIRQL x; KeAcquireSpinLock(&g_BlockLock, &x);
                        BOOLEAN blocked = FALSE;
                        for (ULONG bi = 0; bi < g_BlockCount; bi++) {
                            if (g_BlockList[bi].Addr[0]==ip[0] && g_BlockList[bi].Addr[1]==ip[1] &&
                                g_BlockList[bi].Addr[2]==ip[2] && g_BlockList[bi].Addr[3]==ip[3]) {
                                if (g_BlockList[bi].Port == 0 || g_BlockList[bi].Port == port) {
                                    blocked = TRUE;
                                    break;
                                }
                            }
                        }
                        KeReleaseSpinLock(&g_BlockLock, x);
                        if (blocked) {
                            DbgPrint("ZETA_NET: CONNECT BLOCKED %u.%u.%u.%u:%u (PID=%lu)\n",
                                ip[0], ip[1], ip[2], ip[3], port, pid);
                            RingPush(EVT_CONNECT, pid, cb, cl);
                            // 拒绝连接: 完成 IRP, 不透传到底层
                            IoReleaseRemoveLock(&g_RemoveLock, IoDriverObject);
                            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                            Irp->IoStatus.Information = 0;
                            IoCompleteRequest(Irp, IO_NO_INCREMENT);
                            return STATUS_ACCESS_DENIED;
                        }
                    }
                }
                if (cl) {
                    RingPush(EVT_CONNECT, pid, cb, cl);
                } else {
                    /* 解析失败必须留痕(否则"网络拦截已失效"在现场无从发现), 并附带原始字节 */
                    UCHAR db[4 + NET_DIAG_RAW_MAX];
                    db[0] = (UCHAR)(cl & 0xFF);
                    db[1] = (UCHAR)((cl >> 8) & 0xFF);
                    db[2] = (UCHAR)(ilen & 0xFF);
                    db[3] = (UCHAR)((ilen >> 8) & 0xFF);
                    if (rawLen) RtlCopyMemory(db + 4, rawBuf, rawLen);
                    RingPush(EVT_CONNECT_PARSEFAIL, pid, db, (USHORT)(4 + rawLen));
                    DbgPrint("ZETA_NET: CONNECT parse FAILED (ilen=%lu cl=%u rawLen=%u)\n",
                             ilen, cl, rawLen);
                }
                break;
            }

            case IOCTL_AFD_SEND: {
                // P1: 只聚合不逐条进环(占 86.6%, 会把 connect 顶出环)。字节取真实累加值。
                NetAggAdd(pid, 1, AfdSendBytes(in, ilen));
                break;
            }

            case IOCTL_AFD_SEND_DATAGRAM: {
                // 布局已由 8092 抓样确证与 AFD_SEND 相同(指针+计数, 条目 {len,pad,buf}),
                // 故与 AFD_SEND 走同一个取字节函数。保留抓样(全局上限 16 条)便于后续复核。
                SendDiagDump(pid, in, ilen);
                NetAggAdd(pid, 1, AfdSendBytes(in, ilen));
                break;
            }

            case IOCTL_AFD_BIND: {
                if (in && ilen > ZTA_BIND_ADDR_OFFSET + sizeof(USHORT)) {
                    ProbeForRead(in, ilen, 1);
                    PUCHAR addrData = in + ZTA_BIND_ADDR_OFFSET;
                    USHORT addrLen = *(PUSHORT)(addrData);
                    if (addrLen > 0 && addrLen <= NET_EVENT_MAX) {
                        addrData += sizeof(USHORT) * 2;
                        cl = (addrLen < NET_EVENT_MAX) ? addrLen : NET_EVENT_MAX;
                        RtlCopyMemory(cb, addrData, cl);
                    }
                }
                if (cl) RingPush(EVT_BIND, pid, cb, cl);
                break;
            }

            case IOCTL_AFD_RECEIVE:
            case IOCTL_AFD_RECEIVE_DATAGRAM: {
                if (in && ilen >= sizeof(ULONG)) {
                    // P1: 只计数, 字节暂置 0(recv 输入首 4 字节是否为长度同样未经证实)
                    NetAggAdd(pid, 2, 0);
                    cl = 1; // 标记已处理
                }
                break;
            }

            default:
                break;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // 用户态指针异常 — 不在这里释放 RemoveLock, 统一在 done: 释放
    }

done:
    IoReleaseRemoveLock(&g_RemoveLock, IoDriverObject);
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->Low, Irp);
}

static NTSTATUS DispatchAny(PDEVICE_OBJECT Dev, PIRP Irp) {
    if (Dev == g_Ctrl) return DispatchControl(Dev, Irp);
    return DispatchFilter(Dev, Irp);
}

static NTSTATUS AttachOne(PCWSTR Name, UCHAR Type) {
    UNICODE_STRING n; RtlInitUnicodeString(&n, Name);
    PFILE_OBJECT fo = NULL; PDEVICE_OBJECT td = NULL;
    NTSTATUS st = IoGetDeviceObjectPointer(&n, FILE_READ_ATTRIBUTES, &fo, &td);
    if (!NT_SUCCESS(st)) { DbgPrint("ZETA_NET: open %ws 0x%X\n", Name, st); return st; }

    PDEVICE_OBJECT fd = NULL;
    st = IoCreateDevice(IoDriverObject, sizeof(FILTER_EXT), NULL,
                        FILE_DEVICE_UNKNOWN, 0, FALSE, &fd);
    if (!NT_SUCCESS(st)) { ObDereferenceObject(fo); return st; }

    PFILTER_EXT ex = (PFILTER_EXT)fd->DeviceExtension;
    RtlZeroMemory(ex, sizeof(FILTER_EXT));
    ex->Self = fd; ex->Type = Type;

    PDEVICE_OBJECT low = IoAttachDeviceToDeviceStack(fd, td);
    if (!low) {
        DbgPrint("ZETA_NET: attach %ws failed\n", Name);
        IoDeleteDevice(fd); ObDereferenceObject(fo);
        return STATUS_UNSUCCESSFUL;
    }
    ex->Low = low; ex->Att = TRUE;

    KIRQL x; KeAcquireSpinLock(&g_Lock, &x);
    InsertTailList(&g_List, &ex->Le);
    KeReleaseSpinLock(&g_Lock, x);

    DbgPrint("ZETA_NET: attached %ws\n", Name);
    ObDereferenceObject(fo);
    return STATUS_SUCCESS;
}

static void DetachAll() {
    FILTER_EXT* pending[64];
    ULONG cnt = 0;
    KIRQL x; KeAcquireSpinLock(&g_Lock, &x);
    while (!IsListEmpty(&g_List) && cnt < 64) {
        auto e = RemoveHeadList(&g_List);
        pending[cnt++] = CONTAINING_RECORD(e, FILTER_EXT, Le);
    }
    KeReleaseSpinLock(&g_Lock, x);

    for (ULONG i = 0; i < cnt; i++) {
        // 从设备栈摘除, 不再接收新 IRP.
        if (pending[i]->Att && pending[i]->Low) {
            IoDetachDevice(pending[i]->Low);
            pending[i]->Att = FALSE;
        }
        // 设备对象本身延迟到 Unload 末尾 (等所有在途 IRP 完成) 再删除, 避免 0xCE.
        // 必须登记进全局数组: 局部 pending[] 出作用域即失效, 设备会永久泄漏.
        if (pending[i]->Self && g_DyingCount < NET_MAX_DYING_DEVICES)
            g_DyingDevices[g_DyingCount++] = pending[i]->Self;
    }
}

// IRP 排空后才可安全删除设备对象 (与 ZETA_DiskFilter 的 DeleteDyingDevices 同构)
static void DeleteDyingDevices(void) {
    for (ULONG i = 0; i < g_DyingCount; i++) {
        if (g_DyingDevices[i]) {
            IoDeleteDevice(g_DyingDevices[i]);
            g_DyingDevices[i] = NULL;
        }
    }
    g_DyingCount = 0;
}

static void Unload(PDRIVER_OBJECT) {
    // 1. 标记卸载: DispatchFilter/DispatchControl 入口会直接拒绝新 IRP
    g_Unload = TRUE;

    // 2. 从设备栈摘除, 新 IRP 不再路由到本驱动设备
    DetachAll();

    // 3. 等待所有在途 IRP 真正完成 (包括控制设备上的阻塞读).
    //    用 AndWait 变体, 它会自旋直到所有持有 RemoveLock 的 IRP 释放完毕.
    //    ⚠ 两个硬性要求 (这里原来传 NULL 就是卸载蓝屏 0x7E 的直接原因):
    //      a) Tag 必须与 acquire 完全一致且非 NULL — 传 NULL 会命中 nt 的
    //         "bad release tag" 校验分支 (VfRemLockReportBadReleaseAndWaitTag);
    //      b) 只能在 DriverEntry 已完成 IoInitializeRemoveLock 时调用, 且只释放
    //         DriverEntry 里自持的那一次引用, 不能凭空释放 (否则计数变负).
    if (g_LockInited) {
        IoReleaseRemoveLockAndWait(&g_RemoveLock, IoDriverObject);
        g_LockInited = FALSE;
    }
    DbgPrint("ZETA_NET: all IRPs drained\n");

    // 4. 此时已无任何 IRP 在访问 g_Ring / 设备, 安全清理
    // 4a. 删除所有已摘除的过滤设备. 漏掉这一步 = 驱动对象释放不掉 =
    //     镜像段永久驻留 = .sys 文件锁死 = 之后每次加载都 error 2.
    DeleteDyingDevices();
    if (g_LinkOk) { IoDeleteSymbolicLink(&g_Link); g_LinkOk = FALSE; }
    if (g_Ctrl)  { IoDeleteDevice(g_Ctrl);  g_Ctrl = NULL; }

    // 5. 释放 ring buffer (最后做, 因为 DispatchControl 曾引用它)
    if (g_Ring) { ExFreePool(g_Ring); g_Ring = NULL; }

    DbgPrint("ZETA_NET: unloaded\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R) {
    UNREFERENCED_PARAMETER(R);
    IoDriverObject = D;
    DbgPrint("ZETA_NET: entry\n");

    // RemoveLock: 初始化后立刻用固定 Tag 自持一次引用.
    // 这次引用由 Unload 的 IoReleaseRemoveLockAndWait 配对释放 (Tag 必须一致),
    // 计数因此是平衡的 (0 → 1 → 0), 不会出现 -1.
    IoInitializeRemoveLock(&g_RemoveLock, ZETA_NET_TAG, 0, 0);
    (VOID)IoAcquireRemoveLock(&g_RemoveLock, IoDriverObject);
    g_LockInited = TRUE;
    InitializeListHead(&g_List);
    KeInitializeSpinLock(&g_Lock);
    KeInitializeSpinLock(&g_RLock);
    KeInitializeSpinLock(&g_BlockLock);
    KeInitializeSpinLock(&g_AggLock);

    g_Ring = (PNET_RING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NET_RING), ZETA_NET_TAG);
    if (!g_Ring) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Ring, sizeof(NET_RING));

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        D->MajorFunction[i] = DispatchAny;
    D->DriverUnload = Unload;

    // M1-6: 控制设备加 ACL — 仅 SYSTEM/管理员可打开 (防低权限进程清空/篡改黑名单)
    UNICODE_STRING cn; RtlInitUnicodeString(&cn, CTRL_NAME);
    NTSTATUS st = IoCreateDeviceSecure(D, 0, &cn, FILE_DEVICE_UNKNOWN, 0, FALSE,
                                       &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &g_Ctrl);
    if (!NT_SUCCESS(st)) { ExFreePool(g_Ring); g_Ring = NULL; return st; }

    RtlInitUnicodeString(&g_Link, CTRL_LINK);
    st = IoCreateSymbolicLink(&g_Link, &cn);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(g_Ctrl); g_Ctrl = NULL; ExFreePool(g_Ring); g_Ring = NULL; return st; }
    g_LinkOk = TRUE;
    g_Ctrl->Flags &= ~DO_DEVICE_INITIALIZING;
    g_Ctrl->Flags |= DO_DIRECT_IO;

    // M1-6: 从注册表恢复上次持久化的 IP 黑名单 (重启不丢)
    NetBlockPersist_Load();

    // 只附加 \\Device\\Afd (现代 Windows 所有 socket 流量经过这里)
    // \\Device\\Tcp 和 \\Device\\Udp 仅用于遗留 TDI 客户端 (tdx.sys), 已废弃
    struct { PCWSTR n; UCHAR t; } targets[] = {
        { L"\\Device\\Afd", DEV_AFD },
    };
    ULONG ok = 0;
    for (auto& t : targets)
        if (NT_SUCCESS(AttachOne(t.n, t.t))) ok++;
    DbgPrint("ZETA_NET: attached %lu/%llu\n", ok, (ULONGLONG)(sizeof(targets)/sizeof(targets[0])));
    return STATUS_SUCCESS;
}
