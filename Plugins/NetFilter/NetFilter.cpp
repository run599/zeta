#include <ntddk.h>
#include <ntstrsafe.h>

#define ZETA_NET_TAG    'teN'
#define NET_RING_SIZE   2048
#define NET_EVENT_MAX   512

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

// CONNECT 输入 (IOCTL_AFD_CONNECT=0x12007):
//   +0x00 Padding1[3]    12 字节
//   +0x18 TdiConnectionContext  8 字节
//   +0x20 Padding2        4 字节
//   +0x24 taAddressCount  4 字节
//   +0x28 AddressLength   2 字节 (TA_ADDRESS)
//   +0x2A AddressType     2 字节
//   +0x2C AddressData[]   可变  (SOCKADDR_IN=16, SOCKADDR_IN6=28 字节)
#define ZTA_CONNECT_ADDR_OFFSET     0x28   // 从输入开始到 AddressLength 的偏移
#define ZTA_CONNECT_MIN_SIZE        0x2C   // 最小总大小

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
    LONGLONG  Ts;
    ULONG Pid;
    ULONG Code;
    USHORT    Len;
    UCHAR  Data[NET_EVENT_MAX];
} NET_EVENT, *PNET_EVENT;

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
PDRIVER_OBJECT IoDriverObject = NULL;

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
// RingPush - 不变
// =============================================================================
static void RingPush(ULONG Code, ULONG Pid, const void* Data, USHORT Len) {
    if (!g_Ring) return;
    KIRQL x; KeAcquireSpinLock(&g_RLock, &x);
    LONG h = g_Ring->Head, n = (h + 1) & (NET_RING_SIZE - 1);
    if (n == g_Ring->Tail) g_Ring->Tail = (g_Ring->Tail + 1) & (NET_RING_SIZE - 1);
    PNET_EVENT e = &g_Ring->E[h];
    KeQuerySystemTime((PLARGE_INTEGER)&e->Ts);
    e->Pid = Pid; e->Code = Code;
    e->Len = (Len > NET_EVENT_MAX) ? NET_EVENT_MAX : Len;
    if (Data && e->Len) RtlCopyMemory(e->Data, Data, e->Len);
    MemoryBarrier(); g_Ring->Head = n;
    KeReleaseSpinLock(&g_RLock, x);
}

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
    if (g_Unload || !NT_SUCCESS(IoAcquireRemoveLock(&g_RemoveLock, Irp))) {
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
                    status = STATUS_NO_MORE_ENTRIES;
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
                KIRQL x; KeAcquireSpinLock(&g_BlockLock, &x);
                if (g_BlockCount < NET_BLOCK_IP_MAX) {
                    g_BlockList[g_BlockCount].Addr[0] = in[0];
                    g_BlockList[g_BlockCount].Addr[1] = in[1];
                    g_BlockList[g_BlockCount].Addr[2] = in[2];
                    g_BlockList[g_BlockCount].Addr[3] = in[3];
                    g_BlockList[g_BlockCount].Port = (USHORT)(in[4] | (in[5] << 8));
                    g_BlockCount++;
                    DbgPrint("ZETA_NET: blocked IP %u.%u.%u.%u:%u (total=%lu)\n",
                        in[0], in[1], in[2], in[3], g_BlockList[g_BlockCount-1].Port, g_BlockCount);
                }
                KeReleaseSpinLock(&g_BlockLock, x);
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
            status = STATUS_SUCCESS;
            break;
        }
    } while (FALSE);

    Irp->IoStatus.Status = status;
    IoReleaseRemoveLock(&g_RemoveLock, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
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
    NTSTATUS lockSt = IoAcquireRemoveLock(&g_RemoveLock, Irp);
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
            RingPush(EVT_SOCKET, pid, NULL, 0);
            goto done;
        }

        if (mj == IRP_MJ_DEVICE_CONTROL) {
            ULONG ioctl = s->Parameters.DeviceIoControl.IoControlCode;
            PUCHAR in = (PUCHAR)s->Parameters.DeviceIoControl.Type3InputBuffer;
            ULONG  ilen = s->Parameters.DeviceIoControl.InputBufferLength;

            // ⚠ 先在 PASSIVE_LEVEL 检查并读取用户态数据
            UCHAR cb[NET_EVENT_MAX];
            USHORT cl = 0;

            switch (ioctl) {

            case IOCTL_AFD_CONNECT: {
                if (in && ilen >= ZTA_CONNECT_MIN_SIZE) {
                    PUCHAR addrData = in + ZTA_CONNECT_ADDR_OFFSET;
                    USHORT addrLen = *(PUSHORT)(addrData);
                    if (addrLen > 0 && addrLen <= NET_EVENT_MAX) {
                        addrData += sizeof(USHORT) * 2;
                        cl = (addrLen < NET_EVENT_MAX) ? addrLen : NET_EVENT_MAX;
                        ProbeForRead(addrData, cl, 1);
                        RtlCopyMemory(cb, addrData, cl);
                    }

                    // P1-状态机/网络硬拦截: 目标 IP 黑名单 (C2/恶意服务器阻断)
                    // cb 即 SOCKADDR_IN (AF_INET): [0-1]family [2-3]port(网络序) [4-7]IP
                    // cb[2..3] 端口是网络字节序, 转主机序比较
                    if (cl >= 8 && cb[0] == 0 && cb[1] == 2) {  // AF_INET
                        UCHAR ip0=cb[4], ip1=cb[5], ip2=cb[6], ip3=cb[7];
                        USHORT portNet = (USHORT)(cb[2] | (cb[3] << 8));  // 网络序
                        USHORT portHost = (USHORT)((portNet >> 8) | (portNet << 8));  // 转主机序
                        KIRQL x; KeAcquireSpinLock(&g_BlockLock, &x);
                        BOOLEAN blocked = FALSE;
                        for (ULONG bi = 0; bi < g_BlockCount; bi++) {
                            if (g_BlockList[bi].Addr[0]==ip0 && g_BlockList[bi].Addr[1]==ip1 &&
                                g_BlockList[bi].Addr[2]==ip2 && g_BlockList[bi].Addr[3]==ip3) {
                                if (g_BlockList[bi].Port == 0 || g_BlockList[bi].Port == portHost) {
                                    blocked = TRUE;
                                    break;
                                }
                            }
                        }
                        KeReleaseSpinLock(&g_BlockLock, x);
                        if (blocked) {
                            DbgPrint("ZETA_NET: CONNECT BLOCKED %u.%u.%u.%u:%u (PID=%lu)\n",
                                ip0, ip1, ip2, ip3, portHost, pid);
                            RingPush(EVT_CONNECT, pid, cb, cl);
                            // 拒绝连接: 完成 IRP, 不透传到底层
                            IoReleaseRemoveLock(&g_RemoveLock, Irp);
                            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                            Irp->IoStatus.Information = 0;
                            IoCompleteRequest(Irp, IO_NO_INCREMENT);
                            return STATUS_ACCESS_DENIED;
                        }
                    }
                }
                if (cl) RingPush(EVT_CONNECT, pid, cb, cl);
                break;
            }

            case IOCTL_AFD_SEND: {
                if (in && ilen >= ZTA_SEND_BUFCOUNT_OFFSET + sizeof(ULONG)) {
                    ULONG bufCount = *(PULONG)(in + ZTA_SEND_BUFCOUNT_OFFSET);
                    if (bufCount > 0) {
                        void* bufArray = *(void**)(in + ZTA_SEND_BUFARRAY_OFFSET);
                        if (bufArray) {
                            // 读第一个 WSABUF: bufArray 是用户态指针
                            ProbeForRead(bufArray, ZTA_WSABUF_SIZE, 1);
                            ULONG wbLen = 0;
                            RtlCopyMemory(&wbLen, bufArray, sizeof(ULONG));
                            void* wbBuf = nullptr;
                            RtlCopyMemory(&wbBuf, (PUCHAR)bufArray + ZTA_WSABUF_BUF_OFFSET, sizeof(void*));
                            if (wbLen > 0 && wbBuf) {
                                cl = (wbLen < NET_EVENT_MAX) ? (USHORT)wbLen : NET_EVENT_MAX;
                                ProbeForRead(wbBuf, cl, 1);
                                RtlCopyMemory(cb, wbBuf, cl);
                            }
                        }
                    }
                }
                if (cl) RingPush(EVT_SEND, pid, cb, cl);
                break;
            }

            case IOCTL_AFD_SEND_DATAGRAM: {
                if (in && ilen > ZTA_WSABUF_SIZE) {
                    // WSABUF 直接在输入缓冲区开头 (METHOD_NEITHER)
                    // in 指向用户态, 需要 ProbeForRead
                    ProbeForRead(in, ZTA_WSABUF_SIZE, 1);
                    ULONG wbLen = 0;
                    RtlCopyMemory(&wbLen, in + ZTA_WSABUF_LEN_OFFSET, sizeof(ULONG));
                    void* wbBuf = nullptr;
                    RtlCopyMemory(&wbBuf, in + ZTA_WSABUF_BUF_OFFSET, sizeof(void*));
                    if (wbLen > 0 && wbBuf) {
                        cl = (wbLen < NET_EVENT_MAX) ? (USHORT)wbLen : NET_EVENT_MAX;
                        ProbeForRead(wbBuf, cl, 1);
                        RtlCopyMemory(cb, wbBuf, cl);
                    }
                }
                if (cl) RingPush(EVT_SEND, pid, cb, cl);
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
                    ProbeForRead(in, sizeof(ULONG), 1);
                    ULONG wbLen = *(PULONG)in;
                    RingPush(EVT_RECV, pid, &wbLen, sizeof(ULONG));
                    cl = 1; // 标记已处理, 避免下面重复 push
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
    IoReleaseRemoveLock(&g_RemoveLock, Irp);
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
        // 仅从设备栈摘除, 不再接收新 IRP.
        // 设备对象本身延迟到 Unload 末尾 (等所有在途 IRP 完成) 再删除, 避免 0xCE.
        if (pending[i]->Att && pending[i]->Low) {
            IoDetachDevice(pending[i]->Low);
            pending[i]->Att = FALSE;
        }
    }
}

static void Unload(PDRIVER_OBJECT) {
    // 1. 标记卸载: DispatchFilter/DispatchControl 入口会直接拒绝新 IRP
    g_Unload = TRUE;

    // 2. 从设备栈摘除, 新 IRP 不再路由到本驱动设备
    DetachAll();

    // 3. 等待所有在途 IRP 真正完成 (包括控制设备上的阻塞读).
    //    用 AndWait 变体, 它会自旋直到所有持有 RemoveLock 的 IRP 释放完毕.
    IoReleaseRemoveLockAndWait(&g_RemoveLock, NULL);
    DbgPrint("ZETA_NET: all IRPs drained\n");

    // 4. 此时已无任何 IRP 在访问 g_Ring / 设备, 安全清理
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

    IoInitializeRemoveLock(&g_RemoveLock, ZETA_NET_TAG, 0, 0);
    InitializeListHead(&g_List);
    KeInitializeSpinLock(&g_Lock);
    KeInitializeSpinLock(&g_RLock);
    KeInitializeSpinLock(&g_BlockLock);

    g_Ring = (PNET_RING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NET_RING), ZETA_NET_TAG);
    if (!g_Ring) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Ring, sizeof(NET_RING));

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        D->MajorFunction[i] = DispatchAny;
    D->DriverUnload = Unload;

    UNICODE_STRING cn; RtlInitUnicodeString(&cn, CTRL_NAME);
    NTSTATUS st = IoCreateDevice(D, 0, &cn, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_Ctrl);
    if (!NT_SUCCESS(st)) { ExFreePool(g_Ring); g_Ring = NULL; return st; }

    RtlInitUnicodeString(&g_Link, CTRL_LINK);
    st = IoCreateSymbolicLink(&g_Link, &cn);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(g_Ctrl); g_Ctrl = NULL; ExFreePool(g_Ring); g_Ring = NULL; return st; }
    g_LinkOk = TRUE;
    g_Ctrl->Flags &= ~DO_DEVICE_INITIALIZING;
    g_Ctrl->Flags |= DO_DIRECT_IO;

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
