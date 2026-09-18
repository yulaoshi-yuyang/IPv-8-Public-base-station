/*++

Copyright (c) IPv8+ Project. All rights reserved.

Module Name:

    driver.h

Abstract:

    Header for the IPv8 NDIS 6.30 protocol driver.
    Phase 5A：控制设备 \Device\IPv8Proto + 只读 IOCTL（版本/全局统计/绑定快照）。
    Phase 5B：0xFB14 二层裸帧收发（RECV/SEND IOCTL）+ 本机 MAC 查询，
              照 ndisprot630 官方模型：有界非分页帧池 + pending READ 取消同步。

--*/

#pragma once

#include <ntddk.h>
#include <ndis.h>
#include <wdmsec.h>
/* IoCsq*（cancel-safe IRP queue）声明随 wdm.h 提供，无需额外头文件 */

#define IPv8_PROTOCOL_NAME      L"IPv8Proto"
#define IPv8_POOL_TAG           '8VPI'

#define IPv8_DEVICE_NAME        L"\\Device\\IPv8Proto"
#define IPv8_SYMLINK_NAME       L"\\??\\IPv8Proto"

/* 驱动版本：0.11 — 双机实测修复（收包 packet filter + EtherType 硬校验），ABI 不变 */
#define IPV8_VERSION_MAJOR      0
#define IPV8_VERSION_MINOR      11

/* 控制设备类 GUID（仅用于 IoCreateDeviceSecure 分组，非 PnP 设备） */
/* {6B7A1C4E-8F2D-4A93-B5C1-0AF7E1D2E830} */
DEFINE_GUID(IPV8_DEVICE_CLASS_GUID,
    0x6b7a1c4e, 0x8f2d, 0x4a93, 0xb5, 0xc1, 0x0a, 0xf7, 0xe1, 0xd2, 0xe8, 0x30);

/* ---- IOCTL（METHOD_BUFFERED，管理员仅经设备 SDDL 约束）---- */

#define IOCTL_IPV8_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPV8_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPV8_GET_BINDINGS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPV8_RECV_FRAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPV8_SEND_FRAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* 调试注入：把用户态提供的帧直接投递到接收队列（走 IPv8IndicateOneFrame
   同一路径），仅用于在单机无对端时验证接收侧代码。生产环境不影响正常收发。 */
#define IOCTL_IPV8_INJECT_FRAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- Phase 5B 二层常量 ---- */

#define IPV8_IOCTL_MAGIC        0xFB14UL
#define IPV8_ETH_TYPE           0xFB14
#define IPV8_ETH_HEADER_LEN     14
#define IPV8_FRAME_MIN          60
#define IPV8_FRAME_MAX          1514
#define IPV8_FRAME_HDR_LEN      16
#define IPV8_RECV_IN_LEN        16
#define IPV8_MAC_LEN            6

#define IPV8_RX_QUEUE_NODES     128     /* 已收待读帧节点数（约 196 KB 非分页） */
#define IPV8_TX_INFLIGHT_NODES  32      /* 在途发送帧节点数 */
#define IPV8_IFINDEX_ANY        0xFFFFFFFFUL

/* 用户态镜像必须保持逐字节一致（ping8 driver / ipv8prop.dll） */
#pragma pack(push, 1)

typedef struct _IPV8_VERSION_INFO
{
    ULONG   Magic;          /* 0xFB14 */
    USHORT  Major;
    USHORT  Minor;
    USHORT  NdisMajor;
    USHORT  NdisMinor;
} IPV8_VERSION_INFO, *PIPV8_VERSION_INFO;

typedef struct _IPV8_GLOBAL_STATS
{
    ULONG   Magic;          /* 0xFB14 */
    LONG    OpenCount;
    LONG    Unloading;
    ULONG   Reserved;
} IPV8_GLOBAL_STATS, *PIPV8_GLOBAL_STATS;

#define IPV8_BINDING_NAME_CHARS 64

/* Phase 5B：pack(1) 共 180 字节（旧 5A 为 144 字节，ABI 随版本 0.10 同步） */
typedef struct _IPV8_BINDING_ENTRY
{
    ULONG64 RxPackets;      /* 0xFB14 收包总数 */
    ULONG64 TxPackets;      /* 发送完成总数 */
    ULONG64 RxDropped;      /* 接收丢弃（畸形/队列满） */
    ULONG64 TxDropped;      /* 发送失败/丢弃 */
    ULONG   Bound;
    ULONG   IfIndex;        /* 稳定适配器编号（SEND/RECV 选择用） */
    UCHAR   Mac[IPV8_MAC_LEN];
    UCHAR   Pad[2];
    ULONG   NameChars;      /* 实际字符数（不含终止 0） */
    WCHAR   Name[IPV8_BINDING_NAME_CHARS];
} IPV8_BINDING_ENTRY, *PIPV8_BINDING_ENTRY;

typedef struct _IPV8_BINDINGS_OUT
{
    ULONG   Magic;          /* 0xFB14 */
    ULONG   Total;          /* 链表内绑定总数 */
    ULONG   Count;          /* 本次返回条数 */
    ULONG   Reserved;
    IPV8_BINDING_ENTRY Entries[1];  /* 变长：按输出缓冲容量截断 */
} IPV8_BINDINGS_OUT, *PIPV8_BINDINGS_OUT;

/* RECV 请求输入（METHOD_BUFFERED 与输出共享 SystemBuffer，先解析后覆盖） */
typedef struct _IPV8_RECV_IN
{
    ULONG   Magic;          /* 0xFB14 */
    ULONG   IfIndex;        /* IPV8_IFINDEX_ANY = 任意适配器 */
    ULONG   TimeoutMs;      /* 保留必须为 0：超时由用户态 overlapped 控制 */
    ULONG   Reserved;
} IPV8_RECV_IN, *PIPV8_RECV_IN;

/* RECV 输出 / SEND 输入的帧头，后接 FrameLen 字节完整以太网帧 */
typedef struct _IPV8_FRAME_HDR
{
    ULONG   Magic;          /* 0xFB14 */
    ULONG   IfIndex;
    ULONG   FrameLen;       /* 14..1514 */
    ULONG   Reserved;
} IPV8_FRAME_HDR, *PIPV8_FRAME_HDR;

#pragma pack(pop)

/* 帧节点：RX（收包拷贝/待读）与 TX（在途发送）共用 */
typedef struct _IPV8_FRAME_NODE
{
    LIST_ENTRY  Link;
    ULONG       IfIndex;
    ULONG       FrameLen;
    UCHAR       Frame[IPV8_FRAME_MAX];
} IPV8_FRAME_NODE, *PIPV8_FRAME_NODE;

/* OID 请求包装：区分 MAC 查询与 packet-filter 设置 */
typedef struct _IPV8_OID_WRAPPER
{
    NDIS_OID_REQUEST    Req;
    union {
        UCHAR           MacBuf[IPV8_MAC_LEN];
        ULONG           PacketFilter;
    };
    PVOID               Open;       /* PIPV8_OPEN_CONTEXT */
} IPV8_OID_WRAPPER, *PIPV8_OID_WRAPPER;

/* CSQ PeekContext 统一匹配描述符；PeekContext==NULL 表示匹配全部 */
typedef enum _IPV8_CSQ_MATCH_KIND
{
    IPv8CsqMatchByIfIndex = 0,
    IPv8CsqMatchByFileObject = 1
} IPV8_CSQ_MATCH_KIND;

typedef struct _IPV8_CSQ_MATCH
{
    ULONG   Kind;       /* IPV8_CSQ_MATCH_KIND */
    ULONG   IfIndex;    /* Kind=ByIfIndex 时使用，IPV8_IFINDEX_ANY 为全部 */
    PVOID   FileObject; /* Kind=ByFileObject 时使用：IRP_MJ_CLEANUP 精确取消 */
} IPV8_CSQ_MATCH, *PIPV8_CSQ_MATCH;

typedef struct _IPV8_GLOBAL_DATA
{
    NDIS_HANDLE     NdisProtocolHandle;
    LONG            OpenCount;
    LONG            Unloading;      /* Interlocked 目标，勿改普通字段 */
    PDEVICE_OBJECT  ControlDevice;

    /* Phase 5B 帧设施（FrameLock 一把保护下列全部队列，无嵌套锁） */
    NDIS_SPIN_LOCK  FrameLock;
    LIST_ENTRY      FrameQueue;     /* 已收待读：IPV8_FRAME_NODE */
    LIST_ENTRY      FreeRxNodes;    /* 空闲 RX 节点 */
    LIST_ENTRY      FreeTxNodes;    /* 空闲 TX 节点 */
    LIST_ENTRY      PendingReads;   /* CSQ 回调实际维护：等待帧的 READ IRP */
    IO_CSQ          Csq;            /* cancel-safe IRP queue（回调见 driver-ctl.c） */
    NDIS_HANDLE     NblPool;
    PIPV8_FRAME_NODE RxBlock;       /* 128 节点连续内存块，卸载整体释放 */
    PIPV8_FRAME_NODE TxBlock;       /* 32 节点连续内存块 */
    volatile LONG   NextIfIndex;    /* InterlockedIncrement，从 1 起 */
} IPV8_GLOBAL_DATA, *PIPV8_GLOBAL_DATA;

extern IPV8_GLOBAL_DATA g_Ipv8Global;

/* 绑定注册表（driver.c 定义，driver-ctl.c 快照读取） */
extern LIST_ENTRY       g_OpenList;
extern NDIS_SPIN_LOCK   g_OpenListLock;

typedef struct _IPV8_OPEN_CONTEXT
{
    NDIS_HANDLE     NdisBindingHandle;
    NDIS_HANDLE     BindContext;            /* PENDING open 时留存，OpenComplete 再 complete */
    NDIS_STRING     AdapterName;
    PUCHAR          AdapterNameBuf;
    BOOLEAN         Bound;
    ULONG           IfIndex;                /* 稳定编号 */
    LONG64          PacketsReceived;        /* InterlockedAdd64 目标 */
    LONG64          TxPackets;
    LONG64          RxDropped;
    LONG64          TxDropped;
    LONG64          ReceiveIndications;     /* NDIS 调用 ReceiveNetBufferLists 次数 */
    UCHAR           CurrentMac[IPV8_MAC_LEN];
    BOOLEAN         MacValid;
    LIST_ENTRY      Link;
} IPV8_OPEN_CONTEXT, *PIPV8_OPEN_CONTEXT;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
IPv8Unload(
    _In_ PDRIVER_OBJECT DriverObject
    );

NDIS_STATUS
IPv8BindAdapterEx(
    _In_ NDIS_HANDLE           ProtocolDriverContext,
    _In_ NDIS_HANDLE           BindContext,
    _In_ PNDIS_BIND_PARAMETERS BindParameters
    );

NDIS_STATUS
IPv8UnbindAdapterEx(
    _In_ NDIS_HANDLE UnbindContext,
    _In_ NDIS_HANDLE ProtocolBindingContext
    );

VOID
IPv8OpenAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ NDIS_STATUS Status
    );

VOID
IPv8CloseAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext
    );

VOID
IPv8ReceiveNetBufferLists(
    _In_ NDIS_HANDLE      ProtocolBindingContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG            NumberOfNetBufferLists,
    _In_ ULONG            ReceiveFlags
    );

VOID
IPv8SendNetBufferListsComplete(
    _In_ NDIS_HANDLE      ProtocolBindingContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG            SendCompleteFlags
    );

VOID
IPv8StatusEx(
    _In_ NDIS_HANDLE             ProtocolBindingContext,
    _In_ PNDIS_STATUS_INDICATION StatusIndication
    );

VOID
IPv8OidRequestComplete(
    _In_ NDIS_HANDLE       ProtocolBindingContext,
    _In_ PNDIS_OID_REQUEST OidRequest,
    _In_ NDIS_STATUS       Status
    );

NDIS_STATUS
IPv8NetPnPEvent(
    _In_ NDIS_HANDLE                  ProtocolBindingContext,
    _In_ PNET_PNP_EVENT_NOTIFICATION  NetPnPEvent
    );

/* 控制设备（driver-ctl.c） */
NTSTATUS
IPv8AttachControlDevice(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
IPv8DetachControlDevice(
    VOID
    );

NTSTATUS
IPv8DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

NTSTATUS
IPv8DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

/* Phase 5B 帧设施（driver.c 实现，driver-ctl.c 调用） */
NTSTATUS
IPv8FrameInfrastructureCreate(
    VOID
    );

VOID
IPv8FrameInfrastructureDestroy(
    VOID
    );

/* 卸载开始：取消全部 pending READ IRP（STATUS_DEVICE_REMOVED，锁外完成） */
VOID
IPv8CancelAllPendingReads(
    VOID
    );

/* CSQ 回调（driver-ctl.c，锁复用 FrameLock） */
VOID
IPv8CsqInsertIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp
    );

VOID
IPv8CsqRemoveIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp
    );

PIRP
IPv8CsqPeekNextIrp(
    _In_ PIO_CSQ Csq,
    _In_opt_ PIRP Irp,
    _In_opt_ PVOID PeekContext
    );

VOID
IPv8CsqAcquireLock(
    _In_ PIO_CSQ Csq,
    _Out_ PKIRQL Irql
    );

VOID
IPv8CsqReleaseLock(
    _In_ PIO_CSQ Csq,
    _In_ KIRQL Irql
    );

VOID
IPv8CsqCompleteCanceledIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp
    );

/* 初始化 CSQ（AttachControlDevice 成功后调用一次） */
NTSTATUS
IPv8CsqInitialize(
    VOID
    );

/* 持 FrameLock 调用：从已收帧队列摘第一个匹配 IfIndex（ANY 匹配全部）的节点；
   无匹配返回 NULL。 */
PIPV8_FRAME_NODE
IPv8FrameDequeueLocked(
    _In_ ULONG IfIndex
    );

/* 按 IfIndex 查绑定（持 g_OpenListLock；找不到返回 NULL）。
   找到时 InterlockedIncrement 引用由调用语义保证：仅在锁内用于
   投递发送/读快照；发送 NBL 完成前 NDIS 不会 close 绑定。 */
PIPV8_OPEN_CONTEXT
IPv8LookupBindingLocked(
    _In_ ULONG IfIndex
    );

/* 投递一帧发送：成功时 IRP 已标记 pending（在 SendComplete 回完）；
   失败返回错误码（调用方立即完成 IRP）。frame 为不含帧头的完整以太网帧。 */
NTSTATUS
IPv8SubmitSend(
    _Inout_ PIRP Irp,
    _In_ ULONG IfIndex,
    _In_reads_bytes_(FrameLen) const UCHAR* Frame,
    _In_ ULONG FrameLen
    );

/* 调试注入：把外部帧直接放入接收路径（pending READ 或 FrameQueue）。
   不经过 NDIS，仅用于验证接收侧代码逻辑。返回投递结果。 */
NTSTATUS
IPv8InjectRx(
    _In_ ULONG IfIndex,
    _In_reads_bytes_(FrameLen) const UCHAR* Frame,
    _In_ ULONG FrameLen
    );

/* ---- ABI 静态断言：三处用户态镜像（ping8 / ipv8prop.dll）必须逐字节一致 ---- */
C_ASSERT(sizeof(IPV8_BINDING_ENTRY) == 180);
C_ASSERT(IPV8_FRAME_HDR_LEN == 16);
C_ASSERT(IPV8_RECV_IN_LEN == 16);
C_ASSERT(sizeof(IPV8_FRAME_HDR) == 16);
