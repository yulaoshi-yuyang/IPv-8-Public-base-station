/*++

Copyright (c) IPv8+ Project. All rights reserved.

Module Name:

    driver-ctl.c

Abstract:

    控制设备 \\Device\\IPv8Proto：仅管理员可开（SDDL）。
    Phase 5A：GET_VERSION / GET_STATS / GET_BINDINGS 三个只读 IOCTL。
    Phase 5B：新增 RECV_FRAME（0x803，可挂起）/ SEND_FRAME（0x804，发送期挂起）。
              挂起 READ IRP 经 CSQ（cancel-safe IRP queue）管理；
              IRP_MJ_CLEANUP 精确取消本句柄的等待读。
    绑定快照在 g_OpenListLock 自旋锁内拷贝（SystemBuffer 非分页，安全）。

--*/

#include <initguid.h>  /* 使 driver.h 中 DEFINE_GUID 在本翻译单元实例化 */
#include "driver.h"

/* ==================================================================
 *  CSQ：pending READ IRP 的取消安全队列（锁复用 FrameLock）
 * ================================================================== */

VOID
IPv8CsqInsertIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(Csq);

    /* 等待的 IfIndex 已由调用方写入 DriverContext[0]，此处仅入链 */
    InsertTailList(&g_Ipv8Global.PendingReads,
        &Irp->Tail.Overlay.ListEntry);
}

VOID
IPv8CsqRemoveIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

PIRP
IPv8CsqPeekNextIrp(
    _In_ PIO_CSQ Csq,
    _In_opt_ PIRP Irp,
    _In_opt_ PVOID PeekContext
    )
{
    PLIST_ENTRY start;
    PLIST_ENTRY entry;

    UNREFERENCED_PARAMETER(Csq);

    start = (Irp == NULL)
        ? g_Ipv8Global.PendingReads.Flink
        : Irp->Tail.Overlay.ListEntry.Flink;

    for (entry = start;
         entry != &g_Ipv8Global.PendingReads;
         entry = entry->Flink)
    {
        PIRP candidate =
            CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

        if (PeekContext == NULL)
        {
            return candidate;  /* 卸载路径：任意 */
        }
        else
        {
            PIPV8_CSQ_MATCH match = (PIPV8_CSQ_MATCH)PeekContext;

            if (match->Kind == IPv8CsqMatchByIfIndex)
            {
                ULONG waitIf =
                    (ULONG)(ULONG_PTR)candidate->Tail.Overlay.DriverContext[0];
                if (match->IfIndex == IPV8_IFINDEX_ANY ||
                    waitIf == match->IfIndex)
                {
                    return candidate;
                }
            }
            else /* IPv8CsqMatchByFileObject：CLEANUP 只取本句柄的 IRP */
            {
                PIO_STACK_LOCATION sp =
                    IoGetCurrentIrpStackLocation(candidate);
                if (sp != NULL && sp->FileObject == match->FileObject)
                {
                    return candidate;
                }
            }
        }
    }

    return NULL;
}

VOID
IPv8CsqAcquireLock(
    _In_ PIO_CSQ Csq,
    _Out_ PKIRQL Irql
    )
{
    UNREFERENCED_PARAMETER(Csq);
    UNREFERENCED_PARAMETER(Irql);
    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
}

VOID
IPv8CsqReleaseLock(
    _In_ PIO_CSQ Csq,
    _In_ KIRQL Irql
    )
{
    UNREFERENCED_PARAMETER(Csq);
    UNREFERENCED_PARAMETER(Irql);
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);
}

VOID
IPv8CsqCompleteCanceledIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS
IPv8CsqInitialize(
    VOID
    )
{
    NTSTATUS status;

    status = IoCsqInitialize(
        &g_Ipv8Global.Csq,
        IPv8CsqInsertIrp,
        IPv8CsqRemoveIrp,
        IPv8CsqPeekNextIrp,
        IPv8CsqAcquireLock,
        IPv8CsqReleaseLock,
        IPv8CsqCompleteCanceledIrp
        );
    return status;
}

/* ==================================================================
 *  控制设备创建/摘除
 * ================================================================== */

NTSTATUS
IPv8AttachControlDevice(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING devName;
    UNICODE_STRING symName;
    UNICODE_STRING sddl;
    NTSTATUS status;

    RtlInitUnicodeString(&devName, IPv8_DEVICE_NAME);
    RtlInitUnicodeString(&symName, IPv8_SYMLINK_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)");

    status = IoCreateDeviceSecure(
        DriverObject,
        0,                      /* 无设备扩展 */
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,                  /* 不独占 */
        &sddl,
        &IPV8_DEVICE_CLASS_GUID,
        &g_Ipv8Global.ControlDevice
        );
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_Ipv8Global.ControlDevice);
        g_Ipv8Global.ControlDevice = NULL;
        return status;
    }

    status = IPv8CsqInitialize();
    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(g_Ipv8Global.ControlDevice);
        g_Ipv8Global.ControlDevice = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IPv8DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IPv8DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = IPv8DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IPv8DispatchDeviceControl;

    return status;
}

VOID
IPv8DetachControlDevice(
    VOID
    )
{
    UNICODE_STRING symName;

    RtlInitUnicodeString(&symName, IPv8_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);

    if (g_Ipv8Global.ControlDevice != NULL)
    {
        IoDeleteDevice(g_Ipv8Global.ControlDevice);
        g_Ipv8Global.ControlDevice = NULL;
    }
}

/* ---- Create/Close：一律成功。CLEANUP：先精确取消本句柄的等待读 ---- */

NTSTATUS
IPv8DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(DeviceObject);

    if (irpSp->MajorFunction == IRP_MJ_CLEANUP)
    {
        IPV8_CSQ_MATCH match;
        PIRP pending;

        match.Kind = IPv8CsqMatchByFileObject;
        match.IfIndex = 0;
        match.FileObject = irpSp->FileObject;

        /* 循环取出本句柄全部等待读并取消；取出即归本线程所有 */
        while ((pending = IoCsqRemoveNextIrp(&g_Ipv8Global.Csq, &match))
               != NULL)
        {
            pending->IoStatus.Status = STATUS_CANCELLED;
            pending->IoStatus.Information = 0;
            IoCompleteRequest(pending, IO_NO_INCREMENT);
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ==================================================================
 *  IOCTL：版本 / 全局统计 / 绑定快照
 * ================================================================== */

static NTSTATUS
IPv8IoctlVersion(
    _Inout_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
    )
{
    PIPV8_VERSION_INFO out;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength <
        sizeof(IPV8_VERSION_INFO))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    out = (PIPV8_VERSION_INFO)Irp->AssociatedIrp.SystemBuffer;
    out->Magic = IPV8_IOCTL_MAGIC;
    out->Major = IPV8_VERSION_MAJOR;
    out->Minor = IPV8_VERSION_MINOR;
    out->NdisMajor = 6;
    out->NdisMinor = 30;

    Irp->IoStatus.Information = sizeof(IPV8_VERSION_INFO);
    return STATUS_SUCCESS;
}

static NTSTATUS
IPv8IoctlStats(
    _Inout_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
    )
{
    PIPV8_GLOBAL_STATS out;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength <
        sizeof(IPV8_GLOBAL_STATS))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    out = (PIPV8_GLOBAL_STATS)Irp->AssociatedIrp.SystemBuffer;
    out->Magic = IPV8_IOCTL_MAGIC;
    out->OpenCount = InterlockedCompareExchange(&g_Ipv8Global.OpenCount, 0, 0);
    out->Unloading =
        InterlockedCompareExchange(&g_Ipv8Global.Unloading, 0, 0);
    out->Reserved = 0;

    Irp->IoStatus.Information = sizeof(IPV8_GLOBAL_STATS);
    return STATUS_SUCCESS;
}

static NTSTATUS
IPv8IoctlBindings(
    _Inout_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
    )
{
    PIPV8_BINDINGS_OUT out;
    ULONG outLen;
    ULONG maxEntries;
    ULONG total = 0;
    ULONG count = 0;
    PLIST_ENTRY le;
    const ULONG headerSize =
        (ULONG)FIELD_OFFSET(IPV8_BINDINGS_OUT, Entries);

    outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    if (outLen < headerSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    out = (PIPV8_BINDINGS_OUT)Irp->AssociatedIrp.SystemBuffer;
    maxEntries = (outLen - headerSize) / sizeof(IPV8_BINDING_ENTRY);

    /* 全程持 g_OpenListLock：链表稳定；MAC 写入侧也持同一把锁，无撕裂 */
    NdisAcquireSpinLock(&g_OpenListLock);
    for (le = g_OpenList.Flink; le != &g_OpenList; le = le->Flink)
    {
        PIPV8_OPEN_CONTEXT ctx =
            CONTAINING_RECORD(le, IPV8_OPEN_CONTEXT, Link);

        if (count < maxEntries)
        {
            PIPV8_BINDING_ENTRY e = &out->Entries[count];
            ULONG nameChars;

            e->RxPackets = (ULONG64)InterlockedAdd64(
                (LONG64 volatile*)&ctx->PacketsReceived, 0);
            e->TxPackets = (ULONG64)InterlockedAdd64(
                (LONG64 volatile*)&ctx->TxPackets, 0);
            e->RxDropped = (ULONG64)InterlockedAdd64(
                (LONG64 volatile*)&ctx->RxDropped, 0);
            e->TxDropped = (ULONG64)InterlockedAdd64(
                (LONG64 volatile*)&ctx->TxDropped, 0);
            e->Bound = ctx->Bound ? 1u : 0u;
            e->IfIndex = ctx->IfIndex;

            RtlCopyMemory(e->Mac, ctx->CurrentMac, IPV8_MAC_LEN);
            e->Pad[0] = 0;
            e->Pad[1] = 0;

            /* 名称截断拷贝（ctx 内存非分页，自旋锁下安全） */
            nameChars = ctx->AdapterName.Length / sizeof(WCHAR);
            if (nameChars > (IPV8_BINDING_NAME_CHARS - 1))
            {
                nameChars = (IPV8_BINDING_NAME_CHARS - 1);
            }
            RtlCopyMemory(e->Name, ctx->AdapterName.Buffer,
                nameChars * sizeof(WCHAR));
            e->Name[nameChars] = L'\0';
            e->NameChars = nameChars;

            count++;
        }
        total++;
    }
    NdisReleaseSpinLock(&g_OpenListLock);

    out->Magic = IPV8_IOCTL_MAGIC;
    out->Total = total;
    out->Count = count;
    out->Reserved = 0;

    Irp->IoStatus.Information =
        headerSize + count * sizeof(IPV8_BINDING_ENTRY);
    return STATUS_SUCCESS;
}

/* ==================================================================
 *  IOCTL：RECV（0x803）
 *
 *  METHOD_BUFFERED：SystemBuffer 先承载 16B IPV8_RECV_IN（解析后复用为
 *  输出：16B IPV8_FRAME_HDR + 帧）。内核不实现超时：无帧即挂入 CSQ，
 *  用户态 overlapped + CancelIoEx 控超时；取消/卸载/CLEANUP 经 CSQ 回完。
 * ================================================================== */

static NTSTATUS
IPv8IoctlRecv(
    _Inout_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
    )
{
    PUCHAR sysBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PIPV8_RECV_IN in;
    ULONG ifIndex;
    PIPV8_FRAME_NODE node = NULL;

    if (inLen < IPV8_RECV_IN_LEN ||
        outLen < IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    in = (PIPV8_RECV_IN)sysBuf;
    if (in->Magic != IPV8_IOCTL_MAGIC)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (in->TimeoutMs != 0 || in->Reserved != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ifIndex = in->IfIndex;

    /* 先取已排队帧（队列语义：挂起前到达的帧不丢） */
    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
    node = IPv8FrameDequeueLocked(ifIndex);
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);

    if (node != NULL)
    {
        PIPV8_FRAME_HDR hdr = (PIPV8_FRAME_HDR)sysBuf;
        ULONG gotIfIndex = node->IfIndex;
        ULONG gotFrameLen = node->FrameLen;

        RtlCopyMemory(sysBuf + IPV8_FRAME_HDR_LEN, node->Frame,
            gotFrameLen);

        /* 归还后节点可能立即被收包路径重用：元数据必须先取出 */
        NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
        InsertTailList(&g_Ipv8Global.FreeRxNodes, &node->Link);
        NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);

        hdr->Magic = IPV8_IOCTL_MAGIC;
        hdr->IfIndex = gotIfIndex;
        hdr->FrameLen = gotFrameLen;
        hdr->Reserved = 0;

        Irp->IoStatus.Information =
            IPV8_FRAME_HDR_LEN + gotFrameLen;
        return STATUS_SUCCESS;
    }

    /* 无帧：挂入 CSQ。IoCsqInsertIrp 内部覆盖取消竞态（插入即取消也会被
       CompleteCanceledIrp 正确回完），返回后由 I/O 管理器持有。 */
    Irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)ifIndex;
    IoMarkIrpPending(Irp);
    IoCsqInsertIrp(&g_Ipv8Global.Csq, Irp, NULL);
    return STATUS_PENDING;
}

/* ==================================================================
 *  IOCTL：SEND（0x804）
 *
 *  输入 = 16B IPV8_FRAME_HDR + 完整以太网帧；成功投递后 IRP 挂起至
 *  SendComplete。强校验（magic/长度/EtherType）与发送路径的源 MAC 覆写
 *  共同把通道限制为"只能发 0xFB14 帧、不能伪造主机身份"。
 * ================================================================== */

static NTSTATUS
IPv8IoctlSend(
    _Inout_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
    )
{
    PUCHAR sysBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    PIPV8_FRAME_HDR hdr;
    ULONG frameLen;
    NTSTATUS status;

    if (inLen < IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    hdr = (PIPV8_FRAME_HDR)sysBuf;
    if (hdr->Magic != IPV8_IOCTL_MAGIC)
    {
        return STATUS_INVALID_PARAMETER;
    }
    frameLen = hdr->FrameLen;
    if (frameLen < IPV8_ETH_HEADER_LEN || frameLen > IPV8_FRAME_MAX)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (inLen < IPV8_FRAME_HDR_LEN + frameLen)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* IPv8SubmitSend 负责：绑定存在性 / EtherType=0xFB14 / 节点容量 /
       源 MAC 覆写 / 60 字节补齐。成功返回 STATUS_PENDING（IRP 在
       SendComplete 回完），失败返回即时错误码。 */
    status = IPv8SubmitSend(
        Irp, hdr->IfIndex,
        sysBuf + IPV8_FRAME_HDR_LEN, frameLen);

    if (status == STATUS_PENDING)
    {
        return STATUS_PENDING;
    }
    return status;
}

/* 调试注入 IOCTL：输入格式同 SEND_FRAME（IPV8_FRAME_HDR + 帧），
   但直接送入接收队列，不经过 NDIS 发送。用于单机验证接收侧代码。 */
static NTSTATUS
IPv8IoctlInject(
    _Inout_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
    )
{
    PUCHAR sysBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    PIPV8_FRAME_HDR hdr;
    ULONG frameLen;

    if (inLen < IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    hdr = (PIPV8_FRAME_HDR)sysBuf;
    if (hdr->Magic != IPV8_IOCTL_MAGIC)
    {
        return STATUS_INVALID_PARAMETER;
    }
    frameLen = hdr->FrameLen;
    if (frameLen < IPV8_ETH_HEADER_LEN || frameLen > IPV8_FRAME_MAX)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (inLen < IPV8_FRAME_HDR_LEN + frameLen)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return IPv8InjectRx(
        hdr->IfIndex,
        sysBuf + IPV8_FRAME_HDR_LEN,
        frameLen);
}

/* ==================================================================
 *  IOCTL 总入口
 * ================================================================== */

NTSTATUS
IPv8DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status;
    ULONG ioctl;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctl)
    {
    case IOCTL_IPV8_GET_VERSION:
        status = IPv8IoctlVersion(Irp, irpSp);
        break;
    case IOCTL_IPV8_GET_STATS:
        status = IPv8IoctlStats(Irp, irpSp);
        break;
    case IOCTL_IPV8_GET_BINDINGS:
        status = IPv8IoctlBindings(Irp, irpSp);
        break;
    case IOCTL_IPV8_RECV_FRAME:
        status = IPv8IoctlRecv(Irp, irpSp);
        break;
    case IOCTL_IPV8_SEND_FRAME:
        status = IPv8IoctlSend(Irp, irpSp);
        break;
    case IOCTL_IPV8_INJECT_FRAME:
        status = IPv8IoctlInject(Irp, irpSp);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    /* STATUS_PENDING 时 IRP 已标记，禁止此处完成 */
    if (status == STATUS_PENDING)
    {
        return STATUS_PENDING;
    }

    if (!NT_SUCCESS(status))
    {
        Irp->IoStatus.Information = 0;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
