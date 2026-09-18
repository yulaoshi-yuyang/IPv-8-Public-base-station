/*++

Copyright (c) IPv8+ Project. All rights reserved.

Module Name:

    driver.c

Abstract:

    IPv8 NDIS 6.30 Protocol Driver。
    Phase 5A：控制设备 \Device\IPv8Proto（IOCTL 见 driver.h）。
    Phase 5B：0xFB14 二层裸帧收发。
              - FrameTypeArray 只向 NDIS 登记 0xFB14（非 FB14 帧零指示）；
              - 128 RX / 32 TX 有界非分页帧节点 + 1 NB 的 NBL 池；
              - 收包：优先直接交付 pending READ IRP（CSQ 保证取消安全），
                否则入帧队列（满则丢弃计数）；
              - 发送：IRP pending 至 SendComplete，源 MAC 强制覆写为本网卡地址；
              - Open 成功后异步 OID_802_3_CURRENT_ADDRESS 取真实 MAC。

--*/

#include "driver.h"

IPV8_GLOBAL_DATA g_Ipv8Global = { 0 };

LIST_ENTRY              g_OpenList;
NDIS_SPIN_LOCK          g_OpenListLock;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, IPv8Unload)
#endif

/* 仅登记 0xFB14：减少 NDIS 投递帧数，避免干扰 TCP/IP。
   驱动内部仍硬校验 EtherType。 */
static NET_FRAME_TYPE   g_FrameTypes[1] = { (USHORT)IPV8_ETH_TYPE };

/* ==================================================================
 *  Phase 5B：帧基础设施（节点池 + NBL 池）
 * ================================================================== */

NTSTATUS
IPv8FrameInfrastructureCreate(
    VOID
    )
{
    NET_BUFFER_LIST_POOL_PARAMETERS poolParams;
    ULONG i;

    NdisAllocateSpinLock(&g_Ipv8Global.FrameLock);
    InitializeListHead(&g_Ipv8Global.FrameQueue);
    InitializeListHead(&g_Ipv8Global.FreeRxNodes);
    InitializeListHead(&g_Ipv8Global.FreeTxNodes);
    InitializeListHead(&g_Ipv8Global.PendingReads);
    g_Ipv8Global.NextIfIndex = 0;

    g_Ipv8Global.RxBlock = (PIPV8_FRAME_NODE)NdisAllocateMemoryWithTagPriority(
        NULL,
        (ULONG)(IPV8_RX_QUEUE_NODES * sizeof(IPV8_FRAME_NODE)),
        IPv8_POOL_TAG, NormalPoolPriority);
    if (g_Ipv8Global.RxBlock == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NdisZeroMemory(g_Ipv8Global.RxBlock,
        IPV8_RX_QUEUE_NODES * sizeof(IPV8_FRAME_NODE));

    g_Ipv8Global.TxBlock = (PIPV8_FRAME_NODE)NdisAllocateMemoryWithTagPriority(
        NULL,
        (ULONG)(IPV8_TX_INFLIGHT_NODES * sizeof(IPV8_FRAME_NODE)),
        IPv8_POOL_TAG, NormalPoolPriority);
    if (g_Ipv8Global.TxBlock == NULL)
    {
        NdisFreeMemory(g_Ipv8Global.RxBlock, 0, 0);
        g_Ipv8Global.RxBlock = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NdisZeroMemory(g_Ipv8Global.TxBlock,
        IPV8_TX_INFLIGHT_NODES * sizeof(IPV8_FRAME_NODE));

    for (i = 0; i < IPV8_RX_QUEUE_NODES; i++)
    {
        InsertTailList(&g_Ipv8Global.FreeRxNodes,
            &g_Ipv8Global.RxBlock[i].Link);
    }
    for (i = 0; i < IPV8_TX_INFLIGHT_NODES; i++)
    {
        InsertTailList(&g_Ipv8Global.FreeTxNodes,
            &g_Ipv8Global.TxBlock[i].Link);
    }

    NdisZeroMemory(&poolParams, sizeof(poolParams));
    poolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    poolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.Header.Size =
        NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    /* 必须为 TRUE：发送路径使用合体分配 NdisAllocateNetBufferAndNetBufferList，
       NDIS 契约要求该池标志置位，否则该函数恒返回 NULL（曾实测 os error 1450）。
       DataSize=0 表示不预分配数据缓冲，载荷由发送路径挂载自建 MDL 提供。 */
    poolParams.fAllocateNetBuffer = TRUE;
    poolParams.ContextSize = 0;
    poolParams.PoolTag = IPv8_POOL_TAG;
    poolParams.DataSize = 0;

    /* 注册句柄已就绪：NBL 池挂到协议句柄，随注销自动废弃 */
    g_Ipv8Global.NblPool = NdisAllocateNetBufferListPool(
        g_Ipv8Global.NdisProtocolHandle, &poolParams);
    if (g_Ipv8Global.NblPool == NULL)
    {
        NdisFreeMemory(g_Ipv8Global.TxBlock, 0, 0);
        NdisFreeMemory(g_Ipv8Global.RxBlock, 0, 0);
        g_Ipv8Global.TxBlock = NULL;
        g_Ipv8Global.RxBlock = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

VOID
IPv8FrameInfrastructureDestroy(
    VOID
    )
{
    /* 调用前置条件：NdisDeregisterProtocolDriver 已返回——
       所有在途 SEND 已完成、TX 节点均已归还，帧队列残留帧随整块释放。 */
    if (g_Ipv8Global.NblPool != NULL)
    {
        NdisFreeNetBufferListPool(g_Ipv8Global.NblPool);
        g_Ipv8Global.NblPool = NULL;
    }
    if (g_Ipv8Global.RxBlock != NULL)
    {
        NdisFreeMemory(g_Ipv8Global.RxBlock, 0, 0);
        g_Ipv8Global.RxBlock = NULL;
    }
    if (g_Ipv8Global.TxBlock != NULL)
    {
        NdisFreeMemory(g_Ipv8Global.TxBlock, 0, 0);
        g_Ipv8Global.TxBlock = NULL;
    }
}

VOID
IPv8CancelAllPendingReads(
    VOID
    )
{
    PIRP irp;

    /* CSQ 保证取出即归本线程所有，取消竞态由框架消除 */
    while ((irp = IoCsqRemoveNextIrp(&g_Ipv8Global.Csq, NULL)) != NULL)
    {
        irp->IoStatus.Status = STATUS_DEVICE_REMOVED;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
}

/* 调用方必须持有 FrameLock */
PIPV8_FRAME_NODE
IPv8FrameDequeueLocked(
    _In_ ULONG IfIndex
    )
{
    PLIST_ENTRY entry;

    for (entry = g_Ipv8Global.FrameQueue.Flink;
         entry != &g_Ipv8Global.FrameQueue;
         entry = entry->Flink)
    {
        PIPV8_FRAME_NODE node =
            CONTAINING_RECORD(entry, IPV8_FRAME_NODE, Link);

        if (IfIndex == IPV8_IFINDEX_ANY || node->IfIndex == IfIndex)
        {
            RemoveEntryList(entry);
            return node;
        }
    }
    return NULL;
}

PIPV8_OPEN_CONTEXT
IPv8LookupBindingLocked(
    _In_ ULONG IfIndex
    )
{
    PLIST_ENTRY entry;

    for (entry = g_OpenList.Flink;
         entry != &g_OpenList;
         entry = entry->Flink)
    {
        PIPV8_OPEN_CONTEXT ctx =
            CONTAINING_RECORD(entry, IPV8_OPEN_CONTEXT, Link);
        if (ctx->Bound && ctx->IfIndex == IfIndex)
        {
            return ctx;
        }
    }
    return NULL;
}

/* ==================================================================
 *  MAC 地址异步查询
 * ================================================================== */

static VOID
IPv8QueryMacComplete(
    _In_ PIPV8_OPEN_CONTEXT Ctx,
    _In_ PNDIS_OID_REQUEST OidRequest,
    _In_ NDIS_STATUS Status
    )
{
    PIPV8_OID_WRAPPER wrapper =
        CONTAINING_RECORD(OidRequest, IPV8_OID_WRAPPER, Req);
    BOOLEAN macOk = FALSE;

    if (Status == NDIS_STATUS_SUCCESS &&
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten >= IPV8_MAC_LEN)
    {
        macOk = TRUE;
    }

    /* 与绑定快照共用 g_OpenListLock：保证快照读 6 字节 MAC 不撕裂。
       ctx 生命周期由 NDIS 保证（OID 完成先于 close-complete）。 */
    if (macOk)
    {
        NdisAcquireSpinLock(&g_OpenListLock);
        NdisMoveMemory(Ctx->CurrentMac, wrapper->MacBuf, IPV8_MAC_LEN);
        Ctx->MacValid = TRUE;
        NdisReleaseSpinLock(&g_OpenListLock);
    }
    /* 失败/取消：保持 MacValid=FALSE，发送时不覆写源 MAC */

    NdisFreeMemory(wrapper, 0, 0);
}

static VOID
IPv8QueryCurrentMac(
    _In_ PIPV8_OPEN_CONTEXT Ctx
    )
{
    PIPV8_OID_WRAPPER wrapper;
    NDIS_STATUS status;

    wrapper = (PIPV8_OID_WRAPPER)NdisAllocateMemoryWithTagPriority(
        NULL, sizeof(*wrapper), IPv8_POOL_TAG, NormalPoolPriority);
    if (wrapper == NULL)
    {
        return;
    }
    NdisZeroMemory(wrapper, sizeof(*wrapper));
    wrapper->Open = Ctx;

    wrapper->Req.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    wrapper->Req.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    wrapper->Req.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
    wrapper->Req.RequestType = NdisRequestQueryInformation;
    wrapper->Req.DATA.QUERY_INFORMATION.Oid = OID_802_3_CURRENT_ADDRESS;
    wrapper->Req.DATA.QUERY_INFORMATION.InformationBuffer = wrapper->MacBuf;
    wrapper->Req.DATA.QUERY_INFORMATION.InformationBufferLength =
        sizeof(wrapper->MacBuf);

    status = NdisOidRequest(Ctx->NdisBindingHandle, &wrapper->Req);
    if (status != NDIS_STATUS_PENDING)
    {
        IPv8QueryMacComplete(Ctx, &wrapper->Req, status);
    }
}

/* 设置 packet filter：不设的话 miniport 不会向本协议指示任何帧。
   仅需 DIRECTED+BROADCAST+MULTICAST，不需 PROMISCUOUS。 */
static VOID
IPv8SetPacketFilter(
    _In_ PIPV8_OPEN_CONTEXT Ctx
    )
{
    PIPV8_OID_WRAPPER wrapper;
    NDIS_STATUS status;

    wrapper = (PIPV8_OID_WRAPPER)NdisAllocateMemoryWithTagPriority(
        NULL, sizeof(*wrapper), IPv8_POOL_TAG, NormalPoolPriority);
    if (wrapper == NULL)
    {
        return;
    }
    NdisZeroMemory(wrapper, sizeof(*wrapper));
    wrapper->Open = Ctx;

    wrapper->PacketFilter = NDIS_PACKET_TYPE_DIRECTED |
                            NDIS_PACKET_TYPE_BROADCAST |
                            NDIS_PACKET_TYPE_MULTICAST;

    wrapper->Req.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    wrapper->Req.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    wrapper->Req.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
    wrapper->Req.RequestType = NdisRequestSetInformation;
    wrapper->Req.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
    wrapper->Req.DATA.SET_INFORMATION.InformationBuffer = &wrapper->PacketFilter;
    wrapper->Req.DATA.SET_INFORMATION.InformationBufferLength = sizeof(ULONG);

    status = NdisOidRequest(Ctx->NdisBindingHandle, &wrapper->Req);
    if (status != NDIS_STATUS_PENDING)
    {
        /* 同步完成：直接释放 wrapper */
        NdisFreeMemory(wrapper, 0, 0);
    }
}

/* ==================================================================
 *  Driver Entry / Unload
 * ================================================================== */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NDIS_STATUS status;
    NDIS_PROTOCOL_DRIVER_CHARACTERISTICS protoChars;
    NDIS_STRING protoName;
    NTSTATUS ctlStatus;
    NTSTATUS frameStatus;

    UNREFERENCED_PARAMETER(RegistryPath);

    NdisZeroMemory(&g_Ipv8Global, sizeof(g_Ipv8Global));
    NdisInitializeListHead(&g_OpenList);
    NdisAllocateSpinLock(&g_OpenListLock);

    NdisZeroMemory(&protoChars, sizeof(protoChars));
    protoChars.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
    /* NDIS 6.30 协议：对齐 ndisprot630 样例使用 REVISION_2（多出的 DirectOid 回调保持 NULL） */
    protoChars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    protoChars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    protoChars.MajorNdisVersion = 6;
    protoChars.MinorNdisVersion = 30;

    RtlInitUnicodeString(&protoName, IPv8_PROTOCOL_NAME);
    protoChars.Name = protoName;

    protoChars.BindAdapterHandlerEx              = IPv8BindAdapterEx;
    protoChars.UnbindAdapterHandlerEx            = IPv8UnbindAdapterEx;
    protoChars.OpenAdapterCompleteHandlerEx      = IPv8OpenAdapterCompleteEx;
    protoChars.CloseAdapterCompleteHandlerEx     = IPv8CloseAdapterCompleteEx;
    protoChars.SendNetBufferListsCompleteHandler = IPv8SendNetBufferListsComplete;
    protoChars.ReceiveNetBufferListsHandler      = IPv8ReceiveNetBufferLists;
    protoChars.StatusHandlerEx                   = IPv8StatusEx;
    protoChars.NetPnPEventHandler                = IPv8NetPnPEvent;
    /* OidRequestCompleteHandler 属于 NDIS 协议注册强制非空的核心回调；
       5B 起用于 OID_802_3_CURRENT_ADDRESS 异步完成。 */
    protoChars.OidRequestCompleteHandler         = IPv8OidRequestComplete;

    /* 协议驱动第一个参数（NdisDriverHandle）必须为 NULL；
       仅"同时是迷你端口"的合并驱动才传迷你端口句柄。 */
    status = NdisRegisterProtocolDriver(
        NULL,
        &protoChars,
        &g_Ipv8Global.NdisProtocolHandle
        );
    if (status != NDIS_STATUS_SUCCESS)
    {
        return status;
    }

    frameStatus = IPv8FrameInfrastructureCreate();
    if (!NT_SUCCESS(frameStatus))
    {
        NdisDeregisterProtocolDriver(g_Ipv8Global.NdisProtocolHandle);
        g_Ipv8Global.NdisProtocolHandle = NULL;
        return frameStatus;
    }

    /* 控制设备失败不阻断协议注册：IOCTL 缺席仅影响可见性功能 */
    ctlStatus = IPv8AttachControlDevice(DriverObject);
    if (!NT_SUCCESS(ctlStatus))
    {
        g_Ipv8Global.ControlDevice = NULL;
    }

    DriverObject->DriverUnload = IPv8Unload;
    return STATUS_SUCCESS;
}

VOID
IPv8Unload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DriverObject);

    InterlockedExchange(&g_Ipv8Global.Unloading, 1);

    /* 1) 唤醒并取消全部等待读（STATUS_DEVICE_REMOVED），此后无用户态帧请求在途 */
    IPv8CancelAllPendingReads();

    /* 2) 摘除控制设备：拒绝新 CreateFile/DeviceIoControl */
    IPv8DetachControlDevice();

    /* 3) 注销协议：同步 unbind 全部适配器。NDIS 保证每个绑定在途 SEND
          全部 SendComplete 后才执行 close-complete，因此返回时无 NBL 引用
          帧节点/OPEN_CONTEXT，随后释放池内存安全。 */
    if (g_Ipv8Global.NdisProtocolHandle != NULL)
    {
        NdisDeregisterProtocolDriver(g_Ipv8Global.NdisProtocolHandle);
        g_Ipv8Global.NdisProtocolHandle = NULL;
    }

    /* 4) 释放帧节点块与 NBL 池 */
    IPv8FrameInfrastructureDestroy();
}

/* ==================================================================
 *  Bind / Unbind
 * ================================================================== */

static VOID
IPv8FinishOpen(
    _In_ PIPV8_OPEN_CONTEXT Ctx,
    _In_ NDIS_HANDLE BindContext
    )
{
    Ctx->Bound = TRUE;

    NdisAcquireSpinLock(&g_OpenListLock);
    InsertTailList(&g_OpenList, &Ctx->Link);
    NdisReleaseSpinLock(&g_OpenListLock);
    InterlockedIncrement(&g_Ipv8Global.OpenCount);

    /* 异步取真实 MAC（PENDING/SUCCESS 两分支均在 IPv8QueryMacComplete 收尾） */
    IPv8QueryCurrentMac(Ctx);

    /* 设置 packet filter，否则 miniport 不向本协议指示帧 */
    IPv8SetPacketFilter(Ctx);

    NdisCompleteBindAdapterEx(BindContext, NDIS_STATUS_SUCCESS);
}

NDIS_STATUS
IPv8BindAdapterEx(
    _In_ NDIS_HANDLE           ProtocolDriverContext,
    _In_ NDIS_HANDLE           BindContext,
    _In_ PNDIS_BIND_PARAMETERS BindParameters
    )
{
    NDIS_STATUS status;
    PIPV8_OPEN_CONTEXT ctx;
    NDIS_MEDIUM mediumArray[] = { NdisMedium802_3 };
    UINT selectedMediumIndex = 0;
    NDIS_OPEN_PARAMETERS openParams;

    UNREFERENCED_PARAMETER(ProtocolDriverContext);

    if (InterlockedCompareExchange(&g_Ipv8Global.Unloading, 1, 1) == 1)
    {
        NdisCompleteBindAdapterEx(BindContext, NDIS_STATUS_FAILURE);
        return NDIS_STATUS_FAILURE;
    }

    ctx = (PIPV8_OPEN_CONTEXT)NdisAllocateMemoryWithTagPriority(
        NULL, sizeof(*ctx), IPv8_POOL_TAG, NormalPoolPriority);
    if (ctx == NULL)
    {
        NdisCompleteBindAdapterEx(BindContext, NDIS_STATUS_RESOURCES);
        return NDIS_STATUS_RESOURCES;
    }
    NdisZeroMemory(ctx, sizeof(*ctx));

    ctx->AdapterNameBuf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
        NULL, BindParameters->AdapterName->Length + sizeof(WCHAR),
        IPv8_POOL_TAG, NormalPoolPriority);
    if (ctx->AdapterNameBuf == NULL)
    {
        NdisFreeMemory(ctx, 0, 0);
        NdisCompleteBindAdapterEx(BindContext, NDIS_STATUS_RESOURCES);
        return NDIS_STATUS_RESOURCES;
    }
    NdisMoveMemory(ctx->AdapterNameBuf,
        BindParameters->AdapterName->Buffer,
        BindParameters->AdapterName->Length);
    *(PWCHAR)(ctx->AdapterNameBuf + BindParameters->AdapterName->Length) = L'\0';
    ctx->AdapterName.Buffer = (PWCHAR)ctx->AdapterNameBuf;
    ctx->AdapterName.Length = BindParameters->AdapterName->Length;
    ctx->AdapterName.MaximumLength =
        BindParameters->AdapterName->Length + sizeof(WCHAR);

    /* 稳定编号：从 1 起单调分配，跨 bind/unbind 不回收（用户态可长期引用） */
    ctx->IfIndex =
        (ULONG)InterlockedIncrement(&g_Ipv8Global.NextIfIndex);

    NdisZeroMemory(&openParams, sizeof(openParams));
    openParams.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
    openParams.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVISION_1;
    openParams.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
    openParams.AdapterName = &ctx->AdapterName;
    openParams.MediumArray = mediumArray;
    openParams.MediumArraySize = 1;
    openParams.SelectedMediumIndex = &selectedMediumIndex;
    openParams.FrameTypeArray = g_FrameTypes;
    openParams.FrameTypeArraySize = RTL_NUMBER_OF(g_FrameTypes);

    status = NdisOpenAdapterEx(
        g_Ipv8Global.NdisProtocolHandle,
        ctx,
        &openParams,
        BindContext,
        &ctx->NdisBindingHandle
        );

    if (status == NDIS_STATUS_PENDING)
    {
        /* BindContext 必须留到 OpenAdapterCompleteEx 再完成，禁止此处 complete */
        ctx->BindContext = BindContext;
        return NDIS_STATUS_PENDING;
    }

    if (status != NDIS_STATUS_SUCCESS)
    {
        NdisFreeMemory(ctx->AdapterNameBuf, 0, 0);
        NdisFreeMemory(ctx, 0, 0);
        NdisCompleteBindAdapterEx(BindContext, status);
        return status;
    }

    IPv8FinishOpen(ctx, BindContext);
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
IPv8UnbindAdapterEx(
    _In_ NDIS_HANDLE UnbindContext,
    _In_ NDIS_HANDLE ProtocolBindingContext
    )
{
    PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)ProtocolBindingContext;
    NDIS_STATUS status;

    /* 先摘表并置 Bound=FALSE：新的 SEND/快照查找立即不可见。
       NdisCloseAdapterEx 会等待在途 SEND 全部 SendComplete，
       因此 close-complete 前 ctx 必须保持有效。 */
    ctx->Bound = FALSE;

    InterlockedDecrement(&g_Ipv8Global.OpenCount);
    NdisAcquireSpinLock(&g_OpenListLock);
    RemoveEntryList(&ctx->Link);
    NdisReleaseSpinLock(&g_OpenListLock);

    status = NdisCloseAdapterEx(ctx->NdisBindingHandle);
    if (status != NDIS_STATUS_PENDING)
    {
        if (ctx->AdapterNameBuf != NULL)
        {
            NdisFreeMemory(ctx->AdapterNameBuf, 0, 0);
        }
        NdisFreeMemory(ctx, 0, 0);
    }

    NdisCompleteUnbindAdapterEx(UnbindContext);
    return NDIS_STATUS_SUCCESS;
}

/* ==================================================================
 *  Open/Close Complete
 * ================================================================== */

VOID
IPv8OpenAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ NDIS_STATUS Status
    )
{
    PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)ProtocolBindingContext;

    if (Status != NDIS_STATUS_SUCCESS)
    {
        if (ctx->AdapterNameBuf != NULL)
        {
            NdisFreeMemory(ctx->AdapterNameBuf, 0, 0);
        }
        NdisFreeMemory(ctx, 0, 0);
        NdisCompleteBindAdapterEx(ctx->BindContext, Status);
        return;
    }

    IPv8FinishOpen(ctx, ctx->BindContext);
}

VOID
IPv8CloseAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext
    )
{
    PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)ProtocolBindingContext;

    if (ctx != NULL)
    {
        if (ctx->AdapterNameBuf != NULL)
        {
            NdisFreeMemory(ctx->AdapterNameBuf, 0, 0);
        }
        NdisFreeMemory(ctx, 0, 0);
    }
}

/* ==================================================================
 *  Receive：0xFB14 指示帧分流（IRP 直交优先，否则入有界队列）
 * ================================================================== */

_IRQL_requires_(DISPATCH_LEVEL)
static VOID
IPv8IndicateOneFrame(
    _In_ PIPV8_OPEN_CONTEXT Ctx,
    _In_ PNET_BUFFER NetBuffer,
    _In_ ULONG FrameLen
    )
{
    PIRP waitIrp;
    IPV8_CSQ_MATCH match;
    PIPV8_FRAME_NODE node = NULL;

    if (FrameLen < IPV8_ETH_HEADER_LEN || FrameLen > IPV8_FRAME_MAX)
    {
        InterlockedAdd64(&Ctx->RxDropped, 1);
        return;
    }

    /* 双重校验 EtherType：FrameTypeArray 在 netvsc 上可能不过滤，
       此处硬校验只放行 0xFB14，防止 IP/ARP 等帧混入队列。
       用栈缓冲区兜底：NdisGetDataBuffer 在非连续 MDL 时拷贝到 StorageBuffer。 */
    {
        UCHAR hdrBuf[IPV8_ETH_HEADER_LEN];
        PUCHAR hdr = NdisGetDataBuffer(NetBuffer, IPV8_ETH_HEADER_LEN, hdrBuf, 1, 0);
        if (hdr == NULL || hdr[12] != 0xFB || hdr[13] != 0x14)
        {
            InterlockedAdd64(&Ctx->RxDropped, 1);
            return;
        }
    }

    InterlockedAdd64(&Ctx->PacketsReceived, 1);

    /* 路径 1：直接交给匹配的 pending READ（CSQ 负责取消同步） */
    match.Kind = IPv8CsqMatchByIfIndex;
    match.IfIndex = Ctx->IfIndex;
    match.FileObject = NULL;
    waitIrp = IoCsqRemoveNextIrp(&g_Ipv8Global.Csq, &match);
    if (waitIrp != NULL)
    {
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(waitIrp);
        ULONG outCap =
            stack->Parameters.DeviceIoControl.OutputBufferLength;
        PUCHAR sysBuf =
            (PUCHAR)waitIrp->AssociatedIrp.SystemBuffer;
        PVOID copied;

        if (outCap < IPV8_FRAME_HDR_LEN + FrameLen)
        {
            InterlockedAdd64(&Ctx->RxDropped, 1);
            waitIrp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            waitIrp->IoStatus.Information = 0;
            IoCompleteRequest(waitIrp, IO_NO_INCREMENT);
            return;
        }

        /* NdisGetDataBuffer 直接连续化到用户 SystemBuffer（非分页），零中间拷贝 */
        copied = NdisGetDataBuffer(
            NetBuffer, FrameLen, sysBuf + IPV8_FRAME_HDR_LEN, 1, 0);
        if (copied == NULL)
        {
            InterlockedAdd64(&Ctx->RxDropped, 1);
            waitIrp->IoStatus.Status = STATUS_DATA_ERROR;
            waitIrp->IoStatus.Information = 0;
            IoCompleteRequest(waitIrp, IO_NO_INCREMENT);
            return;
        }
        if (copied != sysBuf + IPV8_FRAME_HDR_LEN)
        {
            NdisMoveMemory(sysBuf + IPV8_FRAME_HDR_LEN, copied, FrameLen);
        }

        {
            PIPV8_FRAME_HDR hdr = (PIPV8_FRAME_HDR)sysBuf;
            hdr->Magic = IPV8_IOCTL_MAGIC;
            hdr->IfIndex = Ctx->IfIndex;
            hdr->FrameLen = FrameLen;
            hdr->Reserved = 0;
        }

        waitIrp->IoStatus.Status = STATUS_SUCCESS;
        waitIrp->IoStatus.Information =
            (ULONG_PTR)(IPV8_FRAME_HDR_LEN + FrameLen);
        IoCompleteRequest(waitIrp, IO_NO_INCREMENT);
        return;
    }

    /* 路径 2：摘空闲节点（锁内只做链表操作，拷贝放锁外） */
    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
    if (!IsListEmpty(&g_Ipv8Global.FreeRxNodes))
    {
        node = CONTAINING_RECORD(
            RemoveHeadList(&g_Ipv8Global.FreeRxNodes),
            IPV8_FRAME_NODE, Link);
    }
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);

    if (node == NULL)
    {
        /* 无等待者且队列满：背压丢弃 */
        InterlockedAdd64(&Ctx->RxDropped, 1);
        return;
    }

    {
        PVOID copied = NdisGetDataBuffer(
            NetBuffer, FrameLen, node->Frame, 1, 0);
        if (copied == NULL)
        {
            InterlockedAdd64(&Ctx->RxDropped, 1);
        }
        else
        {
            if (copied != node->Frame)
            {
                NdisMoveMemory(node->Frame, copied, FrameLen);
            }
            node->IfIndex = Ctx->IfIndex;
            node->FrameLen = FrameLen;

            NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
            InsertTailList(&g_Ipv8Global.FrameQueue, &node->Link);
            NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);
            return;
        }
    }

    /* 拷贝失败：归还节点 */
    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
    InsertTailList(&g_Ipv8Global.FreeRxNodes, &node->Link);
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);
}

/* 调试注入：把用户态提供的帧直接送入接收路径，逻辑与 IPv8IndicateOneFrame
   一致（pending READ 直交 / FrameQueue 入队），仅数据源从 NET_BUFFER 换成
   线性缓冲。用于单机无对端时验证接收侧代码。 */
NTSTATUS
IPv8InjectRx(
    _In_ ULONG IfIndex,
    _In_reads_bytes_(FrameLen) const UCHAR* Frame,
    _In_ ULONG FrameLen
    )
{
    PIPV8_OPEN_CONTEXT ctx;
    PIRP waitIrp;
    IPV8_CSQ_MATCH match;
    PIPV8_FRAME_NODE node = NULL;

    if (FrameLen < IPV8_ETH_HEADER_LEN || FrameLen > IPV8_FRAME_MAX)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ctx = IPv8LookupBindingLocked(IfIndex);
    if (ctx == NULL)
    {
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    InterlockedAdd64(&ctx->PacketsReceived, 1);

    /* 路径 1：直交匹配的 pending READ */
    match.Kind = IPv8CsqMatchByIfIndex;
    match.IfIndex = IfIndex;
    match.FileObject = NULL;
    waitIrp = IoCsqRemoveNextIrp(&g_Ipv8Global.Csq, &match);
    if (waitIrp != NULL)
    {
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(waitIrp);
        ULONG outCap = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PUCHAR sysBuf = (PUCHAR)waitIrp->AssociatedIrp.SystemBuffer;

        if (outCap < IPV8_FRAME_HDR_LEN + FrameLen)
        {
            InterlockedAdd64(&ctx->RxDropped, 1);
            waitIrp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            waitIrp->IoStatus.Information = 0;
            IoCompleteRequest(waitIrp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }

        NdisMoveMemory(sysBuf + IPV8_FRAME_HDR_LEN, Frame, FrameLen);
        {
            PIPV8_FRAME_HDR hdr = (PIPV8_FRAME_HDR)sysBuf;
            hdr->Magic = IPV8_IOCTL_MAGIC;
            hdr->IfIndex = IfIndex;
            hdr->FrameLen = FrameLen;
            hdr->Reserved = 0;
        }
        waitIrp->IoStatus.Status = STATUS_SUCCESS;
        waitIrp->IoStatus.Information =
            (ULONG_PTR)(IPV8_FRAME_HDR_LEN + FrameLen);
        IoCompleteRequest(waitIrp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    /* 路径 2：入 FrameQueue 等待后续 READ */
    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
    if (!IsListEmpty(&g_Ipv8Global.FreeRxNodes))
    {
        node = CONTAINING_RECORD(
            RemoveHeadList(&g_Ipv8Global.FreeRxNodes),
            IPV8_FRAME_NODE, Link);
    }
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);

    if (node == NULL)
    {
        InterlockedAdd64(&ctx->RxDropped, 1);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NdisMoveMemory(node->Frame, Frame, FrameLen);
    node->IfIndex = IfIndex;
    node->FrameLen = FrameLen;

    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
    InsertTailList(&g_Ipv8Global.FrameQueue, &node->Link);
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);
    return STATUS_SUCCESS;
}

VOID
IPv8ReceiveNetBufferLists(
    _In_ NDIS_HANDLE      ProtocolBindingContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG            NumberOfNetBufferLists,
    _In_ ULONG            ReceiveFlags
    )
{
    PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)ProtocolBindingContext;
    PNET_BUFFER_LIST nbl;

    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

    InterlockedAdd64(&ctx->ReceiveIndications, 1);

    /* NDIS 契约：ProtocolBindingContext 即 NdisOpenAdapterEx 传入的 OPEN_CONTEXT，
       存活期覆盖所有 receive 指示，必非空；NBL 链必须无条件归还。 */

    /* FrameTypeArray 已把非 0xFB14 流量挡在 NDIS 层；此处每个 NB 独立分流，
       整条 NBL 链最后一次性归还。 */
    for (nbl = NetBufferLists; nbl != NULL;
         nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
    {
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

        while (nb != NULL)
        {
            ULONG frameLen = (ULONG)NET_BUFFER_DATA_LENGTH(nb);
            IPv8IndicateOneFrame(ctx, nb, frameLen);
            nb = NET_BUFFER_NEXT_NB(nb);
        }
    }

    NdisReturnNetBufferLists(
        ctx->NdisBindingHandle,
        NetBufferLists,
        ReceiveFlags
        );
}

/* ==================================================================
 *  Send
 * ================================================================== */

NTSTATUS
IPv8SubmitSend(
    _Inout_ PIRP Irp,
    _In_ ULONG IfIndex,
    _In_reads_bytes_(FrameLen) const UCHAR* Frame,
    _In_ ULONG FrameLen
    )
{
    PIPV8_OPEN_CONTEXT ctx;
    PIPV8_FRAME_NODE node = NULL;
    PMDL mdl = NULL;
    PNET_BUFFER_LIST nbl = NULL;
    ULONG sendLen;

    if (FrameLen < IPV8_ETH_HEADER_LEN || FrameLen > IPV8_FRAME_MAX)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* 偏移 12..13 为大端 EtherType，必须是 0xFB 0x14：防止本通道被用来
       发送任意以太网帧（ARP/IP 等） */
    if (Frame[12] != 0xFB || Frame[13] != 0x14)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* 固定锁序：OpenListLock -> FrameLock（全局唯一锁序，无反向路径）。
       持 OpenListLock 覆盖到 NdisSendNetBufferLists 返回：unbind 在同一把
       锁摘表，NdisCloseAdapterEx 只会在我们释放后发生，ctx 必然有效。 */
    NdisAcquireSpinLock(&g_OpenListLock);

    ctx = IPv8LookupBindingLocked(IfIndex);
    if (ctx == NULL)
    {
        NdisReleaseSpinLock(&g_OpenListLock);
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
    if (IsListEmpty(&g_Ipv8Global.FreeTxNodes))
    {
        NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);
        NdisReleaseSpinLock(&g_OpenListLock);
        InterlockedAdd64(&ctx->TxDropped, 1);
        return STATUS_DEVICE_BUSY;
    }
    node = CONTAINING_RECORD(
        RemoveHeadList(&g_Ipv8Global.FreeTxNodes),
        IPV8_FRAME_NODE, Link);
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);

    NdisMoveMemory(node->Frame, Frame, FrameLen);
    node->FrameLen = FrameLen;
    node->IfIndex = IfIndex;

    /* 不足以太网最小载荷 60 字节时补零（FCS 由网卡硬件追加） */
    sendLen = (FrameLen < IPV8_FRAME_MIN) ? IPV8_FRAME_MIN : FrameLen;
    if (sendLen > FrameLen)
    {
        NdisZeroMemory(node->Frame + FrameLen, sendLen - FrameLen);
    }

    /* 强制源 MAC = 绑定网卡真实地址：防止用户态伪造主机身份 */
    if (ctx->MacValid)
    {
        NdisMoveMemory(node->Frame + 6, ctx->CurrentMac, IPV8_MAC_LEN);
    }

    mdl = IoAllocateMdl(node->Frame, sendLen, FALSE, FALSE, NULL);
    if (mdl == NULL)
    {
        goto FailBusyResource;
    }
    MmBuildMdlForNonPagedPool(mdl);

    nbl = NdisAllocateNetBufferAndNetBufferList(
        g_Ipv8Global.NblPool, 0, 0, mdl, 0, sendLen);
    if (nbl == NULL)
    {
        IoFreeMdl(mdl);
        goto FailBusyResource;
    }

    /* NBL 上下文（SendComplete 回收/回 IRP 全靠它）：
       [0]=IRP  [1]=帧节点  [2]=OPEN_CONTEXT  [3]=MDL */
    nbl->ProtocolReserved[0] = Irp;
    nbl->ProtocolReserved[1] = node;
    nbl->ProtocolReserved[2] = ctx;
    nbl->ProtocolReserved[3] = mdl;

    IoMarkIrpPending(Irp);

    NdisSendNetBufferLists(
        ctx->NdisBindingHandle,
        nbl,
        NDIS_DEFAULT_PORT_NUMBER,
        0
        );

    NdisReleaseSpinLock(&g_OpenListLock);
    return STATUS_PENDING;

FailBusyResource:
    NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
    InsertTailList(&g_Ipv8Global.FreeTxNodes, &node->Link);
    NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);
    NdisReleaseSpinLock(&g_OpenListLock);
    InterlockedAdd64(&ctx->TxDropped, 1);
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
IPv8SendNetBufferListsComplete(
    _In_ NDIS_HANDLE      ProtocolBindingContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG            SendCompleteFlags
    )
{
    PNET_BUFFER_LIST nbl;

    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(SendCompleteFlags);

    for (nbl = NetBufferLists; nbl != NULL;
         nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
    {
        /* 先取走全部上下文，释放 NBL/MDL 后不得再访问 nbl */
        PIRP irp = (PIRP)nbl->ProtocolReserved[0];
        PIPV8_FRAME_NODE node = (PIPV8_FRAME_NODE)nbl->ProtocolReserved[1];
        PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)nbl->ProtocolReserved[2];
        PMDL mdl = (PMDL)nbl->ProtocolReserved[3];
        NDIS_STATUS sendStatus = NET_BUFFER_LIST_STATUS(nbl);
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);

        NdisFreeNetBufferList(nbl);
        IoFreeMdl(mdl);

        NdisAcquireSpinLock(&g_Ipv8Global.FrameLock);
        InsertTailList(&g_Ipv8Global.FreeTxNodes, &node->Link);
        NdisReleaseSpinLock(&g_Ipv8Global.FrameLock);

        if (sendStatus == NDIS_STATUS_SUCCESS)
        {
            InterlockedAdd64(&ctx->TxPackets, 1);
        }
        else
        {
            InterlockedAdd64(&ctx->TxDropped, 1);
        }

        /* 不支持中途取消：IRP 一定在此回完 */
        if (irp != NULL)
        {
            irp->IoStatus.Status =
                (sendStatus == NDIS_STATUS_SUCCESS)
                    ? STATUS_SUCCESS
                    : STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
        }
    }
}

/* ==================================================================
 *  其它协议回调
 * ================================================================== */

VOID
IPv8StatusEx(
    _In_ NDIS_HANDLE             ProtocolBindingContext,
    _In_ PNDIS_STATUS_INDICATION StatusIndication
    )
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(StatusIndication);
}

VOID
IPv8OidRequestComplete(
    _In_ NDIS_HANDLE       ProtocolBindingContext,
    _In_ PNDIS_OID_REQUEST OidRequest,
    _In_ NDIS_STATUS       Status
    )
{
    PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)ProtocolBindingContext;
    PIPV8_OID_WRAPPER wrapper =
        CONTAINING_RECORD(OidRequest, IPV8_OID_WRAPPER, Req);

    if (OidRequest->RequestType == NdisRequestSetInformation &&
        OidRequest->DATA.SET_INFORMATION.Oid == OID_GEN_CURRENT_PACKET_FILTER)
    {
        /* packet filter set 完成：直接释放 */
        NdisFreeMemory(wrapper, 0, 0);
        return;
    }

    if (ctx != NULL)
    {
        IPv8QueryMacComplete(ctx, OidRequest, Status);
    }
}

NDIS_STATUS
IPv8NetPnPEvent(
    _In_ NDIS_HANDLE                  ProtocolBindingContext,
    _In_ PNET_PNP_EVENT_NOTIFICATION  NetPnPEvent
    )
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(NetPnPEvent);
    return NDIS_STATUS_SUCCESS;
}
