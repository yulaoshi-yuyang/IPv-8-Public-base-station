/*++

Copyright (c) IPv8+ Project. All rights reserved.

Module Name:

    driver.c

Abstract:

    IPv8 NDIS 6.x Protocol Driver.

--*/

#include "driver.h"

IPV8_GLOBAL_DATA g_Ipv8Global = { 0 };

static LIST_ENTRY       g_OpenList;
static NDIS_SPIN_LOCK   g_OpenListLock;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, IPv8Unload)
#endif

/* ---- Driver Entry ---- */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NDIS_STATUS status;
    NDIS_PROTOCOL_DRIVER_CHARACTERISTICS protoChars;
    NDIS_STRING protoName;

    UNREFERENCED_PARAMETER(RegistryPath);

    NdisZeroMemory(&g_Ipv8Global, sizeof(g_Ipv8Global));
    NdisInitializeListHead(&g_OpenList);
    NdisAllocateSpinLock(&g_OpenListLock);

    NdisZeroMemory(&protoChars, sizeof(protoChars));
    protoChars.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
    protoChars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1;
    protoChars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1;
    protoChars.MajorNdisVersion = 6;
    protoChars.MinorNdisVersion = 30;

    RtlInitUnicodeString(&protoName, IPv8_PROTOCOL_NAME);
    protoChars.Name = protoName;

    protoChars.BindAdapterHandlerEx              = IPv8BindAdapterEx;
    protoChars.UnbindAdapterHandlerEx            = IPv8UnbindAdapterEx;
    protoChars.OpenAdapterCompleteHandlerEx      = IPv8OpenAdapterCompleteEx;
    protoChars.CloseAdapterCompleteHandlerEx     = IPv8CloseAdapterCompleteEx;
    protoChars.SendNetBufferListsCompleteHandler = IPv8SendNetBufferListsComplete;
    protoChars.ReceiveNetBufferListsHandler       = IPv8ReceiveNetBufferLists;
    protoChars.StatusHandlerEx                    = IPv8StatusEx;
    protoChars.NetPnPEventHandler                 = IPv8NetPnPEvent;

    status = NdisRegisterProtocolDriver(
        &g_Ipv8Global,
        &protoChars,
        &g_Ipv8Global.NdisProtocolHandle
        );

    if (status != NDIS_STATUS_SUCCESS)
        return status;

    DriverObject->DriverUnload = IPv8Unload;
    return STATUS_SUCCESS;
}

/* ---- Unload ---- */

VOID
IPv8Unload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    g_Ipv8Global.Unloading = TRUE;

    if (g_Ipv8Global.NdisProtocolHandle)
    {
        NdisDeregisterProtocolDriver(g_Ipv8Global.NdisProtocolHandle);
        g_Ipv8Global.NdisProtocolHandle = NULL;
    }
}

/* ---- Bind Adapter ---- */

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

    if (g_Ipv8Global.Unloading)
        return NDIS_STATUS_FAILURE;

    ctx = (PIPV8_OPEN_CONTEXT)NdisAllocateMemoryWithTagPriority(
        NULL, sizeof(*ctx), IPv8_POOL_TAG, NormalPoolPriority);
    if (!ctx)
    {
        NdisCompleteBindAdapterEx(BindContext, NDIS_STATUS_RESOURCES);
        return NDIS_STATUS_RESOURCES;
    }
    NdisZeroMemory(ctx, sizeof(*ctx));

    ctx->AdapterNameBuf = (PUCHAR)NdisAllocateMemoryWithTagPriority(
        NULL, BindParameters->AdapterName->Length + sizeof(WCHAR),
        IPv8_POOL_TAG, NormalPoolPriority);
    if (!ctx->AdapterNameBuf)
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
    ctx->AdapterName.MaximumLength = BindParameters->AdapterName->Length + sizeof(WCHAR);

    NdisZeroMemory(&openParams, sizeof(openParams));
    openParams.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
    openParams.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVISION_1;
    openParams.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
    openParams.AdapterName = &ctx->AdapterName;
    openParams.MediumArray = mediumArray;
    openParams.MediumArraySize = 1;
    openParams.SelectedMediumIndex = &selectedMediumIndex;
    openParams.FrameTypeArray = NULL;
    openParams.FrameTypeArraySize = 0;

    status = NdisOpenAdapterEx(
        g_Ipv8Global.NdisProtocolHandle,
        ctx,
        &openParams,
        BindContext,
        &ctx->NdisBindingHandle
        );

    if (status != NDIS_STATUS_PENDING && status != NDIS_STATUS_SUCCESS)
    {
        NdisFreeMemory(ctx->AdapterNameBuf, 0, 0);
        NdisFreeMemory(ctx, 0, 0);
        NdisCompleteBindAdapterEx(BindContext, status);
        return status;
    }

    ctx->Bound = TRUE;

    NdisAcquireSpinLock(&g_OpenListLock);
    InsertTailList(&g_OpenList, &ctx->Link);
    NdisInterlockedIncrement(&g_Ipv8Global.OpenCount);
    NdisReleaseSpinLock(&g_OpenListLock);

    NdisCompleteBindAdapterEx(BindContext, NDIS_STATUS_SUCCESS);
    return NDIS_STATUS_SUCCESS;
}

/* ---- Unbind Adapter ---- */

NDIS_STATUS
IPv8UnbindAdapterEx(
    _In_ NDIS_HANDLE UnbindContext,
    _In_ NDIS_HANDLE ProtocolBindingContext
    )
{
    PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)ProtocolBindingContext;
    NDIS_STATUS status;

    ctx->Bound = FALSE;

    NdisAcquireSpinLock(&g_OpenListLock);
    RemoveEntryList(&ctx->Link);
    NdisInterlockedDecrement(&g_Ipv8Global.OpenCount);
    NdisReleaseSpinLock(&g_OpenListLock);

    status = NdisCloseAdapterEx(ctx->NdisBindingHandle);

    if (status != NDIS_STATUS_PENDING)
    {
        if (ctx->AdapterNameBuf)
            NdisFreeMemory(ctx->AdapterNameBuf, 0, 0);
        NdisFreeMemory(ctx, 0, 0);
    }

    NdisCompleteUnbindAdapterEx(UnbindContext);
    return NDIS_STATUS_SUCCESS;
}

/* ---- Open/Close Complete ---- */

VOID
IPv8OpenAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ NDIS_STATUS Status
    )
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(Status);
}

VOID
IPv8CloseAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ NDIS_STATUS Status
    )
{
    PIPV8_OPEN_CONTEXT ctx = (PIPV8_OPEN_CONTEXT)ProtocolBindingContext;
    UNREFERENCED_PARAMETER(Status);

    if (ctx)
    {
        if (ctx->AdapterNameBuf)
            NdisFreeMemory(ctx->AdapterNameBuf, 0, 0);
        NdisFreeMemory(ctx, 0, 0);
    }
}

/* ---- Receive (return all packets immediately) ---- */

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

    UNREFERENCED_PARAMETER(PortNumber);

    if (ctx && ctx->NdisBindingHandle)
    {
        ctx->PacketsReceived += NumberOfNetBufferLists;
        NdisReturnNetBufferLists(
            ctx->NdisBindingHandle,
            NetBufferLists,
            ReceiveFlags
            );
    }
}

/* ---- Send Complete (stub) ---- */

VOID
IPv8SendNetBufferListsComplete(
    _In_ NDIS_HANDLE      ProtocolBindingContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG            SendCompleteFlags
    )
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(NetBufferLists);
    UNREFERENCED_PARAMETER(SendCompleteFlags);
}

/* ---- Status (stub) ---- */

VOID
IPv8StatusEx(
    _In_ NDIS_HANDLE             ProtocolBindingContext,
    _In_ PNDIS_STATUS_INDICATION StatusIndication
    )
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(StatusIndication);
}

/* ---- PnP (stub) ---- */

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
