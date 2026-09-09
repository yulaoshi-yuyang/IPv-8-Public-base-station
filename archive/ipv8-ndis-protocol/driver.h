/*++

Copyright (c) IPv8+ Project. All rights reserved.

Module Name:

    driver.h

Abstract:

    Header for the IPv8 NDIS 6.x protocol driver.

--*/

#pragma once

#include <ntddk.h>
#include <ndis.h>

#define IPv8_PROTOCOL_NAME      L"IPv8Proto"
#define IPv8_POOL_TAG           '8VPI'

typedef struct _IPV8_GLOBAL_DATA
{
    NDIS_HANDLE     NdisProtocolHandle;
    LONG            OpenCount;
    BOOLEAN         Unloading;
} IPV8_GLOBAL_DATA, *PIPV8_GLOBAL_DATA;

extern IPV8_GLOBAL_DATA g_Ipv8Global;

typedef struct _IPV8_OPEN_CONTEXT
{
    NDIS_HANDLE     NdisBindingHandle;
    NDIS_STRING     AdapterName;
    PUCHAR          AdapterNameBuf;
    BOOLEAN         Bound;
    ULONG64         PacketsReceived;
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
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ NDIS_STATUS Status
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

NDIS_STATUS
IPv8NetPnPEvent(
    _In_ NDIS_HANDLE                  ProtocolBindingContext,
    _In_ PNET_PNP_EVENT_NOTIFICATION  NetPnPEvent
    );
