// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#include "Types.h"
#include "Driver.h"

#define KERNEL_DEVICE_NAME		L"\\Device\\StateOS"
#define WIN32_DEVICE_NAME		L"\\Global??\\StateOS"

#define MAJOR_DRIVER_VERSION 1
#define MINOR_DRIVER_VERSION 0

#define NDIS_PROT_MAJOR_VERSION 6
#define NDIS_PROT_MINOR_VERSION 30


PDEVICE_OBJECT DeviceObject;

extern "C"
NTSTATUS StateOSDeviceOpen(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(deviceObject);
	NTSTATUS status;
	do
	{
		auto irpStack = IoGetCurrentIrpStackLocation(irp);
		irpStack->FileObject->FsContext = NULL;

		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		status = STATUS_SUCCESS;

	} while (false);
	return status;
}

extern "C"
NTSTATUS StateOSDeviceClose(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(deviceObject);
	
	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

extern "C"
VOID StateOSDeviceUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);

	UNICODE_STRING win32DeviceName;
	RtlInitUnicodeString(&win32DeviceName, WIN32_DEVICE_NAME);
	IoDeleteSymbolicLink(&win32DeviceName);

	IoDeleteDevice(DeviceObject);
}

extern "C"
NTSTATUS StateOSDeviceCleanup(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(deviceObject);
	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return (STATUS_SUCCESS);
}

#define STATEOS_IOCTL_CODE(_function, _method, _access) CTL_CODE(FILE_DEVICE_NETWORK, _function, _method, _access)
#define STATEOS_IOCTL_TEST STATEOS_IOCTL_CODE(0x201, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

extern "C"
NTSTATUS StateOSDeviceIoctl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(deviceObject);
	auto irpStack = IoGetCurrentIrpStackLocation(irp);

	auto functionCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	if (functionCode == STATEOS_IOCTL_TEST)
	{
		//DoTest();
	}

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

extern void MediaServer();

constexpr UINT32 SEND_BUFFER_POOL_SIZE = 24576;
constexpr UINT32 SEND_BUFFERS_PER_POOL = 16;
constexpr UINT32 SEND_BUFFER_SIZE = 1536;

struct SEND_BUFFER_INFO
{
	BYTESTREAM dataStream;
	UINT32 flags;
	PMDL mdl;

	SEND_BUFFER_INFO(PUINT8 address)
	{
		dataStream.setBuffer(address, ETHERNET_FRAME_SIZE);
		mdl = IoAllocateMdl(address, SEND_BUFFER_SIZE, FALSE, FALSE, nullptr);
		MmBuildMdlForNonPagedPool(mdl);
		flags = 0;
	}
};

struct DRIVER_INFO
{
	PUINT8 sendBufferMemory;
	STREAM_BUILDER<SEND_BUFFER_INFO, GLOBAL_STACK, 2048> sendBuffers;

	NDIS_HANDLE NdisProtocolHandle;
	NDIS_HANDLE NdisBufferPoolHandle;
	UINT16 contextSize;
};

DRIVER_INFO* DriverInfoPtr;
DRIVER_INFO& DriverInfo() { return *DriverInfoPtr; }

struct SEND_BUFFER_CONTEXT
{
	SEND_BUFFER_INFO* dataBuffer;
	PNET_BUFFER_LIST bufferList;
};

using PSEND_BUFFER_CONTEXT = SEND_BUFFER_CONTEXT *;
PNET_BUFFER_LIST FreeSendBuffers;

#define PROTOCOL_NAME	L"STATEOS"

NDIS_STATUS InitializeBufferPool()
{
	auto& driverInfo = DriverInfo();

	driverInfo.contextSize = (UINT16)(ROUND_TO(sizeof(SEND_BUFFER_CONTEXT), MEMORY_ALLOCATION_ALIGNMENT));

	auto status = STATUS_SUCCESS;
	NET_BUFFER_LIST_POOL_PARAMETERS poolConfig;
	NdisZeroMemory(&poolConfig, sizeof(poolConfig));

	poolConfig.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	poolConfig.Header.Size = sizeof(NET_BUFFER_LIST_POOL_PARAMETERS);
	poolConfig.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;

	poolConfig.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	poolConfig.fAllocateNetBuffer = TRUE;
	poolConfig.PoolTag = 'CNYS';
	poolConfig.DataSize = 0; // XXX SEND_BUFFER_DATA_SIZE;

	poolConfig.ContextSize = driverInfo.contextSize;

	driverInfo.NdisBufferPoolHandle = NdisAllocateNetBufferListPool(driverInfo.NdisProtocolHandle, &poolConfig);

	driverInfo.sendBufferMemory = (PUINT8)KernelAlloc(SEND_BUFFER_POOL_SIZE * 16);
	for (UINT32 i = 0; i < SEND_BUFFERS_PER_POOL; i++)
	{
		auto start = SEND_BUFFER_SIZE * i;
		for (UINT32 j = 0; j < 16; j++)
		{
			auto address = driverInfo.sendBufferMemory + start + j * SEND_BUFFER_POOL_SIZE;
			driverInfo.sendBuffers.append(address);
		}
	}

	return status;
}

BYTESTREAM& AllocateAdapterBuffer3()
{
	auto& dataStream = KernelAlloc<BYTESTREAM>();
	auto buffer = (PUINT8) ExAllocatePoolWithTag(NonPagedPoolNx, 1500, POOL_TAG);

	dataStream.setBuffer(buffer, 1500);

	return dataStream;
}

BYTESTREAM* GetSendBuffer()
{
	BYTESTREAM* dataStream = nullptr;

	for (auto& sendBuffer : DriverInfo().sendBuffers.toBufferNoConst())
	{
		if (sendBuffer.flags == 0)
		{
			if (InterlockedCompareExchange((LONG *)&sendBuffer.flags, 1, 0) == 0)
			{
				sendBuffer.dataStream.clear();
				dataStream = &sendBuffer.dataStream;
				break;
			}
		}
	}

	return dataStream;
}

BYTESTREAM& AllocateAdapterBuffer()
{
	auto dataStream = GetSendBuffer();
	if (dataStream == nullptr)
	{
		auto bufferPool = (PUINT8)KernelAlloc(SEND_BUFFER_POOL_SIZE);
		ASSERT(bufferPool != nullptr);

		for (UINT32 i = 0; i < SEND_BUFFERS_PER_POOL; i++)
		{
			auto address = bufferPool + i * SEND_BUFFER_SIZE;
			DriverInfo().sendBuffers.append(address);
		}

		dataStream = GetSendBuffer();
		ASSERT(dataStream != nullptr);
	}

	return *dataStream;
}

void FreeSendBuffer(SEND_BUFFER_CONTEXT* context)
{
	NdisFreeNetBufferList(context->bufferList);
}

PROTOCOL_RECEIVE_NET_BUFFER_LISTS NdisReceiveDataHandler;
void NdisReceiveDataHandler(NDIS_HANDLE bindingContext, PNET_BUFFER_LIST recvNBLChain, NDIS_PORT_NUMBER, ULONG bufferListCount, ULONG flags)
{
	auto& adapterInfo = *(ADAPTER_INFO*)bindingContext;
	UNREFERENCED_PARAMETER(bufferListCount);

	OnAdapterReceive(adapterInfo, recvNBLChain, flags);
}

PROTOCOL_OPEN_ADAPTER_COMPLETE_EX NdisOpenAdapterCompleteHandler;
void NdisOpenAdapterCompleteHandler(NDIS_HANDLE bindingContext, NDIS_STATUS status)
{
	DBGBREAK();
	UNREFERENCED_PARAMETER(bindingContext);
	UNREFERENCED_PARAMETER(status);
}

PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX NdisCloseAdapterCompleteHandler;
VOID NdisCloseAdapterCompleteHandler(NDIS_HANDLE bindingContext)
{
	DBGBREAK();
	UNREFERENCED_PARAMETER(bindingContext);
}

PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE NdisSendDataCompleteHandler;
void NdisSendDataCompleteHandler(NDIS_HANDLE, PNET_BUFFER_LIST bufferList, ULONG)
{
	LogInfo("SendData complete");
	auto context = (SEND_BUFFER_CONTEXT *) NET_BUFFER_LIST_CONTEXT_DATA_START(bufferList);
	context->dataBuffer->flags = 0;

	NdisFreeNetBufferList(bufferList);
}

PROTOCOL_OID_REQUEST_COMPLETE NdisOidRequestComplete;
void NdisOidRequestComplete(NDIS_HANDLE bindingContext, PNDIS_OID_REQUEST oidRequest, NDIS_STATUS status)
{
	ASSERT(status == STATUS_SUCCESS);
	LogInfo("Oid Completion: requestType=0x%x, OID=0x%x", oidRequest->RequestType, oidRequest->DATA.SET_INFORMATION.Oid);
	
	auto& adapter = *(ADAPTER_INFO*)bindingContext;
	adapter.oidStatus = status;
	KeSetEvent(&adapter.oidEvent, 0, FALSE);
	UNREFERENCED_PARAMETER(bindingContext);
}

PROTOCOL_STATUS_EX NdisProtocolStatusInd;
void NdisProtocolStatusInd(NDIS_HANDLE bindingContext, PNDIS_STATUS_INDICATION statusIndication)
{
	auto status = statusIndication->StatusCode;	

	LogInfo("ProtocolStatusHandler: status=0x%x", status);
	switch (status)
	{
	case NDIS_STATUS_RESET_START:
		LogInfo("Reset start");
		break;

	case NDIS_STATUS_RESET_END:
		LogInfo("Reset End");
		break;

	case NDIS_STATUS_LINK_STATE:
	{
		auto linkState = (PNDIS_LINK_STATE)statusIndication->StatusBuffer;
		if (linkState->MediaConnectState == MediaConnectStateConnected)
		{
			LogInfo("LinkState: Media connected");
		}
		else
		{
			LogInfo("LinkState: Media disconnected");
		}
		break;
	}
	case NDIS_STATUS_OPER_STATUS:
	{
		auto operState = (PNDIS_OPER_STATE)statusIndication->StatusBuffer;
		if (operState->OperationalStatus == NET_IF_OPER_STATUS_UP)
		{
			LogInfo("OperStatus: Interface is UP");
		}
		else if (operState->OperationalStatus == NET_IF_OPER_STATUS_DORMANT)
		{
			LogInfo("OperStatus: Interface is DORMANT");
		}
		else if (operState->OperationalStatus == NET_IF_OPER_STATUS_DOWN)
		{
			LogInfo("OperStatus: Interface is DOWN");
			LogInfo("OperStatus: Flags: 0x%x", operState->OperationalStatusFlags);
		}
		else
		{
			LogInfo("Unknown oper status");
		}
		break;
	}
	case NDIS_STATUS_PACKET_FILTER:
	{
		auto filter = (UINT32 *)statusIndication->StatusBuffer;
		LogInfo("Status: PacketFilter=0x%x", *filter);
		break;
	}
	default:
		break;
	}

	UNREFERENCED_PARAMETER(bindingContext);
}

PROTOCOL_RECEIVE_NET_BUFFER_LISTS NdisProtocolReceiveData;
void NdisProtocolReceiveData(NDIS_HANDLE bindingContext, PNET_BUFFER_LIST bufferList, NDIS_PORT_NUMBER port, ULONG bufferListCount, ULONG flags)
{
	DBGBREAK();
	UNREFERENCED_PARAMETER(bindingContext);
	UNREFERENCED_PARAMETER(bufferList);
	UNREFERENCED_PARAMETER(port); 
	UNREFERENCED_PARAMETER(bufferListCount);
	UNREFERENCED_PARAMETER(flags);
}

void StartCoreModules();

PROTOCOL_NET_PNP_EVENT NdisPnpEventHandler;
NDIS_STATUS NdisPnpEventHandler(NDIS_HANDLE bindingContext, PNET_PNP_EVENT_NOTIFICATION eventInfo)
{
	LogInfo("NdisPnpEvent");
	auto& adapterInfo = *(ADAPTER_INFO*)bindingContext;
	UNREFERENCED_PARAMETER(adapterInfo);
	switch (eventInfo->NetPnPEvent.NetEvent)
	{
	case NetEventSetPower:
		LogInfo("NetEventsetpower");
		break;

	case NetEventRestart:
	{
		auto restartParams = (PNDIS_PROTOCOL_RESTART_PARAMETERS)eventInfo->NetPnPEvent.Buffer;
		if (restartParams)
		{
			if (restartParams->FilterModuleNameBuffer)
			{
				LogInfo("Filter module restart");
			}

			if (restartParams->RestartAttributes)
			{
				auto attributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)restartParams->RestartAttributes->Data;

				LogInfo("attributes: Mtu:%d", attributes->MtuSize);
			}
		}
		break;
	}

	case NetEventBindsComplete:
		StartCoreModules();
		LogInfo("Bind complete");
		break;

	case NetEventPause:
		LogInfo("Pause");
		break;

	default:
		LogInfo("Unkown");
		break;
	}
	return STATUS_SUCCESS;
}

NTSTATUS MakeOidRequest(const ADAPTER_INFO& adapterInfo, NDIS_REQUEST_TYPE requestType, NDIS_OID oid, PVOID data, UINT32 dataLength)
{
	PAGED_CODE()

	NDIS_OID_REQUEST oidRequest;
	NdisZeroMemory(&oidRequest, sizeof(NDIS_OID_REQUEST));

	oidRequest.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	oidRequest.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	oidRequest.Header.Size = sizeof(NDIS_OID_REQUEST);

	oidRequest.RequestType = requestType;
	oidRequest.PortNumber = NDIS_DEFAULT_PORT_NUMBER;

	if (requestType == NdisRequestSetInformation)
	{
		oidRequest.DATA.SET_INFORMATION.Oid = oid;
		oidRequest.DATA.SET_INFORMATION.InformationBuffer = data;
		oidRequest.DATA.SET_INFORMATION.InformationBufferLength = dataLength;
	}
	else if (requestType == NdisRequestQueryInformation)
	{
		oidRequest.DATA.QUERY_INFORMATION.Oid = oid;
		oidRequest.DATA.QUERY_INFORMATION.InformationBuffer = data;
		oidRequest.DATA.QUERY_INFORMATION.InformationBufferLength = dataLength;
	}
	auto status = NdisOidRequest(adapterInfo.adapterHandle, &oidRequest);
	ASSERT(NT_SUCCESS(status));
	if (status == NDIS_STATUS_PENDING)
	{
		KeWaitForSingleObject((PVOID)&adapterInfo.oidEvent, Executive, KernelMode, FALSE, nullptr);
		status = adapterInfo.oidStatus;
	}

	return status;
}

STREAM_BUILDER<ADAPTER_INFO, GLOBAL_STACK, 8> * AdapterInfoTablePtr;
STREAM_BUILDER<ADAPTER_INFO, GLOBAL_STACK, 8> & AdapterInfoTable()
{
	return *AdapterInfoTablePtr;
}

STREAM_READER<const ADAPTER_INFO> GetAdapterTable()
{
	return AdapterInfoTable().toBuffer();
}

PROTOCOL_BIND_ADAPTER_EX NdisProtocolBindAdapterInd;
NDIS_STATUS NdisBindAdapterHandler(NDIS_HANDLE, NDIS_HANDLE bindingContext, PNDIS_BIND_PARAMETERS bindParams)
{
	auto status = STATUS_SUCCESS;
	do
	{
		auto&& adapterInfo = AdapterInfoTable().append();

		KeInitializeEvent(&adapterInfo.oidEvent, SynchronizationEvent, FALSE);

		RtlCopyUnicodeString(&adapterInfo.adapterName, bindParams->AdapterName);
		ASSERT(bindParams->MacAddressLength == MAC_ADDRESS_LENGTH);
		RtlCopyMemory(adapterInfo.macAddress, bindParams->CurrentMacAddress, MAC_ADDRESS_LENGTH);

		SystemInfo().nicCount++;
		SystemInfo().txBandwidth += bindParams->XmitLinkSpeed / 1000;
		SystemInfo().rxBandwidth += bindParams->RcvLinkSpeed / 1000;

		adapterInfo.mtu = bindParams->MtuSize;
		adapterInfo.isPhysical = bindParams->IfConnectorPresent ? true : false;
		adapterInfo.mediaType = bindParams->MediaType;
		adapterInfo.rxLinkSpeed = bindParams->RcvLinkSpeed;
		adapterInfo.txLinkSpeed = bindParams->XmitLinkSpeed;
		adapterInfo.isConnected = bindParams->MediaConnectState == MediaConnectStateConnected;

		NDIS_OPEN_PARAMETERS openParams;
		RtlZeroMemory(&openParams, sizeof(NDIS_OPEN_PARAMETERS));

		openParams.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
		openParams.Header.Size = sizeof(openParams);
		openParams.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;

		openParams.AdapterName = bindParams->AdapterName;

		NDIS_MEDIUM mediumArray[1] = { NdisMedium802_3 };
		UINT selectedMedium;

		openParams.MediumArray = mediumArray;
		openParams.MediumArraySize = sizeof(mediumArray) / sizeof(NDIS_MEDIUM);
		openParams.SelectedMediumIndex = &selectedMedium;

		NET_FRAME_TYPE frameTypeArray[] = { ETHERTYPE_SYNC, ETHERTYPE_DISCOVER, };
		openParams.FrameTypeArray = frameTypeArray;
		openParams.FrameTypeArraySize = sizeof(frameTypeArray) / sizeof(NET_FRAME_TYPE);

		auto status = NdisOpenAdapterEx(DriverInfo().NdisProtocolHandle, (NDIS_HANDLE)& adapterInfo, &openParams, bindingContext, &adapterInfo.adapterHandle);
		VERIFY_STATUS;

	} while (false);
	LogInfo("BindAdapter Complete");
	return status;
}

NTSTATUS StartReceiver(const ADAPTER_INFO& adapterInfo)
{
	auto status = STATUS_SUCCESS;
	do
	{
		LOCAL_STREAM<32> multicastAddressList;

		multicastAddressList.writeBytes(SYNC_LOCAL_MULTICAST);
		multicastAddressList.writeBytes(SYNC_SUBNET_MULTICAST);
		multicastAddressList.writeBytes(DISCOVER_MULTICAST);

		auto multicastList = multicastAddressList.toBuffer();

		status = MakeOidRequest(adapterInfo, NdisRequestSetInformation, OID_802_3_MULTICAST_LIST, (PVOID)multicastList.data(), multicastList.length());
		VERIFY_STATUS;

		//status = MakeOidRequest(adapterInfo, NdisRequestSetInformation, OID_802_3_ADD_MULTICAST_ADDRESS, (PVOID)SYNC_LOCAL_MULTICAST.data(), 6);
		//VERIFY_STATUS;

		//status = MakeOidRequest(adapterInfo, NdisRequestSetInformation, OID_802_3_ADD_MULTICAST_ADDRESS, (PVOID)SYNC_SUBNET_MULTICAST.data(), 6);
		//VERIFY_STATUS;

		//status = MakeOidRequest(adapterInfo, NdisRequestSetInformation, OID_802_3_ADD_MULTICAST_ADDRESS, (PVOID)DISCOVER_MULTICAST.data(), 6);
		//VERIFY_STATUS;

		DWORD packetFilter = NDIS_PACKET_TYPE_MULTICAST | /*NDIS_PACKET_TYPE_PROMISCUOUS | */NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_ALL_MULTICAST | NDIS_PACKET_TYPE_DIRECTED;
		status = MakeOidRequest(adapterInfo, NdisRequestSetInformation, OID_GEN_CURRENT_PACKET_FILTER, &packetFilter, (UINT32)sizeof(DWORD));
		VERIFY_STATUS;
	} while (false);
	return status;
}

PROTOCOL_UNBIND_ADAPTER_EX NdisUnbindAdapterHandler;
NDIS_STATUS NdisUnbindAdapterHandler(NDIS_HANDLE protocolContext, NDIS_HANDLE bindingContext)
{
	DBGBREAK();
	UNREFERENCED_PARAMETER(protocolContext);
	UNREFERENCED_PARAMETER(bindingContext);
	return STATUS_SUCCESS;
}

void SendToAdapter(const ADAPTER_INFO& adapterInfo, BYTESTREAM& dataStream)
{
	ASSERT(dataStream.count() >= ETHERNET_MIN_FRAME_SIZE);

	auto bufferInfo = CONTAINING_RECORD(&dataStream, SEND_BUFFER_INFO, dataStream);

	auto bufferList = NdisAllocateNetBufferAndNetBufferList(DriverInfo().NdisBufferPoolHandle, DriverInfo().contextSize, 0, bufferInfo->mdl, 0, dataStream.count());
	bufferList->SourceHandle = adapterInfo.adapterHandle;

	auto context = (PSEND_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(bufferList);
	context->dataBuffer = bufferInfo;

	NdisSendNetBufferLists(adapterInfo.adapterHandle, bufferList, 0, 0);
}

const ADAPTER_INFO& FindAdapter(BUFFER macAddress)
{
	return GetAdapterTable().find(macAddress);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNREFERENCED_PARAMETER(driverObject);
	UNREFERENCED_PARAMETER(registryPath);

	do
	{
		DriverInfoPtr = &KernelAlloc<DRIVER_INFO>();
		RtlZeroMemory(DriverInfoPtr, sizeof(DRIVER_INFO));

		InitializeLibrary();

		UNICODE_STRING kernelDeviceName;
		RtlInitUnicodeString(&kernelDeviceName, KERNEL_DEVICE_NAME);

		status = IoCreateDevice(driverObject, 0, &kernelDeviceName, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status))
		{
			LogError("IoCreateDeice failed, error=0x%x", status);
			break;
		}

		UNICODE_STRING win32DeviceName;
		RtlInitUnicodeString(&win32DeviceName, WIN32_DEVICE_NAME);

		status = IoCreateSymbolicLink(&win32DeviceName, &kernelDeviceName);
		if (!NT_SUCCESS(status))
		{
			LogError("IoCreateSymbolicLink failed, error=0x%x", status);
			break;
		}

		DeviceObject->Flags |= DO_DIRECT_IO;

		driverObject->MajorFunction[IRP_MJ_CREATE] = StateOSDeviceOpen;
		driverObject->MajorFunction[IRP_MJ_CLOSE] = StateOSDeviceClose;
		driverObject->MajorFunction[IRP_MJ_CLEANUP] = StateOSDeviceCleanup;
		driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = StateOSDeviceIoctl;

		driverObject->DriverUnload = StateOSDeviceUnload;

		AdapterInfoTablePtr = &KernelAlloc<STREAM_BUILDER<ADAPTER_INFO, GLOBAL_STACK, 8>>();

		status = STATUS_SUCCESS;

		NDIS_PROTOCOL_DRIVER_CHARACTERISTICS protocolInfo;
		NdisZeroMemory(&protocolInfo, sizeof(protocolInfo));

		protocolInfo.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
		protocolInfo.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
		protocolInfo.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;

		protocolInfo.MajorNdisVersion = NDIS_PROT_MAJOR_VERSION;
		protocolInfo.MinorNdisVersion = NDIS_PROT_MINOR_VERSION;

		protocolInfo.MajorDriverVersion = MAJOR_DRIVER_VERSION;
		protocolInfo.MinorDriverVersion = MINOR_DRIVER_VERSION;

		NDIS_STRING protocolName;
		RtlInitUnicodeString(&protocolName, PROTOCOL_NAME);

		protocolInfo.Name = protocolName;

		protocolInfo.SetOptionsHandler = NULL;

		protocolInfo.OpenAdapterCompleteHandlerEx = NdisOpenAdapterCompleteHandler;
		protocolInfo.CloseAdapterCompleteHandlerEx = NdisCloseAdapterCompleteHandler;

		protocolInfo.SendNetBufferListsCompleteHandler = NdisSendDataCompleteHandler;
		protocolInfo.ReceiveNetBufferListsHandler = NdisReceiveDataHandler;

		protocolInfo.OidRequestCompleteHandler = NdisOidRequestComplete;
		protocolInfo.StatusHandlerEx = NdisProtocolStatusInd;
		protocolInfo.UninstallHandler = nullptr;
		protocolInfo.SetOptionsHandler = nullptr;
		protocolInfo.NetPnPEventHandler = NdisPnpEventHandler;

		protocolInfo.BindAdapterHandlerEx = NdisBindAdapterHandler;
		protocolInfo.UnbindAdapterHandlerEx = NdisUnbindAdapterHandler;

		status = NdisRegisterProtocolDriver(nullptr, &protocolInfo, &DriverInfo().NdisProtocolHandle);
		ASSERT(NT_SUCCESS(status));
		VERIFY_STATUS;

		auto status = InitializeBufferPool();
		ASSERT(NT_SUCCESS(status));
		VERIFY_STATUS;

	} while (false);

	return status;
}

#include "RTMP.h"
#include "RTSP.h"

RTSP_SERVICE* RtspService;

constexpr USTRING RTSP_URL = "rtsp://State14/camera";

NTSTATUS InitializeRtsp()
{
	RtspService = &KernelAlloc<RTSP_SERVICE>();
	RtspService->startClient(RTSP_URL);

	return STATUS_SUCCESS;
}

template <>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, RTSP_SESSION<RTSP_SERVICE>& session)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	processorInfo.appStack = &session.context.stack;
	processorInfo.sessionStack = &session.stack;
	processorInfo.schedulerStack = &schedulerStack;
}

template <>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, RTSP_SERVICE& service)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	processorInfo.appStack = &service.stack;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = &schedulerStack;
}

RTMP_SERVICE* rtmpService;

NTSTATUS InitializeRtmp()
{
	DBGBREAK();

	rtmpService = &KernelAlloc<RTMP_SERVICE>();
	rtmpService->start();

	return STATUS_SUCCESS;
}

template <>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, RTMP_SESSION<RTMP_SERVICE>& session)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	processorInfo.appStack = &session.context.stack;
	processorInfo.sessionStack = &session.stack;
	processorInfo.schedulerStack = &schedulerStack;
}

template <>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, RTMP_SERVICE& service)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	processorInfo.appStack = &service.stack;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = &schedulerStack;
}

SCHEDULER_STACK* GetCurrentScheduler()
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	return processorInfo.schedulerStack;
}

NTSTATUS InitializeSyncAgent();
NTSTATUS InitializeRtmp();
NTSTATUS InitializeRtsp();

static bool CoreModulesStarted = false;
void StartCoreModules()
{
	if (CoreModulesStarted == false)
	{
		CoreModulesStarted = true;
		SystemScheduler().runTask(STASK([](PVOID, NTSTATUS, STASK_PARAMS)
			{
				//InitializeRtsp();
				//InitializeRtmp();
				//InitWebApps(); XXX
				// XXX Temp!! Uncomment
				//InitializeSyncAgent();
				//for (auto& adapter : GetAdapterTable())
				//{
				//	StartReceiver(adapter);
				//}

				//MediaServer();
			}, nullptr));
	}
	else DBGBREAK();
}
