#include "Types.h"
#include "SYNC.h"

SYNC_SERVICE* SyncAgentPtr = nullptr;
SYNC_SERVICE& SyncService()
{
	return *SyncAgentPtr;
}

NTSTATUS InitializeSyncAgent()
{
	if (SyncAgentPtr == nullptr)
	{
		SyncAgentPtr = &KernelAlloc<SYNC_SERVICE>();
		SyncAgentPtr->initialize();
	}
	return STATUS_SUCCESS;
}

void OnAdapterReceive(ADAPTER_INFO& adapterInfo, PNET_BUFFER_LIST recvNBLChain, ULONG flags)
{
	ASSERT(NDIS_TEST_RECEIVE_CAN_PEND(flags));

	SyncService().scheduler.runTask(SYNC_RECEIVE_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
		{
			auto& adapterInfo = *(ADAPTER_INFO*)context;
			auto recvNBLChain = argv.read<PNET_BUFFER_LIST>();
			auto flags = argv.read<ULONG>();
			for (auto recvNBL = recvNBLChain; recvNBL; recvNBL = recvNBL->Next)
			{
				ULONG dataLength = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(recvNBL));
				auto mdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(NET_BUFFER_LIST_FIRST_NB(recvNBL));

				PUINT8 data; ULONG mdlLength;
				NdisQueryMdl(NET_BUFFER_CURRENT_MDL(NET_BUFFER_LIST_FIRST_NB(recvNBL)), &data, &mdlLength, NormalPagePriority);

				ASSERT(mdlLength >= dataLength);

				BUFFER recvFrame{ data + mdlOffset, dataLength };
				SyncService().onReceiveFrom(adapterInfo, recvFrame,
					recvNBL->Next ? STASK() : STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
						{
							auto& adapterInfo = *(const ADAPTER_INFO*)context;
							NdisReturnNetBufferLists(adapterInfo.adapterHandle, argv.read<PNET_BUFFER_LIST>(), argv.read<ULONG>());

						}, &adapterInfo, recvNBLChain, flags));
			}
		}, &adapterInfo, recvNBLChain, flags));
}

template<>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, SYNC_SERVICE& service)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];

	processorInfo.appStack = &service.serviceStack;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = &schedulerStack;
}

template<>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, SYNC_SESSION<SYNC_SERVICE>& session)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	processorInfo.appStack = &session.service.serviceStack;
	processorInfo.sessionStack = &session.stack;
	processorInfo.schedulerStack = &schedulerStack;
}