// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

struct WSK_INFO
{
	WSK_REGISTRATION registration;
	const WSK_PROVIDER_DISPATCH* providerInterface;
	PWSK_CLIENT providerContext;
	WSK_CLIENT_CONNECTION_DISPATCH clientDispatch;
	WSK_CLIENT_DATAGRAM_DISPATCH datagramDispatch;
};

extern WSK_INFO WskInfo;

extern const WSK_PROVIDER_DISPATCH& GetProviderDispatch();
extern WSK_CLIENT_CONNECTION_DISPATCH SocketConnectionDispatch;

struct IRPTYPE
{
	UINT8 irp[IoSizeOfIrp(1)];
	PVOID callback;
	ULONG_PTR arg1;
	ULONG_PTR arg2;
};

constexpr UINT32 MDL_BUFSIZE = sizeof(MDL) + (sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES(0, 64 * 1024));
using MDLTYPE = UINT8[MDL_BUFSIZE];

template <typename CONTEXT>
WSK_BUF ResetMdl(CONTEXT& context, BUFFER dataBuffer)
{
	auto mdl = (PMDL)context.mdlData;
	ASSERT(mdl->Size == 0); // no recursive calls
	ASSERT(dataBuffer.length() < 64 * 1024);
	MmInitializeMdl(mdl, (PVOID)dataBuffer.data(), dataBuffer.length());
	MmBuildMdlForNonPagedPool(mdl);
	return { mdl, 0, dataBuffer.length() };
}

template <typename CONTEXT>
void ClearMdl(CONTEXT& context)
{
	auto mdl = (PMDL)context.mdlData;
	mdl->Size = 0;
}

template <typename CONTEXT, typename FUNC>
PIRP ResetIrp(CONTEXT& context, FUNC callback, ULONG_PTR arg1 = 0, ULONG_PTR arg2 = 0)
{
	auto irp = (PIRP)context.irpData.irp;

	IoInitializeIrp(irp, sizeof(context.irpData.irp), 1);
	context.irpData.callback = (PVOID)& callback;
	context.irpData.arg1 = arg1;
	context.irpData.arg2 = arg2;

	IoSetCompletionRoutine(irp, (PIO_COMPLETION_ROUTINE)[](PDEVICE_OBJECT, PIRP irp, PVOID irpContext) -> NTSTATUS
		{
			auto irpData = CONTAINING_RECORD(irp, IRPTYPE, irp);
			auto& context = *(CONTEXT*)irpContext;
			auto callback = (FUNC *)irpData->callback;
			(*callback)(context, irp->IoStatus.Status, irp->IoStatus.Information);
			return STATUS_MORE_PROCESSING_REQUIRED;
		}, &context, TRUE, TRUE, TRUE);
	return irp;
}

template <typename CONTEXT>
NTSTATUS getIrpStatus(CONTEXT& stack)
{
	return ((PIRP)stack.irpData.irp)->IoStatus.Status;
}

template <typename CONTEXT>
NTSTATUS WskReceive(PVOID socketContext, ULONG flags, PWSK_DATA_INDICATION dataIndication, SIZE_T bytesIndicated, SIZE_T* bytesAccepted)
{
	UNREFERENCED_PARAMETER(flags);
	UNREFERENCED_PARAMETER(bytesIndicated);
	UNREFERENCED_PARAMETER(bytesAccepted);
	auto&& stack = *(CONTEXT*)socketContext;
	stack.onReceive(dataIndication);
	return STATUS_PENDING;
}

template <typename CONTEXT>
NTSTATUS WskReceiveFrom(PVOID socketContext, ULONG flags, PWSK_DATAGRAM_INDICATION dataIndication)
{
	UNREFERENCED_PARAMETER(flags);
	auto&& stack = *(CONTEXT*)socketContext;
	stack.onReceiveFrom(dataIndication);
	return STATUS_PENDING;
}

template <typename CONTEXT>
NTSTATUS WskSendBacklog(PVOID socketContext, SIZE_T idealBacklogSize)
{
	DBGBREAK();
	auto&& stack = *(CONTEXT*)socketContext;
	stack.onSendBacklog(idealBacklogSize);
	return STATUS_SUCCESS;
}

template <typename CONTEXT>
NTSTATUS WskDisconnect(PVOID socketContext, ULONG flags)
{
	LogInfo("WskDisconnect invoked");
	UNREFERENCED_PARAMETER(flags);
	auto&& socket = *(CONTEXT*)socketContext;
	socket.onDisconnect();
	return STATUS_SUCCESS;
}

constexpr UINT32 SOCKET_CLOSE_PRIORITY = 0;
constexpr UINT32 SOCKET_RECV_PRIORITY = 2;
constexpr UINT32 SOCKET_CONTROL_PRIORITY = 1;
constexpr UINT32 SOCKET_SEND_PRIORITY = 7;

template <typename SESSION>
struct TCP_SOCKET
{
	SESSION& connection;

	PWSK_SOCKET handle;
	PWSK_PROVIDER_CONNECTION_DISPATCH getConnectionDispatch()
	{
		return (PWSK_PROVIDER_CONNECTION_DISPATCH)handle->Dispatch;
	}
	IRPTYPE irpData;
	MDLTYPE mdlData;
	PADDRINFOEXW resolvedAddressList;

	WSK_CLIENT_CONNECTION_DISPATCH clientDispatch;

	void initialize()
	{
		clientDispatch.WskDisconnectEvent = WskDisconnect<TCP_SOCKET<SESSION>>;
		clientDispatch.WskReceiveEvent = WskReceive<TCP_SOCKET<SESSION>>;
		clientDispatch.WskSendBacklogEvent = WskSendBacklog<TCP_SOCKET<SESSION>>;
	}

	TCP_SOCKET(SESSION& sessionArg) : connection(sessionArg)
	{
		initialize();
	}

	TCP_SOCKET(SESSION& sessionArg, PWSK_SOCKET acceptHandle) : connection(sessionArg)
	{
		initialize();
		handle = acceptHandle;
	}

	template <typename TASK>
	NTSTATUS resolveDns(URL_INFO& urlInfo, TASK&& task)
	{
		auto taskId = connection.getScheduler().queueTask(SOCKET_RECV_PRIORITY + 1, task);

		auto unicodeName = ToUnicodeString(NameToString(urlInfo.hostname));
		auto status = GetProviderDispatch().WskGetAddressInfo(WskInfo.providerContext, unicodeName,
			nullptr, NS_ALL, nullptr, nullptr, &resolvedAddressList, nullptr, nullptr, ResetIrp(*this, [](TCP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR)
				{
					auto taskId = socket.irpData.arg1;
					sockaddr* remoteAddress = nullptr;
					if (status == STATUS_SUCCESS)
					{
						for (auto address = socket.resolvedAddressList; address != nullptr; address = address->ai_next)
						{
							if (address->ai_family == AF_INET)
							{
								remoteAddress = address->ai_addr;
								break;
							}
						}
						ASSERT(remoteAddress);
					}
					socket.connection.getScheduler().updateTask((TASK_ID)taskId, status, (ULONG_PTR)remoteAddress);
				}, taskId));
		return status;
	}

	template <typename TASK>
	NTSTATUS connect(URL_INFO urlInfo, TASK&& task)
	{
		auto taskId = connection.getScheduler().queueTask(SOCKET_RECV_PRIORITY, task);
		return connect(urlInfo, taskId);
	}

	NTSTATUS connect(URL_INFO urlInfo, TASK_ID taskId)
	{
		SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto& socket = *(TCP_SOCKET<SESSION>*)context;
				auto&& urlInfo = argv.read<URL_INFO>();
				auto taskId = argv.read<TASK_ID>();

				socket.resolveDns(urlInfo, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
					{
						auto& socket = *(TCP_SOCKET<SESSION>*)context;
						auto taskId = argv.read<TASK_ID>();

						if (status == STATUS_SUCCESS)
						{
							auto port = argv.read<UINT16>();
							auto remoteAddress = argv.read<SOCKADDR_IN*>();
							remoteAddress->sin_port = HTONS(port);
							SOCKADDR_IN localAddress;
							localAddress.sin_family = AF_INET;
							localAddress.sin_port = 0;
							localAddress.sin_addr.s_addr = 0;

							status = GetProviderDispatch().WskSocketConnect(WskInfo.providerContext, SOCK_STREAM, IPPROTO_TCP,
								(PSOCKADDR)&localAddress, (PSOCKADDR)remoteAddress, 0, &socket, &socket.clientDispatch, nullptr, nullptr, nullptr, ResetIrp(socket, [](TCP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR information)
									{
										socket.handle = (PWSK_SOCKET)information;
										auto taskId = (TASK_ID)socket.irpData.arg1;
										socket.connection.getScheduler().updateTask(taskId, status);
									}, taskId));
							ASSERT(NT_SUCCESS(status));
						}
						else
						{
							socket.connection.getScheduler().updateTask(taskId, status);
						}
					}, &socket, taskId, (UINT16)urlInfo.port));
			}, this, urlInfo, taskId));
		return STATUS_SUCCESS;
	}

	void onReceive(PWSK_DATA_INDICATION dataIndication)
	{
		auto&& scheduler = connection.getScheduler();
		for (auto ptr = dataIndication; ptr; ptr = ptr->Next)
		{
			ASSERT(ptr->Buffer.Length < 1500);
			auto address = ((PUINT8)MmGetSystemAddressForMdlSafe(ptr->Buffer.Mdl, HighPagePriority | MdlMappingNoExecute)) + ptr->Buffer.Offset;
			scheduler.runTask(SOCKET_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto&& socket = *(TCP_SOCKET<SESSION>*)context;
					socket.connection.onReceive(argv.read<BUFFER>());
				}, this, BUFFER{ address, (UINT32)ptr->Buffer.Length }));
		}

		scheduler.runTask(SOCKET_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto&& socket = *(TCP_SOCKET<SESSION>*)context;
				auto dataIndication = argv.read<PWSK_DATA_INDICATION>();
				socket.getConnectionDispatch()->WskRelease(socket.handle, dataIndication);
			}, this, dataIndication));

		scheduler.runNow(SOCKET_RECV_PRIORITY); 
	}

	template <typename TASK>
	NTSTATUS send(BUFFER dataBuffer, TASK&& task)
	{
		auto taskId = connection.getScheduler().queueTask(SOCKET_SEND_PRIORITY, task);

		auto wsaBuf = ResetMdl(*this, dataBuffer);
		auto status = getConnectionDispatch()->WskSend(handle, &wsaBuf, 0, ResetIrp(*this, [](TCP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR information)
			{
				ClearMdl(socket);
				auto taskId = (TASK_ID)socket.irpData.arg2;
				ASSERT(status == STATUS_SUCCESS);
				ASSERT(information == socket.irpData.arg1);
				socket.connection.getScheduler().updateTask(taskId, status);
				if (status == STATUS_CONNECTION_RESET)
				{
					DBGBREAK();
					socket.onDisconnect();
				}
			}, wsaBuf.Length, taskId));
		ASSERT(NT_SUCCESS(status));

		return status;
	}

	void close()
	{
		if (handle != nullptr)
		{
			auto status = getConnectionDispatch()->Basic.WskCloseSocket(handle, ResetIrp(*this, [](TCP_SOCKET<SESSION>& socket, NTSTATUS, ULONG_PTR)
				{
					LogInfo("socket closed");
					socket.connection.onClose();
					socket.handle = nullptr;
				}));
			ASSERT(NT_SUCCESS(status));
		}
	}

	template <typename TASK>
	NTSTATUS close(TASK&& task)
	{
		auto taskId = connection.getScheduler().queueTask(SOCKET_RECV_PRIORITY, task);
		ASSERT(handle != nullptr);
		auto status = getConnectionDispatch()->Basic.WskCloseSocket(handle, ResetIrp(*this, [](TCP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR)
			{
				auto taskId = (TASK_ID)socket.irpData.arg2;
				socket.connection.getScheduler().updateTask(taskId, status);
			}, taskId));
		ASSERT(NT_SUCCESS(status));
		if (!NT_SUCCESS(status))
		{
			connection.getScheduler().updateTask(taskId, status);
		}
		return status;
	}

	void disconnect()
	{
		auto status = getConnectionDispatch()->WskDisconnect(handle, nullptr, 0, ResetIrp(*this, [](TCP_SOCKET<SESSION>& socket, NTSTATUS , ULONG_PTR )
			{
				socket.close();
			}));
		ASSERT(NT_SUCCESS(status));
	}

	void onDisconnect()
	{
		auto&& scheduler = connection.getScheduler();
		scheduler.runTask(SOCKET_CLOSE_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				auto&& socket = *(TCP_SOCKET<SESSION>*)context;
				if (socket.handle)
				{
					socket.disconnect();
				}
			}, this));
	}

	void onSendBacklog(SIZE_T size)
	{
		UNREFERENCED_PARAMETER(size);
	}
};

template <typename SESSION>
struct UDP_SOCKET
{
	SESSION& session;
	PWSK_SOCKET handle = nullptr;;

	WSK_CLIENT_DATAGRAM_DISPATCH clientDispatch;
	IRPTYPE irpData;
	MDLTYPE mdlData;

	SOCKADDR_IN localAddress;
	SOCKADDR_IN remoteAddress;

	bool match(SOCKADDR_IN& other) const
	{
		return localAddress.sin_addr.s_addr == other.sin_addr.s_addr;
	}
	constexpr explicit operator bool() const { return IsValidRef(*this); }

	WSK_PROVIDER_DATAGRAM_DISPATCH& getDispatch()
	{
		return *(PWSK_PROVIDER_DATAGRAM_DISPATCH)handle->Dispatch;
	}

	UDP_SOCKET(SESSION& sessionArg) : session(sessionArg) {}

	template <typename TASK>
	NTSTATUS open(TASK&& task)
	{
		auto taskId = session.getScheduler().queueTask(SOCKET_CONTROL_PRIORITY + 1, task);
		clientDispatch.WskReceiveFromEvent = WskReceiveFrom<UDP_SOCKET<SESSION>>;
		auto status = GetProviderDispatch().WskSocket(WskInfo.providerContext, AF_INET, SOCK_DGRAM, IPPROTO_UDP, WSK_FLAG_DATAGRAM_SOCKET, this, &clientDispatch, nullptr, nullptr, nullptr, ResetIrp(*this, [](UDP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR information)
			{
				ASSERT(NT_SUCCESS(status));
				auto taskId = (TASK_ID)socket.irpData.arg1;
				if (NT_SUCCESS(status))
				{
					socket.handle = (PWSK_SOCKET)information;
				}
				socket.session.getScheduler().updateTask(taskId, status);
			}, taskId));
		ASSERT(NT_SUCCESS(status));
		if (!NT_SUCCESS(status))
		{
			session.getScheduler().updateTask(taskId, status);
		}
		return status;
	}

	template <typename TASK>
	NTSTATUS bind(SOCKADDR_IN& address, TASK&& task)
	{
		auto taskId = session.getScheduler().queueTask(SOCKET_CONTROL_PRIORITY, task);
		auto status = open(STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
			{
				ASSERT(NT_SUCCESS(status));
				auto& socket = *(UDP_SOCKET<SESSION>*)context;
				auto address = argv.read<PSOCKADDR>();
				auto taskId = argv.read<TASK_ID>();
				status = socket.getDispatch().WskBind(socket.handle, (PSOCKADDR)address, 0, ResetIrp(socket, [](UDP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR information)
					{
						UNREFERENCED_PARAMETER(information);
						ASSERT(status == STATUS_SUCCESS);
						auto taskId = (TASK_ID)socket.irpData.arg1;
						if (status == STATUS_SUCCESS)
						{
							socket.getDispatch().WskGetLocalAddress(socket.handle, (PSOCKADDR)& socket.localAddress, ResetIrp(socket, [](UDP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR information)
								{
									UNREFERENCED_PARAMETER(information);
									auto taskId = (TASK_ID)socket.irpData.arg1;
									ASSERT(taskId);
									ASSERT(status == STATUS_SUCCESS);
									LogInfo(" bind complete - 0x%x", socket.localAddress.sin_addr.s_addr);
									socket.session.getScheduler().updateTask(taskId, status);
								}, taskId));
						}
						else
						{
							LogInfo(" bind complete - bind failed async\n");
							socket.session.getScheduler().updateTask(taskId, status);
						}
					}, taskId));
				ASSERT(NT_SUCCESS(status));
				if (!NT_SUCCESS(status))
				{
					LogInfo(" bind complete - bind failed\n");
					socket.session.getScheduler().updateTask(taskId, status);
				}
			}, this, &address, taskId));
		return status;
	}

	NTSTATUS initialize(SOCKADDR_IN& address)
	{
		localAddress = address;
		localAddress.sin_port = HTONS(55555); // XXX TEMP!!!!!!
		return bind(localAddress, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				auto& socket = *(UDP_SOCKET<SESSION>*)context;
				LogInfo("TEST: setting active socket, port=%d", HTONS(socket.localAddress.sin_port));
				socket.session.activeSocket = &socket; // XXX REMOVE
			}, this));
	}

	void onReceiveFrom(PWSK_DATAGRAM_INDICATION dataIndication)
	{
		remoteAddress = *(SOCKADDR_IN *)dataIndication->RemoteAddress;
		auto&& scheduler = session.getScheduler();
		for (auto ptr = dataIndication; ptr; ptr = ptr->Next)
		{
			auto&& buffer = ptr->Buffer;
			scheduler.runTask(SOCKET_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto&& socket = *(UDP_SOCKET<SESSION>*)context;
					auto&& buffer = argv.read<PWSK_BUF>();
					auto&& remoteAddress = argv.read<PSOCKADDR_IN>();

					auto address = ((PUINT8)MmGetSystemAddressForMdlSafe(buffer->Mdl, HighPagePriority)) + buffer->Offset;
					socket.session.onReceiveFrom(socket, BUFFER(address, (UINT32)buffer->Length), *remoteAddress);
				}, this, &buffer, dataIndication->RemoteAddress));
		}

		scheduler.runTask(SOCKET_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto&& socket = *(UDP_SOCKET<SESSION>*)context;
				auto dataIndication = argv.read<PWSK_DATAGRAM_INDICATION>();
				socket.getDispatch().WskRelease(socket.handle, dataIndication);
			}, this, dataIndication));
	}

	template <typename TASK>
	NTSTATUS sendTo(BUFFER sendData, SOCKADDR_IN& remoteAddress, TASK&& task)
	{
		LogInfo("SendTo %d bytes", sendData.length());
		auto taskId = session.getScheduler().queueTask(SOCKET_SEND_PRIORITY, task);
		auto buf = ResetMdl(*this, sendData);
		auto status = getDispatch().WskSendTo(handle, &buf, 0, (PSOCKADDR)& remoteAddress, 0, nullptr, ResetIrp(*this, [](UDP_SOCKET<SESSION>& socket, NTSTATUS status, ULONG_PTR)
			{
				ClearMdl(socket);
				auto taskId = (TASK_ID)socket.irpData.arg1;
				socket.session.getScheduler().updateTask(taskId, status);
			}, taskId));
		return status;
	}

	template <typename TASK>
	NTSTATUS sendTo(BUFFER sendData, TASK&& task)
	{
		return sendTo(sendData, remoteAddress, task);
	}
};

template <typename SERVER, typename SESSION>
NTSTATUS WskAccept(PVOID context, ULONG flags, PSOCKADDR localAddress, PSOCKADDR remoteAddress, PWSK_SOCKET acceptSocket,
	PVOID* acceptSocketContext, CONST WSK_CLIENT_CONNECTION_DISPATCH** acceptSocketDispatch)
{
	LogInfo("WskAccept invoked");
	UNREFERENCED_PARAMETER(flags);
	auto&& listener = *(LISTEN_SOCKET<SERVER, SESSION>*)context;
	listener.onAccept(localAddress, remoteAddress, acceptSocket, acceptSocketContext, acceptSocketDispatch);
	return STATUS_SUCCESS;
}

template <typename SERVER, typename SESSION>
struct LISTEN_SOCKET
{
	SERVER& server;
	WSK_CLIENT_LISTEN_DISPATCH clientDispatch;
	PWSK_SOCKET handle;
	IRPTYPE irpData;
	SOCKADDR_IN localAddress;

	WSK_PROVIDER_LISTEN_DISPATCH& getListenDispatch()
	{
		ASSERT(handle);
		return *(PWSK_PROVIDER_LISTEN_DISPATCH)handle->Dispatch;
	}

	LISTEN_SOCKET(SERVER& serverArg) : server(serverArg)
	{
		clientDispatch.WskAcceptEvent = WskAccept<SERVER, SESSION>;
		clientDispatch.WskAbortEvent = nullptr;
		clientDispatch.WskInspectEvent = nullptr;

		
		auto& provider = GetProviderDispatch();
		auto status = provider.WskSocket(WskInfo.providerContext, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			WSK_FLAG_LISTEN_SOCKET, this, &clientDispatch, nullptr, nullptr, nullptr, ResetIrp(*this, [](LISTEN_SOCKET<SERVER, SESSION>& listener, NTSTATUS status, ULONG_PTR information)
			{
				if (status == STATUS_SUCCESS)
				{
					listener.handle = (PWSK_SOCKET)information;
				}
			}));
		ASSERT(NT_SUCCESS(status));
	}

	template <typename TASK>
	NTSTATUS listen(UINT16 port, TASK&& task)
	{
		auto taskId = server.getScheduler().queueTask(SOCKET_CONTROL_PRIORITY, task);

		SOCKADDR_IN bindAddress;
		bindAddress.sin_family = AF_INET;
		bindAddress.sin_port = HTONS(port);
		bindAddress.sin_addr.s_addr = 0;

		auto status = getListenDispatch().WskBind(handle, (PSOCKADDR)& bindAddress, 0, ResetIrp(*this, [](LISTEN_SOCKET<SERVER, SESSION>& listener, NTSTATUS status, ULONG_PTR)
		{
			ASSERT(status == STATUS_SUCCESS);
			auto taskId = (TASK_ID)listener.irpData.arg1;
			if (status == STATUS_SUCCESS)
			{
				listener.getListenDispatch().WskGetLocalAddress(listener.handle, (PSOCKADDR)& listener.localAddress, ResetIrp(listener, [](LISTEN_SOCKET<SERVER, SESSION>& listener, NTSTATUS status, ULONG_PTR information)
					{
						UNREFERENCED_PARAMETER(listener);
						UNREFERENCED_PARAMETER(information);
						auto taskId = (TASK_ID)listener.irpData.arg1;
						ASSERT(taskId);
						ASSERT(status == STATUS_SUCCESS);
						listener.server.getScheduler().updateTask(taskId, status);
					}, taskId));
			}
			else
			{
				listener.server.getScheduler().updateTask(taskId, status);
			}
		}, taskId));
		return status;
	}

	NTSTATUS onAccept(PSOCKADDR local, PSOCKADDR remote, PWSK_SOCKET acceptSocket, PVOID* acceptSocketContext, CONST WSK_CLIENT_CONNECTION_DISPATCH** acceptSocketDispatch)
	{
		auto&& dataSocket = server.onNewConnection(acceptSocket, (SOCKADDR_IN *)local, (SOCKADDR_IN*)remote);
		dataSocket.handle = acceptSocket;

		*acceptSocketContext = &dataSocket;
		*acceptSocketDispatch = &dataSocket.clientDispatch;

		return STATUS_SUCCESS;
	}
};

/*
struct STP_SOCKET
{
	SOCKADDR_IN remoteAddress;

	PWSK_SOCKET handle;
	WSK_CLIENT_DATAGRAM_DISPATCH clientDispatch;
	IRPTYPE irpData;
	MDLTYPE mdlData;

	WSK_PROVIDER_DATAGRAM_DISPATCH& getDispatch()
	{
		return *(PWSK_PROVIDER_DATAGRAM_DISPATCH)handle->Dispatch;
	}

	NTSTATUS open()
	{
		clientDispatch.WskReceiveFromEvent = WskReceiveFrom<STP_SOCKET>;
		auto status = GetProviderDispatch().WskSocket(WskInfo.providerContext, AF_INET, SOCK_RAW, IPPROTO_SCTP, WSK_FLAG_DATAGRAM_SOCKET, this, &clientDispatch, nullptr, nullptr, nullptr, ResetIrp(*this, [](STP_SOCKET& stpSocket, NTSTATUS status, ULONG_PTR information)
			{
				ASSERT(status == STATUS_SUCCESS);
				if (status == STATUS_SUCCESS)
				{
					stpSocket.handle = (PWSK_SOCKET)information;
					stpSocket.getDispatch().Basic.WskControlSocket(stpSocket.handle, )
				}
			}));
		ASSERT(NT_SUCCESS(status));
		return status;
	}

	void onReceiveFrom(PWSK_DATAGRAM_INDICATION dataIndication)
	{
		remoteAddress = *(SOCKADDR_IN*)dataIndication->RemoteAddress;
		for (auto ptr = dataIndication; ptr; ptr = ptr->Next)
		{
			auto&& buffer = ptr->Buffer;
			auto address = ((PUINT8)MmGetSystemAddressForMdlSafe(buffer.Mdl, HighPagePriority)) + buffer.Offset;
			BUFFER recvData{ address, buffer.Length };

			auto ipHeader = recvData.readBytes(20);
			ASSERT(ipHeader.readByte() == 0x45);
		}
	}

	void close()
	{
		getDispatch().Basic.WskCloseSocket(handle, ResetIrp(*this, [](STP_SOCKET& stpSocket, NTSTATUS status, ULONG_PTR information)
			{
				ASSERT(NT_SUCCESS(status));
				stpSocket.handle = nullptr;
			}));
	}
};
*/