#pragma once
#include "Driver.h"
#include "Storage.h"

constexpr UINT32 SYNC_MSG_HEADER = 8;
constexpr UINT32 SYNC_CONTROL_CHANNEL = 5;

constexpr UINT32 SYNC_BASE_PRIORITY = 0;
constexpr UINT32 SYNC_RECEIVE_PRIORITY = 2;
constexpr UINT32 SYNC_SEND_PRIORITY = 4;

constexpr UINT32 SYNC_DATA_MTU = 1460;

using S3TOKEN_BUFFER = STREAM_READER<VISUAL_TOKEN>;

struct SYNC_COMMAND
{
	TOKEN appId;
	TOKEN objectId;

	TOKEN scope;
	VISUALBUFFER scopeData;

	TOKEN oldTimestamp;
	TOKEN newTimestamp;

	UINT64 diskOffset;
	UINT32 commandSize;
	UINT32 volumeId;
};

struct SYNC_OBJECT
{
	TOKEN objectId;
	STREAM_BUILDER<SYNC_COMMAND, SERVICE_STACK, 512> commandStream;

	SYNC_OBJECT(TOKEN objectIdArg) : objectId(objectIdArg) {}

	bool match(TOKEN other) const { return objectId == other; }

	explicit operator bool() const { return IsValidRef(*this); }

	const SYNC_COMMAND& findCommand(TOKEN scopeId)
	{
		for (auto& command : commandStream.toBuffer())
		{
			if (command.scope == scopeId)
			{
				return command;
			}
		}
		return NullRef<SYNC_COMMAND>();
	}
};

template <typename STACK, UINT32 SIZE>
using COMMAND_STREAM = STREAM_BUILDER<SYNC_COMMAND, STACK, SIZE>;

using COMMAND_BUFFER = STREAM_READER<const SYNC_COMMAND>;

struct QOS
{
	// in kilobytes per second
	UINT32 baseBitRate;
	UINT32 peakBitRate = 0;
	UINT32 peakDuration = 0;

	QOS(UINT32 baseRate) : baseBitRate(baseRate) {}
	QOS(QOS& other) : baseBitRate(other.baseBitRate), peakBitRate(other.peakBitRate), peakDuration(other.peakDuration) {}
};

constexpr UINT32 SHAPER_QUEUE_SIZE = 128;
constexpr UINT32 SHAPER_QUEUE_MASK = ~(SHAPER_QUEUE_SIZE - 1);

constexpr UINT16 SYNC_DATA_FLAG_BEGIN = 0x0001;
constexpr UINT16 SYNC_DATA_FLAG_END = 0x0002;

constexpr UINT32 SYNC_MAX_DATA_LENGTH = 32 * 1024 * 1024;

template <typename SERVICE>
struct SYNC_SESSION
{
	struct TRANSMIT_CHANNEL
	{
		UINT32 channelId;
		UINT32 messageId = 0;

		SYNC_SESSION<SERVICE>& session;
		QOS qos;

		UINT32 transmitQueueRead = 0;
		UINT32 transmitQueueWrite = 0;
		BYTESTREAM* transmitQueue[SHAPER_QUEUE_SIZE];

		KTIMER sendTimer;
		KDPC sendDpc;

		UINT32 tickInterval; // in ms
		UINT32 packetsPerTick;
		UINT32 packetsPerSecond;

		BCRYPT_KEY_HANDLE aesKey = nullptr;
		UINT8 aesIV[AES_IV_LENGTH] = { 0 };

		TRANSMIT_CHANNEL(SYNC_SESSION<SERVICE>& sessionArg, UINT32 channelIdArg, QOS qosArg) : session(sessionArg), channelId(channelIdArg), qos(qosArg)
		{
			packetsPerSecond = (qos.baseBitRate * 1000) / 1500;
			tickInterval = 1000 / packetsPerSecond;
			packetsPerTick = packetsPerSecond > 1000 ? packetsPerSecond / 1000 : 1;

			KeInitializeTimer(&sendTimer);
			KeInitializeDpc(&sendDpc, sendDpcRoutine, this);
		}

		template <typename STREAM>
		NTSTATUS encrypt(STREAM&& outStream)
		{
			auto status = STATUS_SUCCESS;
			if (aesKey)
			{
				outStream.commit(AES_TAG_LENGTH);
				auto outData = outStream.toBuffer();

				outData.shift(ETH_LENGTH_OF_HEADER);
				auto authData = outData.readBytes(SYNC_MSG_HEADER);
				auto tag = outData.shrink(AES_TAG_LENGTH);

				LOCAL_STREAM<AES_IV_LENGTH> ivData;
				ivData.writeBE<UINT32>(0);
				ivData.writeStream(authData);

				XorData(ivData.address(), aesIV, AES_IV_LENGTH);

				status = AES.encrypt(aesKey, outData, authData, ivData.toBuffer(), tag);
			}
			return status;
		}

		void startTimer()
		{
			KeSetTimerEx(&sendTimer, MS_TO_TIMEUNITS(tickInterval), tickInterval, &sendDpc);
		}

		void queueTransmitFrame(BYTESTREAM* frame)
		{
			for (;;)
			{
				auto currentIndex = transmitQueueWrite;
				auto nextIndex = (currentIndex + 1) & SHAPER_QUEUE_MASK;

				if (InterlockedCompareExchange((LONG*)&transmitQueueWrite, nextIndex, currentIndex) == (LONG)currentIndex)
				{
					transmitQueue[currentIndex] = frame;
					break;
				}
			}

			if (sendTimer.Dpc == nullptr)
			{
				startTimer();
			}
		}

		BYTESTREAM* dequeueTransmitFrame()
		{
			BYTESTREAM* result = nullptr;

			if (transmitQueueRead != transmitQueueWrite)
			{
				result = transmitQueue[transmitQueueRead];
				transmitQueueRead = (transmitQueueRead + 1) & SHAPER_QUEUE_MASK;
			}
			return result;
		}

		void sendNextFrame()
		{
			auto nextFrame = dequeueTransmitFrame();
			if (nextFrame)
			{
				SendToAdapter(session.adapter, *nextFrame);
			}
			else
			{
				KeCancelTimer(&sendTimer);
				sendTimer.Dpc = nullptr;
			}
		}

		static void sendDpcRoutine(PKDPC, PVOID context, PVOID, PVOID)
		{
			auto& channel = *(TRANSMIT_CHANNEL*)context;
			channel.sendNextFrame();
		}

		void sendData(BUFFER dataBuffer)
		{
			auto msgId = messageId++;
			dataBuffer = dataBuffer.rebase();

			auto flag = SYNC_DATA_FLAG_BEGIN;
			while (dataBuffer)
			{
				auto& sendStream = AllocateAdapterBuffer();
				session.writeMacHeader(sendStream);

				sendStream.writeBE<UINT32>(channelId);
				sendStream.writeBE<UINT32>(msgId);

				auto transferLength = min(SYNC_DATA_MTU, dataBuffer.length());

				flag |= ((dataBuffer.length() - transferLength) == 0) ? SYNC_DATA_FLAG_END : 0;
				sendStream.writeBE<UINT16>(flag);

				auto packetOffset = flag & SYNC_DATA_FLAG_BEGIN ? dataBuffer.length() : dataBuffer._start;
				sendStream.writeBE<UINT32>(packetOffset);

				sendStream.writeBytes(dataBuffer.readBytes(transferLength));

				encrypt(sendStream);

				queueTransmitFrame(&sendStream);
				flag = 0;
			}
		}

		bool match(UINT32 id)
		{
			return channelId == id;
		}

		explicit operator bool() const { return IsValidRef(*this); }
	};

	struct RECEIVE_CHANNEL
	{
		struct FRAGMENT
		{
			UINT32 offset;
			UINT32 size;

			FRAGMENT(UINT32 offsetArg, UINT32 sizeArg) : offset(offsetArg), size(sizeArg) {}
		};

		struct REASSEMBLY_BUFFER
		{
			UINT32 messageId;
			UINT32 packetSize = 0;
			STREAM_BUILDER<UINT8, SESSION_STACK, 64 * 1024> reassemblyStream;
			STREAM_BUILDER<FRAGMENT, SESSION_STACK, 16> fragmentStream;

			void initialize(UINT32 msgId)
			{
				messageId = msgId;
				fragmentStream.clear();
				reassemblyStream.clear();
				reassemblyStream.commit(reassemblyStream.size());
			}

			void setPacketSize(UINT32 size)
			{
				if (size > reassemblyStream.size())
				{
					reassemblyStream.commit(size - reassemblyStream.size());
				}
				packetSize = size;
			}

			void addFragment(UINT32 offset, BUFFER fragmentData)
			{
				RtlCopyMemory(reassemblyStream.address(offset), fragmentData.data(), fragmentData.length());

				auto merged = false;
				for (auto& fragment : fragmentStream.toBufferNoConst())
				{
					if (fragment.offset + fragment.size == offset)
					{
						fragment.size += fragmentData.length();
						merged = true;
						break;
					}
				}

				if (merged == false)
				{
					fragmentStream.append(offset, fragmentData.length());
				}
			}

			bool isComplete()
			{
				UINT32 sizeTotal = 0;
				for (auto& fragment : fragmentStream.toBuffer())
				{
					sizeTotal += fragment.size;
				}
				return sizeTotal == packetSize;
			}

			BUFFER getPacket()
			{
				if (isComplete() == false)
				{
					DBGBREAK();
					return BUFFER();
				}

				messageId = 0; // can be reused
				return BUFFER{ reassemblyStream.address(), packetSize };
			}
		};

		BCRYPT_KEY_HANDLE aesKey = nullptr;
		UINT8 aesIV[AES_IV_LENGTH] = { 0 };

		UINT32 channelId;
		SYNC_SESSION<SERVICE>& service;
		STREAM_BUILDER<REASSEMBLY_BUFFER, SESSION_STACK, 1> reassemblyQueue;

		RECEIVE_CHANNEL(SYNC_SESSION<SERVICE>& serviceArg, UINT32 channelIdArg) : service(serviceArg), channelId(channelIdArg) {}

		REASSEMBLY_BUFFER& getReassemblyBuffer(UINT32 msgId)
		{
			for (auto& buffer : reassemblyQueue.toBufferNoConst())
			{
				if (buffer.messageId == msgId)
				{
					return buffer;
				}
			}

			for (auto& buffer : reassemblyQueue.toBufferNoConst())
			{
				if (buffer.messageId == 0)
				{
					buffer.initialize(msgId);
					return buffer;
				}
			}

			auto& buffer = reassemblyQueue.append();
			buffer.initialize(msgId);
			return buffer;
		}

		BUFFER decrypt(BUFFER recvData)
		{
			auto authData = recvData.readBytes(SYNC_MSG_HEADER);
			if (aesKey)
			{
				auto tag = recvData.shrink(AES_TAG_LENGTH);

				LOCAL_STREAM<AES_IV_LENGTH> ivData;
				ivData.writeBE<UINT32>(0);
				ivData.writeStream(authData);

				XorData(ivData.address(), aesIV, AES_IV_LENGTH);

				auto status = AES.decrypt(aesKey, recvData, authData, ivData.toBuffer(), tag);
				ASSERT(NT_SUCCESS(status));
			}
			return recvData;
		}

		BUFFER assembleData(BUFFER recvData, UINT32 msgId)
		{
			BUFFER assembledData;

			recvData = decrypt(recvData);

			auto flag = recvData.readBE<UINT16>();
			auto dataOffset = recvData.readBE<UINT32>();

			auto& fragmentBuffer = getReassemblyBuffer(msgId);
			if (flag & SYNC_DATA_FLAG_BEGIN)
			{
				fragmentBuffer.setPacketSize(dataOffset);
				dataOffset = 0;
			}
			fragmentBuffer.addFragment(dataOffset, recvData);
			if (flag & SYNC_DATA_FLAG_END)
			{
				assembledData = fragmentBuffer.getPacket();
			}
			return assembledData;
		}

		bool match(UINT32 id)
		{
			return channelId == id;
		}

		explicit operator bool() const { return IsValidRef(*this); }
	};

	SERVICE& service;
	SYNC_SESSION(SERVICE& inAgent, const ADAPTER_INFO& inAdapter) : 
		service(inAgent), adapter(inAdapter), scheduler(*this)
	{}

	bool initSent = false;
	TOKEN destinationId = Null;
	STREAM_BUILDER<TOKEN, SESSION_STACK, 4> destinationMac;

	STREAM_BUILDER<TRANSMIT_CHANNEL, SESSION_STACK, 32> transmitChannelStream;
	STREAM_BUILDER<RECEIVE_CHANNEL, SESSION_STACK, 32> receiveChannelStream;

	TRANSMIT_CHANNEL& getTransmitChannel(UINT32 channelId)
	{
		return transmitChannelStream.toBufferNoConst().find(channelId);
	}

	RECEIVE_CHANNEL& getReceiveChannel(UINT32 channelId)
	{
		return receiveChannelStream.toBufferNoConst().find(channelId);
	}

	SESSION_STACK stack;
	SCHEDULER_INFO<SYNC_SESSION<SERVICE>> scheduler;
	
	const ADAPTER_INFO& adapter;

	X25519_KEYSHARE keyshare;
	NTSTATUS initialize()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			status = scheduler.initialize();
			VERIFY_STATUS;

			status = InitializeStack(stack, 16 * 1024 * 1024, 0);
			VERIFY_STATUS;

			transmitChannelStream.append(*this, SYNC_CONTROL_CHANNEL, QOS(500));
			receiveChannelStream.append(*this, SYNC_CONTROL_CHANNEL);
		} while (false);

		return status;
	}

	BUFFER getDestinationMac()
	{
		return GetBlobData(destinationMac.at(0));
	}

	template <typename STREAM>
	void writeMacHeader(STREAM&& frameStream)
	{
		frameStream.writeBytes(getDestinationMac());
		frameStream.writeBytes(adapter.macAddress, MAC_ADDRESS_LENGTH);
		frameStream.writeBE<UINT16>(ETHERTYPE_SYNC);
	}

	void generateKeys()
	{
		ASSERT(keyshare.sharedSecret.count() == X25519_KEY_LENGTH);

		auto guidData = GetBlobData(service.systemId);
		LOCAL_STREAM<SHA256_HASH_LENGTH> byteStream;
		auto status = BCryptHash(Algorithms.hmacSha256, keyshare.sharedSecret.address(), X25519_KEY_LENGTH, (PUCHAR)guidData.data(), guidData.length(), byteStream.commit(SHA256_HASH_LENGTH), SHA256_HASH_LENGTH);
		ASSERT(NT_SUCCESS(status));
		
		auto& transmitChannel = getTransmitChannel(SYNC_CONTROL_CHANNEL);
		auto hashData = byteStream.toBuffer();
		status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &transmitChannel.aesKey, nullptr, 0, (PUCHAR)hashData.readBytes(AES128_KEY_LENGTH).data(), AES128_KEY_LENGTH, 0);
		ASSERT(NT_SUCCESS(status));

		RtlCopyMemory(transmitChannel.aesIV, hashData.readBytes(AES_IV_LENGTH).data(), AES_IV_LENGTH);

		auto& receiveChannel = getReceiveChannel(SYNC_CONTROL_CHANNEL);
		guidData = GetBlobData(destinationId);
		byteStream.clear();

		status = BCryptHash(Algorithms.hmacSha256, keyshare.sharedSecret.address(), X25519_KEY_LENGTH, (PUCHAR)guidData.data(), guidData.length(), byteStream.commit(SHA256_HASH_LENGTH), SHA256_HASH_LENGTH);
		ASSERT(NT_SUCCESS(status));
		hashData = byteStream.toBuffer();

		status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &receiveChannel.aesKey, nullptr, 0, (PUCHAR)hashData.readBytes(AES128_KEY_LENGTH).data(), AES128_KEY_LENGTH, 0);
		ASSERT(NT_SUCCESS(status));

		RtlCopyMemory(receiveChannel.aesIV, hashData.readBytes(AES_IV_LENGTH).data(), AES_IV_LENGTH);
	}

	void onControlMessage(BUFFER recvFrame)
	{
		while (recvFrame)
		{
			auto message = ReadNameToken<SERVICE_STACK>(recvFrame);

			if (message.name == SYNC_Init)
			{
				auto signature = recvFrame.shrink(ECDSA_SIGN_LENGTH);
				auto hashMessage = recvFrame;
				BUFFER certificateData;

				while (auto typeData = ReadNameToken<SERVICE_STACK>(recvFrame))
				{
					if (typeData.name == SYNC_Destination)
					{
						auto guidHandle = CreateGuidHandle<SERVICE_STACK>(typeData.valueData.readGuid());
						ASSERT(guidHandle == service.systemId);
					}
					else if (typeData.name == SYNC_Source)
					{
						if (destinationId)
						{
							ASSERT(destinationId == typeData.value);
						}
						else
						{
							destinationId = typeData.value;
						}
					}
					else if (typeData.name == SYNC_ECDH_x25519)
					{
						keyshare.createSecret(typeData.valueData);
					}
					else if (typeData.name == SYNC_ECDSA)
					{
						certificateData = typeData.valueData;
					}
					else DBGBREAK();
				}

				ASSERT(certificateData);

				auto taskId = scheduler.queueTask(SYNC_RECEIVE_PRIORITY + 1, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS)
					{
						ASSERT(NT_SUCCESS(status));
						auto& session = *(SYNC_SESSION<SERVICE>*)context;

						session.generateKeys();
						if (session.initSent == false && session.destinationId)
						{
							session.connect();
							session.service.onNewSession(session);
						}
					}, this));

				SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
					{
						auto& session = *(SYNC_SESSION<SERVICE>*)context;
						auto initData = argv.read<BUFFER>();
						auto certificateData = argv.read<BUFFER>();
						auto signature = argv.read<BUFFER>();
						auto taskId = argv.read<TASK_ID>();

						LOCAL_STREAM<SHA256_HASH_LENGTH> hashData;
						auto status = BCryptHash(Algorithms.hashSha256, nullptr, 0, (PUCHAR)initData.data(), initData.length(), hashData.commit(SHA256_HASH_LENGTH), SHA256_HASH_LENGTH);
						ASSERT(NT_SUCCESS(status));

						auto verifiedStatus = STATUS_SUCCESS;

						CERTIFICATE certificate;
						status = ParseX509(certificateData, certificate);
						ASSERT(NT_SUCCESS(status));

						status = BCryptVerifySignature(certificate.keyHandle, nullptr, hashData.address(), hashData.count(), (PUCHAR)signature.data(), signature.length(), 0);
						ASSERT(NT_SUCCESS(status));
						if (!NT_SUCCESS(status))
							verifiedStatus = STATUS_AUTH_TAG_MISMATCH;

						session.scheduler.updateTask(taskId, verifiedStatus);

					}, this, hashMessage, certificateData, signature, taskId));
			}
			else if (message.name == SYNC_command)
			{
				DBGBREAK();
			}
			else DBGBREAK();
		}
	}

	void onReceive(BUFFER recvFrame)
	{
		auto msgHeader = recvFrame.clone().readBytes(SYNC_MSG_HEADER);

		auto channelId = msgHeader.readBE<UINT32>();
		auto msgId = msgHeader.readBE<UINT32>();

		auto& channel = getReceiveChannel(channelId);
		auto recvData = channel.assembleData(recvFrame, msgId);

		if (recvData)
		{
			scheduler.runTask(SYNC_RECEIVE_PRIORITY + 1, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto& session = *(SYNC_SESSION<SERVICE>*)context;
					auto channelId = argv.read<UINT32>();
					BUFFER recvData = argv.read<BUFFER>();

					if (channelId == SYNC_CONTROL_CHANNEL)
					{
						session.onControlMessage(recvData);
					}
					else
					{
						DBGBREAK();
					}
				}, this, channelId, recvData));
		}
	}

	void connect()
	{
		SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS )
			{
				auto& session = *(SYNC_SESSION<SERVICE>*)context;
				TBYTESTREAM dataStream;
				dataStream.reserve(1450);

				DBGBREAK();

				KEVENT syncEvent;
				KeInitializeEvent(&syncEvent, SynchronizationEvent, FALSE);

				WriteNameToken(dataStream, SYNC_Init, [](TBYTESTREAM& dataStream, SYNC_SESSION<SERVICE>& session, PKEVENT syncEvent)
					{
						auto msgStart = dataStream.count();

						session.scheduler.runTask(SYNC_SEND_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
							{
								auto& session = *(SYNC_SESSION<SERVICE>*)context;
								auto& dataStream = *argv.read<TBYTESTREAM*>();
								auto syncEvent = argv.read<PKEVENT>();

								WriteNameToken(dataStream, SYNC_Source, session.service.systemId);
								WriteNameToken(dataStream, SYNC_Destination, [](TBYTESTREAM& dataStream, SYNC_SESSION<SERVICE>& session)
									{
										dataStream.writeBytes(GetBlobData(session.destinationId));
										for (auto& token : session.destinationMac.toBuffer())
										{
											auto data = GetBlobData(token);
											dataStream.writeBytes(data);
										}
									}, session);

								KeSetEvent(syncEvent, 0, FALSE);
							}, &session, &dataStream, &syncEvent));
						KeWaitForSingleObject(&syncEvent, Executive, KernelMode, FALSE, nullptr);

						WriteNameToken(dataStream, SYNC_ECDH_x25519, [](TBYTESTREAM& dataStream, SYNC_SESSION<SERVICE>& session)
							{
								session.keyshare.getPublicKey(dataStream);
							}, session);

						WriteNameToken(dataStream, SYNC_ECDSA, session.service.certificateBytes);

						LOCAL_STREAM<SHA256_HASH_LENGTH> hashData;

						auto messageData = dataStream.toBuffer(msgStart);
						auto status = BCryptHash(Algorithms.hashSha256, nullptr, 0, (PUCHAR)messageData.data(), messageData.length(), hashData.commit(SHA256_HASH_LENGTH), SHA256_HASH_LENGTH);
						ASSERT(NT_SUCCESS(status));

						ULONG bytesWritten;
						status = BCryptSignHash(session.service.certificateKey, nullptr, hashData.address(), hashData.count(), dataStream.commit(ECDSA_SIGN_LENGTH), ECDSA_SIGN_LENGTH, &bytesWritten, 0);
						ASSERT(NT_SUCCESS(status));
					}, session, &syncEvent);

				session.scheduler.runTask(SYNC_SEND_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
					{
						auto& session = *(SYNC_SESSION<SERVICE>*)context;
						auto& dataStream = *argv.read<TBYTESTREAM*>();
						auto syncEvent = argv.read<PKEVENT>();

						auto& channel = session.getTransmitChannel(SYNC_CONTROL_CHANNEL);
						channel.sendData(dataStream.toBuffer());
						session.initSent = true;
						KeSetEvent(syncEvent, 0, FALSE);
					}, &session, &dataStream, &syncEvent));
				KeWaitForSingleObject(&syncEvent, Executive, KernelMode, FALSE, nullptr);
			}, this));
	}

	bool operator == (TOKEN matchToken)
	{
		if (matchToken.isGuid())
			return destinationId == matchToken;
		else if (matchToken.isMacAddress())
			return destinationMac.toBuffer().exists(matchToken);
		else DBGBREAK();
		return false;
	}

	bool match(TOKEN matchToken)
	{
		if (matchToken.isGuid())
			return destinationId == matchToken;
		else if (matchToken.isMacAddress())
			return destinationMac.toBuffer().exists(matchToken);
		else DBGBREAK();
		return false;
	}

	explicit operator bool() const { return IsValidRef(*this); }
};

constexpr UINT8 LLDP_CHASSIS = 0x02;
constexpr UINT8 LLDP_PORT = 0x04;
constexpr UINT8 LLDP_TTL = 0x06;
constexpr UINT8 LLDP_CUSTOM = 0xFE;
constexpr UINT8 LLDP_SYSTEM_NAME = 0x0A;

constexpr UINT8 LLDP_OUI_DATA[3] = { 0x00ul, 0x15, 0x5d };
constexpr BUFFER LLDP_OUI = LLDP_OUI_DATA;
constexpr UINT8 LLDP_SYSTEM_ID = 0x11;

enum class MACADDRESS_TYPE
{
	UNKNOWN,
	UNICAST,
	SYNC_MULTICAST,
	DISCOVER_MULTICAST,
	MULTICAST,
	IPV4_MULTICAST,
	IPV6_MULTICAST,
	BROADCAST,
};

constexpr BUFFER SYNC_SERVICE_CERTIFICATE =
"MIICRzCCAe2gAwIBAgIURuwRzHE2YdcGgxqEVHCUqhm1t0wwCgYIKoZIzj0EAwIw"
"XDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdQdWxsbWFuMRYw"
"FAYDVQQKDA1OZXR3b3JrIFN0YXRlMRYwFAYDVQQDDA1OZXR3b3JrIFN0YXRlMB4X"
"DTE5MDYxMDE2MTExN1oXDTIyMDMwNjE2MTExN1oweTELMAkGA1UEBhMCVVMxCzAJ"
"BgNVBAgMAk1EMRAwDgYDVQQHDAdQdWxsbWFuMRYwFAYDVQQKDA1OZXR3b3JrIFN0"
"YXRlMRIwEAYDVQQDDAltZWRpYXNydjExHzAdBgkqhkiG9w0BCQEWEHRlc3RAZXhh"
"bXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATpOMmO4ROs0waD6ESO"
"XZmMZRGKedUaYq8vnci5YChiQpkKQOBOfkbL/dUaWy4K/0qP8cPnKw5LZX0F4Mdj"
"glzUo3AwbjAdBgNVHQ4EFgQU6wK3rm/rSZO2PsePNJ9LWovpsXAwHwYDVR0jBBgw"
"FoAUnzurX5pboo6FoKNFaJh/huLJUt4wCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAw"
"FAYDVR0RBA0wC4IJbWVkaWFzcnYxMAoGCCqGSM49BAMCA0gAMEUCIQDlnWYSwOrn"
"6UYVF7To+ut11d9p3/Eos9vOAiwCtlupYwIgZwzToDyg81QH33Lv4JS3XGkMiUqh"
"vK7ksMzi8xoJ+ho=";

constexpr BUFFER SYNC_SERVICE_KEY =
"MHcCAQEEIG3dCF2nFMKDShTNdsKtl2X7t/nGNgCnOKZ3o/59AJsboAoGCCqGSM49"
"AwEHoUQDQgAE6TjJjuETrNMGg+hEjl2ZjGURinnVGmKvL53IuWAoYkKZCkDgTn5G"
"y/3VGlsuCv9Kj/HD5ysOS2V9BeDHY4Jc1A==";

template <typename STREAM>
void WriteNameToken(STREAM&& dataStream, TOKEN name, TOKEN value)
{
	dataStream.writeBE<UINT16>(name.getShortName());
	dataStream.writeByte((UINT8)value.getFullType());
	if (value.isGuid())
	{
		dataStream.writeGuid(GetGuidHandleValue(value));
	}
	else if (value.isString())
	{
		auto offset = dataStream.count();
		dataStream.writeString(value);
		dataStream.writeLengthAt(offset);
	}
	else if (value.isNumber())
	{
		dataStream.writeVInt(GetNumberHandleValue(value));
	}
	else DBGBREAK();
}

template <typename STREAM>
void WriteNameToken(STREAM&& dataStream, TOKEN name, UINT64 number, TOKENTYPE tokenType = TOKENTYPE::NUMBER)
{
	dataStream.writeBE<UINT16>(name.getShortName());
	dataStream.writeByte((UINT8)tokenType);
	dataStream.writeVInt(number);
}

template <typename STREAM>
void WriteNameToken(STREAM&& dataStream, TOKEN name, BUFFER data)
{
	dataStream.writeBE<UINT16>(name.getShortName());
	dataStream.writeByte((UINT)TOKENTYPE::BLOB);
	ASSERT(data);
	dataStream.writeVInt(data.length());
	dataStream.writeBytes(data);
}

template <typename STREAM, typename FUNC, typename ... ARGS>
void WriteNameToken(STREAM&& dataStream, TOKEN name, FUNC callback, ARGS&& ... args)
{
	dataStream.writeBE<UINT16>(name.getShortName());
	dataStream.writeByte((UINT8)TOKENTYPE::BLOB);
	auto lengthOffset = dataStream.count();
	callback(dataStream, args ...);
	dataStream.writeLengthAt(lengthOffset);
}

template <typename STREAM>
static void AddPadding(STREAM&& dataStream)
{
	if (dataStream.count() < ETHERNET_MIN_FRAME_SIZE)
	{
		WriteNameToken(dataStream, SYNC_padding, BUFFER{ ZeroBytes.data(), ETHERNET_MIN_FRAME_SIZE });
	}
}

struct NAME_TOKEN
{
	TOKEN name = Null;
	TOKEN value = Null;
	BUFFER valueData{};

	explicit operator bool() const { return name.toBoolean(); }
};

template <typename STACK>
NAME_TOKEN ReadNameToken(BUFFER& dataBuffer)
{
	if (dataBuffer.length() == 0)
	{
		return NAME_TOKEN();
	}

	NAME_TOKEN nameValue;

	nameValue.name = MakeName(dataBuffer.readBE<UINT16>());
	auto valueType = (TOKENTYPE)dataBuffer.readByte();
	auto typeToken = TOKEN(valueType, 0);

	if (typeToken.isString())
	{
		auto valueLength = dataBuffer.readVInt();
		auto value = dataBuffer.readBytes((UINT32)valueLength);
		nameValue.value = String.parseLiteral<STACK>(value);
	}
	else if (typeToken.getMajorType() == TOKENTYPE::BLOB)
	{
		if (valueType == TOKENTYPE::BLOB_GUID)
		{
			nameValue.value = CreateGuidHandle<STACK>(dataBuffer.readGuid());
		}
		else
		{
			nameValue.value = Null;
			auto valueLength = dataBuffer.readVInt();
			nameValue.valueData = dataBuffer.readBytes((UINT32)valueLength);
		}
	}
	else
	{
		auto value = dataBuffer.readVInt();
		if (typeToken.getMajorType() == TOKENTYPE::NUMBER)
		{
			nameValue.value = CreateNumberHandle<STACK>(value);
		}
		else DBGBREAK();
	}

	return nameValue;
}

constexpr UINT32 MAX_DISKS = 8;

constexpr USTRING jsonSample1 = "";
constexpr USTRING jsonSample2 = "";

struct SYNC_SERVICE
{
	struct PATH_INFO
	{
		TOKEN pathId;

		STREAM_BUILDER<TOKEN, SERVICE_STACK, 32> tokenStream;
		STREAM_BUILDER<TOKEN_BUFFER, SERVICE_STACK, 4> objectStream;

		explicit operator bool() const { return IsValidRef(*this) && this->pathId; }
	};

	SERVICE_STACK serviceStack;
	SCHEDULER_INFO<SYNC_SERVICE> scheduler;

	CERTIFICATE certificate;
	BCRYPT_KEY_HANDLE certificateKey;

	STREAM_BUILDER<UINT8, SERVICE_STACK, 1024> certificateByteStream;
	BUFFER certificateBytes;

	KTIMER discoveryTimer;
	KDPC discoveryDpc;

	TOKEN systemId;
	TOKEN emptySectorId;
	TOKEN mediaAppId;
	STREAM_BUILDER<SYNC_OBJECT, SERVICE_STACK, 32> mediaObjectStream;
	auto mediaObjects() { return mediaObjectStream.toBuffer(); }

	STREAM_BUILDER<SYNC_SESSION<SYNC_SERVICE>, SERVICE_STACK, 64> sessionStream;
	auto sessionTable() { return sessionStream.toBufferNoConst(); }
	
	STREAM_BUILDER<PATH_INFO, SERVICE_STACK, 128> pathStream;
	auto pathTable() { return pathStream.toBufferNoConst(); }

	STREAM_BUILDER<STORAGE_VOLUME_INFO, GLOBAL_STACK, 4> diskVolumes;

	SYNC_SERVICE() : scheduler(*this) {}

	auto& findSession(TOKEN destinationAddress)
	{
		return sessionTable().find(destinationAddress);
	}

	auto& getWriteVolume()
	{
		return diskVolumes.at(0);
	}

	auto& getVolume(UINT32 id)
	{
		for (auto& volume : diskVolumes.toBufferNoConst())
		{
			if (volume.volumeId == id)
				return volume;
		}
		return NullRef<STORAGE_VOLUME_INFO>();
	}

	MACADDRESS_TYPE classifyFrame(const ADAPTER_INFO& adapter, BUFFER destination, BUFFER source)
	{
		UNREFERENCED_PARAMETER(source);
		auto addressType = MACADDRESS_TYPE::UNKNOWN;

		if (destination  == adapter.macAddress)
			addressType = MACADDRESS_TYPE::UNICAST;
		else if (destination == SYNC_LOCAL_MULTICAST || destination == SYNC_SUBNET_MULTICAST)
		{
			DBGBREAK();
			addressType = MACADDRESS_TYPE::SYNC_MULTICAST;
		}
		else if (destination == DISCOVER_MULTICAST)
		{
			DBGBREAK();
			addressType = MACADDRESS_TYPE::DISCOVER_MULTICAST;
		}
		else if (destination[0] == 0x33 && destination[1] == 0x33)
			addressType = MACADDRESS_TYPE::IPV6_MULTICAST;
		else if (destination[0] == 0x01 && destination[1] == 0x80 && destination[2] == 0xC2)
			addressType = MACADDRESS_TYPE::MULTICAST;
		else if (destination[0] == 0x01 && destination[1] == 0x00 && destination[2] == 0x5E)
			addressType = MACADDRESS_TYPE::IPV4_MULTICAST;
		else if (destination[0] == 0xFF && destination[1] == 0xFF && destination[2] == 0xFF)
			addressType = MACADDRESS_TYPE::BROADCAST;

		LogInfo("Destination:%02x:%02x:%02x:%02x:%02x:%02x", destination[0], destination[1], destination[2], destination[3], destination[4], destination[5]);

	}

	template <typename T>
	void onReceiveFrom(const ADAPTER_INFO& adapter, BUFFER recvFrame, T&& callback)
	{
		auto destination = recvFrame.readBytes(MAC_ADDRESS_LENGTH);
		auto sourceBytes = recvFrame.readBytes(MAC_ADDRESS_LENGTH);
		auto etherType = recvFrame.readBE<UINT16>();

		auto sourceMac = CreateMacAddressHandle<SERVICE_STACK>(sourceBytes);

		if (etherType == ETHERTYPE_DISCOVER)
		{
			parseDiscoveryPacket(adapter, recvFrame, sourceMac);
		}
		else if (etherType == ETHERTYPE_SYNC)
		{
			DBGBREAK();
			auto& sessionFound = findSession(sourceMac);
			auto session = sessionFound ? &sessionFound : nullptr;
			if (session == nullptr)
			{
				auto& newSession = sessionStream.append(*this, adapter);
					
				auto status = newSession.initialize();
				ASSERT(NT_SUCCESS(status));

				newSession.destinationMac.append(sourceMac);
				session = &newSession;
			}

			auto taskId = scheduler.queueTask(SYNC_RECEIVE_PRIORITY + 1, callback);
			session->scheduler.runTask(SYNC_RECEIVE_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto& session = *(SYNC_SESSION<SYNC_SERVICE>*)context;
					BUFFER recvFrame = argv.read<BUFFER>();
					session.onReceive(recvFrame);
					session.service.scheduler.updateTask(argv.read<TASK_ID>());
				}, session, recvFrame, taskId));
		}
	}

	void formatDiscoveryPacket(BYTESTREAM& dataStream) const
	{
		WriteNameToken(dataStream, SYNC_discover, [](BYTESTREAM& dataStream, const SYNC_SERVICE& service)
			{
				WriteNameToken(dataStream, SYNC_SystemId, service.systemId);

				for (auto& adapter : GetAdapterTable())
				{
					WriteNameToken(dataStream, SYNC_MacAddress, BUFFER{ adapter.macAddress, MAC_ADDRESS_LENGTH });
				}

			}, *this);
	}

	void sendDiscoveryPacket(const ADAPTER_INFO &adapter) const
	{
		auto& dataStream = AllocateAdapterBuffer();

		auto address = dataStream.address(0);
		UNREFERENCED_PARAMETER(address);

		dataStream.writeBytes(DISCOVER_MULTICAST, MAC_ADDRESS_LENGTH);
		dataStream.writeBytes(adapter.macAddress, MAC_ADDRESS_LENGTH);
		dataStream.writeBE<UINT16>(ETHERTYPE_DISCOVER);

		formatDiscoveryPacket(dataStream);
		AddPadding(dataStream);

		SendToAdapter(adapter, dataStream);
	}

	void parseDiscoveryPacket(const ADAPTER_INFO& adapter, BUFFER& recvFrame, TOKEN remoteMac)
	{
		auto nodeId = Null;

		auto nameToken = ReadNameToken<SERVICE_STACK>(recvFrame);
		if (nameToken.name == SYNC_discover)
		{
			auto recvData = nameToken.valueData;
			while (recvData)
			{
				auto nameToken = ReadNameToken<SERVICE_STACK>(recvData);
				if (nameToken.name == SYNC_SystemId)
				{
					if (sessionTable().exists(nameToken.value) == false)
					{
						auto& newSession = sessionStream.append(*this, adapter);

						auto status = newSession.initialize();
						ASSERT(NT_SUCCESS(status));

						newSession.destinationId = nameToken.value;
						newSession.destinationMac.append(remoteMac);

						newSession.connect();
					}
				}
			}
		}
		else DBGBREAK();
	}

	static void discoveryDpcRoutine(PKDPC, PVOID context, PVOID, PVOID)
	{
		SYNC_SERVICE& service = *(SYNC_SERVICE*)context;
		service.scheduler.runTask(0, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				SYNC_SERVICE& service = *(SYNC_SERVICE*)context;
				for (auto& adapter : GetAdapterTable())
				{
					service.sendDiscoveryPacket(adapter);
				}
			}, &service));
	}

	void startDiscoveryTimer()
	{
		KeInitializeTimer(&discoveryTimer);
		KeInitializeDpc(&discoveryDpc, discoveryDpcRoutine, this);

		KeSetTimerEx(&discoveryTimer, SECONDS_TO_TIMEUNITS(60), 1 * 60 * 1000, &discoveryDpc);
	}

	void syncSystemInfo(SYNC_SESSION<SYNC_SERVICE>& session)
	{
		UNREFERENCED_PARAMETER(session);
		TBYTESTREAM dataStream;
		dataStream.reserve(SYNC_DATA_MTU);

		WriteNameToken(dataStream, SYNC_system, [](TBYTESTREAM& dataStream)
			{
				WriteNameToken(dataStream, SYNC_processor_count, (UINT64)SystemInfo().processorCount);
				WriteNameToken(dataStream, SYNC_memory_size, SystemInfo().memorySize);
				WriteNameToken(dataStream, SYNC_free_disk_space, SystemInfo().freeDiskSpace);
				WriteNameToken(dataStream, SYNC_version, SystemInfo().version);
			});
	}

	void syncObjects(SYNC_SESSION<SYNC_SERVICE>& session)
	{
		ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

		TBYTESTREAM dataStream;
		dataStream.reserve(4 * 1024 * 1024);

		for (auto& mediaObject : mediaObjects())
		{
			for (auto& command : mediaObject.commandStream.toBuffer())
			{
				if (command.scope == SYNC_metadata)
				{
					dataStream.clear();

					dataStream.writeBE<UINT16>(SYNC_command.getShortName());
					dataStream.writeVInt(command.commandSize);

					auto& volume = getVolume(command.volumeId);
					volume.readCommand(command.diskOffset, dataStream);

					KEVENT syncEvent;
					KeInitializeEvent(&syncEvent, SynchronizationEvent, FALSE);

					session.scheduler.runTask(SYNC_SEND_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
						{
							auto& session = *(SYNC_SESSION<SYNC_SERVICE>*) context;
							auto& channel = session.getTransmitChannel(SYNC_CONTROL_CHANNEL);
							channel.sendData(argv.read<BUFFER>());
							KeSetEvent(argv.read<PKEVENT>(), 0, FALSE);
						}, &session, dataStream.toBuffer(), &syncEvent));

					KeWaitForSingleObject(&syncEvent, Executive, KernelMode, FALSE, nullptr);
				}
			}
		}
	}

	void onNewSession(SYNC_SESSION<SYNC_SERVICE>& session)
	{
		TBYTESTREAM dataStream;
		dataStream.reserve(1024);

		SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto& service = *(SYNC_SERVICE*)context;
				auto& session = *argv.read<SYNC_SESSION<SYNC_SERVICE>*>();

				service.syncObjects(session);
			}, (PVOID)this, &session));
	}

	NTSTATUS initialize()
	{
		PAGED_CODE();

		scheduler.initialize();
		InitializeStack(serviceStack, 32 * 1024 * 1024, 0);

		certificateByteStream.decodeBase64(SYNC_SERVICE_CERTIFICATE);
		certificateBytes = certificateByteStream.toBuffer();

		ParseX509(certificateBytes, certificate);

		BUFFER_BUILDER byteStream;
		byteStream.decodeBase64(SYNC_SERVICE_KEY);
		ParsePrivateKey(byteStream.toBuffer(), certificateKey);

		DBGBREAK();

		KEVENT initEvent;
		KeInitializeEvent(&initEvent, SynchronizationEvent, FALSE);

		scheduler.runTask(0, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto& service = *(SYNC_SERVICE*)context;
				auto initEvent = argv.read<PKEVENT>();

				service.systemId = CreateGuidHandle<SERVICE_STACK>(SystemInfo().systemId);
				service.mediaAppId = CreateGuidHandle<SERVICE_STACK>(MEDIA_APPID);
				service.emptySectorId = CreateGuidHandle<SERVICE_STACK>(EMPTY_SECTOR_GUID);

				KeSetEvent(initEvent, 0, FALSE);
			}, this, &initEvent));

		KeWaitForSingleObject(&initEvent, Executive, KernelMode, FALSE, nullptr);

		SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				auto& syncService = *(SYNC_SERVICE*)context;

				syncService.startDiscoveryTimer();

				for (UINT32 i = 0; i < MAX_DISKS; i++)
				{
					auto partitionInfo = ReadDiskLayout(i);
					if (partitionInfo)
					{
						auto& volume = syncService.diskVolumes.append(partitionInfo->PartitionLength.QuadPart, i, partitionInfo->PartitionNumber, partitionInfo->Gpt.PartitionId, i);
						volume.init();
					}
				}

				for (auto& volume : syncService.diskVolumes.toBufferNoConst())
				{
					SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
						{
							auto& syncService = *(SYNC_SERVICE*)context;
							auto& volume = *argv.read<STORAGE_VOLUME_INFO*>();

							SystemInfo().diskSize += volume.capacity;
							UINT64 diskOffset = SECTOR_SIZE;
							
							KEVENT syncServiceEvent;
							KeInitializeEvent(&syncServiceEvent, SynchronizationEvent, FALSE);

							STREAM_BUILDER<UINT8, SCHEDULER_STACK, 1> dataStream;
							dataStream.reserve(32 * 1024 * 1024);

							for (;;)
							{
								auto command = volume.readCommand(diskOffset, dataStream.clear());
								if (command.length() == 0)
								{
									break;
								}
								ASSERT(command.length() < 32 * 1024 * 1024);
								command.readBE<UINT32>();
								if (command.clone().readGuid() == EMPTY_SECTOR_GUID)
								{
									volume.addEmptySector(diskOffset);
									diskOffset += SECTOR_SIZE;
									continue;
								}

								syncService.scheduler.runTask(SYNC_BASE_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
									{
										auto& syncService = *(SYNC_SERVICE*)context;

										BUFFER dataBuffer = argv.read<BUFFER>();
										auto volumeId = argv.read<UINT32>();
										auto diskOffset = argv.read<UINT64>();
										auto syncEvent = argv.read<PKEVENT>();

										SYNC_COMMAND syncCommand;
										syncCommand.volumeId = volumeId;
										syncCommand.diskOffset = diskOffset;
										syncCommand.commandSize = dataBuffer.length();

										auto appId = CreateGuidHandle<SERVICE_STACK>(dataBuffer.readGuid());
										if (appId == syncService.mediaAppId)
										{
											auto objectId = CreateGuidHandle<SERVICE_STACK>(dataBuffer.readGuid());
											auto& object = syncService.mediaObjectStream.toBufferNoConst().find(objectId);
											auto& mediaObject = object ? object : syncService.mediaObjectStream.append(objectId);

											syncCommand.oldTimestamp = CreateTimestampHandle<SERVICE_STACK>(dataBuffer.readBE<UINT64>());
											syncCommand.newTimestamp = CreateTimestampHandle<SERVICE_STACK>(dataBuffer.readBE<UINT64>());

											syncCommand.scope = MakeName(dataBuffer.readBE<UINT16>());
											auto scopeLength = (UINT32)dataBuffer.readVInt();

											auto scopeData = dataBuffer.readBytes(scopeLength);
											auto& tokenStream = GetCurrentStack<SERVICE_STACK>().visualStream;

											auto scopeTokenStart = tokenStream.count();
											while (scopeData)
											{
												auto token = scopeData.readVisualToken<SERVICE_STACK>();
												tokenStream.append(token);
											}
											syncCommand.scopeData = tokenStream.toBuffer(scopeTokenStart);

											mediaObject.commandStream.append(syncCommand);
										}
										else DBGBREAK();
										KeSetEvent(syncEvent, 0, FALSE);
									}, &syncService, command, volume.volumeId, diskOffset, &syncServiceEvent));

								diskOffset += ROUND_TO(dataStream.count(), SECTOR_SIZE);
								KeWaitForSingleObject(&syncServiceEvent, Executive, KernelMode, FALSE, nullptr);
							}

							for (auto& freeSpaceInfo : volume.freeSpaceStream.toBuffer())
							{
								SystemInfo().freeDiskSpace += freeSpaceInfo.size;
							}
			
							ImportMediaFiles();
						}, &syncService, &volume));
				}
			}, this));


		return STATUS_SUCCESS;
	}
};

extern SYNC_SERVICE& SyncService();
