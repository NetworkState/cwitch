// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once
#include "Types.h"

using RTMP_STREAM = STREAM_BUILDER<UINT8, SESSION_STACK, 4 * 1024>;

template <typename CONTEXT>
struct RTMP_SESSION
{
	enum class MSGTYPE : UINT8
	{
		SET_CHUNK_SIZE = 0x01,
		ABORT = 0x02,
		ACK = 0x03,
		CONTROL = 0x04,
		ACK_WINDOW = 0x05,
		BANDWIDTH = 0x06,
		VIRTUAL_CONTROL = 0x07,
		AUDIO = 0x08,
		VIDEO = 0x09,
		DATA_EXT = 0x0F,
		SHARED_OBJECT_AMF3 = 0x10,
		COMMAND_AMF3 = 0x11,
		DATA = 0x12,
		CONTAINER = 0x13,
		COMMAND = 0x14,
		UDP = 0x15,
		SHARED_OBJECT = 0x16,
		PRESENT = 0x17,
	};

	enum class CONTROL_MSGTYPE : UINT16
	{
		STREAM_BEGIN = 0,
		STREAM_EOF = 1,
		STREAM_DRY = 2,
		SET_BUFFER_LENGTH = 3,
		STREAM_IS_RECORDED = 4,
		PING_REQUEST = 6,
		PING_RESPONSE = 7,
		UDP_REQUEST = 8,
		UDP_RESPONSE = 9,
		BANDWIDTH_LIMIT = 10,
		BANDWIDTH = 11,
		THROTTLE_BANDWIDTH = 12,
		STREAM_CREATED = 13,
		STREAM_DELETED = 14,
		SET_READ_ACCESS = 15,
		SET_WRITE_ACCESS = 16,
		STREAM_META_REQUEST = 17,
		STREAM_META_RESPONSE = 18,
		GET_SEGMENT_BOUNDARY = 19,
		SET_SEGMENT_BOUNDARY = 20,
		ON_DISCONNECT = 21,
		SET_CRITICAL_LINK = 22,
		DISCONNECT = 23,
		HASH_UPDATE = 24,
		HASH_TIMEOUT = 25,
		HASH_REQUEST = 26,
		HASH_RESPONSE = 27,
		CHECK_BANDWIDTH = 28,
		SET_AUDIO_ACCESS = 29,
		SET_VIDEO_ACCESS = 30,
		THROTTLE_BEGIN = 31,
		THROTTLE_END = 32,
		DRM_NOTIFY = 33,
		RTMFP_SYNC = 34,
		QUERY_IHELLO = 35,
		FORWARD_IHELLO = 36,
		REDIRECT_IHELLO = 37,
		NOTIFY_EOF = 38,
		PROXY_CONTINUE = 39,
		PROXY_REMOVE_UPSTREAM = 40,
		RTMFP_SET_KEEPALIVES = 41,
		SEGMENT_NOT_FOUND = 46,
	};

	enum class AMFTYPE : UINT8
	{
		NUMBER = 0, 
		BOOLEAN = 1, 
		STRING = 2, 
		OBJECT = 3,
		NuLL = 5, 
		UNDEFINED = 6, 
		ECMA_ARRAY = 8, 
		OBJECT_END = 9,
		STRICT_ARRAY = 10, 
		DATE = 11, 
		LONG_STRING = 12, 
		XML_DOC = 15, 
		AVMPLUS = 17,
	};

	enum class CODEC_ID : UINT16
	{
		AUDIO_RAW = 0x0001,
		AUDIO_MP3 = 0x0004,
		AUDIO_AAC = 0x0400,
		VIDEO_H264 = 0x0080,
	};

	enum class HANDSHAKE
	{
		INIT = 0,
		C0_RECEIVED = 1,
		C1_RECEIVED = 2,
		C2_RECEIVED = 3,
		COMPLETE = C2_RECEIVED,
	};

	HANDSHAKE handshakeState;

	struct MESSAGE_STATE
	{
		UINT32 chunkStreamId;
		UINT32 messageStreamId;
		UINT32 messageLength;
		UINT32 timestampDelta;
		MSGTYPE messageType;

		STREAM_BUILDER<UINT8, SCHEDULER_STACK, 256 * 1024> messageStream;
	};

	MESSAGE_STATE msgState; // TODO: use a queue ....

	CONTEXT& context;

	UINT32 sendChunkSize = 128;
	UINT32 receiveChunkSize = 128;

	UINT32 sendWindowSize;
	UINT32 receiveWindowSize;
	TCP_SOCKET<RTMP_SESSION<CONTEXT>> socket;
	CLOCK timestampClock;

	RTMP_STREAM msgSendStream;
	RTMP_STREAM chunkSendStream;
	RTMP_STREAM socketReceiveStream;

	SCHEDULER_INFO<RTMP_SESSION<CONTEXT>> scheduler;
	SESSION_STACK stack;

	RTMP_SESSION(CONTEXT& contextArg, PWSK_SOCKET socketHandle) : socket(*this, socketHandle), scheduler(*this), context(contextArg)
	{
		timestampClock.start();
		msgSendStream.clear();
		scheduler.initialize();
		InitializeStack(stack, 4 * 1024 * 1024, 0);
	}

	auto& getScheduler() { return scheduler; }

	void start()
	{
	}

	template <typename STREAM>
	void formatAMFString(STREAM&& outStream, USTRING value)
	{
		outStream.writeEnumBE<AMFTYPE>(AMFTYPE::STRING);
		outStream.writeBE<UINT16>((UINT16)value.length());
		outStream.writeStream(value);
	}

	template <typename STREAM>
	void formatAMFNumber(STREAM&& outStream, UINT64 value)
	{
		outStream.writeEnumBE<AMFTYPE>(AMFTYPE::NUMBER);
		outStream.writeBE<double>((double)value);
		//auto outData = outStream.commit(8);
		//*(double*)outData = (double)value;
	}

	template <typename STREAM>
	void formatAMFKeyValue(STREAM&& outStream, USTRING key, USTRING value)
	{
		outStream.writeBE<UINT16>((UINT16)key.length());
		outStream.writeStream(key);

		formatAMFString(outStream, value);
	}

	template <typename STREAM>
	void formatAMFKeyValue(STREAM&& outStream, USTRING key, UINT64 value)
	{
		outStream.writeBE<UINT16>(key.length());
		outStream.writeStream(key);

		formatAMFNumber(value);
	}

	template <typename STREAM>
	void formatObjectEnd(STREAM&& outStream)
	{
		outStream.writeBE<UINT16>(0);
		outStream.writeEnumBE<AMFTYPE>(AMFTYPE::OBJECT_END);
	}

	USTRING parseAMFString(BUFFER& msgData)
	{
		auto valueLength = msgData.readBE<UINT16>();
		return msgData.readBytes(valueLength);
	}

	UINT64 parseAMFNumber(BUFFER& msgData)
	{
		auto type = msgData.readEnumBE<AMFTYPE>();
		ASSERT(type == AMFTYPE::NUMBER);

		return (UINT64)msgData.readBE<double>();
		//return (UINT64)(*(double*)msgData.readBytes(8).data());
	}

	AMFTYPE getAMFType(BUFFER& msgData)
	{
		return msgData.readEnumBE<AMFTYPE>();
	}

	UINT32 getAMFLength(AMFTYPE type, BUFFER& msgData)
	{
		UINT32 valueLength = 0;
		if (type == AMFTYPE::NUMBER)
			valueLength = 8;
		else if (type == AMFTYPE::BOOLEAN)
			valueLength = 1;
		else if (type == AMFTYPE::STRING)
			valueLength = msgData.readBE<UINT16>();
		else if (type == AMFTYPE::UNDEFINED)
			valueLength = 0;
		else DBGBREAK();

		return valueLength;
	}

	void skipObjectValue(BUFFER& msgData)
	{
		auto type = getAMFType(msgData);
		auto length = getAMFLength(type, msgData);

		msgData.readBytes(length);
	}

	USTRING getObjectKey(BUFFER& msgData)
	{
		auto keyString = parseAMFString(msgData);
		if (keyString.length() == 0)
		{
			auto objectEnd = getAMFType(msgData);
			ASSERT(objectEnd == AMFTYPE::OBJECT_END);
		}
		return keyString;
	}

	void parseCreateStream(BUFFER& msgData)
	{
		auto transactionId = parseAMFNumber(msgData);

		auto objectType = getAMFType(msgData);
		ASSERT(objectType == AMFTYPE::NuLL);

		msgSendStream.clear();
		formatMessage(msgSendStream, MSGTYPE::COMMAND, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& session, INT64 transactionId)
			{
				session.formatAMFString(outStream, "_result");
				session.formatAMFNumber(outStream, transactionId);
				outStream.writeEnumBE<AMFTYPE>(AMFTYPE::NuLL);

				session.formatAMFNumber(outStream, 1);
			}, *this, transactionId);

		socket.send(msgSendStream.toBuffer(), STASK());
	}

	void parsePublish(BUFFER& msgData)
	{
		auto transactionId = parseAMFNumber(msgData);

		auto objectType = getAMFType(msgData);
		ASSERT(objectType == AMFTYPE::NuLL);

		objectType = getAMFType(msgData);
		ASSERT(objectType == AMFTYPE::STRING);
		auto name = parseAMFString(msgData);
		UNREFERENCED_PARAMETER(name);

		objectType = getAMFType(msgData);
		ASSERT(objectType == AMFTYPE::STRING);
		auto type = parseAMFString(msgData);
		UNREFERENCED_PARAMETER(type);

		msgSendStream.clear();
		formatMessage(msgSendStream, MSGTYPE::CONTROL, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>&)
			{
				outStream.writeEnumBE(CONTROL_MSGTYPE::STREAM_BEGIN);
				outStream.writeBE<UINT32>(0);
			}, *this);

		formatMessage(msgSendStream, MSGTYPE::COMMAND, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& session, UINT64 transactionId)
			{
				session.formatAMFString(outStream, "_result");
				session.formatAMFNumber(outStream, transactionId);
				outStream.writeEnumBE<AMFTYPE>(AMFTYPE::NuLL);

				outStream.writeEnumBE<AMFTYPE>(AMFTYPE::OBJECT);
				session.formatAMFKeyValue(outStream, "level", "status");
				session.formatAMFKeyValue(outStream, "code", "NetStream.Publish.Success");
				session.formatAMFKeyValue(outStream, "description", "Publish succeeded.");
				session.formatObjectEnd(outStream);
			}, *this, transactionId);

		socket.send(msgSendStream.toBuffer(), STASK());
	}

	void parseConnect(BUFFER& msgData)
	{
		auto transactionId = parseAMFNumber(msgData);

		auto objectType = getAMFType(msgData);
		ASSERT(objectType == AMFTYPE::OBJECT);

		while (auto keyString = getObjectKey(msgData))
		{
			auto key = FindName(keyString);
			ASSERT(key);

			skipObjectValue(msgData);
		}

		if (msgData)
		{
			auto type = getAMFType(msgData);
			ASSERT(type == AMFTYPE::OBJECT);

			while (auto keyString = getObjectKey(msgData))
			{
				auto key = FindName(keyString);
				ASSERT(key);

				skipObjectValue(msgData);
			}
		}

		ASSERT(msgData.length() == 0);

		msgSendStream.clear();
		formatMessage(msgSendStream, MSGTYPE::ACK_WINDOW, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& )
			{
				outStream.writeBE<UINT32>(4 * 1024 * 1024);
			}, *this);

		formatMessage(msgSendStream, MSGTYPE::BANDWIDTH, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& )
			{
				outStream.writeBE<UINT32>(4 * 1024 * 1024);
			}, *this);

		formatMessage(msgSendStream, MSGTYPE::CONTROL, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& )
			{
				outStream.writeEnumBE(CONTROL_MSGTYPE::STREAM_BEGIN);
				outStream.writeBE<UINT32>(0);
			}, *this);

		formatMessage(msgSendStream, MSGTYPE::COMMAND, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& session, UINT64 transactionId)
			{
				session.formatAMFString(outStream, "_result");
				session.formatAMFNumber(outStream, transactionId);
				outStream.writeEnumBE<AMFTYPE>(AMFTYPE::NuLL);

				outStream.writeEnumBE<AMFTYPE>(AMFTYPE::OBJECT);
				session.formatAMFKeyValue(outStream, "level", "status");
				session.formatAMFKeyValue(outStream, "code", "NetConnection.Connect.Success");
				session.formatAMFKeyValue(outStream, "description", "Connection succeeded.");
				session.formatObjectEnd(outStream);
			}, *this, transactionId);

		socket.send(msgSendStream.toBuffer(), STASK());
	}

	template <typename STREAM, typename FUNC, typename ... ARGS>
	void formatMessage(STREAM&& outStream, MSGTYPE msgType, FUNC callback, ARGS&& ... args)
	{
		outStream.writeByte(0x02);
		outStream.writeUIntBE(0, 3);
		auto lengthOffset = outStream.saveOffset(3);
		outStream.writeEnumBE(msgType);
		*(PUINT32)outStream.commit(4) = 0;

		callback(outStream, args ...);

		lengthOffset.writeLength(-5);
	}

	//template <typename STREAM>
	//void formatHeader(STREAM&& outStream, MSGTYPE msgType, UINT32 streamId = 2)
	//{
	//	ASSERT(streamId < 64);
	//	outStream.writeByte((UINT8)streamId); // fmt is always 0.

	//}

	void sendMessageChunks(UINT32 chunkStreamId, BUFFER msgData)
	{
		chunkSendStream.clear();
		chunkSendStream.writeByte(0xC0 | chunkStreamId & 0x3F);

		auto sendLength = min(sendChunkSize, msgData.length());
		chunkSendStream.writeStream(msgData.readBytes(sendLength));

		socket.send(chunkSendStream.toBuffer(), STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
			{
				ASSERT(NT_SUCCESS(status));
				auto& session = *(RTMP_SESSION*)context;
				auto chunkStreamId = argv.read<UINT32>();
				auto msgData = argv.read<BUFFER>();

				if (msgData)
				{
					session.sendMessageChunks(chunkStreamId, msgData);
				}
			}, this, chunkStreamId, msgData));
	}

	void sendMessage(UINT32 chunkStreamId, UINT32 timeStamp, MSGTYPE msgType, BUFFER msgData, UINT32 msgStreamId)
	{
		chunkSendStream.clear();

		ASSERT(chunkStreamId < 64);
		chunkSendStream.writeByte((UINT8)chunkStreamId);

		chunkSendStream.writeUIntBE(timeStamp, 3);
		chunkSendStream.writeUIntBE(msgData.length(), 3);
		chunkSendStream.writeEnumBE<MSGTYPE>(msgType);
		*(PUINT32)chunkSendStream.commit(4) = msgStreamId;

		auto sendLength = min(sendChunkSize, msgData.length());
		chunkSendStream.writeStream(msgData.readBytes(sendLength));

		socket.send(chunkSendStream.toBuffer(), STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
			{
				ASSERT(NT_SUCCESS(status));
				auto& session = *(RTMP_SESSION*)context;
				auto chunkStreamId = argv.read<UINT32>();
				auto msgData = argv.read<BUFFER>();

				if (msgData)
				{
					session.sendMessageChunks(chunkStreamId, msgData);
				}
			}, this, chunkStreamId, msgData));
	}

	void parseCommand(BUFFER msgData)
	{
		auto valueType = msgData.readEnumBE<AMFTYPE>();
		ASSERT(valueType == AMFTYPE::STRING);

		auto valueString = parseAMFString(msgData);
		auto valueName = FindName(valueString);

		if (valueName == RTMP_connect)
		{
			parseConnect(msgData);
		}
		else if (valueName == RTMP_createStream)
		{
			parseCreateStream(msgData);
		}
		else if (valueName == RTMP_publish)
		{
			parsePublish(msgData);
		}
		else if (valueName == RTMP_FCPublish || valueName == RTMP_releaseStream || valueName == RTMP_deleteStream || valueName == RTMP_FCUnpublish)
		{
			//auto transactionId = parseAMFNumber(msgData);
			//msgSendStream.clear();
			//formatMessage(msgSendStream, MSGTYPE::COMMAND, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& session, UINT64 transactionId)
			//	{
			//		session.formatAMFString(outStream, "_result");
			//		session.formatAMFNumber(outStream, transactionId);
			//		outStream.writeEnumBE<AMFTYPE>(AMFTYPE::NuLL);
			//	}, *this, transactionId);
			//socket.send(msgSendStream.toBuffer(), STASK());
		}
		else DbgBreakPoint();
	}

	void parseControl(BUFFER msgData)
	{
		auto msgType = msgData.readEnumBE<CONTROL_MSGTYPE>();
		if (msgType == CONTROL_MSGTYPE::PING_REQUEST)
		{
			msgData.readBE<UINT32>();
		}
		else if (msgType == CONTROL_MSGTYPE::STREAM_BEGIN)
		{
			auto streamId = msgData.readBE<UINT32>();
			LogInfo("Stream Begin: %d", streamId);
		}
		else if (msgType == CONTROL_MSGTYPE::STREAM_DRY)
		{
			auto streamId = msgData.readBE<UINT32>();
			LogInfo("Stream Dry: %d", streamId);
		}
	}

	void parseMetadata(BUFFER msgData)
	{
		auto type = getAMFType(msgData);
		ASSERT(type == AMFTYPE::STRING);

		auto header = parseAMFString(msgData);
		ASSERT(header == "@setDataFrame");

		type = getAMFType(msgData);
		ASSERT(type == AMFTYPE::STRING);

		header = parseAMFString(msgData);
		ASSERT(header == "onMetaData");

		type = getAMFType(msgData);
		ASSERT(type == AMFTYPE::ECMA_ARRAY);

		auto entryCount = msgData.readBE<UINT32>();

		for (UINT32 i = 0; i < entryCount; i++)
		{
			auto name = parseAMFString(msgData);
			auto type = getAMFType(msgData);

			msgData.readBytes(getAMFLength(type, msgData));
		}
	}

	void parseMessage(MSGTYPE msgType, BUFFER msgData)
	{
		if (msgType == MSGTYPE::COMMAND)
		{
			parseCommand(msgData);
		}
		else if (msgType == MSGTYPE::CONTROL)
		{
			parseControl(msgData);
		}
		else if (msgType == MSGTYPE::SET_CHUNK_SIZE)
		{
			receiveChunkSize = msgData.readBE<UINT32>() & 0x7FFFFFFF;
		}
		else if (msgType == MSGTYPE::ACK_WINDOW)
		{
			receiveWindowSize = msgData.readBE<UINT32>();
		}
		else if (msgType == MSGTYPE::ACK)
		{
			msgData.readBE<UINT32>();
		}
		else if (msgType == MSGTYPE::DATA)
		{
			parseMetadata(msgData);
		}
		else if (msgType == MSGTYPE::AUDIO)
		{
			LogInfo("Audio codec data: %d bytes", msgData.length());
		}
		else if (msgType == MSGTYPE::VIDEO)
		{
			LogInfo("Video codec data: %d bytes", msgData.length());
		}
		else DBGBREAK();
	}

	UINT32 parseChunk(BUFFER recvData)
	{
		auto chunkStart = recvData.getPosition();
		UINT32 bytesConsumed = 0;

		auto firstByte = recvData.shift();
		auto format = firstByte >> 6;

		do
		{
			UINT32 streamId = firstByte & 0x3F;
			if (streamId == 0)
			{
				streamId = (UINT32)recvData.readByte() + 64;
			}
			else if (streamId == 1)
			{
				streamId = (UINT32)recvData.readBE<UINT16>() + 64;
			}

			if (streamId == 4)
			{
				LogInfo("firstByte for streamId 4: 0x%x, total:%d", firstByte, recvData.length() + 1);
			}
			if (format == 0 && recvData.length() >= 11)
			{
				msgState.messageStream.clear();
				msgState.chunkStreamId = streamId;
				msgState.timestampDelta = (UINT32)recvData.readUIntBE(3);
				msgState.messageLength = (UINT32)recvData.readUIntBE(3);
				msgState.messageType = recvData.readEnumBE<MSGTYPE>();
				msgState.messageStreamId = *(UINT32*)recvData.readBytes(4).data();
				LogInfo("messageStreamId: %d", msgState.messageStreamId);
			}
			else if (format == 1 && recvData.length() >= 7)
			{
				msgState.messageStream.clear();
				msgState.chunkStreamId = streamId;
				msgState.timestampDelta = (UINT32)recvData.readUIntBE(3);
				msgState.messageLength = (UINT32)recvData.readUIntBE(3);
				msgState.messageType = recvData.readEnumBE<MSGTYPE>();
			}
			else if (format == 2 && recvData.length() >= 3)
			{
				ASSERT(msgState.chunkStreamId == streamId);
				msgState.timestampDelta = (UINT32)recvData.readUIntBE(3);
			}
			else if (format == 3)
			{
				ASSERT(msgState.chunkStreamId == streamId);
			}
			else
			{
				// need more data!
				break;
			}

			auto bytesToRead = msgState.messageLength - msgState.messageStream.count();
			auto chunkLength = bytesToRead > receiveChunkSize ? receiveChunkSize : bytesToRead;
			if (recvData.length() >= chunkLength)
			{
				msgState.messageStream.writeStream(recvData.readBytes(chunkLength));
				if (msgState.messageStream.count() >= msgState.messageLength)
				{
					parseMessage(msgState.messageType, msgState.messageStream.toBuffer());
					msgState.messageStream.clear();
				}
				bytesConsumed = recvData.diffPosition(chunkStart);
			}
		} while (false);

		return bytesConsumed;
	}

	void doHandshake()
	{
		auto recvData = socketReceiveStream.toBuffer();
		msgSendStream.clear();

		if (handshakeState == HANDSHAKE::INIT)
		{
			ASSERT(recvData.readByte() == 0x03);
			handshakeState = HANDSHAKE::C0_RECEIVED;
			socketReceiveStream.remove(0, 1);
			recvData = socketReceiveStream.toBuffer();
			// S0
			msgSendStream.writeByte(0x03);
		}

		if (handshakeState == HANDSHAKE::C0_RECEIVED && recvData.length() >= 1536)
		{
			handshakeState = HANDSHAKE::C1_RECEIVED;
			auto c1Timestamp = recvData.readBE<UINT32>();
			auto c1ReceiptTime = (UINT32)timestampClock.elapsedTime();


			// S1
			msgSendStream.writeBE<UINT32>(0);
			msgSendStream.writeBE<UINT32>(0);

			Random.generateRandom(msgSendStream, 1528);

			// S2
			msgSendStream.writeBE<UINT32>(c1Timestamp);
			msgSendStream.writeBE<UINT32>(c1ReceiptTime);

			Random.generateRandom(msgSendStream, 1528);
			
			socketReceiveStream.clear();
		}

		if (handshakeState == HANDSHAKE::C1_RECEIVED && recvData.length() >= 1536)
		{
			handshakeState = HANDSHAKE::COMPLETE;
			socketReceiveStream.clear();

			msgSendStream.clear();
			formatMessage(msgSendStream, MSGTYPE::SET_CHUNK_SIZE, [](RTMP_STREAM& outStream, RTMP_SESSION<CONTEXT>& session)
				{
					session.sendChunkSize = 4096;
					outStream.writeBE<UINT32>(session.sendChunkSize);
				}, *this);
		}

		if (msgSendStream.count() > 0)
		{
			socket.send(msgSendStream.toBuffer(), STASK());
		}
	}

	void onReceive(BUFFER recvData)
	{
		scheduler.runTask(SOCKET_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
			{
				ASSERT(NT_SUCCESS(status));

				auto& session = *(RTMP_SESSION<CONTEXT>*)context;
				auto recvData = argv.read<BUFFER>();

				session.socketReceiveStream.writeStream(recvData);
				if (session.handshakeState == HANDSHAKE::COMPLETE)
				{
					ASSERT(session.socketReceiveStream.count() > 0);

					auto bytesConsumed = session.parseChunk(session.socketReceiveStream.toBuffer());
					session.socketReceiveStream.remove(0, bytesConsumed);

					if (bytesConsumed > 0 && session.socketReceiveStream.count() > 0)
					{
						session.scheduler.runTask(SOCKET_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
							{
								auto& session = *(RTMP_SESSION<CONTEXT>*)context;
								session.onReceive(NULL_BUFFER);
							}, &session));
					}
				}
				else
				{
					session.doHandshake();
				}

			}, this, recvData));
	}

	void onClose()
	{

	}
};

struct RTMP_SERVICE
{
	LISTEN_SOCKET<RTMP_SERVICE, RTMP_SESSION<RTMP_SERVICE>> socketListener;
	SCHEDULER_INFO<RTMP_SERVICE> scheduler;
	SERVICE_STACK stack;

	RTMP_SERVICE() : scheduler(*this), socketListener(*this)
	{
		scheduler.initialize();
		InitializeStack(stack, 512 * 1024, 0);
	}
	auto& getScheduler() { return scheduler; }

	void start()
	{
		socketListener.listen(RTMP_PORT, STASK([](PVOID, NTSTATUS status, STASK_PARAMS)
			{
				ASSERT(NT_SUCCESS(status));
			}, this));
	}

	auto& onNewConnection(PWSK_SOCKET acceptHandle, SOCKADDR_IN* localAddress, SOCKADDR_IN* remoteAddress)
	{
		UNREFERENCED_PARAMETER(localAddress);
		UNREFERENCED_PARAMETER(remoteAddress);
		auto& connection = KernelAlloc<RTMP_SESSION<RTMP_SERVICE>>(*this, acceptHandle);
		scheduler.runTask(SOCKET_CONTROL_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				auto& connection = *(RTMP_SESSION<RTMP_SERVICE>*)context;
				connection.start();
			}, &connection));
		return connection.socket;
	}
};
