// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once
#include "TLS.h"

constexpr UINT32 TLS_DATA_MAX = 16 * 1024;

constexpr UINT32 TLS_RECORD_SIZE = (TLS_DATA_MAX + 256 + 5); // 16K data + 256 bytes for encryption expansion + 5 bytes for record header
using DATA_BUFFER = LOCAL_STREAM<TLS_RECORD_SIZE>;
constexpr UINT32 HKDF_HASH_LENGTH = 32;

constexpr UINT32 TLS_RECORD_HEADER = 5;
using HKDF_BUFFER = LOCAL_STREAM<HKDF_HASH_LENGTH>;

constexpr USTRING HTTP_SERVER_NAME = "Yet Another Web Server v0.001";

constexpr UINT32 SIGNALING_RECV_PRIORITY = 2;
constexpr UINT32 SIGNALING_SEND_PRIORITY = 3;

struct HKDF_SECRET
{
	UINT8 macKey[HKDF_HASH_LENGTH];

	HKDF_SECRET()
	{
		RtlCopyMemory(macKey, Algorithms.zeroHmac256, HKDF_HASH_LENGTH);
	}

	BUFFER getSecret()
	{
		return BUFFER(macKey, HKDF_HASH_LENGTH);
	}

	NTSTATUS extract(BUFFER sharedSecret)
	{
		UINT32 hashResult[HKDF_HASH_LENGTH];
		auto status = BCryptHash(Algorithms.hmacSha256, macKey, HKDF_HASH_LENGTH, (PUCHAR)sharedSecret.data(), sharedSecret.length(), (PUCHAR)hashResult, HKDF_HASH_LENGTH);
		ASSERT(NT_SUCCESS(status));

		RtlCopyMemory(macKey, hashResult, HKDF_HASH_LENGTH);

		return status;
	}

	NTSTATUS extract()
	{
		UINT8 zeroBytes[HKDF_HASH_LENGTH] = { 0 };
		UINT8 newMacKey[HKDF_HASH_LENGTH];

		auto status = BCryptHash(Algorithms.hmacSha256, macKey, HKDF_HASH_LENGTH, zeroBytes, HKDF_HASH_LENGTH, newMacKey, HKDF_HASH_LENGTH);
		ASSERT(NT_SUCCESS(status));

		RtlCopyMemory(this->macKey, newMacKey, HKDF_HASH_LENGTH);

		return status;
	}

	USTRING TLS_LABEL = "tls13 ";

	NTSTATUS deriveSecret(BUFFER secret, USTRING label, BUFFER context, HKDF_BUFFER& hashResult, UINT16 hashLength = HKDF_HASH_LENGTH)
	{
		ASSERT(secret.length() == HKDF_HASH_LENGTH);

		LOCAL_STREAM<80> hkdfLabel;

		hkdfLabel.writeInt(HTONS(hashLength));
		{
			auto offset = hkdfLabel.saveOffset(1);
			hkdfLabel.writeString(TLS_LABEL);
			hkdfLabel.writeString(label);
		}
		hkdfLabel.writeByte((UINT8)context.length());
		hkdfLabel.writeStream(context);
		hkdfLabel.writeByte(0x01); // Refer RFC5869, for T(1)

		auto buffer = hkdfLabel.toBuffer();

		auto address = hashResult.commit(HKDF_HASH_LENGTH);
		auto status = BCryptHash(Algorithms.hmacSha256, (PUCHAR)secret.data(), HKDF_HASH_LENGTH, (PUCHAR)buffer.data(), buffer.length(), address, HKDF_HASH_LENGTH);
		ASSERT(NT_SUCCESS(status));

		return status;
	}

	NTSTATUS deriveSecret(USTRING label, BUFFER context, HKDF_BUFFER& hashResult)
	{
		return deriveSecret(BUFFER(macKey, HKDF_HASH_LENGTH), label, context, hashResult);
	}

	void update()
	{
		HKDF_BUFFER newMacKey;
		deriveSecret("derived", Algorithms.nullSha256Hash, newMacKey);
		RtlCopyMemory(this->macKey, newMacKey.toBuffer().data(), HKDF_HASH_LENGTH);
	}
};

#define ROUND_TO_BLOCK(x) (((ULONG_PTR)(x) + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1))
constexpr UINT32 AES_BLOCK_SIZE = 16;

struct HKDF_CIPHER
{
	X25519_KEYSHARE keyShare;

	BCRYPT_KEY_HANDLE sendKey = nullptr;
	BCRYPT_KEY_HANDLE recvKey = nullptr;

	HKDF_BUFFER clientHandshakeSecret;
	HKDF_BUFFER serverHandshakeSecret;

	UINT8 sendIV[AES_IV_LENGTH];
	UINT8 recvIV[AES_IV_LENGTH];

	DATA_BUFFER sendRecord;
	DATA_BUFFER recvRecord;

	UINT64 sendSequenceNumber = 0;
	UINT64 recvSequenceNumber = 0;

	bool isEncrypted = false;
	const bool isServer = true;

	template <typename STREAM>
	NTSTATUS writePublicKey(STREAM&& buffer)
	{
		keyShare.getPublicKey(buffer);
		return STATUS_SUCCESS;
	}

	NTSTATUS createSecret(BUFFER importData)
	{
		keyShare.createSecret(importData);
		return STATUS_SUCCESS;
	}

	NTSTATUS generateHandshakeKeys(HKDF_SECRET& secret, TRANSCRIPT_HASH& transcript)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			isEncrypted = true;

			ASSERT(sendKey == nullptr);
			ASSERT(recvKey == nullptr);

			secret.update();

			status = secret.extract(keyShare.sharedSecret.toBuffer());
			VERIFY_STATUS;

			status = secret.deriveSecret("c hs traffic", transcript.getHash(), clientHandshakeSecret);
			VERIFY_STATUS;

			HKDF_BUFFER byteStream;
			status = secret.deriveSecret(clientHandshakeSecret.toBuffer(), "key", NULL_BUFFER, byteStream, AES_BLOCK_SIZE);
			VERIFY_STATUS;

			status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, isServer ? &recvKey : &sendKey, NULL, 0, (PUCHAR)byteStream.toBuffer().data(), AES_BLOCK_SIZE, 0);
			VERIFY_STATUS;

			byteStream.clear();
			status = secret.deriveSecret(clientHandshakeSecret.toBuffer(), "iv", NULL_BUFFER, byteStream, AES_IV_LENGTH);
			RtlCopyMemory(isServer ? recvIV : sendIV, byteStream.toBuffer().data(), AES_IV_LENGTH);

			status = secret.deriveSecret("s hs traffic", transcript.getHash(), serverHandshakeSecret);
			VERIFY_STATUS;

			byteStream.clear();
			status = secret.deriveSecret(serverHandshakeSecret.toBuffer(), "key", NULL_BUFFER, byteStream, AES_BLOCK_SIZE);
			VERIFY_STATUS;

			status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, isServer ? &sendKey : &recvKey, NULL, 0, (PUCHAR)byteStream.toBuffer().data(), AES_BLOCK_SIZE, 0);
			VERIFY_STATUS;

			byteStream.clear();
			status = secret.deriveSecret(serverHandshakeSecret.toBuffer(), "iv", NULL_BUFFER, byteStream, AES_IV_LENGTH);
			RtlCopyMemory(isServer ? sendIV : recvIV, byteStream.toBuffer().data(), AES_IV_LENGTH);

		} while (false);
		return status;
	}

	NTSTATUS generateMasterKeys(HKDF_SECRET & secret, BUFFER transcriptHash)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			secret.update();
			secret.extract();

			sendSequenceNumber = 0;
			recvSequenceNumber = 0;

			BCryptDestroyKey(sendKey);
			BCryptDestroyKey(recvKey);

			HKDF_BUFFER trafficSecret;
			status = secret.deriveSecret("c ap traffic", transcriptHash, trafficSecret);
			VERIFY_STATUS;

			HKDF_BUFFER keySecret;
			status = secret.deriveSecret(trafficSecret.toBuffer(), "key", NULL_BUFFER, keySecret, AES_BLOCK_SIZE);
			VERIFY_STATUS;

			status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, isServer ? &recvKey : &sendKey, NULL, 0, (PUCHAR)keySecret.toBuffer().data(), AES_BLOCK_SIZE, 0);
			VERIFY_STATUS;

			HKDF_BUFFER ivSecret;
			status = secret.deriveSecret(trafficSecret.toBuffer(), "iv", NULL_BUFFER, ivSecret, AES_IV_LENGTH);
			VERIFY_STATUS;

			RtlCopyMemory(isServer ? recvIV : sendIV, ivSecret.toBuffer().data(), AES_IV_LENGTH);

			trafficSecret.clear();
			status = secret.deriveSecret("s ap traffic", transcriptHash, trafficSecret);
			VERIFY_STATUS;

			keySecret.clear();
			status = secret.deriveSecret(trafficSecret.toBuffer(), "key", NULL_BUFFER, keySecret, AES_BLOCK_SIZE);
			VERIFY_STATUS;

			status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, isServer ? &sendKey : &recvKey, NULL, 0, (PUCHAR)keySecret.toBuffer().data(), AES_BLOCK_SIZE, 0);
			VERIFY_STATUS;

			ivSecret.clear();
			status = secret.deriveSecret(trafficSecret.toBuffer(), "iv", NULL_BUFFER, ivSecret, AES_IV_LENGTH);
			VERIFY_STATUS;

			RtlCopyMemory(isServer ? sendIV : recvIV, ivSecret.toBuffer().data(), AES_IV_LENGTH);
		} while (false);
		return status;
	}

	void XorData(PUINT8 data1, PUINT8 data2, ULONG length)
	{
		for (UINT32 i = 0; i < length; i++)
		{
			data1[i] ^= data2[i];
		}
	}

	void encrypt(BUFFER record)
	{
		auto additonalData = record.readBytes(TLS_RECORD_HEADER);
		auto tag = record.shrink(AES_TAG_LENGTH);

		LOCAL_STREAM<AES_IV_LENGTH> ivBuffer;
		ivBuffer.writeBE((UINT32)0);
		ivBuffer.writeBE(sendSequenceNumber++);

		auto ivData = ivBuffer.toBuffer();
		XorData((PUINT8)ivData.data(), sendIV, AES_IV_LENGTH);

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbAuthData = (PUCHAR)additonalData.data();
		authInfo.cbAuthData = 5;
		authInfo.pbNonce = (PUCHAR)ivData.data();
		authInfo.cbNonce = AES_IV_LENGTH;
		authInfo.pbTag = (PUCHAR)tag.data();
		authInfo.cbTag = AES_TAG_LENGTH;

		ULONG bytesEncoded;
		auto status = BCryptEncrypt(sendKey, (PUCHAR)record.data(), record.length(), &authInfo, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesEncoded, 0);
		ASSERT(NT_SUCCESS(status));
	}

	BUFFER decrypt(BUFFER & record)
	{
		auto additonalData = record.readBytes(TLS_RECORD_HEADER);

		auto tag = record.shrink(AES_TAG_LENGTH);

		LOCAL_STREAM<AES_IV_LENGTH> ivBuffer;
		ivBuffer.writeBE((UINT32)0);
		ivBuffer.writeBE(recvSequenceNumber++);

		auto ivData = ivBuffer.toBuffer();
		XorData((PUINT8)ivData.data(), recvIV, AES_IV_LENGTH);

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbAuthData = (PUCHAR)additonalData.data();
		authInfo.cbAuthData = 5;
		authInfo.pbNonce = (PUCHAR)ivData.data();
		authInfo.cbNonce = AES_IV_LENGTH;
		authInfo.pbTag = (PUCHAR)tag.data();
		authInfo.cbTag = AES_TAG_LENGTH;

		ULONG bytesDecoded;
		auto status = BCryptDecrypt(recvKey, (PUCHAR)record.data(), record.length(), &authInfo, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesDecoded, 0);
		ASSERT(NT_SUCCESS(status));

		LogInfo("Decrypted %d bytes", bytesDecoded);
		return record;
	}
};

enum class HTTP_APP
{
	DISPATCH,
	DOWNLOAD,
	WEBSOCKET,
};

enum class WEBSOCKET_OPCODE : UINT8
{
	CONTINUATION = 0x00,
	TEXT_FRAME = 0x01,
	BINARY_FRAME = 0x02,
	CLOSE = 0x08,
	PING = 0x09,
	PONG = 0x0A,
};
DEFINE_ENUM_FLAG_OPERATORS(WEBSOCKET_OPCODE);

struct NAME_STRING
{
	TOKEN name;
	USTRING value;

	NAME_STRING(TOKEN nameArg, USTRING valueArg) : name(nameArg), value(valueArg) {}
	bool match(TOKEN other) const { return name == other; }

	constexpr explicit operator bool() const { return IsValidRef(*this); }
};

USTRING ParseAttribute(USTRING attrValue, TOKEN name)
{
	USTRING match;
	while (attrValue)
	{
		auto pair = String.splitChar(attrValue, ";");
		auto nameString = String.splitChar(pair, "=");
		if (FindCustomName<SERVICE_STACK>(nameString) == name)
		{
			String.trim(pair);
			match = pair;
		}
	}
	return match;
}

template <typename STREAM>
USTRING FormatAttribute(STREAM&& stream, TOKEN name, USTRING value)
{
	auto start = stream.end();
	if (stream.count() > 0)
	{
		stream.writeString(";");
	}
	stream.writeMany(name, "=", value);
	return { start, (UINT32)(stream.end() - start) };
}

using HEADER_STREAM = STREAM_BUILDER<NAME_STRING, SCHEDULER_STACK, 16>;
using HEADER_TABLE = STREAM_READER<const NAME_STRING>;

constexpr USTRING WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

template <typename SERVER>
struct HTTP_CONNECTION
{
	struct TLS13_HANDSHAKE
	{
		SERVER& server;
		HTTP_CONNECTION& connection;

		TRANSCRIPT_HASH transcriptHash;
		HKDF_SECRET secret;
		HKDF_CIPHER cipher;
		CERTIFICATE certPublicKey;
		TCP_SOCKET<TLS13_HANDSHAKE> socket;
		HKDF_BUFFER masterTranscript;
		bool isHandshakeComplete = false;

		TLS13_HANDSHAKE(SERVER& serverArg, HTTP_CONNECTION& connectionArg, PWSK_SOCKET socketHandle) : server(serverArg), connection(connectionArg), socket(*this, socketHandle) {}

		BUFFER readExtension(BUFFER& message, EXTENSION_TYPE& type)
		{
			type = message.readEnumBE<EXTENSION_TYPE>();
			auto length = message.readBE<UINT16>();

			return message.readBytes(length);
		}

		auto& getScheduler() { return connection.scheduler; }

		BUFFER readVariableData(BUFFER& message, UINT8 lengthBytes)
		{
			if (lengthBytes == 3)
			{
				auto c = message.shift(1);
				ASSERT(c == 0);
				lengthBytes = 2;
			}

			ASSERT(lengthBytes == 1 || lengthBytes == 2);

			UINT32 length = lengthBytes == 1 ? message.readByte() : message.readBE<UINT16>();
			return message.readBytes(length);
		}

		void formatServerName(DATA_BUFFER& buffer)
		{
			buffer.writeEnumBE(EXTENSION_TYPE::server_name);
			{
				auto extLength = buffer.saveOffset(2);
				{
					auto nameListLength = buffer.saveOffset(2);
					buffer.writeByte(0); // type
					{
						auto nameLength = buffer.saveOffset(2);
						buffer.writeName(server.getServerName());
					}
				}
			}
		}

		bool parseServerName(BUFFER& data)
		{
			auto isValid = false;
			data = readVariableData(data, 2);
			while (data)
			{
				auto type = data.readByte();
				ASSERT(type == 0);
				auto nameString = readVariableData(data, 2);
				auto name = CreateCustomName<SERVICE_STACK>(nameString);
				if (name == server.getServerName())
					isValid = true;
				LogInfo("server_name, length:%d", nameString.length());
			}
			return isValid;
		}

		void formatKeyshare(DATA_BUFFER& buffer)
		{
			buffer.writeEnumBE(EXTENSION_TYPE::key_share);
			auto extLength = buffer.saveOffset(2);
			if (server.isClient())
			{
				auto dataLength = buffer.saveOffset(2);
				buffer.writeEnumBE(SUPPORTED_GROUPS::x25519);

				buffer.writeBE<UINT16>(0x20); // key length
				cipher.keyShare.getPublicKey(buffer);
			}
			else
			{
				buffer.writeEnumBE(SUPPORTED_GROUPS::x25519);
				buffer.writeBE<UINT16>(0x20); // key length
				cipher.keyShare.getPublicKey(buffer);
			}
		}

		bool parseKeyshare(BUFFER& data)
		{
			auto isValid = false;
			if (server.isClient())
			{
				auto groupName = data.readEnumBE<SUPPORTED_GROUPS>();
				if (groupName == SUPPORTED_GROUPS::x25519)
				{
					auto key = readVariableData(data, 2);
					cipher.keyShare.createSecret(key);
					isValid = true;
				}
			}
			else
			{
				data = readVariableData(data, 2);
				while (data)
				{
					auto groupName = data.readEnumBE<SUPPORTED_GROUPS>();
					auto key = readVariableData(data, 2);
					if (groupName == SUPPORTED_GROUPS::x25519)
					{
						cipher.keyShare.createSecret(key);
						isValid = true;
					}
				}
			}
			return isValid;
		}

		void formatSupportedGroups(DATA_BUFFER& buffer)
		{
			buffer.writeEnumBE(EXTENSION_TYPE::supported_groups);
			auto extLength = buffer.saveOffset(2);
			{
				auto groupLength = buffer.saveOffset(2);
				buffer.writeEnumBE(SUPPORTED_GROUPS::x25519);
			}
		}

		bool parseSupportedGroups(BUFFER& data)
		{
			auto isValid = false;
			if (server.isClient())
			{
				auto group = data.readEnumBE<SUPPORTED_GROUPS>();
				if (group == SUPPORTED_GROUPS::x25519)
					isValid = true;
				else DBGBREAK();
			}
			else
			{
				data = readVariableData(data, 2);
				while (data)
				{
					auto group = data.readEnumBE<SUPPORTED_GROUPS>();
					if (group == SUPPORTED_GROUPS::x25519)
						isValid = true;
				}
			}
			return isValid;
		}

		void formatSignatureAlgorithms(DATA_BUFFER& buffer)
		{
			buffer.writeEnumBE(EXTENSION_TYPE::signature_algorithms);
			auto extLength = buffer.saveOffset(2);
			{
				auto algLength = buffer.saveOffset(2);

				buffer.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_rsae_sha256);
				buffer.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_pss_sha256);
				buffer.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp256r1_sha256);
			}
		}

		bool parseSignatureAlgorithms(BUFFER& data)
		{
			auto isValid = false;
			data = readVariableData(data, 2);
			while (data)
			{
				auto signatureSchme = data.readEnumBE<SIGNATURE_SCHEME>();
				if (signatureSchme == SIGNATURE_SCHEME::ecdsa_secp256r1_sha256)
					isValid = true;
				LogInfo("signature scheme: 0x%x", signatureSchme);
			}
			return isValid;
		}

		void formatSupportedVersions(DATA_BUFFER& buffer)
		{
			buffer.writeEnumBE(EXTENSION_TYPE::supported_versions);
			auto offset = buffer.saveOffset(2);

			if (server.isClient())
			{
				buffer.writeByte(2); // we support only 1 version
				buffer.writeEnumBE(TLS_VERSION::TLS13);
			}
			else
			{
				buffer.writeEnumBE(TLS_VERSION::TLS13);
			}
		}

		bool parseSupportedVersions(BUFFER& data)
		{
			auto isValid = false;
			if (server.isClient())
			{
				auto version = data.readEnumBE<TLS_VERSION>();
				if (version == TLS_VERSION::TLS13)
					isValid = true;
				else DBGBREAK();
			}
			else
			{
				data = readVariableData(data, 1);
				while (data)
				{
					auto version = data.readEnumBE<TLS_VERSION>();
					if (version == TLS_VERSION::TLS13)
						isValid = true;
				}
			}
			return isValid;
		}

		void sendChangeCipherSpec()
		{
			LOCAL_STREAM<16> record;
			record.writeEnumBE(RECORD_TYPE::change_cipher_spec);
			record.writeEnumBE(TLS_VERSION::TLS12);
			record.writeBE<UINT16>(1);
			record.writeByte(1);

			socket.send(record.toBuffer());
		}

		void sendClientHello()
		{
			auto taskId = getScheduler().queueSyncTask(SIGNALING_SEND_PRIORITY);
			sendRecord(taskId, RECORD_TYPE::handshake, [](DATA_BUFFER& buffer, TLS13_HANDSHAKE& handshake)
				{
					auto messageStart = buffer.getPosition();
					buffer.writeEnumBE(MESSAGE_TYPE::client_hello);
					{
						auto msgLength = buffer.saveOffset(3);
						buffer.writeEnumBE(TLS_VERSION::TLS12);

						Random.generateRandom(buffer, 32);

						buffer.writeByte(0); // no session id

						buffer.writeBE<UINT16>(2);
						buffer.writeEnumBE(CIPHER_SUITE::TLS_AES_128_GCM_SHA256);

						buffer.writeByte(1);
						buffer.writeByte(0); // zero compression

						{
							auto extensionOffset = buffer.saveOffset(2);

							handshake.formatSupportedVersions(buffer);
							handshake.formatSignatureAlgorithms(buffer);
							handshake.formatSupportedGroups(buffer);
							handshake.formatServerName(buffer);
							handshake.formatKeyshare(buffer);
						}
					}
					handshake.transcriptHash.addMessage(messageStart.toBuffer());
				}, *this);
		}

		bool parseClientHello(BUFFER data)
		{
			auto isValid = false;
			BUFFER sessionId;
			do
			{
				data.readEnumBE<TLS_VERSION>();
				auto random = data.readBytes(32);

				sessionId = readVariableData(data, 1);

				auto cipherSuites = readVariableData(data, 2);

				while (cipherSuites)
				{
					auto cipher = cipherSuites.readEnumBE<CIPHER_SUITE>();
					if (cipher == CIPHER_SUITE::TLS_AES_128_GCM_SHA256)
						isValid = true;
				}

				if (!isValid)
				{
					DBGBREAK();
					break;
				}

				auto compression = readVariableData(data, 1);
				ASSERT(compression.length() == 1);

				auto extension = readVariableData(data, 2);
				while (extension)
				{
					EXTENSION_TYPE extType;
					auto extData = readExtension(extension, extType);

					if (extType == EXTENSION_TYPE::key_share)
					{
						isValid = parseKeyshare(extData);
					}
					else if (extType == EXTENSION_TYPE::server_name)
					{
						isValid = parseServerName(extData);
					}
					else if (extType == EXTENSION_TYPE::supported_groups)
					{
						isValid = parseSupportedGroups(extData);
					}
					else if (extType == EXTENSION_TYPE::supported_versions)
					{
						isValid = parseSupportedVersions(extData);
					}
					else if (extType == EXTENSION_TYPE::signature_algorithms)
					{
						isValid = parseSignatureAlgorithms(extData);
					}
					else
					{
						LogInfo("Unknown extension: 0x%x", extType);
					}
					if (!isValid)
					{
						DBGBREAK();
						break;
					}
				}
			} while (false);
			if (isValid)
			{
				sendServerHello(sessionId, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
					{
						auto&& handshake = *(TLS13_HANDSHAKE*)context;
						handshake.generateHandshakeKeys();
						auto taskId = handshake.getScheduler().queueTask(SIGNALING_SEND_PRIORITY + 1, STASK());
						SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
							{
								auto&& handshake = *(TLS13_HANDSHAKE*)context;
								handshake.sendRecord(argv.read<TASK_ID>(), RECORD_TYPE::handshake, [](DATA_BUFFER& buffer, TLS13_HANDSHAKE& handshake)
									{
										handshake.formatEncryptedExtensions(buffer);
										handshake.formatCertificates(buffer);
										handshake.formatCertificateVerify(buffer);// Calls BCryptSignash at PASSIVE level
										handshake.formatFinished(buffer);

										handshake.masterTranscript.writeStream(handshake.transcriptHash.getHash());
									}, handshake);
							}, &handshake, taskId));
					}, this));

			}
			else
			{
				DBGBREAK();
				sendAlert(ALERT_LEVEL::fatal, ALERT_DESCRIPTION::illegal_parameter);
			}
			return isValid;
		}

		template <typename TASK>
		void sendServerHello(BUFFER sessionId, TASK&& task)
		{
			auto taskId = getScheduler().queueTask(SIGNALING_SEND_PRIORITY, task);
			sendRecord(taskId, RECORD_TYPE::handshake, [](DATA_BUFFER& buffer, TLS13_HANDSHAKE& handshake, BUFFER sessionId)
				{
					auto transcriptStart = buffer.getPosition();
					buffer.writeEnumBE(MESSAGE_TYPE::server_hello);
					{
						auto msgLength = buffer.saveOffset(3);

						buffer.writeEnumBE(TLS_VERSION::TLS12);
						Random.generateRandom(buffer, 32);
						buffer.writeByte((UINT8)sessionId.length());
						buffer.writeStream(sessionId);
						buffer.writeEnumBE(CIPHER_SUITE::TLS_AES_128_GCM_SHA256);
						buffer.writeByte(0);
						{
							auto extensionOffset = buffer.saveOffset(2);

							handshake.formatKeyshare(buffer);
							handshake.formatSupportedVersions(buffer);
						}
					}
					handshake.transcriptHash.addMessage(transcriptStart.toBuffer());
				}, *this, sessionId);
		}

		void sendAlert(ALERT_LEVEL level, ALERT_DESCRIPTION code)
		{
			auto taskId = getScheduler().queueTask(SIGNALING_SEND_PRIORITY, STASK());
			sendRecord(taskId, RECORD_TYPE::alert, [](DATA_BUFFER& buffer, ALERT_LEVEL level, ALERT_DESCRIPTION code)
				{
					buffer.writeEnumBE(level);
					buffer.writeEnumBE(code);
				}, level, code);
		}

		void parseServerHello(BUFFER data)
		{
			data.readEnumBE<TLS_VERSION>();
			auto random = data.readBytes(32);

			auto sessionId = readVariableData(data, 1);

			data.readEnumBE<CIPHER_SUITE>();

			data.readByte();

			auto extension = readVariableData(data, 2);
			while (extension)
			{
				EXTENSION_TYPE extType;
				auto extData = readExtension(extension, extType);

				if (extType == EXTENSION_TYPE::supported_versions)
				{
					parseSupportedVersions(extData);
				}
				else if (extType == EXTENSION_TYPE::key_share)
				{
					parseKeyshare(extData);
				}
				else if (extType == EXTENSION_TYPE::supported_groups)
				{
					parseSupportedGroups(extData);
				}
				else if (extType == EXTENSION_TYPE::signature_algorithms)
				{
					parseSignatureAlgorithms(extData);
				}
			}
		}

		void formatEncryptedExtensions(DATA_BUFFER& buffer)
		{
			auto transcriptStart = buffer.getPosition();
			buffer.writeEnumBE(MESSAGE_TYPE::encrypted_extensions);
			{
				auto msgLength = buffer.saveOffset(3);
				{
					auto extensionsLength = buffer.saveOffset(2);

					//formatSupportedGroups(buffer);
					//formatServerName(buffer);
				}
			}
			transcriptHash.addMessage(transcriptStart.toBuffer());
		}

		void parseEncryptedExtensions(BUFFER message)
		{
			auto msgData = readVariableData(message, 2);
			while (msgData)
			{
				auto extType = msgData.readEnumBE<EXTENSION_TYPE>();
				auto extData = readVariableData(msgData, 2);

				LogInfo("extenstion type=%d", extType);
			}
		}

		void parseX509Certificate(BUFFER certData)
		{
			LogInfo("Parse certificate");
			ParseX509(certData, certPublicKey);
		}

		void formatCertificates(DATA_BUFFER& buffer)
		{
			auto transcriptStart = buffer.getPosition();
			buffer.writeEnumBE(MESSAGE_TYPE::certificate);
			{
				auto msgLength = buffer.saveOffset(3);

				buffer.writeByte(0); // certificate context
				{
					auto allCertsLength = buffer.saveOffset(3);
					{
						auto certLength = buffer.saveOffset(3);
						buffer.writeStream(server.getCertificateBytes());
					}
					buffer.writeBE<UINT16>(0); // no extensions
				}
			}
			transcriptHash.addMessage(transcriptStart.toBuffer());
		}

		void parseCertificates(BUFFER message)
		{
			auto context = readVariableData(message, 1);

			auto certs = readVariableData(message, 3);

			if (certs)
			{
				// parse the first certificate, ignore the rest...
				auto certData = readVariableData(certs, 3);
				parseX509Certificate(certData);

				auto extension = readVariableData(certs, 2);
			}
		}

		template <typename T>
		BUFFER getVerifyHash(T&& hashResult)
		{
			auto hash = transcriptHash.getHash();

			BUFFER_BUILDER buffer;
			for (UINT32 i = 0; i < 64; i++)
				buffer.writeByte(0x20);
			buffer.writeString("TLS 1.3, server CertificateVerify");
			buffer.writeByte(0);
			buffer.writeStream(hash);

			auto signData = buffer.toBuffer();
			auto status = BCryptHash(Algorithms.hashSha256, NULL, 0, (PUCHAR)signData.data(), signData.length(), hashResult.commit(32), 32);
			ASSERT(NT_SUCCESS(status));

			return hashResult.toBuffer();
		}

		void formatCertificateVerify(DATA_BUFFER& buffer)
		{
			auto transcriptStart = buffer.getPosition();
			buffer.writeEnumBE(MESSAGE_TYPE::certificate_verify);
			{
				auto msgLength = buffer.saveOffset(3);

				buffer.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp256r1_sha256);
				auto verifyHash = getVerifyHash(HKDF_BUFFER());

				auto signatureLength = buffer.saveOffset(2);
				if (server.getSignatureAlgorithm() == SIGNATURE_SCHEME::ecdsa_secp256r1_sha256)
				{
					ULONG bytesCopied;
					LOCAL_STREAM<64> sigData;
					auto status = BCryptSignHash(server.getCertificateKey(), NULL, (PUCHAR)verifyHash.data(), verifyHash.length(), sigData.commit(64), 64, &bytesCopied, 0);
					ASSERT(NT_SUCCESS(status));

					FormatECDSAP256Signature(buffer, sigData.toBuffer());
				}
				else DBGBREAK();
			}
			transcriptHash.addMessage(transcriptStart.toBuffer());
		}

		void parseCertificateVerify(BUFFER message)
		{
			auto signatureScheme = message.readEnumBE<SIGNATURE_SCHEME>();
			auto signature = readVariableData(message, 2);
			auto verifyHash = getVerifyHash(HKDF_BUFFER());

			if (signatureScheme == SIGNATURE_SCHEME::rsa_pss_rsae_sha256)
			{
				BCRYPT_PSS_PADDING_INFO paddingInfo;
				paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
				paddingInfo.cbSalt = 32;

				auto status = BCryptVerifySignature(certPublicKey.keyHandle, &paddingInfo, (PUCHAR)verifyHash.data(), 32, (PUCHAR)signature.data(), signature.length(), BCRYPT_PAD_PSS);
				ASSERT(NT_SUCCESS(status));
			}
			else if (signatureScheme == SIGNATURE_SCHEME::ecdsa_secp256r1_sha256)
			{
				LOCAL_STREAM<64> byteStream;
				auto sigData = ParseECDSAP256Signature(signature, byteStream);

				auto status = BCryptVerifySignature(certPublicKey.keyHandle, NULL, (PUCHAR)verifyHash.data(), 32, (PUCHAR)sigData.data(0), sigData.length(), 0);
				ASSERT(NT_SUCCESS(status));
			}
			else if (signatureScheme == SIGNATURE_SCHEME::rsa_pkcs1_sha256)
			{
				BCRYPT_PKCS1_PADDING_INFO paddingInfo;
				paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

				auto status = BCryptVerifySignature(certPublicKey.keyHandle, NULL, (PUCHAR)verifyHash.data(), 32, (PUCHAR)signature.data(), signature.length(), BCRYPT_PAD_PKCS1);
				ASSERT(NT_SUCCESS(status));
			}
			else DBGBREAK();
			LogInfo("Certificate Verify complete");
		}

		void formatFinished(DATA_BUFFER& buffer)
		{
			auto transcriptStart = buffer.getPosition();
			buffer.writeEnumBE(MESSAGE_TYPE::finished);
			{
				auto msgLength = buffer.saveOffset(3);

				HKDF_BUFFER finishedKeyBuffer;
				secret.deriveSecret(server.isClient() ? cipher.clientHandshakeSecret.toBuffer() : cipher.serverHandshakeSecret.toBuffer(),
					"finished", NULL_BUFFER, finishedKeyBuffer);

				auto finishedKey = finishedKeyBuffer.toBuffer();

				auto transcript = transcriptHash.getHash();
				HKDF_BUFFER verifyHash;

				auto status = BCryptHash(Algorithms.hmacSha256, (PUCHAR)finishedKey.data(), HKDF_HASH_LENGTH, (PUCHAR)transcript.data(), HKDF_HASH_LENGTH, verifyHash.commit(32), 32);
				ASSERT(NT_SUCCESS(status));

				buffer.writeStream(verifyHash.toBuffer());
			}
			transcriptHash.addMessage(transcriptStart.toBuffer());
		}

		void parseFinished(BUFFER message)
		{
			auto receivedHash = message.readBytes(HKDF_HASH_LENGTH);

			HKDF_BUFFER finishedKeyBuffer;
			secret.deriveSecret(server.isClient() ? cipher.serverHandshakeSecret.toBuffer() : cipher.clientHandshakeSecret.toBuffer(),
				"finished", NULL_BUFFER, finishedKeyBuffer);

			auto finishedKey = finishedKeyBuffer.toBuffer();

			auto transcript = transcriptHash.getHash();
			HKDF_BUFFER verifyHash;

			auto status = BCryptHash(Algorithms.hmacSha256, (PUCHAR)finishedKey.data(), HKDF_HASH_LENGTH, (PUCHAR)transcript.data(), HKDF_HASH_LENGTH, verifyHash.commit(32), 32);
			ASSERT(NT_SUCCESS(status));

			if (verifyHash.toBuffer() == receivedHash)
			{
				if (server.isServer())
				{
					generateMasterKeys();
				}
			}
			else DBGBREAK();

			LogInfo("Parse Finished complete");
		}

		UINT32 getRecordLength(DATA_BUFFER& dataBuffer)
		{
			auto buffer = dataBuffer.toBuffer();
			ASSERT(buffer.length() >= TLS_RECORD_HEADER);

			buffer.shift(3);
			return buffer.readBE<UINT16>();
		}

		template <typename F, typename ... Args>
		NTSTATUS sendRecord(TASK_ID taskId, RECORD_TYPE recordType, F func, Args&& ... args)
		{
			auto& buffer = cipher.sendRecord;
			buffer.clear();

			if (cipher.isEncrypted)
			{
				buffer.writeEnumBE(RECORD_TYPE::application_data);
				buffer.writeEnumBE(TLS_VERSION::TLS12);
				{
					auto recordLength = buffer.saveOffset(2);
					func(buffer, args ...);
					buffer.writeEnumBE(recordType);
					buffer.commit(AES_TAG_LENGTH);
				}
				cipher.encrypt(buffer.toBuffer());
			}
			else
			{
				ASSERT(recordType != RECORD_TYPE::application_data);
				buffer.writeEnumBE(recordType);
				buffer.writeEnumBE(TLS_VERSION::TLS12);
				{
					auto recordLength = buffer.saveOffset(2);
					func(buffer, args ...);
				}
			}

			auto status = socket.send(buffer.toBuffer(), STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto&& handshake = *(TLS13_HANDSHAKE*)context;
					auto taskId = argv.read<TASK_ID>();
					handshake.getScheduler().updateTask(taskId, STATUS_SUCCESS);
				}, this, taskId, 0));
			return status;
		}

		BUFFER parseMessageHeader(BUFFER& recvBuffer, MESSAGE_TYPE& msgType, BUFFER& msgData)
		{
			auto msgStart = recvBuffer.data();

			msgType = recvBuffer.readEnumBE<MESSAGE_TYPE>();
			msgData = readVariableData(recvBuffer, 3);

			return { msgStart,  4 + msgData.length() };
		}

		template <typename TASK>
		NTSTATUS sendFinished(TASK&& task)
		{
			auto taskId = getScheduler().queueTask(SIGNALING_SEND_PRIORITY, task);
			auto status = sendRecord(taskId, RECORD_TYPE::handshake, [](DATA_BUFFER& buffer, TLS13_HANDSHAKE& handshake)
				{
					handshake.formatFinished(buffer);
				}, *this);
			return status;
		}

		void parseRecord(BUFFER record)
		{
			auto recordStart = record;

			auto contentType = record.readEnumBE<RECORD_TYPE>();
			record.readEnumBE<TLS_VERSION>();
			record.readBE<UINT16>(); // length

			if (contentType == RECORD_TYPE::handshake)
			{
				MESSAGE_TYPE msgType; BUFFER msgData;
				auto message = parseMessageHeader(record, msgType, msgData);

				transcriptHash.addMessage(message);

				if (msgType == MESSAGE_TYPE::client_hello)
				{
					if (server.isServer())
					{
						parseClientHello(msgData);
					}
				}
				else if (msgType == MESSAGE_TYPE::server_hello)
				{
					parseServerHello(msgData);
					generateHandshakeKeys();
				}
				else DBGBREAK();
			}
			else if (contentType == RECORD_TYPE::application_data)
			{
				record = recordStart; // rewind
				cipher.decrypt(record);

				while (record && record.last() == 0)
					record.shrink(1);

				ASSERT(record.length() > 0);

				contentType = (RECORD_TYPE)record.last();
				record.shrink(1);

				if (contentType == RECORD_TYPE::handshake)
				{
					while (record.length() > 0)
					{
						MESSAGE_TYPE msgType; BUFFER msgData;
						auto message = parseMessageHeader(record, msgType, msgData);
						//auto msgStart = record.data();

						if (msgType == MESSAGE_TYPE::encrypted_extensions)
						{
							parseEncryptedExtensions(msgData);
							transcriptHash.addMessage(message);
						}
						else if (msgType == MESSAGE_TYPE::certificate)
						{
							parseCertificates(msgData);
							transcriptHash.addMessage(message);
						}
						else if (msgType == MESSAGE_TYPE::certificate_verify)
						{
							parseCertificateVerify(msgData);
							transcriptHash.addMessage(message);
						}
						else if (msgType == MESSAGE_TYPE::finished)
						{
							parseFinished(msgData);
							transcriptHash.addMessage(message);
							if (server.isClient())
							{
								masterTranscript.writeStream(transcriptHash.getHash());
								sendFinished(STASK([](PVOID context, NTSTATUS status, STASK_PARAMS)
									{
										auto&& handshake = *(TLS13_HANDSHAKE*)context;
										if (NT_SUCCESS(status))
										{
											handshake.generateMasterKeys();
											handshake.connection.onConnect(STATUS_SUCCESS);
										}
										//sendChangeCipherSpec();
									}, this));
							}
						}
						else
						{
							DBGBREAK();
						}
					}
				}
				else if (contentType == RECORD_TYPE::alert)
				{
					auto alertLevel = record.readEnumBE<ALERT_LEVEL>();
					auto alertDescription = record.readEnumBE<ALERT_DESCRIPTION>();
					LogInfo("Alert: %d/%d", alertLevel, alertDescription);
				}
				else if (contentType == RECORD_TYPE::change_cipher_spec)
				{
					LogInfo("Change Cipher Spec");
					// just ignore it.
				}
				else if (contentType == RECORD_TYPE::application_data)
				{
					connection.onReceive(record);
				}
				else
				{
					DBGBREAK();
				}
			}
		}

		void generateHandshakeKeys()
		{
			cipher.generateHandshakeKeys(secret, transcriptHash);
		}

		void generateMasterKeys()
		{
			cipher.generateMasterKeys(secret, masterTranscript.toBuffer());
		}

		void onReceive(BUFFER recvData)
		{
			auto& record = cipher.recvRecord;

			if (record.count() < TLS_RECORD_HEADER)
			{
				auto bytesNeeded = TLS_RECORD_HEADER - record.count();
				bytesNeeded = min(bytesNeeded, recvData.length());

				record.writeStream(recvData.readBytes(bytesNeeded));
				if (recvData)
				{
					onReceive(recvData);
				}
			}
			else
			{
				auto bytesNeeded = (getRecordLength(record) + TLS_RECORD_HEADER) - record.count();
				bytesNeeded = min(recvData.length(), bytesNeeded);

				record.writeStream(recvData.readBytes(bytesNeeded));

				if (record.count() >= (getRecordLength(record) + TLS_RECORD_HEADER))
				{
					getScheduler().runTask(SIGNALING_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
						{
							auto& handshake = *(TLS13_HANDSHAKE*)context;
							handshake.parseRecord(handshake.cipher.recvRecord.toBuffer());
						}, this));

					getScheduler().runTask(SIGNALING_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
						{
							auto& handshake = *(TLS13_HANDSHAKE*)context;
							handshake.cipher.recvRecord.clear();
							auto recvData = argv.read<BUFFER>();
							if (recvData)
							{
								handshake.onReceive(recvData);
							}
						}, this, recvData));
				}
			}
		}

		void onConnect(NTSTATUS status)
		{
			sendClientHello();
		}

		void onClose()
		{
			connection.onClose();
		}
	};

	STREAM_BUILDER<UINT8, SERVICE_STACK, 4096> recvStream;
	TLS13_HANDSHAKE handshake;
	SERVER& server;
	HTTP_APP dispatchApp;
	USTRING sessionName;
	SCHEDULER_INFO<HTTP_CONNECTION> scheduler;
	TASK_ID recvSyncTask;

	HTTP_CONNECTION(SERVER& serverArg, PWSK_SOCKET socketHandle) : server(serverArg), handshake(serverArg, *this, socketHandle), scheduler(*this)
	{
		dispatchApp = HTTP_APP::DISPATCH;
		scheduler.initialize();
	}

	CERTIFICATE& getServerCertificate()
	{
		return server.serverCertificate;
	}

	BCRYPT_KEY_HANDLE getCertificateKey()
	{
		return server.certificateKey;
	}

	BUFFER& getCertificateBytes()
	{
		return server.certificateBytes;
	}

	SIGNATURE_SCHEME getSignatureAlgorithm()
	{
		return server.signatureAlgorithm;
	}

	TOKEN getServerName()
	{
		return server.hostname;
	}

	void onConnect(NTSTATUS status)
	{
		UNREFERENCED_PARAMETER(status);
		LogInfo("TLS handshake complete");
		// handshake complete, nothing to do.
	}

	void onClose()
	{
		scheduler.runTask(SIGNALING_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				auto&& connection = *(HTTP_CONNECTION*)context;
				connection.server.onClose(&connection);
			}, this));
	}

	void switchToWebsocket(HEADER_TABLE& headers)
	{
		server.onSignalingStart(*this);
		auto taskId = scheduler.queueTask(SIGNALING_SEND_PRIORITY, STASK());
		handshake.sendRecord(taskId, RECORD_TYPE::application_data, [](DATA_BUFFER& sendBuffer, HEADER_TABLE& headers)
			{
				sendBuffer.writeMany("HTTP/1.1 101 Switching Protocols", CRLF);
				sendBuffer.writeMany("Upgrade: websocket", CRLF);
				sendBuffer.writeMany("Connection: Upgrade", CRLF);

				auto&& key = headers.find(HTTP_Sec_WebSocket_Key);
				if (key)
				{
					LOCAL_STREAM<64> keyReply;
					keyReply.writeStream(key.value);
					keyReply.writeStream(WEBSOCKET_GUID);

					LOCAL_STREAM<20> keyHash;
					auto status = BCryptHash(Algorithms.hashSha1, NULL, 0, (PUCHAR)keyReply.address(), keyReply.count(), keyHash.commit(20), 20);
					ASSERT(NT_SUCCESS(status));

					sendBuffer.writeString("Sec-WebSocket-Accept: ");
					sendBuffer.encodeBase64(keyHash.toBuffer());
					sendBuffer.writeStream(CRLF);
				}
				sendBuffer.writeStream(CRLF);
			}, headers);
	}

	void dispatchRequest(BUFFER recvSocketData)
	{
		recvStream.writeStream(recvSocketData);
		auto recvString = recvStream.toBuffer();

		if (auto headerString = String.splitStringIf(recvString, CRLF_CRLF))
		{
			auto title = String.splitString(headerString, CRLF);

			auto verbString = String.splitChar(title, WHITESPACE);
			auto verb = CreateCustomName<SERVICE_STACK>(verbString);
			auto urlPath = String.splitChar(title, WHITESPACE);

			HEADER_STREAM headerStream;
			while (auto line = String.splitString(headerString, CRLF))
			{
				auto nameString = String.splitChar(line, HTTP_HEADER_NAME_PATTERN);
				auto name = CreateCustomName<SERVICE_STACK>(nameString);
				headerStream.append(name, line);
			}

			auto headers = headerStream.toBuffer();
			auto&& upgradeAttr = headers.find(HTTP_Upgrade);

			if (auto && cookieAttribute = headers.find(HTTP_Cookie))
			{
				sessionName = ParseAttribute(cookieAttribute.value, HTTP_Session);
			}
			
			if (upgradeAttr && upgradeAttr.value == "websocket")
			{
				dispatchApp = HTTP_APP::WEBSOCKET;
				recvStream.clear();
				switchToWebsocket(headers);
			}
			else
			{
				if (verb == HTTP_POST)
				{
					auto&& header = headers.find(HTTP_Content_Length);
					ASSERT(IsValidRef(header));
					auto contentLength = String.toNumber(header.value.clone());

					if (recvString.length() >= (UINT32)contentLength)
					{
						server.onRequest(*this, verb, urlPath, headers, recvString);
						recvStream.clear();
					}
				}
				else
				{
					server.onRequest(*this, verb, urlPath, headers, NULL_STRING);
					recvStream.clear();
				}
			}
		}
	}

	void start()
	{
		// nothing for now.
	}

	template <typename TASK>
	void sendResponseHeaders(TOKEN status, TOKEN description, TOKEN contentType, USTRING contentData, TASK&& task)
	{
		auto taskId = scheduler.queueTask(SIGNALING_SEND_PRIORITY, task);
		handshake.sendRecord(taskId, RECORD_TYPE::application_data, [](DATA_BUFFER& buffer, HTTP_CONNECTION<SERVER>& connection,
			TOKEN status, TOKEN description, TOKEN contentType, USTRING& contentData)
			{
				buffer.writeMany("HTTP/1.1 ", status, " ", description, CRLF);
				buffer.writeMany(HTTP_Server, ": ", HTTP_SERVER_NAME, CRLF);
				buffer.writeMany(HTTP_Connection, ": ", HTTP_Keep_Alive, CRLF);

				buffer.writeMany(HTTP_Date, ": ");
				String.formatHttpDate(buffer);
				buffer.writeString(CRLF);

				ASSERT(connection.sessionName);
				TSTRING_BUILDER attrStream;
				auto attrData = FormatAttribute(attrStream.clear(), HTTP_Session, connection.sessionName);
				buffer.writeMany(HTTP_Set_Cookie, ": ", attrData, CRLF);

				if (contentData)
				{
					buffer.writeMany(HTTP_Content_Length, ": ", contentData.length(), CRLF);
					buffer.writeMany(HTTP_Content_Type, ": ", contentType, CRLF);
				}

				buffer.writeString(CRLF);

			}, *this, status, description, contentType, contentData);
	}

	void sendResponseData(BUFFER contentData)
	{
		if (contentData)
		{
			auto transferLength = min(contentData.length(), 12 * 1024);
			auto sendData = contentData.readBytes(transferLength);

			LogInfo("sendResponseData: sending %d bytes", sendData.length());
			auto taskId = scheduler.queueTask(SIGNALING_SEND_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					LogInfo("sendResponseData task callback");
					auto&& connection = *(HTTP_CONNECTION*)context;
					auto contentData = argv.read<BUFFER>();
					connection.sendResponseData(contentData);
				}, this, contentData));

			handshake.sendRecord(taskId, RECORD_TYPE::application_data, [](DATA_BUFFER& buffer, USTRING& content)
				{
					buffer.writeStream(content);
				}, sendData);
		}
		else
		{
			LogInfo("sendResponseData: Complete");
		}
	}

	void sendResponse(TOKEN status, TOKEN description, TOKEN contentType, USTRING contentData)
	{
		sendResponseHeaders(status, description, contentType, contentData, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto&& connection = *(HTTP_CONNECTION*)context;
				auto contentData = argv.read<BUFFER>();
				connection.sendResponseData(contentData);
			}, this, contentData));
	}

	void onWebsocketFrame(BUFFER frameBuffer, WEBSOCKET_OPCODE opCode, BUFFER maskKey)
	{
		auto mask = maskKey.data();
		auto frame = (PUINT8)frameBuffer.data();

		for (UINT32 i = 0; i < frameBuffer.length(); i++)
		{
			frame[i] ^= mask[i % 4];
		}

		if (opCode == WEBSOCKET_OPCODE::CLOSE)
		{
			dispatchApp = HTTP_APP::DISPATCH;
			sendWebsocketData(NULL_STRING, opCode, STASK([](PVOID, NTSTATUS, STASK_PARAMS)
				{
				}, this));
		}
		else if (opCode == WEBSOCKET_OPCODE::PING)
		{
			DBGBREAK();// XXX test it
			sendWebsocketData(frameBuffer, WEBSOCKET_OPCODE::PONG, STASK([](PVOID, NTSTATUS, STASK_PARAMS)
				{
				}, this));
		}
		else
		{
			server.onSignalingReceive(*this, frameBuffer);
		}

		LogInfo("Websocket application data: %d", frameBuffer.length());
	}

	struct FRAGMENT_INFO
	{
		bool isFragmented = false;
		bool assemblyComplete = false;
		WEBSOCKET_OPCODE opCode;
		BUFFER maskKey;
		BUFFER frame;
	};

	template <typename TASK>
	void sendWebsocketData(BUFFER sendData, WEBSOCKET_OPCODE opCode, TASK&& task)
	{
		auto taskId = scheduler.queueTask(SIGNALING_SEND_PRIORITY, task);
		handshake.sendRecord(taskId, RECORD_TYPE::application_data, [](DATA_BUFFER & buffer, BUFFER& sendData, WEBSOCKET_OPCODE opCode)
			{
				buffer.writeByte((UINT8)0x80 | (UINT8)opCode);
				auto payloadLength = sendData.length();

				if (payloadLength <= 125)
				{
					buffer.writeByte((UINT8)payloadLength);
				}
				else
				{
					buffer.writeByte(126);
					buffer.writeBE<UINT16>((UINT16)payloadLength);
				}

				buffer.writeStream(sendData);
			}, sendData, opCode);
	}

	void onWebsocketReceive(BUFFER recvSocketData)
	{
		recvStream.writeStream(recvSocketData);
		auto recvBuffer = recvStream.toBuffer();

		FRAGMENT_INFO fragmentInfo;
		while (recvBuffer)
		{
			if (recvBuffer.length() < 2)
				break;

			auto frameStart = recvBuffer.getPosition();

			auto finByte = recvBuffer.readByte();
			auto isFin = (finByte & 0x80) != 0;
			auto opCode = (WEBSOCKET_OPCODE)(finByte & 0x0F);

			auto maskByte = recvBuffer.readByte();
			auto isMasked = (maskByte & 0x80) != 0;
			UINT32 payloadLength = maskByte & 0x7F;

			if (payloadLength == 126)
			{
				if (recvBuffer.length() < sizeof(UINT16))
					break;
				payloadLength = recvBuffer.readBE<UINT16>();
			}
			else if (payloadLength == 127)
			{
				if (recvBuffer.length() < sizeof(UINT64))
					break;
				auto length = recvBuffer.readBE<UINT64>();
				ASSERT(length < MAXUINT32); // we don't support 64bit length
				payloadLength = (UINT32)length;
			}

			BUFFER maskKey;
			if (isMasked)
			{
				if (recvBuffer.length() < 4)
					break;
				maskKey = recvBuffer.readBytes(4);
			}


			if (recvBuffer.length() < payloadLength)
				break;

			if (isFin && opCode != WEBSOCKET_OPCODE::CONTINUATION)
			{
				// no fragments
				auto frameData = recvBuffer.readBytes(payloadLength);
				LogInfo("Calling onWebSocketFrame");
				onWebsocketFrame(frameData, opCode, maskKey);
				if (recvBuffer)
				{
					LogInfo("recvBuffer not empty");
					recvBuffer = recvStream.remove(frameStart, recvBuffer.getPosition() - frameStart);
				}
				else
				{
					LogInfo("recvBuffer empty, cleaing recvStream");
					recvStream.clear();
				}
			}
			else
			{
				DBGBREAK(); // XXX not tested
				// fragmented
				auto payloadStart = recvBuffer.getPosition();
				auto headerLength = payloadStart - frameStart;
				recvBuffer = recvStream.remove(frameStart, headerLength);
				recvBuffer.shift(payloadLength);

				if (isFin && opCode == WEBSOCKET_OPCODE::CONTINUATION)
				{
					ASSERT(fragmentInfo.isFragmented);
					// last fragment
					fragmentInfo.assemblyComplete = true;
					fragmentInfo.frame.expand(payloadLength);
					onWebsocketFrame(fragmentInfo.frame, fragmentInfo.opCode, fragmentInfo.maskKey);
				}
				else if (isFin == false)
				{
					if (opCode != WEBSOCKET_OPCODE::CONTINUATION)
					{
						// first fragment
						fragmentInfo.isFragmented = true;
						fragmentInfo.opCode = opCode;
						fragmentInfo.frame = BUFFER(recvStream.address(), frameStart, frameStart);
					}
					fragmentInfo.frame.expand(payloadLength);
				}
			}
		}
	}

	void onReceive(BUFFER recvSocketData)
	{
		if (dispatchApp == HTTP_APP::DISPATCH)
		{
			dispatchRequest(recvSocketData);
		}
		else if (dispatchApp == HTTP_APP::WEBSOCKET)
		{
			onWebsocketReceive(recvSocketData);
		}
		else DBGBREAK();
	}
};
