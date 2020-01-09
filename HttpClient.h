// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once
#include <time.h>

constexpr UINT32 PRF_HASH_LENGTH = 0x20;
constexpr UINT32 MASTER_SECRET_LENGTH = 0x30;
constexpr UINT32 PRF_RANDOM_LENGTH = 0x20;
constexpr UINT32 PRF_SEED_LENGTH = 0x40;

constexpr UINT32 TLS12_AES_IV_LENGTH = 4;

constexpr UINT32 TLS_DATA_MAX = 16 * 1024;

constexpr UINT32 TLS_RECORD_SIZE = (TLS_DATA_MAX + 256 + 5); // 16K data + 256 bytes for encryption expansion + 5 bytes for record header
using RECORD_STREAM = LOCAL_STREAM<TLS_RECORD_SIZE>;

constexpr UINT32 TLS_RECORD_HEADER = 5;
extern UINT32 ReadDownloadCache(USTRING path);

struct TLS12_CIPHER
{
	LOCAL_STREAM<MASTER_SECRET_LENGTH> masterSecret;
	LOCAL_STREAM<PRF_RANDOM_LENGTH> clientRandom;
	LOCAL_STREAM<PRF_RANDOM_LENGTH> serverRandom;

	RECORD_STREAM recvRecord;
	RECORD_STREAM sendRecord;

	BCRYPT_KEY_HANDLE sendKey;
	BCRYPT_KEY_HANDLE recvKey;

	UINT8 sendIV[TLS12_AES_IV_LENGTH];
	UINT8 recvIV[TLS12_AES_IV_LENGTH];

	UINT64 sendSequenceNumber = 0;
	UINT64 recvSequenceNumber = 0;

	bool sendEncrypted = false;
	bool recvEncrypted = false;

	void reset()
	{
		masterSecret.clear();
		clientRandom.clear();
		serverRandom.clear();

		sendKey = recvKey = nullptr;

		recvRecord.clear();
		sendRecord.clear();

		sendSequenceNumber = recvSequenceNumber = 0;
		sendEncrypted = recvEncrypted = false;
	}

	void writeExplicitIV(RECORD_STREAM& outStream)
	{
		if (sendEncrypted)
		{
			outStream.writeBE<UINT64>(sendSequenceNumber);
		}
	}

	void writeAEADtags(RECORD_STREAM& outStream)
	{
		if (sendEncrypted)
		{
			outStream.commit(AES_TAG_LENGTH);
		}
	}

	template <typename STREAM>
	BUFFER PRF(USTRING label, BUFFER seed, STREAM&& prfOutput, UINT32 outputLength)
	{
		auto targetCount = prfOutput.count() + outputLength;

		HMAC256 hmac;
		hmac.setSecret(masterSecret.toBuffer());

		LOCAL_STREAM<PRF_HASH_LENGTH> A_Buffer;
		auto status = hmac.getHash(A_Buffer, label, seed);
		ASSERT(NT_SUCCESS(status));

		while (prfOutput.count() < targetCount)
		{
			LOCAL_STREAM<PRF_HASH_LENGTH> hashOutput;
			status = hmac.getHash(hashOutput, A_Buffer.toBuffer(), label, seed);
			ASSERT(NT_SUCCESS(status));

			prfOutput.writeBytes(hashOutput.address(), min(PRF_HASH_LENGTH, (targetCount - prfOutput.count())));

			LOCAL_STREAM<PRF_HASH_LENGTH> hashData;
			hashData.writeStream(A_Buffer.toBuffer());

			status = hmac.getHash(A_Buffer.clear(), hashData.toBuffer());
			ASSERT(NT_SUCCESS(status));
		}

		hmac.close();
		return prfOutput.toBuffer();
	}

	void generateTrafficKeys()
	{
		do
		{
			LOCAL_STREAM<PRF_SEED_LENGTH> seed;
			seed.writeStream(serverRandom.toBuffer());
			seed.writeStream(clientRandom.toBuffer());

			LOCAL_STREAM<40> hashOutput;
			auto hash = PRF("key expansion", seed.toBuffer(), hashOutput, 40);

			auto status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &sendKey, NULL, 0, (PUCHAR)hash.readBytes(AES128_KEY_LENGTH).data(), AES128_KEY_LENGTH, 0);
			VERIFY_STATUS;

			status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &recvKey, NULL, 0, (PUCHAR)hash.readBytes(AES128_KEY_LENGTH).data(), AES128_KEY_LENGTH, 0);
			VERIFY_STATUS;

			RtlCopyMemory(sendIV, hash.readBytes(TLS12_AES_IV_LENGTH).data(), TLS12_AES_IV_LENGTH);
			RtlCopyMemory(recvIV, hash.data(), TLS12_AES_IV_LENGTH);

		} while (false);
	}

	void generateMasterSecret(BUFFER sharedSecret)
	{
		ASSERT(sharedSecret.length() == 32);
		LOCAL_STREAM<PRF_SEED_LENGTH> seed;
		seed.writeStream(clientRandom.toBuffer());
		seed.writeStream(serverRandom.toBuffer());

		LOCAL_STREAM<MASTER_SECRET_LENGTH> newSecret;
		ASSERT(masterSecret.count() == 0);
		masterSecret.writeStream(sharedSecret); // use sharedSecret as preMasterSecret
		PRF("master secret", seed.toBuffer(), newSecret, MASTER_SECRET_LENGTH);

		masterSecret.clear().writeStream(newSecret.toBuffer());
	}

	void encrypt(BUFFER record)
	{
		if (sendEncrypted)
		{
			auto recordHeader = record.readBytes(TLS_RECORD_HEADER);

			LOCAL_STREAM<12> ivData;
			ivData.writeBytes(sendIV, 4);
			ivData.writeStream(record.readBytes(8));

			auto tag = record.shrink(AES_TAG_LENGTH);

			LOCAL_STREAM<sizeof(UINT64) + TLS_RECORD_HEADER> additionalData;
			additionalData.writeBE(sendSequenceNumber++);
			additionalData.writeByte(recordHeader.readByte());
			additionalData.writeEnumBE(TLS_VERSION::TLS12);
			additionalData.writeBE<UINT16>((UINT16)record.length());

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
			BCRYPT_INIT_AUTH_MODE_INFO(aead);

			aead.pbAuthData = additionalData.address();
			aead.cbAuthData = sizeof(UINT64) + TLS_RECORD_HEADER;
			aead.pbNonce = ivData.address();
			aead.cbNonce = 12;
			aead.pbTag = (PUCHAR)tag.data();
			aead.cbTag = AES_TAG_LENGTH;

			ULONG bytesEncoded;
			auto status = BCryptEncrypt(sendKey, (PUCHAR)record.data(), record.length(), &aead, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesEncoded, 0);
			ASSERT(NT_SUCCESS(status));
		}
	}

	BUFFER decrypt(BUFFER record, BUFFER recordHeader)
	{
		if (recvEncrypted)
		{
			auto tag = record.shrink(AES_TAG_LENGTH);

			LOCAL_STREAM<12> ivData;
			ivData.writeBytes(recvIV, 4);
			ivData.writeStream(record.readBytes(8));

			LOCAL_STREAM<sizeof(UINT64) + TLS_RECORD_HEADER> additionalData;
			additionalData.writeBE(recvSequenceNumber++);
			additionalData.writeByte(recordHeader.readByte());
			auto tlsVersion = recordHeader.readEnumBE<TLS_VERSION>();
			additionalData.writeEnumBE(tlsVersion);
			additionalData.writeBE<UINT16>((UINT16)record.length());

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
			BCRYPT_INIT_AUTH_MODE_INFO(aead);

			aead.pbAuthData = additionalData.address();
			aead.cbAuthData = sizeof(UINT64) + TLS_RECORD_HEADER;
			aead.pbNonce = ivData.address();
			aead.cbNonce = 12;
			aead.pbTag = (PUCHAR)tag.data();
			aead.cbTag = AES_TAG_LENGTH;

			ULONG bytesDecoded;
			auto status = BCryptDecrypt(recvKey, (PUCHAR)record.data(), record.length(), &aead, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesDecoded, 0);
			ASSERT(NT_SUCCESS(status));
		}
		return record;
	}
};

template <typename CONTEXT>
struct TLS12_HANDSHAKE
{
	ECDH_KEYSHARE keyShare;
	TLS12_CIPHER cipher;

	TCP_SOCKET<TLS12_HANDSHAKE> socket;
	TOKEN serverName;

	TRANSCRIPT_HASH handshakeHash;

	STREAM_BUILDER<CERTIFICATE, SERVICE_STACK, 4> certificates;

	CONTEXT& context;

	TLS12_HANDSHAKE(CONTEXT& contextArg) : context(contextArg), socket(*this) {}

	auto& getScheduler() { return context.scheduler; }

	void reset()
	{
		handshakeHash.reset();
		certificates.clear();
		socket.close();
		cipher.reset();
	}

	UINT32 getUnixTime()
	{
		LARGE_INTEGER systemTime;
		KeQuerySystemTime(&systemTime);

		UINT32 seconds;
		RtlTimeToSecondsSince1970(&systemTime, (ULONG*)&seconds);

		return seconds;
	}

	template <UINT32 SZ>
	BUFFER generateRandom(LOCAL_STREAM<SZ>& stream)
	{
		ASSERT(stream.count() == 0);
		stream.writeBE<UINT32>(getUnixTime());
		Random.generateRandom(stream, 28);

		return stream.toBuffer();
	}

	void formatServerName(RECORD_STREAM& outStream)
	{
		outStream.writeEnumBE(EXTENSION_TYPE::server_name);
		{
			auto extLength = outStream.saveOffset(2);
			{
				auto nameListLength = outStream.saveOffset(2);
				outStream.writeByte(0); // type
				{
					auto nameLength = outStream.saveOffset(2);
					outStream.writeName(serverName);
				}
			}
		}
	}

	void formatSupportedGroups(RECORD_STREAM& outStream)
	{
		outStream.writeEnumBE(EXTENSION_TYPE::supported_groups);
		auto extLength = outStream.saveOffset(2);

		{
			auto groupLength = outStream.saveOffset(2);
			//buffer.writeEnumBE(SUPPORTED_GROUPS::x25519);
			outStream.writeEnumBE(SUPPORTED_GROUPS::secp256r1);
		}
	}

	void formatECPointFormats(RECORD_STREAM& outStream)
	{
		outStream.writeEnumBE(EXTENSION_TYPE::ec_point_formats);
		auto extLength = outStream.saveOffset(2);
		{
			outStream.writeByte(0x01);
			outStream.writeByte(0);
		}
	}


	void formatSignatureAlgorithms(RECORD_STREAM& outStream)
	{
		outStream.writeEnumBE(EXTENSION_TYPE::signature_algorithms);
		auto extLength = outStream.saveOffset(2);
		{
			auto algLength = outStream.saveOffset(2);

			outStream.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_rsae_sha256);
			outStream.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_pss_sha256);
			outStream.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_rsae_sha512);
			outStream.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_pss_sha512);
			outStream.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp256r1_sha256);
			outStream.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp521r1_sha512);
		}
	}

	template <typename FUNC, typename ... ARGS>
	void formatRecord(RECORD_STREAM& outStream, RECORD_TYPE recordType, MESSAGE_TYPE msgType, FUNC func, ARGS&& ... args)
	{
		auto recordStart = outStream.getPosition();

		outStream.writeEnumBE(recordType);
		outStream.writeEnumBE(TLS_VERSION::TLS12);
		{
			auto recordLength = outStream.saveOffset(2);
			cipher.writeExplicitIV(outStream);

			if (recordType == RECORD_TYPE::handshake)
			{
				auto msgStart = outStream.getPosition();
				outStream.writeEnumBE(msgType);
				{
					auto msgLength = outStream.saveOffset(3);
					func(outStream, *this, args ...);
				}
				handshakeHash.addMessage(msgStart.toBuffer());
			}
			else
			{
				func(outStream, *this, args ...);
			}
			cipher.writeAEADtags(outStream);
		}

		cipher.encrypt(recordStart.toBuffer());
	}

	void formatClientHello(RECORD_STREAM& outStream)
	{
		formatRecord(outStream, RECORD_TYPE::handshake, MESSAGE_TYPE::client_hello, [](RECORD_STREAM& outStream, TLS12_HANDSHAKE<CONTEXT>& handshake)
			{
				outStream.writeEnumBE(TLS_VERSION::TLS12);
				auto random = handshake.generateRandom(handshake.cipher.clientRandom);
				outStream.writeStream(random);

				outStream.writeByte(0); // session id

				outStream.writeBE<UINT16>(4);
				outStream.writeEnumBE(CIPHER_SUITE::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
				outStream.writeEnumBE(CIPHER_SUITE::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

				outStream.writeByte(1);
				outStream.writeByte(0); // zero compression.

				{
					auto extensionOffset = outStream.saveOffset(2);
					handshake.formatServerName(outStream);
					handshake.formatSupportedGroups(outStream);
					handshake.formatECPointFormats(outStream);
					handshake.formatSignatureAlgorithms(outStream);
				}
			});
	}

	BUFFER readExtension(BUFFER& message, EXTENSION_TYPE& type)
	{
		type = message.readEnumBE<EXTENSION_TYPE>();
		auto length = message.readBE<UINT16>();

		return message.readBytes(length);
	}

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

	void parseServerHello(BUFFER data)
	{
		auto version = data.readEnumBE<TLS_VERSION>();
		UNREFERENCED_PARAMETER(version);

		data.copyTo(cipher.serverRandom.commit(32), 32);

		auto sessionId = readVariableData(data, 1);

		auto cipherSuite = data.readEnumBE<CIPHER_SUITE>();
		UNREFERENCED_PARAMETER(cipherSuite);

		data.readByte(); // compression
	}

	void parseServerKeyExchange(BUFFER buffer)
	{
		auto hashStart = buffer.data();

		auto curveType = buffer.readByte();
		ASSERT(curveType == 0x03); // named curve

		auto group = buffer.readEnumBE<SUPPORTED_GROUPS>();
		keyShare.initialize(group);

		auto peerKey = readVariableData(buffer, 1);
		keyShare.createSharedSecret(peerKey);
		cipher.generateMasterSecret(keyShare.sharedSecret.toBuffer());
		cipher.generateTrafficKeys();

		BUFFER hashInput{ hashStart, (UINT32)(buffer.data() - hashStart) };

		auto signatureAlgorithm = buffer.readEnumBE<SIGNATURE_SCHEME>();

		auto signatureBuf = readVariableData(buffer, 2);


		auto&& certificate = certificates.at(0);

		if (signatureAlgorithm == SIGNATURE_SCHEME::ecdsa_secp256r1_sha256)
		{
			LOCAL_STREAM<SHA256_HASH_LENGTH> hashOutput;
			HashSha256.getHash(hashOutput, cipher.clientRandom.toBuffer(), cipher.serverRandom.toBuffer(), hashInput);

			LOCAL_STREAM<64> sigData;
			auto signature = ParseECDSAP256Signature(signatureBuf, sigData);

			auto status = BCryptVerifySignature(certificate.keyHandle, NULL, hashOutput.address(), SHA256_HASH_LENGTH, (PUCHAR)signature.data(), signature.length(), 0);
			ASSERT(NT_SUCCESS(status));
		}
		else if (signatureAlgorithm == SIGNATURE_SCHEME::rsa_pkcs1_sha256)
		{
			LOCAL_STREAM<SHA256_HASH_LENGTH> hashOutput;
			HashSha256.getHash(hashOutput, cipher.clientRandom.toBuffer(), cipher.serverRandom.toBuffer(), hashInput);

			BCRYPT_PKCS1_PADDING_INFO paddingInfo;
			paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

			auto status = BCryptVerifySignature(certificate.keyHandle, &paddingInfo, hashOutput.address(), SHA256_HASH_LENGTH, (PUCHAR)signatureBuf.data(), signatureBuf.length(), BCRYPT_PAD_PKCS1);
			ASSERT(NT_SUCCESS(status));
		}
		else if (signatureAlgorithm == SIGNATURE_SCHEME::rsa_pkcs1_sha1)
		{
			LOCAL_STREAM<SHA1_HASH_LENGTH> hashOutput;
			HashSha1.getHash(hashOutput, cipher.clientRandom.toBuffer(), cipher.serverRandom.toBuffer(), hashInput);

			BCRYPT_PKCS1_PADDING_INFO paddingInfo;
			paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;

			auto status = BCryptVerifySignature(certificate.keyHandle, &paddingInfo, hashOutput.address(), SHA1_HASH_LENGTH, (PUCHAR)signatureBuf.data(), signatureBuf.length(), BCRYPT_PAD_PKCS1);
			ASSERT(NT_SUCCESS(status));
		}
		else if (signatureAlgorithm == SIGNATURE_SCHEME::rsa_pss_rsae_sha256)
		{
			LOCAL_STREAM<SHA256_HASH_LENGTH> hashOutput;
			HashSha256.getHash(hashOutput, cipher.clientRandom.toBuffer(), cipher.serverRandom.toBuffer(), hashInput);

			BCRYPT_PSS_PADDING_INFO paddingInfo;
			paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
			paddingInfo.cbSalt = 32;

			auto status = BCryptVerifySignature(certificate.keyHandle, &paddingInfo, hashOutput.address(), SHA256_HASH_LENGTH, (PUCHAR)signatureBuf.data(), signatureBuf.length(), BCRYPT_PAD_PSS);
			ASSERT(NT_SUCCESS(status));
		}
		else
		{
			DBGBREAK();
		}
	}

	void parseCertificateStatus(BUFFER buffer)
	{
		auto statusType = buffer.readByte();

		ASSERT(statusType == 1); // OSCP
	}

	void formatClientKeyExchange(RECORD_STREAM& outStream)
	{
		formatRecord(outStream, RECORD_TYPE::handshake, MESSAGE_TYPE::client_key_exchange, [](RECORD_STREAM& outStream, TLS12_HANDSHAKE<CONTEXT>& handshake)
			{
				auto length = outStream.saveOffset(1);
				handshake.keyShare.getPublicKey(outStream);
			});
	}

	void formatFinishMessage(RECORD_STREAM& outStream)
	{
		formatRecord(outStream, RECORD_TYPE::handshake, MESSAGE_TYPE::finished, [](RECORD_STREAM& outStream, TLS12_HANDSHAKE<CONTEXT>& handshake)
			{
				handshake.cipher.PRF("client finished", handshake.handshakeHash.getHash(), outStream, 12);
			});
	}

	NTSTATUS formatChangeCipherSepc(RECORD_STREAM& outStream)
	{
		auto status = STATUS_SUCCESS;
		outStream.writeEnumBE(RECORD_TYPE::change_cipher_spec);
		outStream.writeEnumBE(TLS_VERSION::TLS12);
		{
			auto recordLength = outStream.saveOffset(2);
			outStream.writeByte(0x01);
		}

		cipher.sendEncrypted = true;

		cipher.sendSequenceNumber = 0;
		cipher.recvSequenceNumber = 0;

		return status;
	}

	void sendAlert(ALERT_DESCRIPTION code)
	{
		formatRecord(cipher.sendRecord.clear(), RECORD_TYPE::alert, MESSAGE_TYPE::unknown, [](RECORD_STREAM& outStream, TLS12_HANDSHAKE<CONTEXT>& handshake, ALERT_DESCRIPTION code)
			{
				outStream.writeEnumBE(ALERT_LEVEL::fatal);
				outStream.writeEnumBE(code);
			}, code);
		session.sendTo(cipher.sendRecord.toBuffer(), STASK());
	}

	void parseCertificates(BUFFER message)
	{
		auto certsData = readVariableData(message, 3);

		while (certsData)
		{
			auto certData = readVariableData(certsData, 3);
			auto& certificate = certificates.append();
			ParseX509(certData, certificate);
		}
	}

	bool parseFinished(BUFFER message, BUFFER transcriptHash)
	{
		auto receivedHash = message.readBytes(12);

		LOCAL_STREAM<12> expectedHash;
		cipher.PRF("server finished", transcriptHash, expectedHash, 12);
		auto result = receivedHash == expectedHash.toBuffer();
		ASSERT(result);
		return result;
	}

	void parseRecord(BUFFER record)
	{
		auto recordHeader = record.readBytes(TLS_RECORD_HEADER);
		auto data = cipher.decrypt(record, recordHeader);

		auto recordType = recordHeader.readEnumBE<RECORD_TYPE>();

		if (recordType == RECORD_TYPE::handshake)
		{
			auto message = data;

			auto finishMessageHash = handshakeHash.getHash();
			handshakeHash.addMessage(message);

			auto msgType = message.readEnumBE<MESSAGE_TYPE>();
			auto msgData = readVariableData(message, 3);

			if (msgType == MESSAGE_TYPE::server_hello)
			{
				parseServerHello(msgData);
			}
			else if (msgType == MESSAGE_TYPE::server_key_exchange)
			{
				parseServerKeyExchange(msgData);
			}
			else if (msgType == MESSAGE_TYPE::certificate_status)
			{
				parseCertificateStatus(msgData);
			}
			else if (msgType == MESSAGE_TYPE::certificate)
			{
				parseCertificates(msgData);
			}
			else if (msgType == MESSAGE_TYPE::server_hello_done)
			{
				formatClientKeyExchange(cipher.sendRecord.clear());
				formatChangeCipherSepc(cipher.sendRecord);
				formatFinishMessage(cipher.sendRecord);

				socket.send(cipher.sendRecord.toBuffer(), STASK());
			}
			else if (msgType == MESSAGE_TYPE::finished)
			{
				auto isValid = parseFinished(msgData, finishMessageHash);
				context.onTlsConnect(isValid ? STATUS_SUCCESS : STATUS_AUTH_TAG_MISMATCH);
			}
			else DBGBREAK();
		}
		else if (recordType == RECORD_TYPE::change_cipher_spec)
		{
			cipher.recvSequenceNumber = 0;
			cipher.recvEncrypted = true;
			LogInfo("change_cipher_spec");
		}
		else if (recordType == RECORD_TYPE::application_data)
		{
			context.onReceive(data);
		}
		else if (recordType == RECORD_TYPE::alert)
		{
			auto alertType = data.readByte();
			auto alertRecord = data.readByte();

			LogInfo("alert received, %d/%d", alertType, alertRecord);
		}
	}

	template <typename F, typename ... Args>
	NTSTATUS sendData(F func, Args&& ... args)
	{
		auto& outStream = cipher.sendRecord;
		outStream.clear();

		outStream.writeEnumBE(RECORD_TYPE::application_data);
		outStream.writeEnumBE(TLS_VERSION::TLS12);
		{
			auto recordLength = outStream.saveOffset(2);

			outStream.writeBE(cipher.sendSequenceNumber);

			func(outStream, args ...);

			outStream.commit(AES_TAG_LENGTH);
		}

		cipher.encrypt(outStream.toBuffer());

		auto status = socket.send(outStream.toBuffer(), STASK());
		return status;
	}

	UINT32 getRecordLength(RECORD_STREAM& stream)
	{
		auto buffer = stream.toBuffer();

		ASSERT(buffer.length() >= TLS_RECORD_HEADER);

		buffer.shift(3);
		return buffer.readBE<UINT16>();
	}

	void onClose()
	{

	}
	void onReceive(BUFFER recvData)
	{
		auto& record = cipher.recvRecord;

		if (record.count() < TLS_RECORD_HEADER)
		{
			auto bytesNeeded = TLS_RECORD_HEADER - record.count();
			bytesNeeded = min(bytesNeeded, recvData.length());

			record.writeStream(recvData.readBytes(bytesNeeded));
		}
		else
		{
			auto bytesNeeded = (getRecordLength(record) + TLS_RECORD_HEADER) - record.count();
			bytesNeeded = min(recvData.length(), bytesNeeded);

			record.writeStream(recvData.readBytes(bytesNeeded));

			if (record.count() >= (getRecordLength(record) + TLS_RECORD_HEADER))
			{
				parseRecord(record.toBuffer());
				record.clear();
			}
		}

		if (recvData)
		{
			onReceive(recvData);
		}

	}

	NTSTATUS startClient(URL_INFO& url)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			serverName = url.hostname;

			status = socket.connect(url, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS)
				{
					auto& handshake = *(TLS12_HANDSHAKE<CONTEXT>*)context;
					if (NT_SUCCESS(status))
					{
						handshake.formatClientHello(handshake.cipher.sendRecord.clear()); // formatRecord(MESSAGE_TYPE::client_hello);
						handshake.socket.send(handshake.cipher.sendRecord.toBuffer(), STASK());
					}
					else
					{
						handshake.context.onTlsConnect(status);
					}
				}, this));
			VERIFY_STATUS;

		} while (false);
		return status;
	}
};

struct CHUNK_TRANSFER
{
	bool chunkSizeKnown = false;

	UINT32 chunkSize = 0;
	UINT32 chunkStart = 0;

	void reset()
	{
		chunkSize = 0;
		chunkStart = 0;
	}

	template <typename STREAM>
	bool processData(STREAM&& recvStream)
	{
		DBGBREAK();
		auto transferComplete = false;

		if (chunkSize > 0)
		{
			auto chunkBytesReceived = recvStream.count() - chunkStart;
			if (chunkBytesReceived > chunkSize)
			{
				chunkStart += chunkSize;
				chunkSize = 0;
			}
		}

		if (chunkSize == 0)
		{
			auto chunkString = BUFFER{ recvStream.address(chunkStart), recvStream.count() - chunkStart };
			if (chunkString.length() > 2)
			{
				if (auto lineString = String.splitStringIf(chunkString, CRLF))
				{
					auto sizeString = String.splitChar(lineString, ';');
					if (sizeString)
					{
						chunkSize = String.toHexNumber(sizeString);
						auto bytesShifted = chunkString._start;

						//chunkStart += bytesShifted;
						recvStream.remove(chunkStart, bytesShifted);

						if (chunkSize == 0)
						{
							transferComplete = true;
						}
						else if (recvStream.count() > chunkStart)
						{
							return processData(recvStream);
						}
					}
				}
			}
		}

		return transferComplete;
	}
};

constexpr USTRING CACHE_DIRECTORY = "cache";
template <typename CONTEXT>
struct HTTP_CLIENT
{
	CONTEXT& context;
	SCHEDULER_INFO<HTTP_CLIENT> scheduler;
	HTTP_CLIENT(CONTEXT& contextArg) : context(contextArg), handshake(*this), scheduler(*this) 
	{
		scheduler.initialize();
	}

	TLS12_HANDSHAKE<HTTP_CLIENT> handshake;
	URL_INFO requestUrl;

	STREAM_BUILDER<UINT8, SERVICE_STACK, 1> recvStream;

	CHUNK_TRANSFER chunkState;

	UINT32 contentLength = 0;
	bool chunkTransfer = false;
	bool isKeepAlive = false;
	bool headersParsed = false;

	bool waitingForHeaders = true;
	bool downloadComplete = false;

	TASK_ID completionTaskId;

	void setCookie(USTRING text)
	{
		auto nameValuePair = String.splitChar(text, ";");
		auto nameText = String.splitChar(nameValuePair, "=");

		auto name = CreateCustomName<SERVICE_STACK>(nameText);
		auto value = CreateCustomName<SERVICE_STACK>(nameValuePair);

		auto& cookie = context.setCookie(name, value);

		while (auto param = String.splitChar(text, ";"))
		{
			auto nameText = String.splitChar(param, "=");
			auto name = FindName(nameText);

			if (name == HTTP_Expires)
			{
				cookie.expires = String.parseRfcDate(param);
			}
			else if (name == HTTP_Domain)
			{
				cookie.domain = CreateCustomName<SERVICE_STACK>(param);
			}
			else if (name == HTTP_Path)
			{
				cookie.path = CreateCustomName<SERVICE_STACK>(param);
			}
			else if (name == HTTP_Max_Age)
			{
				auto seconds = String.toNumber(param);
				LARGE_INTEGER systemTime;
				KeQuerySystemTime(&systemTime);

				cookie.expires = systemTime.QuadPart + (seconds * TIMEUNITS_PER_SECOND);
			}
		}
	}

	void parseResponseHeaders()
	{
		auto responseString = recvStream.toBuffer();
		if (auto headerString = String.splitStringIf(responseString, HTTP_HEADERS_DELIMITER))
		{
			waitingForHeaders = false;

			auto title = String.splitString(headerString, CRLF);
			auto httpVersion = String.splitChar(title, WHITESPACE_PATTERN);
			auto httpStatus = String.splitChar(title, WHITESPACE_PATTERN);

			while (auto line = String.splitString(headerString, CRLF))
			{
				auto header = String.splitChar(line, HTTP_HEADER_NAME_PATTERN);
				auto headerName = FindName(header);
				if (headerName == HTTP_Content_Length)
				{
					contentLength = String.toNumber(line);
				}
				else if (headerName == HTTP_Transfer_Encoding)
				{
					chunkTransfer = String.equals(line, "chunked");
				}
				else if (headerName == HTTP_Connection)
				{
					isKeepAlive = String.equals(line, "keep-alive");
				}
				else if (headerName == HTTP_Set_Cookie)
				{
					setCookie(line);
				}
			}

			auto bytesConsumed = responseString._start;
			recvStream.remove(0, bytesConsumed);
		}
	}

	void sendRequest()
	{
		handshake.sendData([](RECORD_STREAM& outStream, HTTP_CLIENT& download)
			{
				auto cookieTable = download.context.getCookieTable();

				outStream.writeMany("GET /", download.requestUrl.path, " HTTP/1.1", CRLF);
				outStream.writeMany("Host: ", download.requestUrl.hostname, CRLF);
				outStream.writeString(UserAgent);
				outStream.writeMany("Accept: */*", CRLF);
				outStream.writeMany("Connection: Keep-Alive", CRLF);
				if (cookieTable)
				{
					outStream.writeString("Cookie: ");
					for (auto cookie : cookieTable)
					{
						outStream.writeMany(cookie.name, "=", cookie.value, ";");
					}
					outStream.writeString(CRLF);
				}
				outStream.writeString(CRLF);
			}, *this);
	}

	void onReceive(BUFFER dataBuffer)
	{
		recvStream.writeStream(dataBuffer);
		auto transferComplete = false;

		if (waitingForHeaders)
		{
			parseResponseHeaders();
			if (contentLength > 0)
			{
				recvStream.reserve(contentLength);
			}
		}
		else
		{
			if (chunkTransfer)
			{
				transferComplete = chunkState.processData(recvStream);
			}
			else if (contentLength > 0)
			{
				if (recvStream.count() >= contentLength)
				{
					transferComplete = true;
				}
			}
		}
		if (transferComplete)
		{
			auto filename = urlToFilename(requestUrl, GetStringBuilder<SERVICE_STACK>());
			SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
				{
					ASSERT(NT_SUCCESS(status));
					auto& httpClient = *(HTTP_CLIENT<CONTEXT>*)context;
					auto filename = argv.read<USTRING>();

					WriteFile(filename, httpClient.recvStream.toBuffer());
					httpClient.context.scheduler.updateTask(httpClient.completionTaskId, STATUS_SUCCESS, httpClient.recvStream.toBuffer());

				}, this, filename));
		}
		LogInfo("Received %d bytes", dataBuffer.length());
	}

	void onTlsConnect(NTSTATUS status)
	{
		if (NT_SUCCESS(status))
		{
			sendRequest();
		}
		else
		{
			context.scheduler.updateTask(completionTaskId, status);
		}
	}

	template <typename STREAM>
	USTRING urlToFilename(URL_INFO url, STREAM&& pathStream)
	{
		pathStream.writeMany(CACHE_DIRECTORY, "\\", url.hostname);

		SystemScheduler().runTask(STASK([](PVOID, NTSTATUS, STASK_PARAMS argv)
			{
				auto filename = argv.read<USTRING>();
				CreateDirectory(filename);
			}, nullptr, pathStream.toBuffer()));

		pathStream.writeString("\\");
		if (IsEmptyString(url.path))
		{
			pathStream.writeString("index.html");
		}
		else
		{
			auto pathString = NameToString(url.path);
			ASSERT(pathString);
			pathString = String.splitChar(pathString, "?#");
			pathStream.writeString(pathString);
		}
		return pathStream.toBuffer();
	}

	template <typename TASK>
	NTSTATUS download(URL_INFO url, TASK&& task)
	{
		auto status = STATUS_SUCCESS;
		completionTaskId = context.scheduler.queueTask(SOCKET_RECV_PRIORITY - 1, task);

		requestUrl = url;
		auto filename = urlToFilename(requestUrl, GetStringBuilder<SCHEDULER_STACK>());
		auto fileSize = ReadDownloadCache(filename);
		if (fileSize > 0)
		{
			recvStream.reserve(fileSize);
			SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto& httpClient = *(HTTP_CLIENT<CONTEXT>*)context;
					auto filename = argv.read<USTRING>();

					httpClient.recvStream.readFile(filename);

					httpClient.context.scheduler.updateTask(httpClient.completionTaskId, STATUS_SUCCESS, httpClient.recvStream.toBuffer());
				}, this, filename));
		}
		else
		{
			recvStream.reserve(256 * 1024);
			scheduler.runTask(SOCKET_RECV_PRIORITY - 1, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
				{
					auto& httpClient = *(HTTP_CLIENT<CONTEXT>*)context;
					auto status = httpClient.handshake.startClient(httpClient.requestUrl);
					ASSERT(NT_SUCCESS(status));
				}, this));
		}

		return status;
	}

	void close()
	{
		downloadComplete = true;
	}
};
