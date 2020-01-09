#pragma once

#include "..\UMLibrary\Crypto.h"
#include "Tls.h"

constexpr UINT32 PRF_HASH_LENGTH = 0x20;
constexpr UINT32 MASTER_SECRET_LENGTH = 0x30;
constexpr UINT32 PRF_RANDOM_LENGTH = 0x20;
constexpr UINT32 PRF_SEED_LENGTH = 0x40;

constexpr UINT32 AES_IV_LENGTH = 4;
constexpr UINT32 AES_KEY_LENGTH = 16;

constexpr UINT32 TLS_DATA_MAX = 16 * 1024;
constexpr UINT32 CIPHER_EXPANSION_MAX = 256;

constexpr UINT32 TLS_RECORD_SIZE = (TLS_DATA_MAX + 256 + 5); // 16K data + 256 bytes for encryption expansion + 5 bytes for record header
using DATA_BUFFER = LOCAL_STREAM<TLS_RECORD_SIZE>;

constexpr UINT32 TLS_RECORD_HEADER = 5;

struct TLS12_CIPHER
{
	LOCAL_STREAM<MASTER_SECRET_LENGTH> masterSecret;
	LOCAL_STREAM<PRF_RANDOM_LENGTH> clientRandom;
	LOCAL_STREAM<PRF_RANDOM_LENGTH> serverRandom;

	DATA_BUFFER recvRecord;
	DATA_BUFFER sendRecord;

	BCRYPT_KEY_HANDLE sendKey;
	BCRYPT_KEY_HANDLE recvKey;

	UINT8 sendIV[AES_IV_LENGTH];
	UINT8 recvIV[AES_IV_LENGTH];

	UINT64 sendSequenceNumber = 0;
	UINT64 recvSequenceNumber = 0;

	template <UINT32 SZ>
	BUFFER PRF(USTRING label, BUFFER seed, LOCAL_STREAM<SZ>& prfOutput, UINT32 outputLength = SZ)
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

			status = hmac.getHash(A_Buffer, A_Buffer.toBuffer());
			ASSERT(NT_SUCCESS(status));
		}

		return prfOutput.toBuffer();
	}

	void testPRF()
	{
		masterSecret.clear();
		auto secret = "9bbe436ba940f017b17652849a71db35";
		masterSecret.readHexString(secret);

		LOCAL_STREAM<32> seedBuffer;
		seedBuffer.readHexString("a0ba9f936cda311827a6f796ffd5198c");

		LOCAL_STREAM<32> label;
		label.readHexString("74657374206c6162656c");
		LOCAL_STREAM<128> outputBuffer;
		auto output = PRF(label.toBuffer(), seedBuffer.toBuffer(), outputBuffer, 100);
		printf("output done");

		LOCAL_STREAM<128> result;
		result.readHexString("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66");
		auto resultCount = result.count();

	}

	void generateTrafficKeys()
	{
		do
		{
			LOCAL_STREAM<PRF_SEED_LENGTH> seed;
			seed.writeStream(serverRandom.toBuffer());
			seed.writeStream(clientRandom.toBuffer());

			LOCAL_STREAM<40> hashOutput;
			auto hash = PRF("key expansion", seed.toBuffer(), hashOutput);

			auto status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &sendKey, NULL, 0, (PUCHAR)hash.data(), AES_KEY_LENGTH, 0);
			VERIFY_STATUS;

			hash.shift(AES_KEY_LENGTH);
			status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &recvKey, NULL, 0, (PUCHAR)hash.data(), AES_KEY_LENGTH, 0);
			VERIFY_STATUS;
			
			hash.shift(AES_KEY_LENGTH);
			RtlCopyMemory(sendIV, hash.data(), AES_IV_LENGTH);

			hash.shift(AES_IV_LENGTH);
			RtlCopyMemory(recvIV, hash.data(), AES_IV_LENGTH);

		} while (false);
	}

	void generateMasterSecret(BCRYPT_SECRET_HANDLE sharedSecret)
	{
		LOCAL_STREAM<PRF_SEED_LENGTH> seed;
		seed.writeStream(clientRandom.toBuffer());
		seed.writeStream(serverRandom.toBuffer());

		BCryptBuffer BufferArray[3];
		BufferArray[0].BufferType = KDF_TLS_PRF_SEED;
		BufferArray[0].cbBuffer = PRF_SEED_LENGTH;
		BufferArray[0].pvBuffer = (PVOID)seed.address();

		auto label = "master secret";
		BufferArray[1].BufferType = KDF_TLS_PRF_LABEL;
		BufferArray[1].cbBuffer = (DWORD)strlen(label);
		BufferArray[1].pvBuffer = (PVOID)label;

		DWORD tlsVersion = 0x0303;
		BufferArray[2].BufferType = KDF_TLS_PRF_PROTOCOL;
		BufferArray[2].cbBuffer = sizeof(tlsVersion);
		BufferArray[2].pvBuffer = &tlsVersion;

		BCryptBufferDesc ParameterList;
		ParameterList.cBuffers = 3;
		ParameterList.pBuffers = BufferArray;
		ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

		ULONG bytesWritten;
		auto status = BCryptDeriveKey(sharedSecret, BCRYPT_KDF_TLS_PRF, &ParameterList, masterSecret.commit(MASTER_SECRET_LENGTH), MASTER_SECRET_LENGTH, &bytesWritten, 0);
		ASSERT(NT_SUCCESS(status));
	}

	void encrypt(BUFFER record)
	{
		auto recordHeader = record.readBytes(TLS_RECORD_HEADER);

		LOCAL_STREAM<12> ivData;
		ivData.writeBytes(sendIV, 4);
		record.copyTo(ivData.commit(8), 8);

		auto tag = record.shrink(AES_128_GCM_EXPANSION);

		LOCAL_STREAM<sizeof(UINT64) + TLS_RECORD_HEADER> additionalData;
		additionalData.writeBE(sendSequenceNumber++);
		additionalData.writeByte(recordHeader.readByte());
		additionalData.writeEnumBE(TLS_VERSION::TLS12);
		additionalData.writeBE<UINT16>(record.length());

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
		BCRYPT_INIT_AUTH_MODE_INFO(aead);

		aead.pbAuthData = additionalData.address();
		aead.cbAuthData = sizeof(UINT64) + TLS_RECORD_HEADER;
		aead.pbNonce = ivData.address();
		aead.cbNonce = 12;
		aead.pbTag = (PUCHAR)tag.data();
		aead.cbTag = AES_128_GCM_EXPANSION;

		ULONG bytesEncoded;
		auto status = BCryptEncrypt(sendKey, (PUCHAR)record.data(), record.length(), &aead, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesEncoded, 0);
		ASSERT(NT_SUCCESS(status));
	}

	BUFFER decrypt(BUFFER record)
	{
		auto recordHeader = record.readBytes(TLS_RECORD_HEADER);

		auto tag = record.shrink(AES_128_GCM_EXPANSION);

		LOCAL_STREAM<12> ivData;
		ivData.writeBytes(recvIV, 4);
		record.copyTo(ivData.commit(8), 8);

		LOCAL_STREAM<sizeof(UINT64) + TLS_RECORD_HEADER> additionalData;
		additionalData.writeBE(recvSequenceNumber++);
		additionalData.writeByte(recordHeader.readByte());
		auto tlsVersion = recordHeader.readEnumBE<TLS_VERSION>();
		additionalData.writeEnumBE(tlsVersion);
		additionalData.writeBE<UINT16>(record.length());

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
		BCRYPT_INIT_AUTH_MODE_INFO(aead);

		aead.pbAuthData = additionalData.address();
		aead.cbAuthData = sizeof(UINT64) + TLS_RECORD_HEADER;
		aead.pbNonce = ivData.address();
		aead.cbNonce = 12;
		aead.pbTag = (PUCHAR)tag.data();
		aead.cbTag = AES_128_GCM_EXPANSION;

		ULONG bytesDecoded;
		auto status = BCryptDecrypt(recvKey, (PUCHAR)record.data(), record.length(), &aead, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesDecoded, 0);
		ASSERT(NT_SUCCESS(status));

		return record;
	}
};

constexpr ULONG ECDH_KEY_SIZE = 0x20;
constexpr ULONG ECDH_KEY_XY_SIZE = 0x40;
constexpr ULONG ECDH_KEY_BLOB_SIZE = sizeof(BCRYPT_ECCKEY_BLOB) + ECDH_KEY_XY_SIZE;

struct ECDH_KEYSHARE
{
	BCRYPT_KEY_HANDLE keyPair;
	BCRYPT_SECRET_HANDLE sharedSecret;
	BCRYPT_ALG_HANDLE algorithm;

	ULONG bytesNeeded;
	LOCAL_STREAM<ECDH_KEY_BLOB_SIZE> keyBlob;
	SUPPORTED_GROUPS group;

	NTSTATUS initialize(SUPPORTED_GROUPS groupName)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			group = groupName;
			if (group == SUPPORTED_GROUPS::x25519)
				algorithm = Algorithms.ecdh25519;
			else if (group == SUPPORTED_GROUPS::secp256r1)
				algorithm = Algorithms.ecdh256;
			else DBGBREAK();

			status = BCryptGenerateKeyPair(algorithm, &keyPair, 0, 0);
			VERIFY_STATUS;

			status = BCryptFinalizeKeyPair(keyPair, 0);
			VERIFY_STATUS;

		} while (false);
		return status;
	}

	template <UINT32 SZ>
	BUFFER getPublicKey(LOCAL_STREAM<SZ>& keyBuffer)
	{
		BUFFER returnValue{};
		do
		{
			keyBlob.clear();

			ULONG bytesCopied;
			auto status = BCryptExportKey(keyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)keyBlob.commit(ECDH_KEY_BLOB_SIZE), ECDH_KEY_BLOB_SIZE, &bytesCopied, 0);
			VERIFY_STATUS;

			auto blob = keyBlob.toBuffer();
			blob.shift(sizeof(BCRYPT_ECCKEY_BLOB));

			if (group == SUPPORTED_GROUPS::x25519)
			{
				returnValue = keyBuffer.writeBytes((PUINT8)blob.data(), ECDH_KEY_SIZE);
			}
			else
			{
				auto address = keyBuffer.commit(ECDH_KEY_XY_SIZE + 1);
				keyBuffer.writeByte(0x04); // key flag, uncompressed key
				keyBuffer.writeStream(blob);

				returnValue = BUFFER(address, ECDH_KEY_XY_SIZE + 1);
			}
		} while (false);
		return returnValue;
	}

	void createSharedSecret(BUFFER peerKey)
	{
		do
		{
			if (group == SUPPORTED_GROUPS::secp256r1 && peerKey.at(0) == 0x04)
				peerKey.shift();

			keyBlob.clear();
			keyBlob.reserve(ECDH_KEY_BLOB_SIZE);

			auto header = (BCRYPT_ECCKEY_BLOB*)keyBlob.commit(sizeof(BCRYPT_ECCKEY_BLOB));
			header->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
			header->cbKey = ECDH_KEY_SIZE;

			keyBlob.writeStream(peerKey);
			if (group == SUPPORTED_GROUPS::x25519)
			{
				UINT8 zeroBytes[32] = {};
				keyBlob.writeBytes(zeroBytes, 32);
			}
			BCRYPT_KEY_HANDLE publicKey;
			auto blob = keyBlob.toBuffer();
			auto status = BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, &publicKey, (PUCHAR)blob.data(), blob.length(), 0);
			VERIFY_STATUS;

			status = BCryptSecretAgreement(keyPair, publicKey, &sharedSecret, 0);
			VERIFY_STATUS;
			 
		} while (false);
	}
};

template <typename T>
struct TLS12_HANDSHAKE
{
	ECDH_KEYSHARE keyShare;
	TLS12_CIPHER cipher;

	SOCKET_CONNECTION<TLS12_HANDSHAKE> socket;
	RTHANDLE serverName;

	HASH256 hash256;
	RUNNING_HASH handshakeHash;

	CERT_STREAM certificates;
	bool encryptionOn = false;

	T& context;

	TLS12_HANDSHAKE(T& contextArg) : context(contextArg), socket(*this) {}

	template <UINT32 SZ>
	BUFFER generateRandom(LOCAL_STREAM<SZ>& buffer)
	{
		__time32_t seconds;
		_time32(&seconds);

		ASSERT(buffer.count() == 0);
		buffer.writeBE<UINT32>(seconds);
		Random.generateRandom(buffer, 28);

		return buffer.toBuffer();
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
					buffer.writeName(serverName);
				}
			}
		}
	}

	void formatSupportedGroups(DATA_BUFFER& buffer)
	{
		buffer.writeEnumBE(EXTENSION_TYPE::supported_groups);
		auto extLength = buffer.saveOffset(2);

		{
			auto groupLength = buffer.saveOffset(2);
			buffer.writeEnumBE(SUPPORTED_GROUPS::x25519);
			buffer.writeEnumBE(SUPPORTED_GROUPS::secp256r1);
		}
	}

	void formatECPointFormats(DATA_BUFFER& buffer)
	{
		buffer.writeEnumBE(EXTENSION_TYPE::ec_point_formats);
		auto extLength = buffer.saveOffset(2);
		{
			buffer.writeByte(0x01);
			buffer.writeByte(0);
		}
	}


	void formatSignatureAlgorithms(DATA_BUFFER& buffer)
	{
		buffer.writeEnumBE(EXTENSION_TYPE::signature_algorithms);
		auto extLength = buffer.saveOffset(2);
		{
			auto algLength = buffer.saveOffset(2);

			buffer.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_rsae_sha256);
			buffer.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_pss_sha256);
			buffer.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_rsae_sha512);
			buffer.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_pss_sha512);
			buffer.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp256r1_sha256);
			buffer.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp521r1_sha512);
		}
	}

	void formatClientHello(DATA_BUFFER& buffer)
	{
		buffer.writeEnumBE(TLS_VERSION::TLS12);
		auto random = generateRandom(cipher.clientRandom);
		buffer.writeStream(random);

		buffer.writeByte(0); // session id

		buffer.writeBE<UINT16>(2);
		buffer.writeEnumBE(CIPHER_SUITE::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);

		buffer.writeByte(1);
		buffer.writeByte(0); // zero compression.
		
		{
			auto extensionOffset = buffer.saveOffset(2);
			formatServerName(buffer);
			formatSupportedGroups(buffer);
			formatECPointFormats(buffer);
			formatSignatureAlgorithms(buffer);
		}
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
		data.copyTo(cipher.serverRandom.commit(32), 32);

		auto sessionId = readVariableData(data, 1); 

		auto cipherSuite = data.readEnumBE<CIPHER_SUITE>();

		auto compression = data.readByte();
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
		cipher.generateMasterSecret(keyShare.sharedSecret);
		cipher.generateTrafficKeys();

		BUFFER hashInput{ hashStart, (UINT32)(buffer.data() - hashStart) };

		auto signatureAlgorithm = buffer.readEnumBE<SIGNATURE_SCHEME>();

		auto signatureBuf = readVariableData(buffer, 2);

		LOCAL_STREAM<32> hashOutput;
		hash256.getHash(hashOutput, cipher.clientRandom.toBuffer(), cipher.serverRandom.toBuffer(), hashInput);

		auto&& certificate = certificates.at(0);

		if (signatureAlgorithm == SIGNATURE_SCHEME::ecdsa_secp256r1_sha256)
		{ 
			LOCAL_STREAM<64> sigData;
			auto signature = ParseECDSAP256Signature(signatureBuf, sigData);

			auto status = BCryptVerifySignature(certificate.keyHandle, NULL, hashOutput.address(), 32, (PUCHAR)signature.data(), signature.length(), 0);
			ASSERT(NT_SUCCESS(status));
		}
		else
		{
			DBGBREAK();
		}

		// BCryptVerifySignature()


	}

	void parseCertificateStatus(BUFFER buffer)
	{
		auto statusType = buffer.readByte();

		ASSERT(statusType == 1); // OSCP
	}

	void formatClientKeyExchange(DATA_BUFFER& buffer)
	{
		buffer.writeByte(0x20);
		keyShare.getPublicKey(buffer);
	}

	void formatFinishMessage(DATA_BUFFER& sendBuffer)
	{
		LOCAL_STREAM<32> transcriptHash;
		sendBuffer.writeEnumBE(MESSAGE_TYPE::finished);
		{
			auto offset = sendBuffer.saveOffset(3);
			cipher.PRF("client finished", handshakeHash.finish(transcriptHash), sendBuffer, 12);
		}
	}

	NTSTATUS sendFinished()
	{
		auto& buffer = cipher.sendRecord;
		buffer.clear();

		buffer.writeEnumBE(RECORD_TYPE::handshake);
		buffer.writeEnumBE(TLS_VERSION::TLS12);
		{
			auto recordLength = buffer.saveOffset(2);

			buffer.writeBE(cipher.sendSequenceNumber);

			formatFinishMessage(buffer);

			buffer.commit(AES_128_GCM_EXPANSION);
		}

		cipher.encrypt(buffer.toBuffer());

		//cipher.decrypt(buffer.toReader());

		auto status = socket.send(buffer.toBuffer());
		return status;
	}

	NTSTATUS sendChangeCipherSpec()
	{
		auto& buffer = cipher.sendRecord;
		buffer.clear();

		buffer.writeEnumBE(RECORD_TYPE::change_cipher_spec);
		buffer.writeEnumBE(TLS_VERSION::TLS12);
		{
			auto recordLength = buffer.saveOffset(2);
			buffer.writeByte(0x01);
		}

		cipher.sendSequenceNumber = 0;
		cipher.recvSequenceNumber = 0;

		auto status = socket.send(buffer.toBuffer());
		return status;
	}

	BUFFER formatRecord(MESSAGE_TYPE msgType)
	{
		auto& buffer = cipher.sendRecord;
		buffer.clear();

		buffer.writeEnumBE(RECORD_TYPE::handshake);
		buffer.writeEnumBE(TLS_VERSION::TLS12);

		{
			auto recordLength = buffer.saveOffset(2);

			buffer.writeEnumBE(msgType);

			{
				auto msgLength = buffer.saveOffset(3);

				switch (msgType)
				{
				case MESSAGE_TYPE::client_hello:
					formatClientHello(buffer);
					break;

				case MESSAGE_TYPE::client_key_exchange:
					formatClientKeyExchange(buffer);
					break;

				default:
					DBGBREAK();
					break;
				}
			}
		}

		{
			auto handshakeMsg = buffer.toBuffer();
			handshakeMsg.shift(TLS_RECORD_HEADER);

			handshakeHash.addData(handshakeMsg);
		}
		return cipher.sendRecord.toBuffer();
	}

	void parseCertificates(BUFFER message)
	{
		auto certsData = readVariableData(message, 3);

		while (certsData)
		{
			auto certData = readVariableData(certsData, 3);
			auto &certificate = certificates.append();
			ParseX509(certData, certificate);
		}
	}

	void parseRecord(BUFFER data)
	{
		auto record = data;

		auto recordType = data.readEnumBE<RECORD_TYPE>();
		auto version = data.readEnumBE<TLS_VERSION>();
		auto length = data.readBE<UINT16>();

		if (encryptionOn)
		{
			data = cipher.decrypt(record);
			length = data.length();
		}

		if (recordType == RECORD_TYPE::handshake)
		{
			auto message = data.readBytes(length);

			handshakeHash.addData(message);

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
				auto buffer = formatRecord(MESSAGE_TYPE::client_key_exchange);
				socket.send(buffer);
				sendChangeCipherSpec();
				sendFinished();
			}
			else if (msgType == MESSAGE_TYPE::finished)
			{
				onConnect(STATUS_SUCCESS);
			}
			else DBGBREAK();
		}
		else if (recordType == RECORD_TYPE::change_cipher_spec)
		{
			cipher.recvSequenceNumber = 0;
			encryptionOn = true;
			LogInfo("change_cipher_spec");
		}
		else if (recordType == RECORD_TYPE::application_data)
		{
			cipher.decrypt(record);
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
		auto& buffer = cipher.sendRecord;
		buffer.clear();

		buffer.writeEnumBE(RECORD_TYPE::application_data);
		buffer.writeEnumBE(TLS_VERSION::TLS12);
		{
			auto recordLength = buffer.saveOffset(2);

			buffer.writeBE(cipher.sendSequenceNumber);

			func(buffer, args ...);

			buffer.commit(AES_128_GCM_EXPANSION);
		}

		cipher.encrypt(buffer.toBuffer());

		auto status = socket.send(buffer.toBuffer());
		return status;
	}

	UINT32 getRecordLength(DATA_BUFFER& dataBuffer)
	{
		auto buffer = dataBuffer.toBuffer();

		ASSERT(buffer.length() >= TLS_RECORD_HEADER);

		buffer.shift(3);
		return buffer.readBE<UINT16>();
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

	//void setOnConnect(TASK_HANDLER callback, PVOID context)
	//{
	//	onConnect = callback;
	//	onConnectContext = context;
	//}

	//void setOnReceive(TASK_HANDLER callback, PVOID context)
	//{
	//	onReceive = callback;
	//	onReceiveContext = context;
	//}

	//void setOnClose(TASK_HANDLER callback, PVOID context)
	//{
	//	onClose = callback;
	//	onCloseContext = context;
	//}

	void onConnect(NTSTATUS status)
	{
		auto dataBuffer = formatRecord(MESSAGE_TYPE::client_hello);
		socket.send(dataBuffer);
		socket.startReceiver();
	}

	NTSTATUS startClient(URL_INFO& url)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			status = socket.connect(url.hostname);
			VERIFY_STATUS;

		} while (false);
		return status;
	}

};