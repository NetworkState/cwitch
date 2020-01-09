// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

#include "TLS.h"

//RFC8285 - RTP Header extensions
//RFC6184 - RTP payload for H.264
//RFC4566 - SDP
//draft-ietf-mmusic-ice-sip-sdp-24
//draft-ietf-mmusic-sdp-bundle-negotiation-54.txt
//draft-ietf-rtcweb-jsep-26
//draft-ietf-rtcweb-sdp-11

constexpr UINT32 DTLS_RECORD_HEADER = 13;
constexpr UINT32 DTLS_RECORD_LENGTH_OFFSET = 11;
constexpr UINT32 MSG_HEADER = 6;
constexpr UINT32 MASTER_SECRET_LENGTH = 0x30;
constexpr UINT32 PRF_RANDOM_LENGTH = 0x20;
constexpr UINT32 PRF_SEED_LENGTH = 0x40;
constexpr UINT32 PRF_HASH_LENGTH = 0x20;

constexpr UINT32 AES_KEY_LENGTH = 16;
constexpr UINT32 AES_BLOCK_LENGTH = 16;
constexpr UINT32 AES_EXPLICIT_IV_LENGTH = 8;
constexpr UINT32 AES_IMPLICIT_IV_LENGTH = 4;

constexpr UINT32 SRTP_MASTER_KEY_LENGTH = 16;
constexpr UINT32 SRTP_MASTER_SALT_LENGTH = 14;

constexpr UINT32 DTLS_DATA_MAX = 16 * 1024;

constexpr UINT32 DTLS_RECORD_SIZE = DTLS_DATA_MAX + CIPHER_EXPANSION_MAX + DTLS_RECORD_HEADER;

using DTLS_RECORD_STREAM = STREAM_BUILDER<UINT8, SESSION_STACK, DTLS_RECORD_SIZE>;

constexpr UINT32 SEQUENCE_NUMBER_OFFSET = 3;

constexpr UINT16 RTP_FLAGS_V = 0xC000;
constexpr UINT16 RTP_FLAGS_P = 0x2000;
constexpr UINT16 RTP_FLAGS_X = 0x1000;
constexpr UINT16 RTP_FLAGS_CC = 0x0F00;

constexpr UINT16 RTP_FLAGS_M = 0x0080;
constexpr UINT16 RTP_FLAGS_PT = 0x007F;

constexpr UINT8 RTP_FIXED_HEADER_SIZE = 12;

enum class SRTP_PRF_LABEL : UINT8
{
	rtp_encryption = 0x00,
	rtp_msg_auth = 0x01,
	rtp_salt = 0x02,
	rtcp_encryption = 0x03,
	rtcp_msg_auth = 0x04,
	rtcp_salt = 0x05,
	rtp_header_encryption = 0x06,
	rtp_header_salt = 0x07
};

struct RTP_FLAGS
{
	UINT16 value;

	RTP_FLAGS(UINT16 input) : value(input) {}
	RTP_FLAGS() : value(0x8000) {}

	UINT16 getCsrcCount() { return (value & RTP_FLAGS_CC) >> 8; }
	void setCsrcCount(UINT16 csrcCount) { value |= ((csrcCount & 0x0F) << 8); }

	UINT8 getPacketType() { return (UINT8)(value & 0x7F); }
	void setPaketType(UINT8 packetType) { value |= (packetType & 0x7F); }

	bool getPadding() { return value & RTP_FLAGS_P ? true : false; }
	void setPadding() { value |= RTP_FLAGS_P; }

	bool getMarker() { return value & RTP_FLAGS_M ? true : false; }
	void setMarker() { value |= RTP_FLAGS_M; }

	bool getExtension() { return value & RTP_FLAGS_X ? true : false; }
	void setExtension() { value |= RTP_FLAGS_X; }
};

struct RTCP_FLAGS
{
	UINT16 value;
	RTCP_FLAGS(UINT16 input) : value(input) {}
	RTCP_FLAGS() : value(0x8000) {}

	UINT16 getRecordCount() { return (value & 0x1F00) >> 8; }
	void setRecordCount(UINT16 count) { value |= ((count & 0x1F) << 8); }

	UINT8 getPacketType() { return (UINT8)(value & 0xFF); }
	void setPacketType(UINT16 type) { value |= (type & 0xFF); }

	bool getPadding() { return value & 0x2000 ? true : false; };
	void setPadding() { value |= 0x2000; }
};

constexpr UINT32 POPULATE_PACKETS_TIMER_INTERVAL = 5000;

template <typename SESSION>
struct SRTP_SHAPER
{
	STREAM_BUILDER<UINT8, SESSION_STACK, 16> packetStreams[2];
	UINT8 currentStream;

	KTIMER populatePacketsTimer;
	KTIMER sendPacketsTimer;

	KDPC populatePacketsDpc;
	KDPC sendPacketsDpc;

	CLOCK playClock;
	UINT32 populatePacketsDuration = 5000; // ms

	SESSION& session;

	SRTP_SHAPER(SESSION& sessionArg) : session(sessionArg)
	{
		packetStreams[0].writeBE<UINT32>(0);
		packetStreams[1].writeBE<UINT32>(0);

		KeInitializeTimerEx(&populatePacketsTimer, NotificationTimer);

		KeInitializeTimerEx(&sendPacketsTimer, NotificationTimer);

		KeInitializeDpc(&populatePacketsDpc, [](PKDPC dpc, PVOID context, PVOID, PVOID)
			{
				auto& shaper = *(SRTP_SHAPER*)context;
				SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
					{
						auto& shaper = *(SRTP_SHAPER*)context;
						shaper.populatePackets();
					}, &shaper));
			}, this);

		KeInitializeDpc(&sendPacketsDpc, [](PKDPC dpc, PVOID context, PVOID, PVOID)
			{
				auto& shaper = *(SRTP_SHAPER*)context;
				shaper.session.scheduler.runTask(SIGNALING_SEND_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
					{
						auto& shaper = *(SRTP_SHAPER*)context;
						shaper.sendPackets();
					}, &shaper));
			}, this);
	}

	void start()
	{
		playClock.start();
		KeSetTimerEx(&populatePacketsTimer, LARGE_INTEGER{ -1 }, POPULATE_PACKETS_TIMER_INTERVAL, &populatePacketsDpc);
	}

	void populatePackets()
	{
		auto startTime = (playClock.elapsedTime() / 1000) * 1000; // convert to seconds first (ignore milliseconds), then to ms
		auto& packetStream = packetStreams[currentStream ^ 1];
	}

	void sendPackets()
	{

	}
};

struct SRTP_CIPHER
{
	BCRYPT_KEY_HANDLE recvRTPkey = nullptr;
	BCRYPT_KEY_HANDLE recvRTCPkey = nullptr;

	UINT8 recvRTPsalt[AES_IV_LENGTH] = { 0 };
	UINT8 recvRTCPsalt[AES_IV_LENGTH] = { 0 };

	BCRYPT_KEY_HANDLE sendRTPkey = nullptr;
	BCRYPT_KEY_HANDLE sendRTCPkey = nullptr;

	UINT8 sendRTPsalt[AES_IV_LENGTH] = { 0 };
	UINT8 sendRTCPsalt[AES_IV_LENGTH]{ 0 };

	UINT16 recvSeqNumber;
	UINT32 recvROC;

	UINT16 sendSeqNumber;
	UINT32 sendROC; // roll over counter, incremented on seq number rollover.

	LOCAL_STREAM<1500> rtpSendStream;
	LOCAL_STREAM<1500> rtcpSendStream;

	UINT16 getNextRecvSeqNumber(UINT32& roc)
	{
		roc = recvROC + ((recvSeqNumber + 1) / sizeof(UINT16));
		return (recvSeqNumber + 1) & 0xFFFF;
	}

	void claimNextRecvSeqNumber()
	{
		recvSeqNumber = getNextRecvSeqNumber(recvROC);
	}

	UINT16 getNextSendSeqNumber()
	{
		sendROC += ((sendSeqNumber + 1) / sizeof(UINT16));
		return (sendSeqNumber + 1) & 0xFFFF;
	}

	NTSTATUS aesDecrypt(BCRYPT_KEY_HANDLE aesKey, BUFFER recvData, BUFFER authData, BUFFER ivData, BUFFER tag)
	{
		ASSERT(ivData.length() == AES_IV_LENGTH);
		ASSERT(tag.length() == AES_TAG_LENGTH);

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
		BCRYPT_INIT_AUTH_MODE_INFO(aead);

		aead.pbAuthData = (PUCHAR)authData.data();
		aead.cbAuthData = authData.length();
		aead.pbNonce = (PUCHAR)ivData.data();
		aead.cbNonce = AES_IV_LENGTH;
		aead.pbTag = (PUCHAR)tag.data();
		aead.cbTag = AES_TAG_LENGTH;

		ULONG bytesDecoded;
		auto status = BCryptDecrypt(aesKey, (PUCHAR)recvData.data(), recvData.length(), &aead, NULL, 0, (PUCHAR)recvData.data(), recvData.length(), &bytesDecoded, 0);
		ASSERT(NT_SUCCESS(status));

		return status;
	}


	NTSTATUS aesEncrypt(BCRYPT_KEY_HANDLE aesKey, BUFFER sendData, BUFFER authData, BUFFER ivData, BUFFER tag)
	{
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
		BCRYPT_INIT_AUTH_MODE_INFO(aead);

		aead.pbAuthData = (PUCHAR)authData.data();
		aead.cbAuthData = authData.length();
		aead.pbNonce = (PUCHAR)ivData.data();
		aead.cbNonce = AES_IV_LENGTH;
		aead.pbTag = (PUCHAR)tag.data();
		aead.cbTag = AES_TAG_LENGTH;

		ULONG bytesEncoded;
		auto status = BCryptEncrypt(aesKey, (PUCHAR)sendData.data(), sendData.length(), &aead, nullptr, 0, (PUCHAR)sendData.data(), sendData.length(), &bytesEncoded, 0);
		ASSERT(NT_SUCCESS(status));

		return status;
	}

	NTSTATUS decryptRTP(BUFFER recvData, BUFFER authData, UINT32 ssrc, UINT16 receivedSeqNumber)
	{
		LOCAL_STREAM<AES_IV_LENGTH> ivData;
		ivData.writeStream(recvRTPsalt);

		LOCAL_STREAM<AES_IV_LENGTH> header;
		header.writeBE<UINT16>(0);
		header.writeBE<UINT32>(ssrc);

		UINT32 ROC;
		getNextRecvSeqNumber(ROC);

		header.writeBE<UINT32>(ROC);
		header.writeBE<UINT16>(receivedSeqNumber);

		XorData(ivData.address(), header.address(), AES_IV_LENGTH);

		auto tag = recvData.shrink(AES_TAG_LENGTH);

		return aesDecrypt(recvRTPkey, recvData, authData, ivData.toBuffer(), tag);
	}

	NTSTATUS decryptRTCP(bool isEncrypted, BUFFER recvData, BUFFER authData, UINT32 ssrc, UINT32 receivedSeqNumber)
	{
		LOCAL_STREAM<AES_IV_LENGTH> ivData;
		ivData.writeStream(recvRTPsalt);

		LOCAL_STREAM<AES_IV_LENGTH> header;
		header.writeBE<UINT16>(0);
		header.writeBE<UINT32>(ssrc);

		header.writeBE<UINT16>(0);
		header.writeBE<UINT32>(receivedSeqNumber);

		XorData(ivData.address(), header.address(), AES_IV_LENGTH);

		auto tag = recvData.shrink(AES_TAG_LENGTH);

		return aesDecrypt(recvRTCPkey, isEncrypted ? recvData : NULL_BUFFER, authData, ivData.toBuffer(), tag);
	}

	template <typename F, typename ... ARGS>
	BUFFER formatRTP(UINT8 packetType, bool isKeyFrame, UINT32 timestamp, UINT32 ssrc, BUFFER csrcData,
		BUFFER extensionData, UINT16 extensionType, F func, ARGS&& ... args)
	{
		RTP_FLAGS flags;
		if (extensionData) flags.setExtension();
		if (csrcData) flags.setCsrcCount(csrcData.length() / sizeof(UINT32));
		if (isKeyFrame) flags.setMarker();
		flags.setPaketType(packetType);

		auto& outStream = rtpSendStream.clear();

		auto authStart = outStream.getPosition();

		outStream.writeBE<UINT16>(flag.value);
		outStream.writeBE<UINT16>(getNextSendSeqNumber());
		outstream.writeBE<UINT32>(timestamp);
		outStream.writeBE<UINT32>(ssrc);

		if (csrcData)
		{
			outStream.writeStream(csrcData);
		}

		if (extensionData)
		{
			outStream.writeBE<UINT16>(extensionType);
			auto extensionOffset = outStream.getPosition();
			outStream.writeBE<UINT16>(0);
			outStream.writeStream(extensionData);
			outStream.writeAtBE<UINT16>(extensionOffset.getLength() / sizeof(UINT32));
		}

		auto authBuffer = authStart.toBuffer();

		func(outStream, args ...);

		return outStream.toBuffer();
	}

	template <typename F, typename ... ARGS>
	BUFFER formatRTP(UINT8 packetType, bool isKeyFrame, UINT32 timestamp, UINT32 ssrc, F func, ARGS&& ... args)
	{
		return formatRTP(packetType, isKeyFrame, timestamp, ssrc, NULL_BUFFER, NULL_BUFFER, 0, func, args ...);
	}
};

constexpr UINT32 DTLS_MESSAGE_HEADER = 12;
constexpr UINT32 DTLS_FRAGMENT_OVERHEAD = 8;
constexpr UINT32 DTLS_PMTU = 1450;

constexpr auto stunServerName = "stun.l.google.com";
constexpr auto stunServerPort = 19302;

enum class STUN_MESSAGE : UINT16
{
	BINDING_REQUEST = 0x0001,
	BINDING_SUCCESS = 0x0101,
	BINDING_FAILURE = 0x0111,
};

constexpr UINT16 STUN_ATTR_OPTIONAL = 0x8000;
constexpr UINT32 STUN_FINGERPRINT_MAGIC = 0x5354554e;
constexpr UINT32 STUN_MESSAGE_INTEGRITY_SIZE = 24; // includes attribute header
constexpr UINT32 STUN_HEADER_SIZE = 20;
constexpr UINT32 STUN_MAGIC = 0x2112A442;
constexpr UINT32 STUN_ATTR_HEADER = 4;
constexpr UINT32 STUN_FINGERPRINT_LENGTH = 4;

enum class STUN_ATTR : UINT16
{
	MAPPED_ADDRESS = 0x0001,
	USERNAME = 0x0006,
	MESSAGE_INTEGRITY = 0x0008,
	ERROR_CODE = 0x0009,
	UNKNOWN_ATTR = 0x000A,
	REALM = 0x0014,
	NONCE = 0x0015,
	XOR_MAPPED_ADDRESS = 0x0020,
	PRIORITY = 0x0024,
	USE_CANDIDATE = 0x0025,
	ICE_CONTROLLED = 0x0026,
	ICE_CONTROLLING = 0x0027,

	SOFTWARE = 0x8022,
	ALTERNATE_SERVER = 0x8023,
	FINGERPRINT = 0x8028,
};


TOKEN TOKEN::getSdpName() { return this->isSdp() ? SDP_KEYWORDS[getValue()] : Undefined; }

constexpr UINT32 PRF_OUTPUT_LENGTH_SRTP = 2 * SRTP_MASTER_KEY_LENGTH + 2 * SRTP_MASTER_SALT_LENGTH;

template <typename SERVER> 
struct MEDIA_SESSION
{
	struct DTLS_CIPHER
	{
		MEDIA_SESSION& session;

		UINT64 sendEpoch = 0;
		UINT64 _sendSequenceNumber = 0;

		UINT64 recvEpoch = 0;
		UINT64 _recvSequenceNumber = 0;

		DTLS_CIPHER(MEDIA_SESSION& context) : session(context) {}

		UINT64 claimSendSeqNumber()
		{
			auto seqNumber = (sendEpoch << 48) | (_sendSequenceNumber & 0xFFFFFFFFFF);
			_sendSequenceNumber++;
			return seqNumber;
		}

		UINT64 nextRecvSeqNumber()
		{
			return (recvEpoch << 48) | (_recvSequenceNumber & 0xFFFFFFFFFF);
		}

		void claimRecvSeqNumber()
		{
			_recvSequenceNumber++;
		}

		//LOCAL_STREAM<32> sendRecordHeader;

		BCRYPT_KEY_HANDLE sendKey;
		BCRYPT_KEY_HANDLE recvKey;

		UINT8 sendIV[AES_IMPLICIT_IV_LENGTH];
		UINT8 recvIV[AES_IMPLICIT_IV_LENGTH];

		LOCAL_STREAM<MASTER_SECRET_LENGTH> masterSecret;

		LOCAL_STREAM<PRF_RANDOM_LENGTH> serverRandom;
		LOCAL_STREAM<PRF_RANDOM_LENGTH> clientRandom;

		bool sendEncrypted = false;
		bool recvEncrypted = false;

		void writeExplicitIV(DTLS_RECORD_STREAM& buffer)
		{
			if (sendEncrypted)
			{
				buffer.writeBE<UINT64>(_sendSequenceNumber);
			}
		}

		void writeAEADtags(DTLS_RECORD_STREAM& buffer)
		{
			if (sendEncrypted)
			{
				buffer.commit(AES_TAG_LENGTH);
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

		void SRTP_PRF(BCRYPT_KEY_HANDLE aesKey, BUFFER salt, SRTP_PRF_LABEL labelByte, LOCAL_STREAM<AES_BLOCK_LENGTH>& output)
		{
			ASSERT(salt.length() == SRTP_MASTER_SALT_LENGTH);

			output.writeStream(salt);
			output.writeBE<UINT16>(0);

			UINT8 label[AES_BLOCK_LENGTH] = { 0 };
			label[7] = (UINT8)labelByte;

			XorData(output.address(), label, AES_BLOCK_LENGTH);

			ULONG bytesCoded;
			auto status = BCryptEncrypt(aesKey, output.address(), AES_BLOCK_LENGTH, NULL, nullptr, 0, output.address(), AES_BLOCK_LENGTH, &bytesCoded, 0);
			ASSERT(NT_SUCCESS(status));
		}

		void testSRTPkeys()
		{
			LOCAL_STREAM<16> stream;
			stream.readHexString("E1F97A0D3E018BE0D64FA32C06DE4139");

			BCRYPT_KEY_HANDLE keyHandle;
			auto status = BCryptGenerateSymmetricKey(Algorithms.aesCounter, &keyHandle, NULL, 0, stream.address(), 16, 0);
			ASSERT(NT_SUCCESS(status));

			stream.clear().readHexString("0EC675AD498AFEEBB6960B3AABE6");
			auto salt = stream.toBuffer();

			LOCAL_STREAM<16> outputKey;
			outputKey.writeStream(salt);
			outputKey.writeBE<UINT16>(0);

			UINT8 label[AES_BLOCK_LENGTH] = { 0 };
			label[7] = (UINT8)0;

			XorData(outputKey.address(), label, 16);

			ULONG bytesCoded;
			status = BCryptEncrypt(keyHandle, outputKey.address(), 16, NULL, NULL, 0, outputKey.address(), 16, &bytesCoded, 0);
			ASSERT(NT_SUCCESS(status));
		}

		void extractSRTPkeys(SRTP_CIPHER& srtpChiper)
		{
			ASSERT(session.server.isServer());

			do
			{
				LOCAL_STREAM<PRF_SEED_LENGTH> seed;
				seed.writeStream(clientRandom.toBuffer());
				seed.writeStream(serverRandom.toBuffer());

				LOCAL_STREAM<PRF_OUTPUT_LENGTH_SRTP> hashOutput;
				auto hash = PRF("EXTRACTOR-dtls_srtp", seed.toBuffer(), hashOutput, PRF_OUTPUT_LENGTH_SRTP);

				BCRYPT_KEY_HANDLE recvKey;
				auto status = BCryptGenerateSymmetricKey(Algorithms.aesCounter, &recvKey, NULL, 0, (PUCHAR)hash.readBytes(SRTP_MASTER_KEY_LENGTH).data(), SRTP_MASTER_KEY_LENGTH, 0);
				VERIFY_STATUS;

				BCRYPT_KEY_HANDLE writeKey;
				status = BCryptGenerateSymmetricKey(Algorithms.aesCounter, &writeKey, NULL, 0, (PUCHAR)hash.readBytes(SRTP_MASTER_KEY_LENGTH).data(), SRTP_MASTER_KEY_LENGTH, 0);
				VERIFY_STATUS;

				auto recvSalt = hash.readBytes(SRTP_MASTER_SALT_LENGTH);
				auto sendSalt = hash.readBytes(SRTP_MASTER_SALT_LENGTH);

				LOCAL_STREAM<AES_BLOCK_LENGTH> keyData;
				{
					SRTP_PRF(recvKey, recvSalt, SRTP_PRF_LABEL::rtp_encryption, keyData.clear());
					status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &srtpChiper.recvRTPkey, NULL, 0, keyData.address(), AES_KEY_LENGTH, 0);
					VERIFY_STATUS;

					SRTP_PRF(recvKey, recvSalt, SRTP_PRF_LABEL::rtp_salt, keyData.clear());
					RtlCopyMemory(srtpChiper.recvRTPsalt, keyData.address(), AES_IV_LENGTH);

					SRTP_PRF(recvKey, recvSalt, SRTP_PRF_LABEL::rtcp_encryption, keyData.clear());
					status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &srtpChiper.recvRTCPkey, NULL, 0, keyData.address(), AES_KEY_LENGTH, 0);
					VERIFY_STATUS;

					SRTP_PRF(recvKey, recvSalt, SRTP_PRF_LABEL::rtcp_salt, keyData.clear());
					RtlCopyMemory(srtpChiper.recvRTCPsalt, keyData.address(), AES_IV_LENGTH);
				}
				{
					SRTP_PRF(writeKey, sendSalt, SRTP_PRF_LABEL::rtp_encryption, keyData.clear());
					status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &srtpChiper.sendRTPkey, NULL, 0, keyData.address(), AES_KEY_LENGTH, 0);
					VERIFY_STATUS;

					SRTP_PRF(writeKey, sendSalt, SRTP_PRF_LABEL::rtp_salt, keyData.clear());
					RtlCopyMemory(srtpChiper.sendRTPsalt, keyData.address(), AES_IV_LENGTH);

					SRTP_PRF(writeKey, sendSalt, SRTP_PRF_LABEL::rtcp_encryption, keyData.clear());
					status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, &srtpChiper.sendRTCPkey, NULL, 0, keyData.address(), AES_KEY_LENGTH, 0);
					VERIFY_STATUS;

					SRTP_PRF(writeKey, sendSalt, SRTP_PRF_LABEL::rtcp_salt, keyData.clear());
					RtlCopyMemory(srtpChiper.sendRTCPsalt, keyData.address(), AES_IV_LENGTH);
				}
			} while (false);
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

				auto status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, session.server.isClient() ? &sendKey : &recvKey, NULL, 0, (PUCHAR)hash.readBytes(AES_KEY_LENGTH).data(), AES_KEY_LENGTH, 0);
				VERIFY_STATUS;

				status = BCryptGenerateSymmetricKey(Algorithms.aesGCM, session.server.isClient() ? &recvKey : &sendKey, NULL, 0, (PUCHAR)hash.readBytes(AES_KEY_LENGTH).data(), AES_KEY_LENGTH, 0);
				VERIFY_STATUS;

				RtlCopyMemory(session.server.isClient() ? sendIV : recvIV, hash.readBytes(AES_IMPLICIT_IV_LENGTH).data(), AES_IMPLICIT_IV_LENGTH);
				RtlCopyMemory(session.server.isClient() ? recvIV : sendIV, hash.data(), AES_IMPLICIT_IV_LENGTH);

			} while (false);
		}

		void generateMasterSecret(BUFFER sharedSecret)
		{
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
			if (!sendEncrypted)
				return;

			auto recordHeader = record.readBytes(DTLS_RECORD_HEADER);
			auto recordType = recordHeader.readByte();
			auto recordVersion = recordHeader.readEnumBE<TLS_VERSION>();
			auto recordSequenceNumber = recordHeader.readBytes(8);
			auto recordLength = recordHeader.readBE<UINT16>();

			LOCAL_STREAM<12> ivData;
			ivData.writeBytes(sendIV, AES_IMPLICIT_IV_LENGTH);
			ivData.writeStream(record.readBytes(AES_EXPLICIT_IV_LENGTH));
			//record.copyTo(ivData.commit(8), 8);

			auto tag = record.shrink(AES_TAG_LENGTH);

			LOCAL_STREAM<DTLS_RECORD_HEADER> additionalData;
			additionalData.writeStream(recordSequenceNumber);
			additionalData.writeByte(recordType);
			additionalData.writeEnumBE(recordVersion);
			additionalData.writeBE<UINT16>(recordLength - AES_TAG_LENGTH - AES_EXPLICIT_IV_LENGTH);

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
			BCRYPT_INIT_AUTH_MODE_INFO(aead);

			aead.pbAuthData = additionalData.address();
			aead.cbAuthData = DTLS_RECORD_HEADER;
			aead.pbNonce = ivData.address();
			aead.cbNonce = AES_IV_LENGTH;
			aead.pbTag = (PUCHAR)tag.data();
			aead.cbTag = AES_TAG_LENGTH;

			ULONG bytesEncoded;
			auto status = BCryptEncrypt(sendKey, (PUCHAR)record.data(), record.length(), &aead, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesEncoded, 0);
			ASSERT(NT_SUCCESS(status));
		}

		BUFFER decrypt(BUFFER record)
		{
			auto recordHeader = record.readBytes(DTLS_RECORD_HEADER);
			if (recvEncrypted)
			{
				auto recordType = recordHeader.readByte();
				auto recordVersion = recordHeader.readEnumBE<TLS_VERSION>();
				auto recordSequenceNumber = recordHeader.readBytes(8);
				auto recordLength = recordHeader.readBE<UINT16>();

				auto tag = record.shrink(AES_TAG_LENGTH);

				LOCAL_STREAM<12> ivData;
				ivData.writeBytes(recvIV, AES_IMPLICIT_IV_LENGTH);
				ivData.writeStream(record.readBytes(AES_EXPLICIT_IV_LENGTH));
				//record.copyTo(ivData.commit(8), 8);

				//auto seqNumber = nextRecvSeqNumber();

				LOCAL_STREAM<DTLS_RECORD_HEADER> additionalData;
				additionalData.writeStream(recordSequenceNumber);
				additionalData.writeByte(recordType);
				additionalData.writeEnumBE(recordVersion);
				additionalData.writeBE<UINT16>(recordLength - AES_TAG_LENGTH - AES_EXPLICIT_IV_LENGTH);

				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
				BCRYPT_INIT_AUTH_MODE_INFO(aead);

				aead.pbAuthData = additionalData.address();
				aead.cbAuthData = DTLS_RECORD_HEADER;
				aead.pbNonce = ivData.address();
				aead.cbNonce = AES_IV_LENGTH;
				aead.pbTag = (PUCHAR)tag.data();
				aead.cbTag = AES_TAG_LENGTH;

				ULONG bytesDecoded;
				auto status = BCryptDecrypt(recvKey, (PUCHAR)record.data(), record.length(), &aead, NULL, 0, (PUCHAR)record.data(), record.length(), &bytesDecoded, 0);
				ASSERT(NT_SUCCESS(status));

			}
			return record;
		}

	};

	struct DTLS_HANDSHAKE
	{
		DTLS_CIPHER cipher;
		UINT16 sendMsgSeqNumber = 0;
		UINT16 recvMsgSeqNumber = 0;
		HASH256 hash256;
		TRANSCRIPT_HASH transcriptHash;
		ECDH_KEYSHARE keyShare;

		KTIMER retransmitTimer;
		KDPC retransmitDpc;
		LARGE_INTEGER retransmitTime;

		DTLS_RECORD_STREAM sendRecordStream;
		DTLS_RECORD_STREAM recvRecordStream;

		TASK_ID systemTaskId;
		STREAM_BUILDER<CERTIFICATE, SESSION_STACK, 4> peerCertificates;

		MEDIA_SESSION& session;
		DTLS_HANDSHAKE(MEDIA_SESSION& contextArg) : session(contextArg), cipher(contextArg)
		{
			KeInitializeTimer(&retransmitTimer);
			KeInitializeDpc(&retransmitDpc, RetransmitTimerCallback, this);
			retransmitTime.QuadPart = 10000 * 5000 * 10000000ull;
		}

		bool isClient() { return session.server.isClient(); }
		bool isServer() { return session.server.isServer(); }

		static void RetransmitTimerCallback(PKDPC, PVOID context, PVOID, PVOID)
		{
			DBGBREAK();
			auto& handshake = *(DTLS_HANDSHAKE*)context;
			handshake.retransmit();
		}

		void startRetransmitTimer()
		{
			//KeSetTimer(&retransmitTimer, retransmitTime, &retransmitDpc); // XXX temp!
		}

		void stopRetransmitTimer()
		{
			KeCancelTimer(&retransmitTimer);
		}

		void retransmit()
		{
			session.sendTo(sendRecordStream.toBuffer(), STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
				{
					auto& handshake = *(DTLS_HANDSHAKE*)context;
					handshake.startRetransmitTimer();
				}, this));
		}
		
		template <typename FUNC, typename ... Args>
		void formatRecord(DTLS_RECORD_STREAM& outStream, RECORD_TYPE recordType, MESSAGE_TYPE msgType, FUNC func, Args&& ... args)
		{
			auto recordStart = outStream.getPosition();

			outStream.writeEnumBE(recordType);
			outStream.writeEnumBE(TLS_VERSION::DTLS12);
			outStream.writeBE<UINT64>(cipher.claimSendSeqNumber());

			{
				auto recordLength = outStream.saveOffset(2);
				cipher.writeExplicitIV(outStream);
				if (recordType == RECORD_TYPE::handshake)
				{
					auto messageOffset = outStream.getPosition();

					ASSERT(msgType != MESSAGE_TYPE::unknown);

					outStream.writeEnumBE(msgType);
					{
						auto msgLength = outStream.saveOffset(3);
						outStream.writeBE(sendMsgSeqNumber++);
						outStream.writeBytes(ZeroBytes, 3); // frame offset
						{
							auto fragmentOffset = outStream.saveOffset(3);
							func(outStream, args ...);
							fragmentOffset.writeLength();
						}
						msgLength.writeLength(-1 * (INT32)DTLS_FRAGMENT_OVERHEAD); // msgLength doesn't include fragment info
					}
					LogInfo("%d: send message %d", isClient(), msgType);

					transcriptHash.addMessage(messageOffset.toBuffer());
				}
				else
				{
					func(outStream, args ...);
				}
				cipher.writeAEADtags(outStream);
			}

			if (recordStart.getLength() > DTLS_PMTU)
			{
				DBGBREAK(); // fragments!!! There shouldn't be fragments, make sure certificate(s) not too big
			}
			auto dataBuffer = recordStart.toBuffer();
			cipher.encrypt(dataBuffer);
		}

		void formatServerName(DTLS_RECORD_STREAM& buffer)
		{
			buffer.writeEnumBE(EXTENSION_TYPE::server_name);
			{
				auto extLength = buffer.saveOffset(2);
				{
					auto nameListLength = buffer.saveOffset(2);
					buffer.writeByte(0); // type
					{
						auto nameLength = buffer.saveOffset(2);
						buffer.writeName(session.server.getServerName());
					}
				}
			}
		}

		void formatUseSrtp(DTLS_RECORD_STREAM& outStream)
		{
			outStream.writeEnumBE(EXTENSION_TYPE::use_srtp);
			{
				auto extLength = outStream.saveOffset(2);
				{
					{
						auto profileLength = outStream.saveOffset(2);
						outStream.writeEnumBE(SRTP_PROTECTION_PROFILE::SRTP_AEAD_AES_128_GCM);
					}
					outStream.writeByte(0); // for MKI, 
				}
			}
		}

		void formatSupportedGroups(DTLS_RECORD_STREAM& outStream)
		{
			outStream.writeEnumBE(EXTENSION_TYPE::supported_groups);
			auto extLength = outStream.saveOffset(2);
			{
				auto groupLength = outStream.saveOffset(2);
				//outStream.writeEnumBE(SUPPORTED_GROUPS::x25519);
				outStream.writeEnumBE(SUPPORTED_GROUPS::secp256r1);
			}
		}

		void formatECPointFormats(DTLS_RECORD_STREAM& outStream)
		{
			outStream.writeEnumBE(EXTENSION_TYPE::ec_point_formats);
			auto extLength = outStream.saveOffset(2);
			{
				outStream.writeByte(0x01);
				outStream.writeByte(0);
			}
		}

		void formatSignatureAlgorithms(DTLS_RECORD_STREAM& outStream)
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

		void formatClientHello(DTLS_RECORD_STREAM& msgStream, BUFFER cookie)
		{
			msgStream.writeEnumBE(TLS_VERSION::DTLS12);

			cipher.clientRandom.writeBE<UINT32>(getUnixTime());
			Random.generateRandom(cipher.clientRandom, PRF_RANDOM_LENGTH - sizeof(UINT32));
			msgStream.writeStream(cipher.clientRandom.toBuffer());

			msgStream.writeByte(0); // session id

			msgStream.writeByte((UINT8)cookie.length());
			msgStream.writeStream(cookie);

			msgStream.writeBE<UINT16>(2);
			msgStream.writeEnumBE(CIPHER_SUITE::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);

			msgStream.writeByte(1);
			msgStream.writeByte(0);
			{
				auto extensionOffset = msgStream.saveOffset(2);
				formatServerName(msgStream);
				formatECPointFormats(msgStream);
				formatSupportedGroups(msgStream);
				formatSignatureAlgorithms(msgStream);
				formatUseSrtp(msgStream);
			}
		}

		UINT32 getUnixTime()
		{
			LARGE_INTEGER systemTime;
			KeQuerySystemTime(&systemTime);

			UINT32 seconds;
			RtlTimeToSecondsSince1970(&systemTime, (ULONG *)&seconds);

			return seconds;
		}

		void formatServerHelloInternal(DTLS_RECORD_STREAM& msgStream, BUFFER sessionId)
		{
			msgStream.writeEnumBE(TLS_VERSION::DTLS12);

			cipher.serverRandom.writeBE<UINT32>(getUnixTime());
			Random.generateRandom(cipher.serverRandom, PRF_RANDOM_LENGTH - sizeof(UINT32));
			msgStream.writeStream(cipher.serverRandom.toBuffer());

			msgStream.writeByte((UINT8)sessionId.length());
			msgStream.writeStream(sessionId);

			msgStream.writeEnumBE(CIPHER_SUITE::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
			msgStream.writeByte(0);
			{
				auto extensionLength = msgStream.saveOffset(2);
				formatECPointFormats(msgStream);
				formatUseSrtp(msgStream);
			}
		}

		void formatCertificatesInternal(DTLS_RECORD_STREAM& msgStream)
		{
			auto allCertsLength = msgStream.saveOffset(3);
			{
				auto certLength = msgStream.saveOffset(3);
				msgStream.writeStream(session.server.getCertificateBytes());
			}
		}

		void formatCertificateRequest(DTLS_RECORD_STREAM& msgStream)
		{
			{
				auto typeLength = msgStream.saveOffset(1);
				msgStream.writeEnumBE(CLIENT_CERTIFICATE_TYPE::ecdsa_sign);
				msgStream.writeEnumBE(CLIENT_CERTIFICATE_TYPE::rsa_sign);
			}
			{
				auto algLength = msgStream.saveOffset(2);
				msgStream.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp256r1_sha256);
				msgStream.writeEnumBE(SIGNATURE_SCHEME::rsa_pss_rsae_sha256);
				msgStream.writeEnumBE(SIGNATURE_SCHEME::rsa_pkcs1_sha256);
			}
			msgStream.writeBE<UINT16>(0); // no CAs requested.
		}

		void formatCertificateVerify(DTLS_RECORD_STREAM& msgStream)
		{
			msgStream.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp256r1_sha256);

			LOCAL_STREAM<64> sigData;
			ULONG bytesCopied;
			auto hash = transcriptHash.getHash();
			auto status = BCryptSignHash(session.server.getCertificateKey(), NULL, (PUCHAR)hash.data(), hash.length(), sigData.commit(64), 64, &bytesCopied, 0);
			ASSERT(NT_SUCCESS(status));

			LOCAL_STREAM<128> asnSigData;
			FormatECDSAP256Signature(asnSigData, sigData.toBuffer());
			{
				auto signatureLength = msgStream.saveOffset(2);
				msgStream.writeStream(asnSigData.toBuffer());
			}
		}

		void formatServerKeyExchangeInternal(DTLS_RECORD_STREAM& msgStream)
		{
			auto msgStart = msgStream.getPosition();

			msgStream.writeEnumBE(EC_CURVE_TYPE::named_curve);
			msgStream.writeEnumBE(SUPPORTED_GROUPS::secp256r1);

			keyShare.initialize(SUPPORTED_GROUPS::secp256r1);
			{
				auto keyLength = msgStream.saveOffset(1);
				keyShare.getPublicKey(msgStream);
			}

			auto hashInput = msgStart.toBuffer();

			msgStream.writeEnumBE(SIGNATURE_SCHEME::ecdsa_secp256r1_sha256);

			LOCAL_STREAM<32> hashOutput;
			hash256.getHash(hashOutput, cipher.clientRandom.toBuffer(), cipher.serverRandom.toBuffer(), hashInput);

			LOCAL_STREAM<64> sigData;
			ULONG bytesCopied;
			auto status = BCryptSignHash(session.server.getCertificateKey(), NULL, hashOutput.address(), 32, sigData.commit(64), 64, &bytesCopied, 0);
			ASSERT(NT_SUCCESS(status));

			LOCAL_STREAM<128> asnSigData;
			FormatECDSAP256Signature(asnSigData, sigData.toBuffer());

			{
				auto sigLength = msgStream.saveOffset(2);
				msgStream.writeStream(asnSigData.toBuffer());
			}
		}

		NTSTATUS formatChangeCipherSpec(DTLS_RECORD_STREAM& outStream)
		{
			outStream.writeEnumBE(RECORD_TYPE::change_cipher_spec);
			outStream.writeEnumBE(TLS_VERSION::DTLS12);
			outStream.writeBE<UINT64>(cipher.claimSendSeqNumber());
			{
				auto recordLength = outStream.saveOffset(2);
				outStream.writeByte(0x01);
			}

			cipher._sendSequenceNumber = 0;
			cipher.sendEpoch++;

			cipher.sendEncrypted = true;

			//session.getSocket().sendTo(outStream.toBuffer(), STASK());
			return STATUS_SUCCESS;
		}

		void sendClientHello(BUFFER cookie = NULL_BUFFER)
		{
			auto& outStream = sendRecordStream.clear();
			transcriptHash.reset();
			formatRecord(outStream, RECORD_TYPE::handshake, MESSAGE_TYPE::client_hello, [](DTLS_RECORD_STREAM& msgBuffer, DTLS_HANDSHAKE& handshake, BUFFER cookie)
				{
					handshake.formatClientHello(msgBuffer, cookie);
					return 0;
				}, *this, cookie);

			session.sendTo(outStream.toBuffer(), STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
				{
					auto& handshake = *(DTLS_HANDSHAKE*)context;
					handshake.startRetransmitTimer();
				}, this));
		}

		void formatClientKeyExchange(DTLS_RECORD_STREAM& dataStream)
		{
			formatRecord(dataStream, RECORD_TYPE::handshake, MESSAGE_TYPE::client_key_exchange, [](DTLS_RECORD_STREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
				{
					auto msgLength = msgBuffer.saveOffset(1);
					handshake.keyShare.getPublicKey(msgBuffer);
				}, *this);
		}

		void formatServerHello(DTLS_RECORD_STREAM& dataStream, BUFFER sessionId)
		{
			formatRecord(dataStream, RECORD_TYPE::handshake, MESSAGE_TYPE::server_hello, [](DTLS_RECORD_STREAM& msgBuffer,
				DTLS_HANDSHAKE& handshake, BUFFER sessionId)
				{
					handshake.formatServerHelloInternal(msgBuffer, sessionId);
					return 0;
				}, *this, sessionId);
		}

		void formatCertificates(DTLS_RECORD_STREAM& dataStream)
		{
			formatRecord(dataStream, RECORD_TYPE::handshake, MESSAGE_TYPE::certificate, [](DTLS_RECORD_STREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
				{
					handshake.formatCertificatesInternal(msgBuffer);
					return 0;
				}, *this);
		}

		void formatServerKeyExchange(DTLS_RECORD_STREAM& dataStream)
		{
			formatRecord(dataStream, RECORD_TYPE::handshake, MESSAGE_TYPE::server_key_exchange, [](DTLS_RECORD_STREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
				{
					handshake.formatServerKeyExchangeInternal(msgBuffer);
					return 0;
				}, *this);
		}

		void formatServerHelloDone(DTLS_RECORD_STREAM& dataStream)
		{
			formatRecord(dataStream, RECORD_TYPE::handshake, MESSAGE_TYPE::server_hello_done, [](DTLS_RECORD_STREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
				{
					UNREFERENCED_PARAMETER(handshake);
					UNREFERENCED_PARAMETER(msgBuffer);
				}, *this);
		}

		void sendAlert(ALERT_DESCRIPTION code)
		{
			auto& dataStream = sendRecordStream.clear();
			formatRecord(dataStream, RECORD_TYPE::alert, MESSAGE_TYPE::unknown, [](DTLS_RECORD_STREAM& msgBuffer, ALERT_DESCRIPTION code)
				{
					msgBuffer.writeEnumBE(ALERT_LEVEL::fatal);
					msgBuffer.writeEnumBE(code);
				}, code);
			session.sendTo(dataStream.toBuffer(), STASK());
		}

		void formatFinished(DTLS_RECORD_STREAM& dataStream)
		{
			formatRecord(dataStream, RECORD_TYPE::handshake, MESSAGE_TYPE::finished, [](DTLS_RECORD_STREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
				{
					auto label = handshake.isClient() ? "client finished" : "server finished";
					handshake.cipher.PRF(label, handshake.transcriptHash.getHash(), msgBuffer, 12);
				}, *this);
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

		UINT16 readUINT24(BUFFER& data)
		{
			data.shift();
			return data.readBE<UINT16>();
		}

		void parseFinished(BUFFER msgData)
		{
			auto receiveHash = msgData.readBytes(12);

			LOCAL_STREAM<12> expectedHash;
			cipher.PRF(session.server.isServer() ? "client finished" : "server finished", transcriptHash.getHash(), expectedHash, 12);
			ASSERT(receiveHash == expectedHash.toBuffer());
		}

		void parseClientKeyExchange(BUFFER msgData)
		{
			auto keyData = readVariableData(msgData, 1);
			keyShare.createSharedSecret(keyData);

			cipher.generateMasterSecret(keyShare.sharedSecret.toBuffer());
			cipher.generateTrafficKeys();
		}

		void parseServerKeyExchange(BUFFER msgData)
		{
			auto hashStart = msgData.data();

			auto curveType = msgData.readByte();
			ASSERT(curveType == 0x03); // named curve

			auto group = msgData.readEnumBE<SUPPORTED_GROUPS>();
			keyShare.initialize(group);

			auto peerKey = readVariableData(msgData, 1);
			keyShare.createSharedSecret(peerKey);
			cipher.generateMasterSecret(keyShare.sharedSecret.toBuffer());
			cipher.generateTrafficKeys();
			cipher.extractSRTPkeys(session.srtpCipher);

			BUFFER hashInput{ hashStart, (UINT32)(msgData.data() - hashStart) };

			LOCAL_STREAM<32> hashOutput;
			hash256.getHash(hashOutput, cipher.clientRandom.toBuffer(), cipher.serverRandom.toBuffer(), hashInput);

			auto signatureAlgorithm = msgData.readEnumBE<SIGNATURE_SCHEME>();

			auto signatureBuf = readVariableData(msgData, 2);

			auto&& certificate = peerCertificates.at(0);

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
		}

		BUFFER readExtension(BUFFER& message, EXTENSION_TYPE& type)
		{
			type = message.readEnumBE<EXTENSION_TYPE>();
			auto length = message.readBE<UINT16>();

			return message.readBytes(length);
		}

		bool parseClientHello(BUFFER data, BUFFER& sessionId)
		{
			bool cipherSuiteValid = false, srtpProfileValid = false;

			data.readEnumBE<TLS_VERSION>();
			cipher.clientRandom.writeStream(data.readBytes(PRF_RANDOM_LENGTH));

			sessionId = readVariableData(data, 1);

			auto cookie = readVariableData(data, 1);

			auto cipherSuiteData = readVariableData(data, 2);
			while (cipherSuiteData)
			{
				auto cipherSuite = cipherSuiteData.readEnumBE<CIPHER_SUITE>();
				if (cipherSuite == CIPHER_SUITE::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
				{
					cipherSuiteValid = true;
					break;
				}
			}
			readVariableData(data, 1); // compression ...
			
			auto extensions = readVariableData(data, 2);
			while (extensions)
			{
				EXTENSION_TYPE extType;
				auto extData = readExtension(extensions, extType);

				if (extType == EXTENSION_TYPE::use_srtp)
				{
					auto profileData = readVariableData(extData, 2);
					while (profileData)
					{
						auto profile = profileData.readEnumBE<SRTP_PROTECTION_PROFILE>();
						if (profile == SRTP_PROTECTION_PROFILE::SRTP_AEAD_AES_128_GCM)
						{
							srtpProfileValid = true;
						}
					}
				}
				else if (extType == EXTENSION_TYPE::server_name)
				{

				}
			}
			return cipherSuiteValid && srtpProfileValid;
		}

		bool parseServerHello(BUFFER data)
		{
			auto isValid = false;

			data.readEnumBE<TLS_VERSION>();
			
			cipher.serverRandom.writeStream(data.readBytes(PRF_RANDOM_LENGTH));

			auto sessionId = readVariableData(data, 1);

			data.readEnumBE<CIPHER_SUITE>();

			data.readByte(); // compression

			auto extension = readVariableData(data, 2);
			while (extension)
			{
				EXTENSION_TYPE extType;
				auto extData = readExtension(extension, extType);

				if (extType == EXTENSION_TYPE::use_srtp)
				{
					auto profile = extData.readEnumBE<SRTP_PROTECTION_PROFILE>();
					if (profile == SRTP_PROTECTION_PROFILE::SRTP_AEAD_AES_128_GCM)
						isValid = true;
					else DBGBREAK();
				}
				else if (extType == EXTENSION_TYPE::server_name)
				{

				}
				else DBGBREAK();
			}

			return isValid;
		}

		void parseCertificates(BUFFER message)
		{
			auto certsData = readVariableData(message, 3);

			while (certsData)
			{
				auto certData = readVariableData(certsData, 3);
				auto& certificate = peerCertificates.append();
				ParseX509(certData, certificate);
			}
		}

		bool parseCertificateRequest(BUFFER message)
		{
			auto certificateTypes = readVariableData(message, 1);
			auto signatureSchemes = readVariableData(message, 2);
			auto CAs = readVariableData(message, 2);

			auto certificateTypeValid = false;
			while (certificateTypes)
			{
				if (certificateTypes.readEnumBE<CLIENT_CERTIFICATE_TYPE>() == CLIENT_CERTIFICATE_TYPE::ecdsa_sign)
				{
					certificateTypeValid = true;
					break;
				}
			}

			auto signatureSchemeValid = false;
			while (signatureSchemes)
			{
				if (signatureSchemes.readEnumBE<SIGNATURE_SCHEME>() == SIGNATURE_SCHEME::ecdsa_secp256r1_sha256)
				{
					signatureSchemeValid = true;
					break;
				}
			}

			return certificateTypeValid && signatureSchemeValid;
		}

		bool parseCertificateVerify(BUFFER message)
		{
			auto signatureScheme = message.readEnumBE<SIGNATURE_SCHEME>();
			auto receivedSignature = readVariableData(message, 2);

			auto hash = transcriptHash.getHash();
			auto& certificate = peerCertificates.at(0);

			if (signatureScheme == SIGNATURE_SCHEME::ecdsa_secp256r1_sha256)
			{
				LOCAL_STREAM<64> calculatedSignature;
				ULONG bytesCopied;
				auto status = BCryptSignHash(peerCertificates.at(0).keyHandle, nullptr, (PUCHAR)hash.data(), hash.length(), calculatedSignature.commit(64), 64, &bytesCopied, 0);
				ASSERT(NT_SUCCESS(status));
			}
			else DBGBREAK();
			// 
		}

		void parseMessage(BUFFER fragment)
		{
			BUFFER newMessage;
			{
				auto fragmentCopy = fragment;

				fragment.readEnumBE<MESSAGE_TYPE>(); // msgType
				auto msgLength = readUINT24(fragment);

				auto msgSeqNumber = fragment.readBE<UINT16>();
				auto fragmentOffset = readUINT24(fragment);
				auto fragmentLength = readUINT24(fragment);

				if (msgSeqNumber == recvMsgSeqNumber)
				{
					if (fragmentLength == msgLength)
					{
						newMessage = fragmentCopy;
					}
					else
					{
						auto& recvStream = recvRecordStream;
						if (fragmentOffset == 0)
						{
							recvStream.clear();
							recvStream.writeStream(BUFFER(fragmentCopy.data(), DTLS_MESSAGE_HEADER - 2)); // copy header upto fragment offset
							recvStream.writeBE<UINT16>(msgLength);
						}
						else
						{
							ASSERT(recvStream.count() == (fragmentOffset + DTLS_MESSAGE_HEADER));
						}
						recvStream.writeStream(fragment);
						if (recvStream.count() >= (msgLength + DTLS_MESSAGE_HEADER)) 
						{
							newMessage = recvStream.toBuffer();
						}
					}
				}
				else DBGBREAK();
			}

			if (newMessage)
			{
				stopRetransmitTimer();

				auto messageHash = newMessage;

				auto msgType = newMessage.readEnumBE<MESSAGE_TYPE>();
				auto msgLength = readUINT24(newMessage);
				newMessage.shift(DTLS_FRAGMENT_OVERHEAD);

				auto msgData = newMessage.readBytes(msgLength);
				ASSERT(newMessage.length() == 0); // multiple messages in a record, handle it.

				recvMsgSeqNumber++;

				if (msgType != MESSAGE_TYPE::finished)
				{
					LogInfo("%d: parse message %d", isClient(), msgType);
					transcriptHash.addMessage(messageHash);
				}

				if (msgType == MESSAGE_TYPE::hello_verify_request)
				{
					msgData.readEnumBE<TLS_VERSION>(); // version
					auto cookie = readVariableData(msgData, 1);
					sendClientHello(cookie);
				}
				else if (msgType == MESSAGE_TYPE::server_hello)
				{
					parseServerHello(msgData);
				}
				else if (msgType == MESSAGE_TYPE::client_hello)
				{
					BUFFER sessionId;
					auto isValid = parseClientHello(msgData, sessionId);
					if (isValid)
					{
						systemTaskId = session.getScheduler().queueTask(SIGNALING_SEND_PRIORITY + 1, STASK());
						SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
							{
								auto& handshake = *(DTLS_HANDSHAKE*)context;
								auto sessionId = argv.read<BUFFER>();
								auto& dataStream = handshake.sendRecordStream.clear();

								handshake.formatServerHello(dataStream, sessionId);
								handshake.formatCertificates(dataStream);
								handshake.formatServerKeyExchange(dataStream);
								handshake.formatCertificateRequest(dataStream);
								handshake.formatServerHelloDone(dataStream);

								ASSERT(dataStream.count() < DTLS_PMTU);
								handshake.session.sendTo(dataStream.toBuffer(), STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
									{
										auto& handshake = *(DTLS_HANDSHAKE*)context;
										handshake.startRetransmitTimer();
										handshake.session.getScheduler().updateTask(handshake.systemTaskId);
									}, &handshake));
								
							}, this, sessionId));
					}
					else
					{
						sendAlert(ALERT_DESCRIPTION::illegal_parameter);
					}
				}
				else if (msgType == MESSAGE_TYPE::server_hello_done)
				{
					auto& outStream = sendRecordStream.clear();
					formatClientKeyExchange(outStream);
					formatChangeCipherSpec(outStream);
					formatFinished(outStream);
					session.sendTo(outStream.toBuffer(), STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
						{
							auto& handshake = *(DTLS_HANDSHAKE*)context;
							handshake.startRetransmitTimer();
						}, this));
				}
				else if (msgType == MESSAGE_TYPE::server_key_exchange)
				{
					systemTaskId = session.getScheduler().queueTask(SIGNALING_SEND_PRIORITY + 1, STASK());
					SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
						{
							auto& handshake = *(DTLS_HANDSHAKE*)context;
							auto msgData = argv.read<BUFFER>();
							handshake.parseServerKeyExchange(msgData);
							handshake.session.getScheduler().updateTask(handshake.systemTaskId);
						}, this, msgData));
				}
				else if (msgType == MESSAGE_TYPE::certificate)
				{
					DBGBREAK();
					parseCertificates(msgData);
				}
				else if (msgType == MESSAGE_TYPE::client_key_exchange)
				{
					systemTaskId = session.getScheduler().queueTask(SIGNALING_SEND_PRIORITY + 1, STASK());
					SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
						{
							auto& handshake = *(DTLS_HANDSHAKE*)context;
							auto msgData = argv.read<BUFFER>();
							handshake.parseClientKeyExchange(msgData);
							handshake.session.getScheduler().updateTask(handshake.systemTaskId);
						}, this, msgData));
				}
				else if (msgType == MESSAGE_TYPE::finished)
				{
					parseFinished(msgData);
					auto& outStream = sendRecordStream.clear();
					LogInfo("%d: parse message %d", isClient(), msgType);
					transcriptHash.addMessage(messageHash);
					if (session.server.isServer())
					{
						formatChangeCipherSpec(outStream);
						formatFinished(outStream);
						session.sendTo(outStream.toBuffer(), STASK());
					}
				}
				else DBGBREAK();
			}
		}

		void parseRecord(BUFFER recvData1)
		{
			BUFFER record;
			{
				auto dataCopy = recvData1;
				dataCopy.shift(DTLS_RECORD_LENGTH_OFFSET);
				auto length = dataCopy.readBE<UINT16>();
				record = recvData1.readBytes(length + DTLS_RECORD_HEADER);
			}

			auto recordCopy = record;

			auto recordType = record.readEnumBE<RECORD_TYPE>();
			record.readEnumBE<TLS_VERSION>();

			auto seqNumber = record.readBE<UINT64>();
			if (seqNumber == cipher.nextRecvSeqNumber())
			{
				cipher.claimRecvSeqNumber();
				auto userData = cipher.decrypt(recordCopy);
				if (recordType == RECORD_TYPE::handshake)
				{
					parseMessage(userData);
				}
				else if (recordType == RECORD_TYPE::change_cipher_spec)
				{
					cipher.recvEncrypted = true;
					cipher.recvEpoch++;
					cipher._recvSequenceNumber = 0;
				}
				else if (recordType == RECORD_TYPE::application_data)
				{
					DBGBREAK();
					// call user
				}
				else if (recordType == RECORD_TYPE::alert)
				{
					DBGBREAK();
					auto alertType = userData.readByte();
					auto alertDescription = userData.readByte();

					LogInfo("alert received, %d/%d", alertType, alertDescription);
				}
			}
			else
			{
				DBGBREAK();
			}

			if (recvData1)
			{
				session.scheduler.runTask(SIGNALING_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
					{
						auto& handshake = *(DTLS_HANDSHAKE*)context;
						auto recvData = argv.read<BUFFER>();
						handshake.parseRecord(recvData);
					}, this, recvData1));
			}
		}

		void onReceive(BUFFER recvData)
		{
			session.scheduler.runTask(SIGNALING_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto& handshake = *(DTLS_HANDSHAKE*)context;
					BUFFER recvData = argv.read<BUFFER>();
					handshake.parseRecord(recvData);
				}, this, recvData));
		}

		NTSTATUS startClient()
		{
			sendClientHello(NULL_BUFFER);
			return STATUS_SUCCESS;
		}

		void startServer()
		{
			// nothing to do
		}
	};

	STREAM_BUILDER<UDP_SOCKET<MEDIA_SESSION>, SESSION_STACK, 4> dataTransports;
	
	SESSION_STACK sessionStack;
	SERVER& server;
	SCHEDULER_INFO<MEDIA_SESSION<SERVER>> scheduler;

	STREAM_BUILDER<SDP_STREAM, SESSION_STACK, 3> streamConfig;
	SDP_STREAM sdpStream;

	STREAM_BUILDER<ICE_CANDIDATE, SESSION_STACK, 3> localIceCandidates;
	STREAM_BUILDER<ICE_CANDIDATE, SESSION_STACK, 3> remoteIceCandidates;

	SDP_BUFFER audioStream;
	SDP_BUFFER videoStream;
	SDP_BUFFER dataStream;

	UINT32 videoSsrc;
	UINT32 videoRtxSsrc;
	UINT32 audioSsrc;

	STREAM_BUILDER<UINT8, SESSION_STACK, 512> textBuffer;

	LOCAL_STREAM<32> cookie;
	BUFFER getCookie() { ASSERT(cookie.count() > 0); return cookie.toBuffer(); }

	STREAM_BUILDER<UDP_SOCKET<MEDIA_SESSION>, SESSION_STACK, 3> socketConnections;

	LOCAL_STREAM<4> localIceUfrag;
	LOCAL_STREAM<4> remoteIceUfrag;

	LOCAL_STREAM<32> localIcePassword;
	LOCAL_STREAM<32> remoteIcePassword; // XXX write code to populate!

	DTLS_HANDSHAKE handshake;
	SRTP_CIPHER srtpCipher;

	LOCAL_STREAM<128> stunRequest;

	UDP_SOCKET<MEDIA_SESSION>* activeSocket;
	MEDIA_SESSION(SERVER& serverArg) : server(serverArg), handshake(*this), scheduler(*this) {}

	bool isClient() { return false; }
	bool isServer() { return true; }

	auto& getScheduler() { return scheduler; }
	auto& getSocket() { return *activeSocket; }

	BUFFER readStunAttribute(BUFFER& message, STUN_ATTR& attrName)
	{
		BUFFER attrData;
		if (message.length() >= 4)
		{
			attrName = message.readEnumBE<STUN_ATTR>();
			auto length = message.readBE<UINT16>();
			attrData = message.readBytes(length);

			message.shift(ROUND_TO(length, 4) - length);
		}
		return attrData;
	}

	void sendStunResponse(UDP_SOCKET<MEDIA_SESSION>& socket, BUFFER transactionId, SOCKADDR_IN& fromAddress)
	{
		stunRequest.writeEnumBE(STUN_MESSAGE::BINDING_SUCCESS);
		auto msgLengthOffset = stunRequest.count();
		stunRequest.writeBE<UINT16>(0);
		stunRequest.writeBE<UINT32>(STUN_MAGIC);
		stunRequest.writeStream(transactionId);

		auto attrStart = stunRequest.count();
		stunRequest.writeEnumBE(STUN_ATTR::XOR_MAPPED_ADDRESS);
		{
			auto attrOffset = stunRequest.saveOffset(2);
			stunRequest.writeByte(0);
			stunRequest.writeByte(0x01); // IPV4

			//auto port = HTONS(fromAddress.sin_port) ^ ((UINT16)(STUN_MAGIC & 0xFFFF));
			auto port = HTONS(fromAddress.sin_port) ^ ((UINT16)(STUN_MAGIC >> 16));
			stunRequest.writeBE<UINT16>((UINT16)port);

			auto addr = HTONL(fromAddress.sin_addr.s_addr) ^ STUN_MAGIC;
			stunRequest.writeBE<UINT32>(addr);
			attrOffset.writeLength();
		}
		stunRequest.writeStream(ZeroBytes, ROUND_TO(stunRequest.count(), 4) - stunRequest.count());

		stunRequest.writeEnumBE(STUN_ATTR::USERNAME);
		{
			auto attrOffset = stunRequest.saveOffset(2);
			stunRequest.writeMany(localIceUfrag.toBuffer(), ":", remoteIceUfrag.toBuffer());
			attrOffset.writeLength();
		}
		stunRequest.writeStream(ZeroBytes, ROUND_TO(stunRequest.count(), 4) - stunRequest.count());

		stunRequest.writeEnumBE(STUN_ATTR::MESSAGE_INTEGRITY);
		{
			auto attrOffset = stunRequest.saveOffset(2);
			stunRequest.writeAtBE<UINT16>(msgLengthOffset, (UINT16)((stunRequest.count() - attrStart) + SHA1_HASH_LENGTH));
			//msgLengthOffset.writeLength(4); // -(STUN_HEADER_SIZE - 4) + SHA1_HASH_LENGTH
			CalculateHmacSha1(stunRequest, localIcePassword.toBuffer(), BUFFER(stunRequest.address(), stunRequest.count() - 4));
			attrOffset.writeLength();
		}

		stunRequest.writeAtBE<UINT16>(msgLengthOffset, (UINT16)((stunRequest.count() - attrStart) + STUN_ATTR_HEADER + sizeof(UINT32)));
		auto crc32 = ComputeCrc32(stunRequest.toBuffer()) ^ STUN_FINGERPRINT_MAGIC;

		stunRequest.writeEnumBE(STUN_ATTR::FINGERPRINT);
		auto attrOffset = stunRequest.saveOffset(2);
		stunRequest.writeBE<UINT32>(crc32);
		attrOffset.writeLength();

		LogInfo("Sent STUN response");
		socket.sendTo(stunRequest.toBuffer(), fromAddress, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				auto& session = *(MEDIA_SESSION<SERVER>*)context;
				session.stunRequest.clear();
			}, this));
	}

	void onStunRequest(UDP_SOCKET<MEDIA_SESSION>& socket, BUFFER transactionId, BUFFER message, SOCKADDR_IN& fromAddress)
	{
		STUN_ATTR attrName;
		auto isRequestValid = true;
		while (message)
		{
			auto attrData = readStunAttribute(message, attrName);
			if (attrName == STUN_ATTR::USERNAME)
			{
				LOCAL_STREAM<16> username;
				username.writeMany(localIceUfrag.toBuffer(), ":", remoteIceUfrag.toBuffer());
				if (username.toBuffer() != attrData)
				{
					DBGBREAK();
					isRequestValid = false;
					break;
				}
			}
			else if (attrName == STUN_ATTR::USE_CANDIDATE)
			{
				activeSocket = &socket;
				socket.remoteAddress = fromAddress;
			}
		}

		sendStunResponse(socket, transactionId, fromAddress);
	}

	void onStunResponse(UDP_SOCKET<MEDIA_SESSION>& socket, BUFFER transactionId, BUFFER message, SOCKADDR_IN& fromAddress)
	{
		UNREFERENCED_PARAMETER(socket);
		UNREFERENCED_PARAMETER(transactionId);
		UNREFERENCED_PARAMETER(message);
		UNREFERENCED_PARAMETER(fromAddress);
	}

	void onStunMessage(UDP_SOCKET<MEDIA_SESSION>& socket, BUFFER recvMessage, SOCKADDR_IN& fromAddress)
	{
		LogInfo("onStunMessage: received %d bytes", recvMessage.length());
		BUFFER messageCopy = recvMessage;

		auto type = recvMessage.readEnumBE<STUN_MESSAGE>();
		auto length = recvMessage.readBE<UINT16>();
		auto magic = recvMessage.readBE<UINT32>();
		ASSERT(magic == STUN_MAGIC);

		auto transactionId = recvMessage.readBytes(12);
		BUFFER attributes{ recvMessage.data(), length };
		auto attributesCopy = attributes;

		auto attrStart = attributes.data();

		STUN_ATTR attrName;
		auto isValidRequest = true;
		while (attributes)
		{
			auto attrData = readStunAttribute(attributes, attrName);
			if (attrName == STUN_ATTR::MESSAGE_INTEGRITY)
			{
				BUFFER hashData{ attrStart, (UINT32)(attributes.data() - attrStart - STUN_MESSAGE_INTEGRITY_SIZE) }; // hash data doesn't include this attr

				LOCAL_STREAM<32> headerStream;
				headerStream.writeEnumBE(type);
				headerStream.writeBE<UINT16>((UINT16)(attributes.data() - attrStart));
				headerStream.writeBE<UINT32>(STUN_MAGIC);
				headerStream.writeStream(transactionId);

				LOCAL_STREAM<20> hash;
				CalculateHmacSha1(hash, localIcePassword.toBuffer(), headerStream.toBuffer(), hashData);

				if (attrData != hash.toBuffer())
				{
					DBGBREAK();
					isValidRequest = false;
					break;
				}
			}
			else if (attrName == STUN_ATTR::FINGERPRINT)
			{
				ASSERT(attrData.length() == STUN_FINGERPRINT_LENGTH);
				auto crcReceived = attrData.readBE<UINT32>();

				messageCopy.shrink(STUN_FINGERPRINT_LENGTH + STUN_ATTR_HEADER);
				auto crcComputed = ComputeCrc32(messageCopy) ^ STUN_FINGERPRINT_MAGIC;
				if (crcReceived != crcComputed)
				{
					DBGBREAK();
					isValidRequest = false;
					break;
				}
			}
		}

		if (!isValidRequest)
		{
			DBGBREAK(); // send error response
		}

		if (type == STUN_MESSAGE::BINDING_REQUEST)
		{
			onStunRequest(socket, transactionId, attributesCopy, fromAddress);
		}
		else if (type == STUN_MESSAGE::BINDING_SUCCESS)
		{
			onStunResponse(socket, transactionId, BUFFER(recvMessage.data(), length), fromAddress);
		}
		else if (type == STUN_MESSAGE::BINDING_FAILURE)
		{
			DBGBREAK();
		}
		else DBGBREAK();
	}

	void onSignalingReceive(USTRING recvData)
	{
		TOKEN_BUILDER<SCHEDULER_STACK> jsonStream;
		auto&& json = ParseJson<SESSION_STACK>(jsonStream, recvData);
		auto type = FindJson(json, SDP_type);
		if (type == SDP_offer)
		{
			auto sdp = FindJson(json, SDP_sdp);
			auto sdpString = String.getLiteral<SESSION_STACK>(sdp);
			Sdp.parseSdp(sdpString, sdpStream);
			chooseMedia();

			auto& outStream = sessionStack.charStream;

			auto answerStart = outStream.getPosition();
			outStream.writeString("{ \"type\" : \"answer\", \"sdp\" : \"");
			generateSdp(sessionStack.charStream);
			outStream.writeString("\"}");
			server.sendSignalingData(*this, answerStart.toBuffer());
		}
		else if (type == SDP_candidate)
		{
			auto line = FindJson(json, SDP_candidate);
			auto sdpString = String.getLiteral<SESSION_STACK>(line);
			SDP_LINE sdpLine;
			Sdp.parseSdpLine(sdpString, sdpLine, 'a');
			auto iceCandidate = Sdp.parseIceCandidate(sdpLine);
			remoteIceCandidates.append(iceCandidate);
		}
		else DBGBREAK();
	}


	void chooseMedia()
	{
		videoStream = SDP_BUFFER();

		auto sdpBuffer = sdpStream.toBuffer();
		UINT8 profileId = 0, profileLevel = 0;
		while (auto mediaStream = Sdp.findSdpStream(SDP_video, sdpBuffer))
		{
			auto fmtp = Sdp.findSdpStream(SDP_fmtp, mediaStream);
			for (UINT32 i = 0; i < fmtp.length(); i += 2)
			{
				if (fmtp.at(i) == SDP_profile_level_id)
				{
					auto valueHandle = fmtp.at(i + 1);
					auto value = (UINT32)GetNumberHandleValue(valueHandle);
					auto id = (UINT8)((value & 0xFF0000) >> 16);
					auto level = (UINT8)(value & 0xFF);

					if ((id >= profileId) || ((id == profileId) && (level > profileLevel)))
					{
						profileId = id;
						profileLevel = level;
						videoStream = mediaStream.rewind();
					}
				}
			}
		}

		audioStream = Sdp.findSdpStream(SDP_audio, sdpStream.toBuffer());
	}

	template <typename STREAM>
	void generateSdp(STREAM&& sdpString, SDP_BUFFER media)
	{
		sdpString.writeString(" 9 UDP/TLS/RTP/SAVPF");
		auto rtp = Sdp.findSdpStream(SDP_rtpmap, media.rewind());
		TOKEN packetType = NULL_NAME;
		ASSERT(rtp);
		if (rtp)
		{
			packetType = rtp.at(0);
			sdpString.writeMany(" ", packetType);
		}
		auto rtx = Sdp.findSdpStream(SDP_rtx, media.rewind());
		if (rtx)
		{
			sdpString.writeMany(" ", rtx.at(0));
		}
		sdpString.writeString(ESC_CRLF);
		sdpString.writeMany("c=IN IP4 0.0.0.0", ESC_CRLF, "a=rtcp:9 IN IP4 0.0.0.0", ESC_CRLF, "a=rtcp-mux", ESC_CRLF, "a=rtcp-rsize", ESC_CRLF, "a=sendrecv", ESC_CRLF, "a=setup:passive", ESC_CRLF);
		if (auto mid = Sdp.findSdpStream(SDP_mid, media.rewind()))
		{
			sdpString.writeMany("a=mid:", mid.shift(), ESC_CRLF);
		}

		sdpString.writeMany("a=ice-ufrag:", localIceUfrag.toBuffer(), ESC_CRLF);
		sdpString.writeMany("a=ice-pwd:", localIcePassword.toBuffer(), ESC_CRLF);
		sdpString.writeMany("a=ice-options:trickle", ESC_CRLF);

		auto cert = server.getCertificateBytes();
		LOCAL_STREAM<32> hashData;
		auto status = BCryptHash(Algorithms.hashSha256, NULL, 0, (PUCHAR)cert.data(), cert.length(), hashData.commit(32), 32);
		ASSERT(NT_SUCCESS(status));
	
		sdpString.writeString("a=fingerprint:sha-256 ");
		for (auto& hexChar : hashData.toBuffer())
		{
			sdpString.writeHex(hexChar);
			sdpString.writeString(":");
		}
		sdpString.trim(); // remove the trailing ':'
		sdpString.writeString(ESC_CRLF);

		ASSERT(rtp);
		sdpString.writeMany("a=rtpmap:", packetType, " ");
		auto codec = Sdp.findSdpStream(SDP_codec, media.rewind());
		ASSERT(codec);
		while (codec)
		{
			sdpString.writeMany(codec.shift(), "/");
		}
		sdpString.trim(); // remove trailing '/'
		sdpString.writeString(ESC_CRLF);

		auto fmtp = Sdp.findSdpStream(SDP_fmtp, media.rewind());
		ASSERT(fmtp);
		sdpString.writeMany("a=fmtp:", packetType, " ");
		while (fmtp)
		{
			auto key = fmtp.shift();
			sdpString.writeMany(key, "=");

			auto value = fmtp.shift();
			auto number = GetNumberHandleValue(value);
			sdpString.writeString(number, 16);
			sdpString.writeString(";");
		}
		sdpString.trim(); // remove trailing ';'
		sdpString.writeString(ESC_CRLF);

		auto rtcp = Sdp.findSdpStream(SDP_rtcp_fb, media.rewind());
		while (rtcp)
		{
			sdpString.writeMany("a=rtcp-fb:", packetType, " ");
			auto name = rtcp.shift();
			sdpString.writeMany(name == SDP_nack ? "nack"
				: name == SDP_nack_pli ? "nack pli"
				: name == SDP_nack_sli ? "nack sli"
				: name == SDP_nack_rpsi ? "nack rpsi"
				: name == SDP_ccm_fir ? "ccm fir"
				: name == SDP_ccm_tmmbr ? "ccm tmmbr"
				: name == SDP_ccm_tstr ? "ccm tstr" : NameToString(name));
			sdpString.writeString(ESC_CRLF);
		}

		if (rtx)
		{
			sdpString.writeMany("a=rtpmap:", rtx.at(0), " rtx/");
			codec.rewind().shift();
			while (codec)
			{
				sdpString.writeMany(codec.shift(), "/");
			}
			sdpString.trim();
			sdpString.writeString(ESC_CRLF);
			//a=fmtp:115 apt=114

			sdpString.writeMany("a=fmtp:", rtx.at(0), " apt=", packetType, ESC_CRLF);
		}

		auto extmap = Sdp.findSdpStream(SDP_extmap, sdpStream.toBuffer());
		while (extmap)
		{
			auto id = extmap.shift();
			auto url = extmap.shift();

			if (url == RTPEXT_MID)
			{
				sdpString.writeMany("a=extmap:", id, " ", RTPEXT_MID, ESC_CRLF);
			}
			else if (url == RTPEXT_RID)
			{
				sdpString.writeMany("a=extmap:", id, " ", RTPEXT_RID, ESC_CRLF);
			}
			else if (url == RTPEXT_RRID)
			{
				sdpString.writeMany("a=extmap:", id, " ", RTPEXT_RRID, ESC_CRLF);
			}
		}
		media.rewind();

		for (auto& transport : dataTransports.toBuffer())
		{
			ICE_CANDIDATE iceCandidate{ transport.localAddress };
			Sdp.formatIceCandidate(sdpString, iceCandidate);
		}
		sdpString.writeMany("a=end-of-candidates", ESC_CRLF);
	}

	template <typename STREAM>
	USTRING generateSdp(STREAM&& sdpString)
	{
		UINT64 randomNumber;
		Random.generateRandom((PUINT8)&randomNumber, 8);
		sdpString.writeMany("v=0", ESC_CRLF, "o=- ");
		sdpString.writeString(randomNumber);
		sdpString.writeMany(" 2 IN IP4 127.0.0.1", ESC_CRLF, "s=-", ESC_CRLF, "t=0 0", ESC_CRLF);

		ASSERT(audioStream && videoStream);

		sdpString.writeString("a=group:BUNDLE ");
		sdpString.writeMany(Sdp.findSdpStream(SDP_mid, audioStream).at(0), " ");
		sdpString.writeString(Sdp.findSdpStream(SDP_mid, videoStream).at(0));
		sdpString.writeString(ESC_CRLF);

		sdpString.writeMany("a=msid-semantic: WMS StateMedia", ESC_CRLF);

		ASSERT(audioStream);

		sdpString.writeMany("m=audio");
		generateSdp(sdpString, audioStream);

		Random.generateRandom((PUINT8)& audioSsrc, 4);
		Random.generateRandom((PUINT8)& videoSsrc, 4);
		Random.generateRandom((PUINT8)& videoRtxSsrc, 4);

		sdpString.writeMany("a=ssrc:", audioSsrc, " cname:StateMedia", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", audioSsrc, " msid:StateMedia audio0", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", audioSsrc, " mslabel:StateMedia", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", audioSsrc, " label:audio0", ESC_CRLF);

		sdpString.writeMany("m=video");
		generateSdp(sdpString, videoStream);

		sdpString.writeMany("a=ssrc-group:FID ", videoSsrc, " ", videoRtxSsrc, ESC_CRLF);

		sdpString.writeMany("a=ssrc:", videoSsrc, " cname:StateMedia", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", videoSsrc, " msid:StateMedia video0", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", videoSsrc, " mslabel:StateMedia", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", videoSsrc, " label:video0", ESC_CRLF);

		sdpString.writeMany("a=ssrc:", videoRtxSsrc, " cname:StateMedia", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", videoRtxSsrc, " msid:StateMedia video0", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", videoRtxSsrc, " mslabel:StateMedia", ESC_CRLF);
		sdpString.writeMany("a=ssrc:", videoRtxSsrc, " label:video0", ESC_CRLF);

		return sdpString.toBuffer();
	}

	void addIceCandidate(ULONG srcAddress)
	{
	}

	void gatherIceCandidates()
	{
		PMIB_UNICASTIPADDRESS_TABLE addrTable;
		GetUnicastIpAddressTable(AF_INET, &addrTable);

		PMIB_IPFORWARD_TABLE2 routeTable;
		auto result = GetIpForwardTable2(AF_INET, &routeTable);
		ASSERT(result == STATUS_SUCCESS);

		for (UINT32 i = 0; i < routeTable->NumEntries; i++)
		{
			auto&& route = routeTable->Table[i];

			auto destination = route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr;
			auto addrString = String.formatIPAddress(destination, GetTempStream());

			PMIB_UNICASTIPADDRESS_ROW addrEntry = nullptr;
			for (UINT32 j = 0; j < addrTable->NumEntries; j++)
			{
				if (addrTable->Table[j].InterfaceIndex == route.InterfaceIndex)
				{
					ASSERT(addrEntry == nullptr);  // duplicates???
					addrEntry = &addrTable->Table[j];
				}
			}

			MIB_IPINTERFACE_ROW ipInterfaceEntry;
			RtlZeroMemory(&ipInterfaceEntry, sizeof(ipInterfaceEntry));
			ipInterfaceEntry.InterfaceIndex = addrEntry->InterfaceIndex;
			ipInterfaceEntry.Family = AF_INET;
			result = GetIpInterfaceEntry(&ipInterfaceEntry);
			ASSERT(result == STATUS_SUCCESS);

			MIB_IF_ROW2 ifEntry;
			RtlZeroMemory(&ifEntry, sizeof(ifEntry));
			ifEntry.InterfaceIndex = addrEntry->InterfaceIndex;
			result = GetIfEntry2(&ifEntry);
			ASSERT(result == STATUS_SUCCESS);

			if (!route.Loopback && route.Origin != NlroWellKnown && ifEntry.OperStatus == IfOperStatusUp)
			{
				auto ipaddr = HTONL(addrEntry->Address.Ipv4.sin_addr.s_addr);
				if ((ipaddr & 0xFF000000) == 0x7F000000)
					continue;

				if (route.DestinationPrefix.PrefixLength < 32)
				{
					auto& address = addrEntry->Address.Ipv4;
					if (!dataTransports.toBuffer().find(address))
					{
						auto&& transport = dataTransports.append(*this);
						transport.initialize(address);
					}
				}
			}
		}
	}

	NTSTATUS initialize(UINT16 recvPort = 0)
	{
		UNREFERENCED_PARAMETER(recvPort);
		auto status = STATUS_SUCCESS;
		do
		{
			scheduler.initialize();

			InitializeStack(sessionStack, 16 * 1024 * 1024, 0);

			LOCAL_STREAM<32> byteStream;
			Random.generateRandom(byteStream, 3);
			localIceUfrag.encodeBase64(byteStream.toBuffer());

			Random.generateRandom(byteStream.clear(), 18);
			localIcePassword.encodeBase64(byteStream.toBuffer());

			auto random = Random.generateRandom(byteStream.clear(), 18);
			cookie.encodeBase64(random);

			LogInfo("Session Initialize");
			auto syncTask = scheduler.queueTask(SIGNALING_RECV_PRIORITY, STASK());
			SystemScheduler().runTask(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
				{
					auto&& session = *(MEDIA_SESSION*)context;
					LogInfo("Gathering candidates ...");
					session.gatherIceCandidates();
					LogInfo("Done ...\n");
					session.scheduler.updateTask(argv.read<TASK_ID>());
				}, this, syncTask));

		} while (false);

		return status;
	}

	template <typename TASK>
	NTSTATUS sendTo(BUFFER sendData, TASK&& task)
	{
		return getSocket().sendTo(sendData, task);
	}

	void onReceiveFrom(UDP_SOCKET<MEDIA_SESSION>& socket, BUFFER recvData, SOCKADDR_IN& fromAddress)
	{
		auto firstByte = recvData.at(0);
		if (firstByte >= 0 && firstByte <= 3)
		{
			onStunMessage(socket, recvData, fromAddress);
		}
		else if (firstByte >= 20 && firstByte <= 63)
		{
			handshake.onReceive(recvData);
		}
		else if (firstByte >= 64 && firstByte <= 79)
		{
			DBGBREAK();
			parseTurnMessage(recvData);
		}
		else if (firstByte >= 128 && firstByte <= 191)
		{
			DBGBREAK();
			auto secondByte = recvData.at(1);
			if (secondByte >= 192 && secondByte <= 223)
			{
				parseRtcpPacket(recvData);
			}
			else
			{
				parseSrtpPacket(recvData);
			}
		}
		else DBGBREAK();
	}

	void parseSrtpPacket(BUFFER recvData)
	{
		ASSERT(recvData.length() > RTP_FIXED_HEADER_SIZE);

		auto recvDataStart = recvData.data();

		auto fixedHeader = recvData.readBytes(RTP_FIXED_HEADER_SIZE);

		RTP_FLAGS rtpFlags{ fixedHeader.readBE<UINT16>() };

		auto seqNumber = fixedHeader.readBE<UINT16>();
		auto timestamp = fixedHeader.readBE<UINT32>();
		UNREFERENCED_PARAMETER(timestamp);

		auto ssrc = fixedHeader.readBE<UINT32>();

		auto csrcCount = rtpFlags.getCsrcCount();
		auto csrcData = recvData.readBytes(csrcCount * sizeof(UINT32));

		if (rtpFlags.getExtension())
		{
			auto extType = recvData.readBE<UINT16>();
			UNREFERENCED_PARAMETER(extType);
			auto extLength = (UINT32)(recvData.readBE<UINT16>() * sizeof(UINT32));

			auto extData = recvData.readBytes(extLength);
		}

		BUFFER authData { recvDataStart, (UINT32)(recvData.data() - recvDataStart) };

		auto status = srtpCipher.decryptRTP(recvData, authData, ssrc, seqNumber);

		if (NT_SUCCESS(status))
		{
			// process received data
		}
	}

	void parseRtcpPacket(BUFFER recvData)
	{
		auto fixedHeader = recvData.readBytes(8);
		auto authData = fixedHeader;

		RTCP_FLAGS rtcpFlags{ fixedHeader.readBE<UINT16>() };
		auto recordCount = rtcpFlags.getRecordCount();
		UNREFERENCED_PARAMETER(recordCount);
		auto packetType = rtcpFlags.getPacketType();
		UNREFERENCED_PARAMETER(packetType);
		auto recordLength = fixedHeader.readBE<UINT16>();
		UNREFERENCED_PARAMETER(recordLength);

		auto ssrc = fixedHeader.readBE<UINT32>();

		auto trailer = recvData.shrink(sizeof(UINT32));
		auto recvIndex = trailer.readBE<UINT32>();

		auto isEncrypted = !!(recvIndex & 0x80000000);
		recvIndex |= 0x7FFFFFF;

		auto status = srtpCipher.decryptRTCP(isEncrypted, recvData, authData, ssrc, recvIndex);
		if (NT_SUCCESS(status))
		{
			// process data
		}
	}

	void parseTurnMessage(BUFFER recvData)
	{
		UNREFERENCED_PARAMETER(recvData);
	}
};

