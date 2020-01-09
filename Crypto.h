// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

#define ALG_MODE  BCRYPT_PROV_DISPATCH

constexpr UINT32 SHA256_HASH_LENGTH = 32;
constexpr UINT32 MD5_HASH_LENGTH = 16;
constexpr UINT32 SHA384_HASH_LENGTH = 48;
constexpr UINT32 AES_TAG_LENGTH = 16;
constexpr UINT32 SHA1_HASH_LENGTH = 20;
constexpr UINT32 AES_IV_LENGTH = 12;
constexpr UINT32 ECDSA_SIGN_LENGTH = 64;
constexpr UINT32 AES128_KEY_LENGTH = 16;

struct CNG_ALGORITHMS
{
	BCRYPT_ALG_HANDLE hashSha256;
	UINT32 hash256ObjectSize;
	UINT8 nullSha256Hash[SHA256_HASH_LENGTH];

	BCRYPT_ALG_HANDLE hmacSha256;
	UINT32 hmac256ObjectSize;
	UINT8 zeroHmac256[SHA256_HASH_LENGTH];

	BCRYPT_ALG_HANDLE hashSha384;
	UINT32 hash384ObjectSize;
	UINT8 nullSha384Hash[SHA384_HASH_LENGTH];

	BCRYPT_KEY_HANDLE hmacSha384;
	UINT32 hmac384ObjectSize;
	UINT8 zeroHmac384[SHA384_HASH_LENGTH];

	BCRYPT_ALG_HANDLE hashSha1;
	BCRYPT_ALG_HANDLE hmacSha1;

	BCRYPT_ALG_HANDLE md5;

	BCRYPT_ALG_HANDLE random;
	BCRYPT_ALG_HANDLE aesGCM;
	BCRYPT_ALG_HANDLE aesCounter;

	BCRYPT_ALG_HANDLE ecdh256;
	BCRYPT_ALG_HANDLE ecdsa256;
	BCRYPT_ALG_HANDLE ecdh25519;

	BCRYPT_ALG_HANDLE rsaSign;

	BCRYPT_ALG_HANDLE rsa;

	NTSTATUS initialize()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			status = BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, NULL, ALG_MODE);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&random, BCRYPT_RNG_ALGORITHM, NULL, ALG_MODE);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&md5, BCRYPT_MD5_ALGORITHM, NULL, ALG_MODE);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&hashSha1, BCRYPT_SHA1_ALGORITHM, NULL, ALG_MODE);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&hmacSha1, BCRYPT_SHA1_ALGORITHM, NULL, ALG_MODE | BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&hashSha256, BCRYPT_SHA256_ALGORITHM, NULL, ALG_MODE | BCRYPT_HASH_REUSABLE_FLAG);
			VERIFY_STATUS;

			ULONG bytesCopied;
			status = BCryptGetProperty(hashSha256, BCRYPT_OBJECT_LENGTH, (PUCHAR)& hash256ObjectSize, sizeof(hash256ObjectSize), &bytesCopied, 0);
			VERIFY_STATUS;

			status = BCryptHash(hashSha256, NULL, 0, NULL, 0, nullSha256Hash, SHA256_HASH_LENGTH);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&hashSha384, BCRYPT_SHA384_ALGORITHM, NULL, ALG_MODE | BCRYPT_HASH_REUSABLE_FLAG);
			VERIFY_STATUS;

			status = BCryptGetProperty(hashSha384, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash384ObjectSize, sizeof(hash384ObjectSize), &bytesCopied, 0);
			VERIFY_STATUS;

			status = BCryptHash(hashSha384, NULL, 0, NULL, 0, nullSha384Hash, SHA384_HASH_LENGTH);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&hmacSha256, BCRYPT_SHA256_ALGORITHM, NULL, ALG_MODE | BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
			VERIFY_STATUS;

			bytesCopied;
			status = BCryptGetProperty(hmacSha256, BCRYPT_OBJECT_LENGTH, (PUCHAR)& hmac256ObjectSize, sizeof(hmac256ObjectSize), &bytesCopied, 0);
			VERIFY_STATUS;

			status = BCryptHash(hmacSha256, (PUCHAR)ZeroBytes.data(), SHA256_HASH_LENGTH, (PUCHAR)ZeroBytes.data(), SHA256_HASH_LENGTH, zeroHmac256, SHA256_HASH_LENGTH);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&hmacSha384, BCRYPT_SHA384_ALGORITHM, NULL, ALG_MODE | BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
			VERIFY_STATUS;

			bytesCopied;
			status = BCryptGetProperty(hmacSha384, BCRYPT_OBJECT_LENGTH, (PUCHAR)& hmac384ObjectSize, sizeof(hmac384ObjectSize), &bytesCopied, 0);
			VERIFY_STATUS;

			status = BCryptHash(hmacSha384, (PUCHAR)ZeroBytes.data(), SHA384_HASH_LENGTH, (PUCHAR)ZeroBytes.data(), SHA384_HASH_LENGTH, zeroHmac384, SHA384_HASH_LENGTH);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&aesGCM, BCRYPT_AES_ALGORITHM, NULL, ALG_MODE);
			VERIFY_STATUS;

			status = BCryptSetProperty(aesGCM, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&aesCounter, BCRYPT_AES_ALGORITHM, NULL, ALG_MODE);
			VERIFY_STATUS;

			status = BCryptSetProperty(aesCounter, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
			VERIFY_STATUS;

			BCRYPT_AUTH_TAG_LENGTHS_STRUCT tagLength;
			status = BCryptGetProperty(aesGCM, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)& tagLength, sizeof(tagLength), &bytesCopied, 0);
			VERIFY_STATUS;

			ASSERT(tagLength.dwMaxLength == AES_TAG_LENGTH);

			status = BCryptOpenAlgorithmProvider(&ecdh256, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0); // DPC not supported
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&ecdsa256, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&ecdh25519, BCRYPT_ECDH_ALGORITHM, NULL, 0);
			VERIFY_STATUS;

			status = BCryptSetProperty(ecdh25519, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
			VERIFY_STATUS;

			status = BCryptOpenAlgorithmProvider(&rsaSign, BCRYPT_RSA_SIGN_ALGORITHM, NULL, ALG_MODE);
			VERIFY_STATUS;


		} while (false);
		return status;
	}
};

extern CNG_ALGORITHMS Algorithms;

struct RANDOM
{
	void generateRandom(PUINT8 address, ULONG size)
	{
		auto status = BCryptGenRandom(Algorithms.random, address, size, 0);
		ASSERT(NT_SUCCESS(status));
	}

	template <typename STREAM>
	BUFFER generateRandom(STREAM&& buffer, ULONG size)
	{
		auto address = buffer.commit(size);
		generateRandom(address, size);
		return { address, size };
	}
};

extern BUFFER ParseECDSAP256Signature(BUFFER input, LOCAL_STREAM<64>& sigData);

extern RANDOM Random;

struct HMAC256
{
	BCRYPT_KEY_HANDLE hashHandle;

	NTSTATUS setSecret(BUFFER secret)
	{
		auto status = BCryptCreateHash(Algorithms.hmacSha256, &hashHandle, NULL, 0, (PUCHAR)secret.data(), secret.length(), BCRYPT_HASH_REUSABLE_FLAG);
		ASSERT(NT_SUCCESS(status));
		return status;
	}

	template <typename STREAM, typename ... Args>
	NTSTATUS getHash(STREAM&& outBuffer, Args&& ... args)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			ASSERT(hashHandle);

			BUFFER bufferArray[] = { args ... };
			for (auto& buffer : bufferArray)
			{
				status = BCryptHashData(hashHandle, (PUCHAR)buffer.data(), buffer.length(), 0);
				VERIFY_STATUS;
			}
			VERIFY_STATUS;

			//outBuffer.clear();
			status = BCryptFinishHash(hashHandle, (PUCHAR)outBuffer.commit(32), 32, 0);
			VERIFY_STATUS;

		} while (false);
		return status;
	}

	void close()
	{
		ASSERT(hashHandle);

		auto status = BCryptDestroyHash(hashHandle);
		ASSERT(NT_SUCCESS(status));

		hashHandle = nullptr;
	}
};

extern HMAC256 Hmac;

template <typename STREAM, typename ... ARGS>
BUFFER CalculateHmacSha1(STREAM&& outStream, BUFFER secret, ARGS&& ... args)
{
	auto offset = outStream.getPosition();
	auto status = STATUS_SUCCESS;
	do
	{
		BCRYPT_KEY_HANDLE hashHandle;
		status = BCryptCreateHash(Algorithms.hmacSha1, &hashHandle, NULL, 0, (PUCHAR)secret.data(), secret.length(), BCRYPT_HASH_REUSABLE_FLAG);
		VERIFY_STATUS;

		BUFFER bufferArray[] = { args ... };
		for (auto& buffer : bufferArray)
		{
			status = BCryptHashData(hashHandle, (PUCHAR)buffer.data(), buffer.length(), 0);
			VERIFY_STATUS;
		}
		VERIFY_STATUS;

		status = BCryptFinishHash(hashHandle, (PUCHAR)outStream.commit(SHA1_HASH_LENGTH), SHA1_HASH_LENGTH, 0);
		VERIFY_STATUS;

		BCryptDestroyHash(hashHandle);
	} while (false);
	return offset.toBuffer();
}

struct HASH256
{
	BCRYPT_KEY_HANDLE hashHandle;

	template <typename ... Args>
	NTSTATUS getHash(LOCAL_STREAM<SHA256_HASH_LENGTH>& outBuffer, Args && ... args)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			if (hashHandle == nullptr)
			{
				status = BCryptCreateHash(Algorithms.hashSha256, &hashHandle, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
				VERIFY_STATUS;
			}

			BUFFER bufferArray[] = { args ... };
			for (auto& buffer : bufferArray)
			{
				status = BCryptHashData(hashHandle, (PUCHAR)buffer.data(), buffer.length(), 0);
				VERIFY_STATUS;
			}
			VERIFY_STATUS;

			status = BCryptFinishHash(hashHandle, (PUCHAR)outBuffer.commit(SHA256_HASH_LENGTH), SHA256_HASH_LENGTH, 0);
			VERIFY_STATUS;
		} while (false);
		return status;
	}
};

struct HASHSHA1
{
	BCRYPT_KEY_HANDLE hashHandle;

	template <typename ... Args>
	NTSTATUS getHash(LOCAL_STREAM<SHA1_HASH_LENGTH>& outBuffer, Args&& ... args)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			if (hashHandle == nullptr)
			{
				status = BCryptCreateHash(Algorithms.hashSha1, &hashHandle, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
				VERIFY_STATUS;
			}

			BUFFER bufferArray[] = { args ... };
			for (auto& buffer : bufferArray)
			{
				status = BCryptHashData(hashHandle, (PUCHAR)buffer.data(), buffer.length(), 0);
				VERIFY_STATUS;
			}
			VERIFY_STATUS;

			status = BCryptFinishHash(hashHandle, (PUCHAR)outBuffer.commit(SHA1_HASH_LENGTH), SHA1_HASH_LENGTH, 0);
			VERIFY_STATUS;
		} while (false);
		return status;
	}
};

struct RUNNING_HASH
{
	BCRYPT_KEY_HANDLE keyHandle = nullptr;

	RUNNING_HASH()
	{
		auto status = BCryptCreateHash(Algorithms.hashSha256, &keyHandle, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
		ASSERT(NT_SUCCESS(status));
	}

	NTSTATUS addData(BUFFER data)
	{
		auto status = BCryptHashData(keyHandle, (PUCHAR)data.data(), data.length(), 0);
		ASSERT(NT_SUCCESS(status));

		return status;
	}

	template <typename STREAM>
	BUFFER finish(STREAM&& outBuffer)
	{
		auto position = outBuffer.getPosition();
		ASSERT(keyHandle != nullptr);
		auto address = outBuffer.commit(SHA256_HASH_LENGTH);
		auto status = BCryptFinishHash(keyHandle, address, SHA256_HASH_LENGTH, 0);
		ASSERT(NT_SUCCESS(status));

		return position.toBuffer();
	}

	void clear()
	{
		LOCAL_STREAM<SHA256_HASH_LENGTH> hash;
		BCryptFinishHash(keyHandle, hash.commit(SHA256_HASH_LENGTH), SHA256_HASH_LENGTH, 0);
	}
};

struct TRANSCRIPT_HASH
{
	UINT8 hash[SHA256_HASH_LENGTH];
	BCRYPT_KEY_HANDLE provider;

	TRANSCRIPT_HASH()
	{
		auto status = BCryptCreateHash(Algorithms.hashSha256, &provider, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
		ASSERT(NT_SUCCESS(status));
	}

	NTSTATUS addMessage(BUFFER message)
	{
		ASSERT(provider != nullptr);
		auto status = BCryptHashData(provider, (PUCHAR)message.data(), message.length(), 0);
		ASSERT(NT_SUCCESS(status));
		return status;
	}

	BUFFER getHash()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			auto irql = KeGetCurrentIrql();
			UNREFERENCED_PARAMETER(irql);

			BCRYPT_HASH_HANDLE tempHashHandle;
			auto hashObject = StackAlloc<SCHEDULER_STACK>(Algorithms.hash256ObjectSize);
			status = BCryptDuplicateHash(provider, &tempHashHandle, (PUCHAR)hashObject, Algorithms.hash256ObjectSize, 0);
			VERIFY_STATUS;

			status = BCryptFinishHash(tempHashHandle, hash, SHA256_HASH_LENGTH, 0);
			VERIFY_STATUS;

			status = BCryptDestroyHash(tempHashHandle);
			VERIFY_STATUS;

		} while (false);
		return BUFFER{ hash, SHA256_HASH_LENGTH };
	}

	void close()
	{
		BCryptDestroyHash(provider);
		provider = nullptr;
	}

	void reset()
	{
		close();
		auto status = BCryptCreateHash(Algorithms.hashSha256, &provider, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
		ASSERT(NT_SUCCESS(status));
	}
};

struct AES_OPS
{
	NTSTATUS encrypt(BCRYPT_KEY_HANDLE key, BUFFER data, BUFFER additionalData, BUFFER ivData, BUFFER tag)
	{
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbAuthData = (PUCHAR)additionalData.data();
		authInfo.cbAuthData = additionalData.length();
		authInfo.pbNonce = (PUCHAR)ivData.data();
		authInfo.cbNonce = AES_IV_LENGTH;
		authInfo.pbTag = (PUCHAR)tag.data();
		authInfo.cbTag = AES_TAG_LENGTH;

		ULONG bytesEncoded;
		auto status = BCryptEncrypt(key, (PUCHAR)data.data(), data.length(), &authInfo, NULL, 0, (PUCHAR)data.data(), data.length(), &bytesEncoded, 0);
		ASSERT(NT_SUCCESS(status) && bytesEncoded == data.length());

		return status;
	}

	NTSTATUS decrypt(BCRYPT_KEY_HANDLE key, BUFFER data, BUFFER additionalData, BUFFER ivData, BUFFER tag)
	{
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbAuthData = (PUCHAR)additionalData.data();
		authInfo.cbAuthData = additionalData.length();
		authInfo.pbNonce = (PUCHAR)ivData.data();
		authInfo.cbNonce = AES_IV_LENGTH;
		authInfo.pbTag = (PUCHAR)tag.data();
		authInfo.cbTag = AES_TAG_LENGTH;

		ULONG bytesDecoded;
		auto status = BCryptDecrypt(key, (PUCHAR)data.data(), data.length(), &authInfo, NULL, 0, (PUCHAR)data.data(), data.length(), &bytesDecoded, 0);
		ASSERT(NT_SUCCESS(status) && bytesDecoded == data.length());

		return status;
	}
};

extern void X25519_public_from_private(UINT8 out_public_value[32], const UINT8 private_key[32]);
extern int X25519(UINT8 out_shared_key[32], const UINT8 private_key[32], const UINT8 peer_public_value[32]);

constexpr UINT32 X25519_KEY_LENGTH = 32;

struct X25519_KEYSHARE
{
	LOCAL_STREAM<X25519_KEY_LENGTH> privateKey;
	LOCAL_STREAM<X25519_KEY_LENGTH> sharedSecret;

	X25519_KEYSHARE()
	{
		auto key = Random.generateRandom(privateKey, X25519_KEY_LENGTH);

		auto data = (PUINT8)key.data();
		data[0] &= 248;
		data[31] &= 127;
		data[31] |= 64;
	}

	template <typename STREAM>
	BUFFER getPublicKey(STREAM&& keyBuffer)
	{
		ASSERT(privateKey.count() == X25519_KEY_LENGTH);

		auto address = keyBuffer.commit(X25519_KEY_LENGTH);
		X25519_public_from_private(address, privateKey.toBuffer().data());

		return { address, X25519_KEY_LENGTH };
	}

	void createSecret(BUFFER peerKey)
	{
		ASSERT(peerKey.length() == X25519_KEY_LENGTH);

		X25519(sharedSecret.commit(X25519_KEY_LENGTH), privateKey.toBuffer().data(), peerKey.data());
	}

	void importPrivateKey(BUFFER keyData)
	{
		ASSERT(keyData.length() == X25519_KEY_LENGTH);

		privateKey.clear();
		privateKey.writeStream(keyData);
	}
};

constexpr ULONG ECDH_KEY_SIZE = 0x20;
constexpr ULONG ECDH_KEY_XY_SIZE = 0x40;
constexpr ULONG ECDH_KEY_BLOB_SIZE = sizeof(BCRYPT_ECCKEY_BLOB) + ECDH_KEY_XY_SIZE;

struct ECDH_KEYSHARE
{
	LOCAL_STREAM<ECDH_KEY_SIZE> privateKey;
	LOCAL_STREAM<ECDH_KEY_XY_SIZE> publicKey;
	LOCAL_STREAM<ECDH_KEY_XY_SIZE> sharedSecret;

	NTSTATUS initialize(SUPPORTED_GROUPS group)
	{
		ASSERT(group == SUPPORTED_GROUPS::secp256r1);
		auto status = STATUS_SUCCESS;
		do
		{
			status = ECDH256_GenPrivateKey(privateKey);
			VERIFY_STATUS;

			status = ECDH256_GetPublicKey(privateKey.toBuffer(), publicKey);
			VERIFY_STATUS;

		} while (false);
		return status;
	}

	template <typename STREAM>
	BUFFER getPublicKey(STREAM&& outStream)
	{
		auto start = outStream.getPosition();
		outStream.writeByte(0x04); // non compressed
		outStream.writeStream(publicKey.toBuffer());
		return start.toBuffer();
	}

	BUFFER createSharedSecret(BUFFER peerKey)
	{
		BUFFER result;
		if (peerKey.peek() == 0x04)
			peerKey.shift();

		auto status = ECDH256_GetSharedSecret(privateKey.toBuffer(), peerKey, sharedSecret);
		if (NT_SUCCESS(status))
		{
			sharedSecret.trim(ECDH_KEY_SIZE); // we don't use Y, just X
			result = sharedSecret.toBuffer();
		}
		return result;
	}
};

inline void XorData(PUINT8 data1, PUINT8 data2, ULONG length)
{
	for (UINT32 i = 0; i < length; i++)
	{
		data1[i] ^= data2[i];
	}
}

extern AES_OPS AES;
extern HASH256 HashSha256;
extern HASHSHA1 HashSha1;

inline BUFFER ComputeHash(BUFFER data)
{
	auto hashValue = (PUINT8)StackAlloc<SCHEDULER_STACK>(SHA256_HASH_LENGTH);
	auto status = BCryptHash(Algorithms.hashSha256, nullptr, 0, (PUCHAR)data.data(), data.length(), hashValue, SHA256_HASH_LENGTH);
	ASSERT(NT_SUCCESS(status));

	return BUFFER{ hashValue, SHA256_HASH_LENGTH };
}