// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'.
#include "pch.h"
#include "Types.h"
#include "X509.h"

struct ASN_DATA
{
	ASN_TAG tag;
	BUFFER data;
};

ASN_DATA ReadASNData(BUFFER &docBytes)
{
	ASN_DATA property{ ASN_TAG::INVALID, NULL_STRING };
	do
	{
		if (docBytes.length() > 0)
		{
			auto type = docBytes.readChar();
			UINT32 length = 0;

			if (type == 0 && docBytes.readChar() == 0)
				break;

			auto lengthByte = docBytes.readChar();
			if (lengthByte & 0x80)
			{
				auto byteCount = (UINT8)(lengthByte & 0x7F);
				if (byteCount > 0)
				{
					for (UINT8 i = byteCount; i > 0; i--)
					{
						UINT32 in = docBytes.readChar();
						length |= (in << (i - 1) * 8);
					}
				}
				else length = 0;
			}
			else
			{
				length = lengthByte & 0x7F;
			}

			property.tag = (ASN_TAG)type;
			property.data = docBytes.readBytes(length);

			if (property.tag == ASN_TAG::BITSTRING )
			{
				ASSERT(property.data.at(0) == 0);
				property.data.shift();
			}
			else if (property.tag == ASN_TAG::INTEGER)
			{
				auto& data = property.data;
				if (data.length() >= 2 && data.at(0) == 0 && data.at(1) & 0x80)
					data.shift();
			}
		}
	} while (false);
	return property;
}

void ParsePrivateKey(BUFFER keyBytes, BCRYPT_KEY_HANDLE& privateKeyHandle)
{
	// RFC 5915
	auto keySequence = ReadASNData(keyBytes);
	BCRYPT_ALG_HANDLE algHandle = nullptr;

	if (keySequence.tag == ASN_TAG::SEQUENCE)
	{
		auto version = ReadASNData(keySequence.data);
		ASSERT(version.tag == ASN_TAG::INTEGER);
		ASSERT(version.data.at(0) == 1);

		auto privateKeyBytes = ReadASNData(keySequence.data);
		ASSERT(privateKeyBytes.tag == ASN_TAG::OCTETSTRING);

		auto privateKey = privateKeyBytes.data;

		auto ecParamsBytes = ReadASNData(keySequence.data);
		if (ecParamsBytes.tag == ASN_TAG::CONTEXT_TAG_0)
		{
			auto curveNameBytes = ReadASNData(ecParamsBytes.data);
			if (curveNameBytes.tag == ASN_TAG::OID && curveNameBytes.data == OID_secp256r1)
			{
				algHandle = Algorithms.ecdsa256;
			}
		}
		else DBGBREAK();

		auto publicKeyBytes = ReadASNData(keySequence.data);
		if (publicKeyBytes.tag == ASN_TAG::CONTEXT_TAG_1)
		{
			publicKeyBytes = ReadASNData(publicKeyBytes.data);
			ASSERT(publicKeyBytes.tag == ASN_TAG::BITSTRING);
		}
		else DBGBREAK();

		auto publicKey = publicKeyBytes.data;

		publicKey.shift(); // mode param, ignore it.

		BUFFER_BUILDER blobStream;
		blobStream.commit(sizeof(BCRYPT_ECCKEY_BLOB));
		blobStream.writeStream(publicKey);
		blobStream.writeStream(privateKey);

		auto blobHeader = (BCRYPT_ECCKEY_BLOB*)blobStream.address();
		blobHeader->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
		blobHeader->cbKey = 0x20;

		auto blob = blobStream.toBuffer();
		auto status = BCryptImportKeyPair(algHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, &privateKeyHandle, (PUCHAR)blob.data(), blob.length(), 0);
		ASSERT(NT_SUCCESS(status));
	}
	else DBGBREAK();
}


void ParsePublicKey(ASN_DATA keySequence, CERTIFICATE &publicKey)
{
	auto algorithm = ReadASNData(keySequence.data);

	if (algorithm.tag == ASN_TAG::SEQUENCE)
	{
		auto algorithmClass = ReadASNData(algorithm.data);
		auto algorithmType = ReadASNData(algorithm.data);

		if (algorithmClass.tag == ASN_TAG::OID)
		{
			if (algorithmClass.data == OID_EC_public_key)
			{
				if (algorithmType.tag == ASN_TAG::OID && algorithmType.data == OID_secp256r1)
				{
					publicKey.algHandle = Algorithms.ecdsa256; // BCRYPT_ECDSA_P256_ALG_HANDLE;
				}
				else DBGBREAK();

				auto keyData = ReadASNData(keySequence.data);
				if (keyData.tag == ASN_TAG::BITSTRING)
				{
					auto asnData = keyData.data;
					//if (asnData.at(0) == 0)
					//	asnData.shift();

					asnData.shift(); // mode param, ignore it.

					BUFFER_BUILDER buffer;
					buffer.commit(sizeof(BCRYPT_ECCKEY_BLOB));
					buffer.writeStream(asnData);

					auto keyBlob = (BCRYPT_ECCKEY_BLOB*)buffer.address();
					RtlZeroMemory(keyBlob, sizeof(BCRYPT_ECCKEY_BLOB));
					keyBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
					keyBlob->cbKey = 0x20;

					auto blobBuffer = buffer.toBuffer();

					auto status = BCryptImportKeyPair(publicKey.algHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, &publicKey.keyHandle, (PUCHAR)blobBuffer.data(), blobBuffer.length(), 0);
					ASSERT(NT_SUCCESS(status));
				}
			}
			else if (algorithmClass.data == OID_RSAEncryption)
			{
				publicKey.algHandle =  Algorithms.rsaSign;
				auto keyData = ReadASNData(keySequence.data);

				if (keyData.tag == ASN_TAG::BITSTRING)
				{
					auto asnData = keyData.data;

					auto sequence = ReadASNData(asnData);
					ASSERT(sequence.tag == ASN_TAG::SEQUENCE);

					auto modulus = ReadASNData(sequence.data);
					auto exponent = ReadASNData(sequence.data);

					BUFFER_BUILDER buffer;
					buffer.commit(sizeof(BCRYPT_RSAKEY_BLOB));

					buffer.writeStream(exponent.data);

					while ((modulus.data.length() % 0x10) && (modulus.data.at(0) == 0))
					{
						modulus.data.shift(); // XXX debug!
					}

					buffer.writeStream(modulus.data);

					auto importBlob = (BCRYPT_RSAKEY_BLOB*)buffer.address();
					RtlZeroMemory(importBlob, sizeof(BCRYPT_RSAKEY_BLOB));
					importBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
					importBlob->cbPublicExp = exponent.data.length();
					importBlob->cbModulus = modulus.data.length();
					importBlob->BitLength = importBlob->cbModulus * 8;

					auto importData = buffer.toBuffer();

					auto status = BCryptImportKeyPair(publicKey.algHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, &publicKey.keyHandle, (PUCHAR)importData.data(), importData.length(), 0);
					ASSERT(NT_SUCCESS(status));

				}
				else DBGBREAK();
			}
		}
	}
}

BUFFER ParseECDSAP256Signature(BUFFER input, LOCAL_STREAM<64> &sigData)
{
	auto sequence = ReadASNData(input);
	ASSERT(sequence.tag == ASN_TAG::SEQUENCE);

	{
		auto fieldR = ReadASNData(sequence.data);
		ASSERT(fieldR.tag == ASN_TAG::INTEGER);
		ASSERT(fieldR.data.length() == 0x20);
		sigData.writeStream(fieldR.data);
	}
	{
		auto fieldS = ReadASNData(sequence.data);
		ASSERT(fieldS.tag == ASN_TAG::INTEGER);
		ASSERT(fieldS.data.length() == 0x20);
		sigData.writeStream(fieldS.data);
	}

	return sigData.toBuffer();
}


USTRING ParseName(BUFFER rdnData)
{
	USTRING name;
	while (rdnData)
	{
		auto set = ReadASNData(rdnData);
		if (set.tag == ASN_TAG::SET)
		{
			auto sequence = ReadASNData(set.data);
			auto oid = ReadASNData(sequence.data);
			if (oid.tag == ASN_TAG::OID)
			{
				auto value = ReadASNData(sequence.data);
				if (oid.data == OID_id_at_commonName)
				{
					ASSERT(value.tag == ASN_TAG::PRINTSTRING || value.tag == ASN_TAG::UTF8STRING);
					name = value.data;
					break;
				}
			}
			else DBGBREAK();
		}
		else DBGBREAK();
	}
	return name;
}

NTSTATUS ParseX509(BUFFER certificateData, CERTIFICATE &certificate)
{
	auto topLevel = ReadASNData(certificateData);
	ASSERT(topLevel.tag == ASN_TAG::SEQUENCE);

	auto hashStart = topLevel.data.data();

	auto certLevel = ReadASNData(topLevel.data);
	ASSERT(certLevel.tag == ASN_TAG::SEQUENCE);

	auto hashData = BUFFER{ hashStart, (ULONG)(certLevel.data.length() + certLevel.data.data() - hashStart) };

	auto version = ReadASNData(certLevel.data);
	ASSERT(version.tag == ASN_TAG::CONTEXT_TAG_0);

	auto versionNumber = ReadASNData(version.data);
	ASSERT(versionNumber.tag == ASN_TAG::INTEGER);

	ASSERT(versionNumber.data.at(0) == 2);

	auto serialNumber = ReadASNData(certLevel.data);

	auto algorithmLevel = ReadASNData(certLevel.data);
	if (algorithmLevel.tag == ASN_TAG::SEQUENCE)
	{
		auto algorithm = ReadASNData(algorithmLevel.data);
		if (algorithm.data == OID_sha256WithRSAEncryption)
		{
			LogInfo("Certificate: OID_sha256WithRSAEncryption");
				// SHA256, dont' do anyting
		}
		else if (algorithm.data == OID_ecdsa_with_SHA256)
		{
			LogInfo("Certificate: OID_ecdsa with SHA256");
		}
		else if (algorithm.data == OID_sha384WithRSAEncryption)
		{
			LogInfo("Certificate: OID_sha384WithRSAEncryption");
		}
		else
		{
			DBGBREAK();
		}
	}

	auto issuedBy = ReadASNData(certLevel.data);
	certificate.issuedBy = ParseName(issuedBy.data);

	auto validity = ReadASNData(certLevel.data);

	auto subject = ReadASNData(certLevel.data);

	certificate.subject = ParseName(subject.data);

	auto keySequence = ReadASNData(certLevel.data);

	ParsePublicKey(keySequence, certificate);

	auto algSequence = ReadASNData(topLevel.data);
	if (algSequence.tag == ASN_TAG::SEQUENCE)
	{
		auto alg = ReadASNData(algSequence.data);
		if (alg.tag == ASN_TAG::OID)
		{
			auto signature = ReadASNData(topLevel.data);
			certificate.signature = signature.data;

			if (alg.data == OID_sha256WithRSAEncryption || alg.data == OID_ecdsa_with_SHA256)
			{
				auto status = BCryptHash(Algorithms.hashSha256, NULL, 0, (PUCHAR)hashData.data(), hashData.length(),
					certificate.hash.commit(SHA256_HASH_LENGTH), SHA256_HASH_LENGTH);
				ASSERT(NT_SUCCESS(status));
			}
			else if (alg.data == OID_sha384WithRSAEncryption || alg.data == OID_ecdsa_with_SHA384)
			{
				auto status = BCryptHash(Algorithms.hashSha384, NULL, 0, (PUCHAR)hashData.data(), hashData.length(),
					certificate.hash.commit(SHA384_HASH_LENGTH), SHA384_HASH_LENGTH);
				ASSERT(NT_SUCCESS(status));
			}
		}
	}
	else DBGBREAK();

	return STATUS_SUCCESS;
}

void ParseOID(USTRING oidBytes)
{
	if (oidBytes == OID_sha256WithRSAEncryption)
	{
		LogInfo("SHA1\n");
	}
	else if (oidBytes == OID_id_at_countryName)
	{
		LogInfo("C\n");
	}
	else if (oidBytes == OID_id_at_organizationName)
	{
		LogInfo("O\n");
	}
	else if (oidBytes == OID_id_at_commonName)
	{
		LogInfo("common name\n");
	}
	else if (oidBytes == OID_id_at_stateOrProvinceName)
	{
		LogInfo("state\n");
	}
	else if (oidBytes == OID_id_at_serialNumber)
	{
		LogInfo("serial number\n");
	}
	else if (oidBytes == OID_id_at_localityName)
	{
		LogInfo("locality name\n");
	}
	else if (oidBytes == OID_EC_public_key)
	{
		LogInfo("EC public key\n");
	}
	else if (oidBytes == OID_secp256r1)
	{
		LogInfo("EC secp256r1\n");
	}
	else
	{
		LogInfo("Unknown");
	}

}

INT8 ASNPosition[16];

using ParseASNCallback =  void (*)(INT8 *yPos, UINT8 x, UINT8 type, USTRING data, USTRING lastOid);
