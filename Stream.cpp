// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#include "pch.h"
#include "Types.h"	

UINT32 strLen(const UINT8 *string)
{
	auto match = (const UINT8 *)memchr(string, 0, 2048);
	ASSERT(match != nullptr);
	return ((UINT32)(match - string));
}

UINT32 strLen(const char *string)
{
	return strLen((const UINT8 *)string);
}

template<>
UINT32 StreamWrite(UINT8 *address, UINT8 value)
{
	*address = value;
	return sizeof(value);
}

template<>
UINT32 StreamWrite(UINT8 *address, UINT16 value)
{
	*(UINT16 *)address = value;
	return sizeof(value);
}

template<>
UINT32 StreamWrite(UINT8 *address, UINT32 value)
{
	*(UINT32 *)address = value;
	return sizeof(value);
}

template<>
UINT32 StreamWrite(UINT8* address, UINT64 value)
{
	*(UINT64*)address = value;
	return sizeof(value);
}

template<>
UINT32 StreamWrite(UINT8* address, INT64 value)
{
	*(INT64*)address = value;
	return sizeof(value);
}

template<>
UINT32 StreamWriteString(UINT8 *address, USTRING inputString, UINT32 length)
{
	RtlCopyMemory(address, inputString.data(), length);
	address[length] = 0;
	return length;
}

template<>
UINT32 StreamWriteString(UINT16* address, USTRING inputString, UINT32 length)
{
	for (UINT32 i = 0; i < length; i++)
	{
		address[i] = inputString.shift();
	}
	address[length] = 0;
	return length;
}

template<>
UINT32 StreamWriteBE<UINT8>(UINT8 *address, UINT8 value)
{
	*address++ = value;
	return sizeof(UINT8);
}

template<>
UINT32 StreamWriteBE<UINT16>(UINT8 *address, UINT16 value)
{
	*address++ = (UINT8)((value & 0xFF00) >> 8);
	*address++ = (UINT8)(value & 0xFF);
	return sizeof(UINT16);
}

template<>
UINT32 StreamWriteBE<UINT32>(UINT8 *address, UINT32 value)
{
	*address++ = (UINT8)((value & 0xFF000000) >> 24);
	*address++ = (UINT8)((value & 0x00FF0000) >> 16);
	*address++ = (UINT8)((value & 0x0000FF00) >> 8);
	*address++ = (UINT8)(value & 0x000000FF);

	return sizeof(UINT32);
}

template<>
UINT32 StreamWriteBE<UINT64>(UINT8 *address, UINT64 value)
{
	*address++ = (UINT8)((value & 0xFF00000000000000) >> 56);
	*address++ = (UINT8)((value & 0x00FF000000000000) >> 48);
	*address++ = (UINT8)((value & 0x0000FF0000000000) >> 40);
	*address++ = (UINT8)((value & 0x000000FF00000000) >> 32);

	*address++ = (UINT8)((value & 0xFF000000) >> 24);
	*address++ = (UINT8)((value & 0x00FF0000) >> 16);
	*address++ = (UINT8)((value & 0x0000FF00) >> 8);
	*address++ = (UINT8)(value & 0x000000FF);

	return sizeof(UINT64);
}

template<>
UINT32 StreamWriteBE<double>(UINT8* address, double value)
{
	char* data = (char*)&value;

	*address++ = data[7];
	*address++ = data[6];
	*address++ = data[5];
	*address++ = data[4];

	*address++ = data[3];
	*address++ = data[2];
	*address++ = data[1];
	*address++ = data[0];

	return sizeof(double);
}

template <>
UINT8 StreamReadBE<UINT8>(const UINT8* address, UINT32 &bytesRead)
{
	bytesRead += sizeof(UINT8);
	auto byte1 = *address++;
	return byte1;
}

template <>
UINT16 StreamReadBE<UINT16>(const UINT8* address, UINT32 &bytesRead)
{
	bytesRead += sizeof(UINT16);

	auto byte1 = *address++;
	auto byte2 = *address++;

	return (UINT16)(byte1 << 8 | byte2);
}

template <>
UINT32 StreamReadBE<UINT32>(const UINT8 *address, UINT32 &bytesRead)
{
	bytesRead += sizeof(UINT32);

	auto byte1 = *address++;
	auto byte2 = *address++;
	auto byte3 = *address++;
	auto byte4 = *address++;

	return (UINT32)((byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4);
}

template <>
float StreamReadBE<float>(const UINT8* address, UINT32& bytesRead)
{
	bytesRead += sizeof(UINT32);

	auto byte1 = *address++;
	auto byte2 = *address++;
	auto byte3 = *address++;
	auto byte4 = *address++;

	UINT8 data[] = {byte4, byte3, byte2, byte1};
	return *(float*)data;
}

template <>
double StreamReadBE<double>(const UINT8* address, UINT32& bytesRead)
{
	bytesRead += sizeof(double);

	auto byte1 = *address++;
	auto byte2 = *address++;
	auto byte3 = *address++;
	auto byte4 = *address++;
	auto byte5 = *address++;
	auto byte6 = *address++;
	auto byte7 = *address++;
	auto byte8 = *address++;

	UINT8 data[] = { byte8, byte7, byte6, byte5, byte4, byte3, byte2, byte1 };
	return *(double*)data;
}

template <>
UINT64 StreamReadBE<UINT64>(const UINT8 *address, UINT32 &bytesRead)
{
	bytesRead += sizeof(UINT64);

	UINT64 byte1 = *address++;
	UINT64 byte2 = *address++;
	UINT64 byte3 = *address++;
	UINT64 byte4 = *address++;
	UINT64 byte5 = *address++;
	UINT64 byte6 = *address++;
	UINT64 byte7 = *address++;
	UINT64 byte8 = *address++;

	return (UINT64)((byte1 << 56) | (byte2 << 48) | (byte3 << 40) | (byte4 << 32) | (byte5 << 24) | (byte6 << 16) | (byte7 << 8) | byte8);
}

void StreamWriteBytes(PUINT8 destination, const UINT8 * source, ULONG length)
{
	RtlCopyMemory(destination, source, length);
}

PUNICODE_STRING ToUnicodeString(USTRING input)
{
	auto& unicodeString = StackAlloc<UNICODE_STRING, SCHEDULER_STACK>();

	UINT32 byteLength = input.length() * 2 + 2;
	auto dest = (PUINT16) StackAlloc<SCHEDULER_STACK>(byteLength);
	for (UINT32 i = 0; i < input.length(); i++)
	{
		dest[i] = input.at(i);
	}
	dest[input.length()] = 0;

	unicodeString.MaximumLength = (USHORT)byteLength;
	unicodeString.Length = (USHORT)(input.length() * 2);
	unicodeString.Buffer = dest;

	return &unicodeString;
}

POBJECT_ATTRIBUTES ToObjectAttributes(USTRING path)
{
	auto& objectAttributes = StackAlloc<OBJECT_ATTRIBUTES,SCHEDULER_STACK>();
	auto unicodeName = ToUnicodeString(path);

	InitializeObjectAttributes(&objectAttributes, unicodeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

	return &objectAttributes;
}

NTSTATUS CreateDirectory(USTRING name)
{
	HANDLE directoryHandle;
	if (name.peek() != '\\')
	{
		name = TSTRING_BUILDER().writeMany(DATA_DIRECTORY, name);
	}

	IO_STATUS_BLOCK statusBlock;
	auto status = ZwCreateFile(&directoryHandle, GENERIC_WRITE | SYNCHRONIZE, ToObjectAttributes(name), &statusBlock, NULL,
		FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, nullptr, 0);

	ZwClose(directoryHandle);
	return status;
}

UINT32 GetFileSize(USTRING filename)
{
	IO_STATUS_BLOCK statusBlock;
	HANDLE fileHandle;
	UINT32 fileSize = 0;
	do
	{
		auto status = ZwCreateFile(&fileHandle, GENERIC_READ | SYNCHRONIZE, ToObjectAttributes(filename), &statusBlock, NULL,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

		if (!NT_SUCCESS(status))
			break;

		FILE_STANDARD_INFORMATION fileInformation;
		status = ZwQueryInformationFile(fileHandle, &statusBlock, &fileInformation, sizeof(fileInformation), FileStandardInformation);
		VERIFY_STATUS;

		fileSize = (UINT32)(fileInformation.EndOfFile.QuadPart + 1);

		ZwClose(fileHandle);
	} while (false);
	return fileSize;
}

NTSTATUS WriteFile(USTRING filename, USTRING data)
{
	auto status = STATUS_SUCCESS;
	HANDLE fileHandle = nullptr;
	do
	{
		if (filename.peek() != '\\')
		{
			filename = TSTRING_BUILDER().writeMany(DATA_DIRECTORY, filename);
		}

		auto objectAttributes = ToObjectAttributes(filename);

		IO_STATUS_BLOCK statusBlock;
		status = ZwCreateFile(&fileHandle, GENERIC_WRITE | SYNCHRONIZE, objectAttributes, &statusBlock, NULL,
			FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
		VERIFY_STATUS;

		status = ZwWriteFile(fileHandle, nullptr, nullptr, nullptr, &statusBlock, (PVOID)data.data(), data.length(), nullptr, nullptr);
		VERIFY_STATUS;

		ASSERT((UINT32)statusBlock.Information == data.length());

	} while (false);
	if (fileHandle) ZwClose(fileHandle);
	return status;
}

NTSTATUS DeleteFile(USTRING filename)
{
	auto object = ToObjectAttributes(filename);
	auto status = ZwDeleteFile(object);
	ASSERT(NT_SUCCESS(status));
	return status;
}
