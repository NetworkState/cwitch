#pragma once
#include <ntdddisk.h>

constexpr UINT32 SECTOR_SIZE = 512;
constexpr GUID STATEOS_PARTITION = { 0x5f3c4045, 0x1f16, 0x445b, { 0x91, 0x31, 0x3b, 0xa5, 0x42, 0xa9, 0x1e, 0x42 } };
// 5f3c4045-1f16-445b-9131-3ba542a91e42 
constexpr GUID MEDIA_APPID = { 0x6acc56dc, 0x5bab, 0x449a, {0x87, 0x90, 0xf8, 0xa4, 0x9d, 0x62, 0xf4, 0xd6 } };
// {B8281B3B-203F-43B8-B7A2-B866FE5A80A9}
constexpr GUID EMPTY_SECTOR_GUID = { 0xb8281b3b, 0x203f, 0x43b8, 0xb7, 0xa2, 0xb8, 0x66, 0xfe, 0x5a, 0x80, 0xa9 };

constexpr USTRING MEDIA_DIRECTORY = "media";

struct DISK_ROOT_SECTOR
{
	GUID diskId;
	UINT64 creationTime;
	UINT64 lastWriteTime;
	UINT64 lastAccessTime;

	UINT8 filler[SECTOR_SIZE];
};

void ImportMediaFiles();

constexpr UINT64 DISK_CACHE_SIZE = 32 * 1024 * 1024;
constexpr UINT16 CommandHeaerLength = 54;

struct DISK_OFFSET
{
	UINT64 _offset;
	
	DISK_OFFSET() : _offset(0) {}

	DISK_OFFSET(UINT64 offset, UINT64 volumeId = 0)
	{
		_offset = volumeId << 56 | (offset & 0xFFFFFFFFFFFFFF);
	}

	UINT32 getVoluemId()
	{
		return (UINT32)(_offset >> 56);
	}

	UINT64 getOffset()
	{
		return _offset & 0xFFFFFFFFFFFFFF;
	}
};

struct STORAGE_VOLUME_INFO
{
	struct FREE_SPACE_INFO
	{
		UINT64 offset;
		UINT64 size;

		FREE_SPACE_INFO(UINT64 offsetArg) : offset(offsetArg), size(SECTOR_SIZE) {}
	};

	GUID diskId;
	UINT32 volumeId;

	UINT64 capacity;
	UINT32 diskIndex;
	UINT32 partitionIndex;

	DISK_ROOT_SECTOR rootSector;

	ERESOURCE writeLock;

	HANDLE deviceHandle;

	STREAM_BUILDER<FREE_SPACE_INFO, GLOBAL_STACK, 128> freeSpaceStream;

	PUINT8 diskCache;
	UINT32 cacheSize;
	UINT64 cacheOffset;

	STORAGE_VOLUME_INFO(UINT64 capacity, UINT32 diskIndex, UINT32 partIndex, GUID guid, UINT32 id) : capacity(capacity), diskIndex(diskIndex), partitionIndex(partIndex), diskId(guid), volumeId(id)
	{
	}

	NTSTATUS readDisk(UINT64 offset, PUINT8 address, UINT32 size)
	{
		if (offset + size > capacity)
		{
			return STATUS_END_OF_FILE;
		}

		PUINT8 dataAddress = nullptr;
		if (offset >= cacheOffset && (offset + size) <= (cacheOffset + cacheSize))
		{
			dataAddress = diskCache + (offset - cacheOffset);
		}
		else
		{
			IO_STATUS_BLOCK ioStatus;
			auto readSize = min(DISK_CACHE_SIZE, capacity - offset);
			auto status = ZwReadFile(deviceHandle, nullptr, nullptr, nullptr, &ioStatus, (PVOID)diskCache, (ULONG)readSize, (PLARGE_INTEGER)&offset, nullptr);
			if (NT_SUCCESS(status))
			{
				cacheOffset = offset;
				cacheSize = (UINT32)ioStatus.Information;
				dataAddress = diskCache;
			}
			else
			{
				DBGBREAK();
				cacheOffset = 0;
				cacheSize = 0;
				dataAddress = nullptr;
			}
		}
		if (dataAddress)
		{
			RtlCopyMemory(address, dataAddress, size);
			return STATUS_SUCCESS;
		}
		return STATUS_END_OF_FILE;
	}

	void formatVolume()
	{
		rootSector.diskId = diskId;
		rootSector.creationTime = GetStateOsTime();
		rootSector.lastAccessTime = GetStateOsTime();
		rootSector.lastWriteTime = GetStateOsTime();

		IO_STATUS_BLOCK ioStatus;
		UINT64 diskOffset = 0;
		auto status = ZwWriteFile(deviceHandle, nullptr, nullptr, nullptr, &ioStatus, &rootSector, SECTOR_SIZE, (PLARGE_INTEGER)& diskOffset, nullptr);
		ASSERT(NT_SUCCESS(status));

		auto sector = (PUINT8)StackAlloc<SCHEDULER_STACK>(SECTOR_SIZE);
		RtlFillBytes(sector, SECTOR_SIZE, 0xFF);
		BYTESTREAM dataStream{ sector, SECTOR_SIZE };

		dataStream.writeBE<UINT32>(SECTOR_SIZE);
		dataStream.writeGuid(EMPTY_SECTOR_GUID);

		UINT64 blockSize = SECTOR_SIZE * 2048;
		auto block = (PUINT8)StackAlloc<SCHEDULER_STACK>((UINT32)blockSize);
		BYTESTREAM blockStream{ block, (UINT32)blockSize };

		for (UINT32 i = 0; i < 2048; i++)
		{
			blockStream.writeBytes(sector, SECTOR_SIZE);
		}

		diskOffset = SECTOR_SIZE;
		while (diskOffset < capacity)
		{
			auto writeSize = min(blockSize, capacity - diskOffset);
			status = ZwWriteFile(deviceHandle, nullptr, nullptr, nullptr, &ioStatus, block, (UINT32)writeSize, (PLARGE_INTEGER)& diskOffset, nullptr);
			if (!NT_SUCCESS(status))
			{
				DBGBREAK();
				break;
			}

			diskOffset += ioStatus.Information;
		}
	}

	DISK_OFFSET writeDataInternal(PUINT8 address, UINT32 length)
	{
		auto writeLength = ROUND_TO(length, SECTOR_SIZE);

		UINT64 writeOffset = 0;
		auto freeSpaces = freeSpaceStream.toBufferNoConst();
		for (auto& freeSpace : freeSpaces)
		{
			if (freeSpace.size >= writeLength)
			{
				writeOffset = freeSpace.offset;
				freeSpace.offset += writeLength;
				freeSpace.size -= writeLength;
				break;
			}
		}

		ASSERT(writeOffset > 0);

		IO_STATUS_BLOCK ioStatus;
		auto status = ZwWriteFile(deviceHandle, nullptr, nullptr, nullptr, &ioStatus, address, writeLength, (PLARGE_INTEGER)& writeOffset, nullptr);
		ASSERT(NT_SUCCESS(status));

		return DISK_OFFSET(writeOffset, volumeId);
	}

	DISK_OFFSET writeData(BUFFER buffer)
	{
		ExAcquireResourceExclusiveLite(&writeLock, TRUE);
		auto writeOffset = writeDataInternal((PUINT8)buffer.data(), buffer.length());
		ExReleaseResourceLite(&writeLock);
		return writeOffset;
	}

	template <typename FUNC, typename ... ARGS>
	DISK_OFFSET writeData(FUNC callback, ARGS&& ... args)
	{
		ExAcquireResourceExclusiveLite(&writeLock, TRUE);

		auto& dataStream = writeStream.clear();
		auto lengthOffset = dataStream.saveOffset(4);
		dataStream.writeGuid(MEDIA_APPID);

		callback(dataStream, args ...);

		lengthOffset.writeLength();

		auto writeOffset = writeDataInternal(dataStream.address(), dataStream.count());

		ExReleaseResourceLite(&writeLock);

		return writeOffset;
	}

	UINT32 readCommandSize(UINT64 diskOffset)
	{
		UINT32 commandSize = 0;

		LOCAL_STREAM<512> sectorData;
		auto status = readDisk(diskOffset, sectorData.commit(SECTOR_SIZE), SECTOR_SIZE);
		if (NT_SUCCESS(status))
		{
			auto dataBuffer = sectorData.toBuffer();
			commandSize = dataBuffer.readBE<UINT32>();
		}
		return commandSize;
	}

	template <typename STREAM>
	BUFFER readCommand(UINT64 diskOffset, STREAM&& dataStream)
	{
		BUFFER result;

		auto dataStart = dataStream.count();
		do
		{
			auto commandSize = readCommandSize(diskOffset);
			if (commandSize == 0)
				break;

			ASSERT(commandSize < 32 * 1024 * 1024);
			auto readSize = ROUND_TO(commandSize, SECTOR_SIZE);
			dataStream.reserve(readSize);

			auto status = readDisk(diskOffset, dataStream.commit(commandSize), readSize);
			if (!NT_SUCCESS(status))
				break;

			result = dataStream.toBuffer(dataStart);
		} while (false);
		return result;
	}

	void addEmptySector(UINT64 diskOffset)
	{
		do
		{
			if (freeSpaceStream.count() > 0)
			{
				auto& freeSpace = freeSpaceStream.last();
				if (freeSpace.offset + freeSpace.size == diskOffset)
				{
					freeSpace.size += SECTOR_SIZE;
					break;
				}
			}

			freeSpaceStream.append(diskOffset);
			
		} while (false);
	}

	NTSTATUS init()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			LOCAL_STREAM<64> charStream;
			auto name = charStream.writeMany("\\??\\Harddisk", diskIndex, "Partition", partitionIndex);

			IO_STATUS_BLOCK ioStatus;
			auto status = ZwCreateFile(&deviceHandle, SYNCHRONIZE | GENERIC_ALL, ToObjectAttributes(name), &ioStatus, nullptr,
				0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
			VERIFY_STATUS;

			ExInitializeResourceLite(&writeLock);

			UINT64 fileOffset = 0;
			status = ZwReadFile(deviceHandle, nullptr, nullptr, nullptr, &ioStatus, &rootSector, SECTOR_SIZE, (PLARGE_INTEGER)& fileOffset, 0);
			ASSERT(NT_SUCCESS(status));

			//if (rootSector.diskId != diskId)
			{
				formatVolume();
			}

			diskCache = (PUINT8)KernelAlloc(DISK_CACHE_SIZE);
			ASSERT(diskCache);

		} while (false);
		return status;
	}
};

PARTITION_INFORMATION_EX* ReadDiskLayout(UINT32 index);
