// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#include "pch.h"
#include "Types.h"
#include "SYNC.h"
#include "MkvParser.h"

PARTITION_INFORMATION_EX * ReadDiskLayout(UINT32 index)
{
	PARTITION_INFORMATION_EX* partitionInfo = nullptr;

	auto status = STATUS_SUCCESS;
	do
	{
		auto name = GetTempStream().writeMany("\\??\\PhysicalDrive", index);
		HANDLE deviceHandle;
		IO_STATUS_BLOCK ioStatus;
		status = ZwCreateFile(&deviceHandle, SYNCHRONIZE | GENERIC_READ, ToObjectAttributes(name), &ioStatus, nullptr,
			0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
		if (!NT_SUCCESS(status))
			break;

		auto layoutSize = (UINT32)(sizeof(DRIVE_LAYOUT_INFORMATION_EX) + (sizeof(PARTITION_INFORMATION_EX) * 10));
		auto& diskLayout = *(DRIVE_LAYOUT_INFORMATION_EX *)StackAlloc<SCHEDULER_STACK>(layoutSize);
		status = ZwDeviceIoControlFile(deviceHandle, nullptr, nullptr, nullptr, &ioStatus, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, &diskLayout, layoutSize);
		VERIFY_STATUS;

		if (diskLayout.PartitionStyle == PARTITION_STYLE_GPT)
		{
			for (UINT32 i = 0; i < diskLayout.PartitionCount; i++)
			{
				auto& partition = diskLayout.PartitionEntry[i];

				if (partition.Gpt.PartitionType == STATEOS_PARTITION)
				{
					partitionInfo = &partition;
					break;
				}
			}
		}

		ZwClose(deviceHandle);
	} while (false);
	return partitionInfo;
}

BUFFER GetCommandData(BUFFER command)
{
	command.shift(CommandHeaerLength);
	auto scopeLength = command.readVInt();
	command.shift((UINT32)scopeLength);

	return command;
}

BUFFER GetCommandScope(BUFFER command)
{
	command.shift(CommandHeaerLength);
	auto scopeLength = command.readVInt();
	return command.readBytes((UINT32)scopeLength);
}

struct MEDIA_PARSER
{
	struct MEDIA_TRACK
	{
		TOKEN type;
		UINT32 trackId;
		TOKEN codecPrivate;
		VISUALSTREAM<SCHEDULER_STACK> visualStream;
		STREAM_BUILDER<UINT8, SCHEDULER_STACK, 1> commandStream;

		UINT64 maxPacketSize = 0;
		UINT64 totalBytes = 0;
		explicit operator bool() const { return IsValidRef(*this); }
	};

	GUID id;
	UINT64 timecodeScale = 0;

	UINT64 timestamp;
	VISUALSTREAM<SCHEDULER_STACK> metadataStream;;

	STREAM_BUILDER<MEDIA_TRACK, SCHEDULER_STACK, 4> mediaTracks;

	DISK_OFFSET metadataDiskOffset;

	auto& findTrack(UINT32 trackId)
	{
		for (auto& track : mediaTracks.toBufferNoConst())
		{
			if (track.trackId == trackId)
			{
				return track;
			}
		}
		return NullRef<MEDIA_TRACK>();
	}

	void clear()
	{
		mediaTracks.clear();
		metadataStream.stream.clear();
	}
};

template <typename STREAM>
void WriteCommandHeader(STREAM&& dataStream, GUID appId, GUID objectId, UINT64 oldTimestamp, UINT64 newTimestamp, TOKEN command)
{
	dataStream.writeBE<UINT32>(0);
	dataStream.writeGuid(appId);
	dataStream.writeGuid(objectId);

	dataStream.writeBE<UINT64>(oldTimestamp);
	dataStream.writeBE<UINT64>(newTimestamp);

	dataStream.writeBE<UINT16>(command.getShortName());

	ASSERT(dataStream.count() == CommandHeaerLength);
}

template <typename STREAM>
void FormatMetadata(MEDIA_PARSER& mediaParser, STREAM&& commandStream)
{
	commandStream.clear().reserve(8 * 1024);

	WriteCommandHeader(commandStream, MEDIA_APPID, mediaParser.id, 0, mediaParser.timestamp, SYNC_metadata);
	commandStream.writeVInt(0);

	mediaParser.metadataStream.format(commandStream);

	for (auto& track : mediaParser.mediaTracks.toBufferNoConst())
	{
		if (track.codecPrivate)
		{
			commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(track.codecPrivate, VSIZE::MEDIUM, VSPAN::WORD));
			commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(SYNC_codec_data, VSIZE::SMALL, VSPAN::COLON));

			commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(CreateNumberHandle<SCHEDULER_STACK>(track.maxPacketSize), VSIZE::MEDIUM, VSPAN::WORD));
			commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(SYNC_track_packet_max, VSIZE::SMALL, VSPAN::COLON));

			commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(CreateNumberHandle<SCHEDULER_STACK>(track.totalBytes), VSIZE::MEDIUM, VSPAN::WORD));
			commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(SYNC_track_size_total, VSIZE::SMALL, VSPAN::COLON));
		}
		track.visualStream.format(commandStream);
	}

	commandStream.writeAtBE<UINT32>(0, commandStream.count());
}

void WriteMetadata(MEDIA_PARSER& mediaParser)
{
	auto& diskVolume = SyncService().getWriteVolume();
	TBYTESTREAM commandStream;

	FormatMetadata(mediaParser, commandStream);

	//// test code - BEGIN
	//auto commandData = commandStream.toBuffer(CommandHeaerLength + 1); 

	//VISUALSTREAM<SCHEDULER_STACK, 1> visualStream1;
	//visualStream1.stream.reserve(512);
	//visualStream1.parse(commandData);

	//VISUALSTREAM<SCHEDULER_STACK, 1> visualStream2;
	//visualStream2.stream.reserve(512);
	//visualStream2.parse(commandData);

	//DiffBot(visualStream1.toBuffer(), visualStream2.toBuffer());
	//// test code - END

	mediaParser.metadataDiskOffset = diskVolume.writeData(commandStream.toBuffer());
}

void MergeMetadata(MEDIA_PARSER& mediaParser)
{
	DBGBREAK();

	auto& diskVolume = SyncService().getVolume(mediaParser.metadataDiskOffset.getVoluemId());

	TBYTESTREAM diskStream;
	diskStream.reserve(8 * 1024);

	auto diskCommand = diskVolume.readCommand(mediaParser.metadataDiskOffset.getOffset(), diskStream);
	diskCommand = GetCommandData(diskCommand);

	VISUALSTREAM<SCHEDULER_STACK, 1> diskVisual;
	diskVisual.stream.reserve(64) ;
	
	VISUALSTREAM<SCHEDULER_STACK, 1> newVisual;
	newVisual.stream.reserve(64);

	TBYTESTREAM metadataStream;
	metadataStream.reserve(8 * 1024);

	FormatMetadata(mediaParser, metadataStream);
	auto commandData = GetCommandData(metadataStream.toBuffer());

	diskVisual.parse(diskCommand);
	newVisual.parse(commandData);

	auto diffCommand = DiffBot(diskVisual.toBuffer(), newVisual.toBuffer());

	metadataStream.clear();
	WriteCommandHeader(metadataStream, MEDIA_APPID, mediaParser.id, mediaParser.timestamp, GetStateOsTime(), SYNC_metadata);

	metadataStream.writeVInt(0); // no scope data

	FormatVisual<SCHEDULER_STACK>(diffCommand, metadataStream);

	diskVolume.writeData(metadataStream.toBuffer());
}

constexpr UINT8 MKV_XIPH_LACING = 0x02;
constexpr UINT8 MKV_FIXED_SIZE_LACING = 0x04;
constexpr UINT8 MKV_EBML_LACING = 0x06;
constexpr UINT8 MKV_LACING_MASK = 0x06;

void ReadCluster(MEDIA_PARSER& mediaParser, MKV_MASTER_ELEMENT& cluster)
{
	auto& volume = SyncService().getWriteVolume();

	UINT64 clusterTimeCode = 0;
	while (auto id = cluster.readElementId())
	{
		auto length = cluster.readDataLength();
		if (id == MKV_ClusterTimecode)
		{
			//LogInfo("TimeCode: %d", length);
			auto data = cluster.readData((UINT32)length);
			clusterTimeCode = data.readUIntBE((UINT32)length);
			LogInfo("Import clusterTime: %d", clusterTimeCode);
		}
		else if (id == MKV_SimpleBlock)
		{
			auto block = cluster.readMasterElement(id, length);
			auto trackNumber = block.readVInt();

			auto header = block.readData(3);
			UINT64 timeCode = header.readBE<UINT16>();
			timeCode += clusterTimeCode;

			auto flags = header.readByte();

			if (flags & MKV_LACING_MASK)
			{
				// XXX TODO: add support for lacing.
			}

			auto& track = mediaParser.findTrack((UINT32)trackNumber);
			ASSERT(track);

			if (track)
			{
				if (track.commandStream.count() == 0)
				{
					WriteCommandHeader(track.commandStream, MEDIA_APPID, mediaParser.id, 0, mediaParser.timestamp, SYNC_frame);
					track.visualStream.format(track.commandStream);

					track.commandStream.writeVisualToken(nullptr, clusterTimeCode, TOKENTYPE::NUMBER, VSIZE::MEDIUM, VSPAN::WORD);
					track.commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(SYNC_cluster_time, VSIZE::SMALL, VSPAN::COLON));

					track.commandStream.writeLengthAt(CommandHeaerLength);
				}
				track.totalBytes += block.bytesLeft;
				track.maxPacketSize += block.bytesLeft;
				auto& dataStream = track.commandStream;
				auto offset = dataStream.saveOffset(4);

				dataStream.writeInt<UINT64>(timeCode);

				while (block.bytesLeft > 0)
				{
					auto toRead = min(block.bytesLeft, 512 * 1024);
					auto readData = block.readData((UINT32)toRead);

					dataStream.writeStream(readData);
				}

				offset.writeLength();
			}
		}
		else
		{
			//LogInfo("Unknown LEN:%d", length);
			cluster.readData((UINT32)length);
		}
	}

	for (auto& track : mediaParser.mediaTracks.toBufferNoConst())
	{
		if (track.commandStream.count() > 0)
		{
			track.commandStream.writeAtBE<UINT32>(0, (UINT32)track.commandStream.count());
			volume.writeData(track.commandStream.toBuffer());
			track.commandStream.clear();
			track.maxPacketSize = 0;
		}
	}
}

void ReadElements(MEDIA_PARSER& mediaParser, MKV_MASTER_ELEMENT& master)
{
	master.readElements([](TOKEN name, UINT64 length, MEDIA_PARSER& mediaParser, MKV_MASTER_ELEMENT& master)
		{
			if (IsMasterElement(name))
			{
				auto childElement = master.readMasterElement(name, length);
				if (name == MKV_TrackEntry)
				{
					auto& track = mediaParser.mediaTracks.append();
					track.visualStream.writeSpan(VSPAN::ITEM);
					ReadElements(mediaParser, childElement);
				}
				else if (name == MKV_Tracks)
				{
					ReadElements(mediaParser, childElement);
					WriteMetadata(mediaParser);
				}
				else if (name == MKV_Cluster)
				{
					//LogInfo("Cluster: %d, BytesLeft: %d", childElement.bytesLeft, master.bytesLeft);
					ReadCluster(mediaParser, childElement);
				}
				else
				{
					ReadElements(mediaParser, childElement);
				}
			}
			else
			{
				auto data = master.readData((UINT32)length);
				if (master.elementName == MKV_Info)
				{
					auto& visualStream = mediaParser.metadataStream;

					if (name == MKV_Title)
					{
						visualStream.writeValue(String.parseLiteral<SCHEDULER_STACK>(data), VSIZE::LARGE, VSPAN::WORD);
					}
					else if (name == MKV_SegmentUID)
					{
						ASSERT(data.length() == sizeof(GUID));
						mediaParser.id = data.readGuid();
						visualStream.writeValue(CreateGuidHandle<SCHEDULER_STACK>(mediaParser.id), VSIZE::XSMALL, VSPAN::WORD);
						visualStream.writeAttr(SYNC_id, VSIZE::XXSMALL, VSPAN::COLON);
					}
					else if (name == MKV_TimecodeScale)
					{
						auto value = data.readUIntBE((UINT32)length);
						mediaParser.timecodeScale = value;
					}
					else if (name == MKV_Duration)
					{
						ASSERT(data.length() == 8);
						auto number = data.readBE<double>();
						visualStream.writeValueAttr(CreateNumberHandle<SCHEDULER_STACK>((INT64)number), SYNC_duration);
					}
					else if (name == MKV_DateUTC)
					{
						auto value = data.readUIntBE((UINT32)length) / 100; // to 100ns resolution
						auto systemTime = MkvToSystemTime(value);
						visualStream.writeValueAttr(CreateNumberHandle<SCHEDULER_STACK>(systemTime), SYNC_date);
					}
				}
				else if (master.elementName == MKV_TrackEntry)
				{
					auto& track = mediaParser.mediaTracks.last();
					if (name == MKV_TrackType)
					{
						auto typeData = data.readByte();
						track.type = typeData == 0x01 ? SYNC_video
							: typeData == 0x02 ? SYNC_audio
							: typeData == 0x03 ? SYNC_subtitle
							: SYNC_unknown;

						track.visualStream.writeValue(track.type);
					}
					else if (name == MKV_TrackNumber)
					{
						track.trackId = data.readByte();
					}
					else if (name == MKV_CodecID)
					{
						auto mkvCodecId = String.parseLiteral<SCHEDULER_STACK>(data);
						auto codecId = mkvCodecId == MKV_V_MPEG4_ISO_AVC ? SYNC_h264 :
							mkvCodecId == MKV_A_VORBIS ? SYNC_vorbis :
							mkvCodecId == MKV_A_OPUS ? SYNC_opus : SYNC_unknown;

						LogInfo("Coded ID = 0x%x", codecId.getShortName());
						track.visualStream.writeValue(codecId);
					}
					else if (name == MKV_CodecPrivate)
					{
						track.codecPrivate = CreateBlobHandle<SCHEDULER_STACK>(data);
					}
				}
				else if (master.elementName == MKV_TrackVideo)
				{
					auto& track = mediaParser.mediaTracks.last();
					if (name == MKV_VideoPixelWidth)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto videoSize = value == 1920 ? MEDIA_1080p
							: value == 4096 ? MEDIA_4k
							: value == 1280 ? MEDIA_720p
							: value == 720 ? MEDIA_480p
							: SYNC_unknown;

						track.visualStream.writeValue(videoSize);
					}
					if (name == MKV_VideoPixelHeight)
					{
					}
				}
				else if (master.elementName == MKV_TrackAudio)
				{
					auto& track = mediaParser.mediaTracks.last();
					if (name == MKV_AudioSamplingFreq)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto frequency = value == 48000 ? MEDIA_48000hz
							: value == 96000 ? MEDIA_96000hz
							: value == 19200 ? MEDIA_192000hz
							: value == 22500 ? MEDIA_22500hz
							: SYNC_unknown;

						track.visualStream.writeValue(frequency);
					}
					else if (name == MKV_AudioChannels)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto channels = value == 6 ? MEDIA_5_1
							: value == 1 ? MEDIA_mono
							: value == 2 ? MEDIA_stereo
							: SYNC_unknown;

						ASSERT(channels != SYNC_unknown);
						track.visualStream.writeValue(channels);
					}
					else if (name == MKV_AudioBitDepth)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto bitDepth = value == 32 ? MEDIA_32bit
							: value == 24 ? MEDIA_24bit
							: value == 16 ? MEDIA_16bit
							: value == 8 ? MEDIA_8bit
							: SYNC_unknown;

						ASSERT(bitDepth != SYNC_unknown);
						track.visualStream.writeValue(bitDepth);
					}
				}

			}
		}, mediaParser, master);
}

void ImportMkvFile(MEDIA_PARSER& mediaParser, USTRING filename)
{
	auto status = STATUS_SUCCESS;
	do
	{
		FILE_READER fileReader;

		mediaParser.clear();
		mediaParser.timestamp = GetStateOsTime();

		mediaParser.metadataStream.writeSpan(VSPAN::SECTION);

		status = fileReader.open(filename);
		if (!NT_SUCCESS(status))
			break;

		//auto& tokenStream = StackAlloc<STREAM_BUILDER<TOKEN, SCHEDULER_STACK, 512>, SCHEDULER_STACK>();
		auto masterElement = MKV_MASTER_ELEMENT(NULL_NAME, fileReader, fileReader.fileSize);
		ReadElements(mediaParser, masterElement);

		MergeMetadata(mediaParser);

		fileReader.Close();

		LogInfo("ImportMkvFile: Done with %s", filename.data());
	} while (false);
}

void ImportMediaFiles()
{
	auto path = GetTempStream().writeMany(DATA_DIRECTORY, MEDIA_DIRECTORY);
	auto& mediaParser = StackAlloc<MEDIA_PARSER, SCHEDULER_STACK>();
	ListDirectory(path, NULL_STRING, [](USTRING relativeName, USTRING fullPath, MEDIA_PARSER &mediaParser)
		{
			UNREFERENCED_PARAMETER(relativeName);
			if (String.endsWith(fullPath, ".mkv"))
			{
				ImportMkvFile(mediaParser, fullPath);
				//DeleteFile(fullPath);
			}
		}, mediaParser);
}
