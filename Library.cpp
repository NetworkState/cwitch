// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#include "pch.h"
#include "Types.h"

UINT8 Base64Index[128];
CNG_ALGORITHMS Algorithms;
HMAC256 Hmac;
STRINGOPS String;
RANDOM Random;
AES_OPS AES;
HASHSHA1 HashSha1;
HASH256 HashSha256;
HTTP_OPS Http;
SDP_OPS Sdp;

extern void NameInitialize();
extern void ParserInitialize();

PVOID KernelAlloc(UINT32 size)
{
	auto address = (PUINT8)ExAllocatePoolWithTag(NonPagedPoolNx, size, POOL_TAG);
	ASSERT(address); // panic time
	RtlZeroMemory(address, size);
	return address;
}

static const UINT32 kCrc32Polynomial = 0xEDB88320;
static UINT32 kCrc32Table[256] = { 0 };

static void InitCrc32Table() 
{
	for (UINT32 i = 0; i < ARRAYSIZE(kCrc32Table); ++i) 
	{
		UINT32 c = i;
		for (size_t j = 0; j < 8; ++j) {
			if (c & 1) {
				c = kCrc32Polynomial ^ (c >> 1);
			}
			else {
				c >>= 1;
			}
		}
		kCrc32Table[i] = c;
	}
}

UINT32 UpdateCrc32(UINT32 start, const void* buf, size_t len) 
{
	UINT32 c = start ^ 0xFFFFFFFF;
	const UINT8* u = static_cast<const UINT8*>(buf);
	for (size_t i = 0; i < len; ++i) {
		c = kCrc32Table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
	}
	return c ^ 0xFFFFFFFF;
}

GLOBAL_STACK* GlobalStackPtr;

GLOBAL_STACK& GlobalStack()
{
	return *GlobalStackPtr;
}

THREAD_STACK* ThreadStack;

template<>
GLOBAL_STACK& GetCurrentStack<GLOBAL_STACK>()
{
	return GlobalStack();
}

template<>
THREAD_STACK& GetCurrentStack<THREAD_STACK>()
{
	return *ThreadStack;
}

constexpr USTRING SystemRoot = "\\SystemRoot";

template <typename STREAM>
USTRING GetSymbolicLink(USTRING linkname, STREAM&& outStream)
{
	USTRING result;

	NTSTATUS			status;
	OBJECT_ATTRIBUTES	oa;
	UNICODE_STRING		symbolicLink{ 0, 0, nullptr };
	HANDLE				linkHandle;
	ULONG				symbolicLinkLength;

	//auto unicodeName = ToUnicodeString(linkname);
	//InitializeObjectAttributes(&oa, &unicodeName, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, ToObjectAttributes(linkname));
	if (STATUS_SUCCESS == status)
	{
		status = ZwQuerySymbolicLinkObject(linkHandle, &symbolicLink, &symbolicLinkLength);

		if (STATUS_BUFFER_TOO_SMALL == status && symbolicLinkLength > 0)
		{
			symbolicLink.Buffer = (PWCH) ExAllocatePool(NonPagedPoolNx, symbolicLinkLength);
			symbolicLink.Length = 0;
			symbolicLink.MaximumLength = (USHORT)symbolicLinkLength;

			status = ZwQuerySymbolicLinkObject(linkHandle, &symbolicLink, &symbolicLinkLength);
			if (STATUS_SUCCESS == status)
			{
				result = FromUnicodeString(symbolicLink, outStream);
			}
			ExFreePool(symbolicLink.Buffer);
			ZwClose(linkHandle);
		}
	}
	return result;
}

const WSK_CLIENT_DISPATCH WskClientDispatch = {
	MAKE_WSK_VERSION(1, 0),
	0,
	NULL
};

WSK_INFO WskInfo;

const WSK_PROVIDER_DISPATCH& GetProviderDispatch()
{
	return *WskInfo.providerInterface;
}

NTSTATUS InitializeWsk()
{
	auto status = STATUS_SUCCESS;
	do
	{
		ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

		RtlZeroMemory(&WskInfo, sizeof(WskInfo));

		WSK_CLIENT_NPI clientNpi;

		clientNpi.ClientContext = &WskInfo;
		clientNpi.Dispatch = &WskClientDispatch;

		status = WskRegister(&clientNpi, &WskInfo.registration);
		VERIFY_STATUS;

		WSK_PROVIDER_NPI wskInterface;
		NdisZeroMemory(&wskInterface, sizeof(wskInterface));

		status = WskCaptureProviderNPI(&WskInfo.registration, WSK_INFINITE_WAIT, &wskInterface);
		VERIFY_STATUS;

		WskInfo.providerContext = wskInterface.Client;
		WskInfo.providerInterface = wskInterface.Dispatch;

		WSK_EVENT_CALLBACK_CONTROL callbackControl{ (PNPIID)& NPI_WSK_INTERFACE_ID, WSK_EVENT_ACCEPT | WSK_EVENT_RECEIVE | WSK_EVENT_DISCONNECT | WSK_EVENT_RECEIVE_FROM | WSK_EVENT_SEND_BACKLOG };
		status = wskInterface.Dispatch->WskControlClient(wskInterface.Client, WSK_SET_STATIC_EVENT_CALLBACKS, sizeof(callbackControl), &callbackControl, 0, NULL, NULL, NULL);
		VERIFY_STATUS;


	} while (false);

	return status;
}

CLOCK SystemClock;

//void SetStateOsTimeOrigin()
//{
//	TIME_FIELDS time;
//	NdisZeroMemory(&time, sizeof(time));
//
//	time.Year = 2012;
//	time.Month = 12;
//	time.Day = 12;
//	time.Hour = 12;
//	time.Minute = 12;
//	time.Second = 12;
//	time.Milliseconds = 12;
//
//	auto ret = RtlTimeFieldsToTime(&time, (PLARGE_INTEGER)&StateOsTimeOrigin);
//	ASSERT(ret == TRUE);
//}
//
//void SetMkvTimeOrigin()
//{
//	TIME_FIELDS time;
//	NdisZeroMemory(&time, sizeof(time));
//
//	time.Year = 2001;
//	time.Month = 1;
//	time.Day = 1;
//
//	auto ret = RtlTimeFieldsToTime(&time, (PLARGE_INTEGER)&MkvTimeOrigin);
//	ASSERT(ret == TRUE);
//}
//
//void SetUnixTimeOrigin()
//{
//	TIME_FIELDS time;
//	NdisZeroMemory(&time, sizeof(time));
//
//	time.Year = 1970;
//	time.Month = 1;
//	time.Day = 1;
//
//	auto ret = RtlTimeFieldsToTime(&time, (PLARGE_INTEGER)&UnixTimeOrigin);
//	ASSERT(ret == TRUE);
//}

UINT64 GetStateOsTime()
{
	LARGE_INTEGER currentTime;
	KeQuerySystemTimePrecise(&currentTime);

	return (currentTime.QuadPart - StateOsTimeOrigin) / SYSTEM_TIME_TO_MS;
}

static GUID GetMachineId()
{
	GUID result = NULL_GUID;
	RTL_QUERY_REGISTRY_TABLE query[2];
	WCHAR* regPath = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography";

	RtlZeroMemory(query, sizeof(RTL_QUERY_REGISTRY_TABLE) * 2);

	UINT16 buffer[40];
	UNICODE_STRING data;
	data.Buffer = buffer;
	data.MaximumLength = sizeof(buffer);
	data.Length = 0;

	query[0].Name = L"MachineGuid";
	query[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	query[0].EntryContext = &data;

	auto status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, regPath, query, NULL, NULL);
	if (NT_SUCCESS(status))
	{
		LOCAL_STREAM<40> charStream;
		result = String.parseGuid(charStream.writeString(data));
	}
	return result;
}

SYSTEM_INFO *SystemInfoPtr;
SYSTEM_INFO& SystemInfo() { return *SystemInfoPtr; }

void PopulateSystemInfo()
{
	auto&systemInfo = StackAlloc<SYSTEM_INFO, GLOBAL_STACK>();
	SystemInfoPtr = &systemInfo;

	RtlZeroMemory(SystemInfoPtr, sizeof(SYSTEM_INFO));

	systemInfo.systemId = GetMachineId();
	systemInfo.memorySize = (UINT64)SharedUserData->NumberOfPhysicalPages * PAGE_SIZE;
	systemInfo.processorCount = SharedUserData->ActiveProcessorCount;
	systemInfo.hostVersion = SharedUserData->NtMajorVersion << 16 | SharedUserData->NtMinorVersion;
	systemInfo.version = CreateName(__DATE__ " " __TIME__);
	systemInfo.buildNumber = 0;
}

#define MIN3(x,y,z)  ((y) <= (z) ? \
                         ((x) <= (y) ? (x) : (y)) \
                     : \
                         ((x) <= (z) ? (x) : (z)))

#define MAX3(x,y,z)  ((y) >= (z) ? \
                         ((x) >= (y) ? (x) : (y)) \
                     : \
                         ((x) >= (z) ? (x) : (z)))

HSV RGBtoHSV(RGB rgb)
{
	UINT8 hue, sat, val;
	//HSV hsv;
	//hsv.flag = 0;
	unsigned char rgb_min, rgb_max;
	rgb_min = MIN3(rgb.r, rgb.g, rgb.b);
	rgb_max = MAX3(rgb.r, rgb.g, rgb.b);
	val = (rgb_max + rgb_min) / 2;
	if (rgb_max == 0) {
		hue = sat = 0;
		return HSV(hue, sat, val);
	}
	sat = 255 * long(rgb_max - rgb_min) / rgb_max;
	if (sat == 0) {
		hue = 0;
		return HSV(hue, sat, val);
	}
	/* Compute hue */
	if (rgb_max == rgb.r) {
		hue = 0 + 43 * (rgb.g - rgb.b) / (rgb_max - rgb_min);
	}
	else if (rgb_max == rgb.g) {
		hue = 85 + 43 * (rgb.b - rgb.r) / (rgb_max - rgb_min);
	}
	else /* rgb_max == rgb.b */ {
		hue = 171 + 43 * (rgb.r - rgb.g) / (rgb_max - rgb_min);
	}
	return HSV(hue, sat, val);
}

PROCESSOR_INFO ProcessorInfo[MAX_PROCESSOR_COUNT];

SYSTEM_SCHEDULER* SystemSchedulerPtr;

SYSTEM_SCHEDULER& SystemScheduler()
{
	return *SystemSchedulerPtr;
}

NTSTATUS CreateSystemScheduler()
{
	SystemSchedulerPtr = &KernelAlloc<SYSTEM_SCHEDULER>();
	SystemSchedulerPtr->initialize();

	return STATUS_SUCCESS;
}

NTSTATUS InitializeLibrary()
{
	KEVENT syncEvent;
	KeInitializeEvent(&syncEvent, SynchronizationEvent, FALSE);

	CreateSystemScheduler();
	SystemScheduler().runTask(STASK([](PVOID eventPtr, NTSTATUS, STASK_PARAMS)
		{
			RtlZeroMemory(ProcessorInfo, sizeof(ProcessorInfo));

			SystemClock.start();

			InitCrc32Table();

			LogInfo("State OS Time: %lld", GetStateOsTime());

			GlobalStackPtr = &KernelAlloc<GLOBAL_STACK>();
			ThreadStack = &KernelAlloc<THREAD_STACK>();

			InitializeStack(*GlobalStackPtr, 64 * 1024 * 1024, 0);

			for (UINT32 i = 0; i < Base64Chars.length(); i++)
			{
				Base64Index[Base64Chars.at(i)] = (UINT8)i;
			}

			NameInitialize();

			PopulateSystemInfo();
			Algorithms.initialize();

			UINT8 secret[16];
			Random.generateRandom(secret, sizeof(secret));
			Hmac.setSecret(BUFFER(secret, sizeof(secret)));

			ParserInitialize();

			InitializeWsk();

			KeSetEvent((PKEVENT)eventPtr, 0, FALSE);
		}, (PVOID)&syncEvent));

	KeWaitForSingleObject(&syncEvent, Executive, KernelMode, FALSE, nullptr);
	return STATUS_SUCCESS;
}
