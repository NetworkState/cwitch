#pragma once

constexpr UINT8 __SYNC_LOCAL_MULTICAST[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0D };
constexpr BUFFER SYNC_LOCAL_MULTICAST = __SYNC_LOCAL_MULTICAST;

constexpr UINT8 __SYNC_SUBNET_MULTICAST[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0xCD };
constexpr BUFFER SYNC_SUBNET_MULTICAST = __SYNC_SUBNET_MULTICAST;

//constexpr UINT8 __DISCOVER_MULTICAST[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
constexpr UINT8 __DISCOVER_MULTICAST[] = { 0x00, 0x15, 0x5d, 0xb3, 0xb8, 0x00 };
constexpr BUFFER DISCOVER_MULTICAST = __DISCOVER_MULTICAST;

constexpr UINT32 ETHERNET_FRAME_SIZE = 1514;
constexpr UINT32 ETHERNET_MIN_FRAME_SIZE = 60;

struct ADAPTER_INFO
{
	NDIS_HANDLE adapterHandle;
	MACADDRESS macAddress;
	NDIS_STRING adapterName;
	ULONG mtu;
	bool isPhysical;
	NDIS_MEDIUM mediaType;
	ULONG64 txLinkSpeed;
	ULONG64 rxLinkSpeed;
	bool isConnected;

	KEVENT oidEvent;
	NTSTATUS oidStatus;

	bool match(BUFFER address) const
	{
		auto result = RtlCompareMemory(address.data(), macAddress, MAC_ADDRESS_LENGTH) == MAC_ADDRESS_LENGTH;
		return result;
	}
};

constexpr UINT16 ETHERTYPE_SYNC = 0x9999;
constexpr UINT16 ETHERTYPE_DISCOVER = 0x8888;

extern const ADAPTER_INFO& FindAdapter(TOKEN macAddress);
extern STREAM_READER<const ADAPTER_INFO> GetAdapterTable();
extern void SendToAdapter(const ADAPTER_INFO& adapter, BYTESTREAM& dataStream);

BYTESTREAM& AllocateAdapterBuffer();
void FreeAdapterBuffer(BYTESTREAM& dataStream);

extern void OnAdapterReceive(ADAPTER_INFO& adapterInfo, PNET_BUFFER_LIST recvNBLChain, ULONG flags);
