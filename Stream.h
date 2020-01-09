// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

extern UINT32 GetNameLength(TOKEN handle);

constexpr bool isHexChar(UINT8 c) {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

constexpr bool isGuidChar(UINT8 c) {
	return isHexChar(c) || c == '-';
}

constexpr bool isMacAddressChar(UINT8 c) {
	return isHexChar(c) || c == ':';
}

template<typename T>
const T &StreamRead(const UINT8* address, UINT32 &offset)
{
	offset += sizeof(T);
	return *(T *)address;
}

template <typename T>
T StreamReadBE(const UINT8* address, UINT32 &bytesRead);

template <typename T>
T StreamReadEnumBE(const UINT8 *address, UINT32 &bytesRead)
{
	if constexpr (sizeof(T) == 1)
	{
		return (T)StreamReadBE<UINT8>(address, bytesRead);
	}
	else if constexpr (sizeof(T) == 2)
	{
		return (T)StreamReadBE<UINT16>(address, bytesRead);
	}
	else if constexpr (sizeof(T) == 4)
	{
		return (T)StreamReadBE<UINT32>(address, bytesRead);
	}
	else DBGBREAK();
}

UINT32 strLen(const UINT8 *string);
UINT32 strLen(const char *string);

template <typename T>
struct STREAM_READER;

template <typename T>
struct STREAM_ITER
{
	STREAM_READER<T> arr;
	int index;

	STREAM_ITER(STREAM_READER<T> arr, int index) : arr(arr), index(index) {};

	T& operator *()
	{
		return arr.at(this->index);
	}

	auto operator ++()
	{
		this->index++;
		return *this;
	}

	bool operator != (STREAM_ITER &other)
	{
		return this->index != other.index;
	}
};

constexpr UINT32 stringLen(const char* input)
{
	for (UINT32 i = 0; i < 2048; i++)
	{
		if (input[i] == 0)
			return i;
	}
	return 0;
}

constexpr UINT8 ToHexNumber(UINT8 c)
{
	UINT8 hex = 0;
	if (c >= '0' && c <= '9')
		hex = c - '0';
	else if (c >= 'a' && c <= 'f')
		hex = 10 + (c - 'a');
	else if (c >= 'A' && c <= 'F')
		hex = 10 + (c - 'A');
	else
		DBGBREAK();

	return hex;
}

template <typename T, typename ST, UINT32 SZ>
struct STREAM_BUILDER;

template <typename T>
struct STREAM_READER
{

	UINT32 _start;
	UINT32 _end;
	const void * _data;

	STREAM_READER(const T *array, UINT32 length) : _data(array), _end(length), _start(0) {}

	constexpr STREAM_READER(const char* array) : _data(array), _end(stringLen(array)), _start(0) {}
	STREAM_READER(const char* array, UINT32 length) : _data(array), _end(length), _start(0) {}

	template <UINT32 SZ>
	constexpr STREAM_READER(const T(&inData)[SZ]) : _data(&inData), _start(0), _end(SZ) {}

	template <UINT32 SZ>
	STREAM_READER(const char(&inData)[SZ]) : _data(&inData), _start(0), _end(SZ) 
	{
		DBGBREAK(); // shouldn't happen!
	}

	STREAM_READER(const T* array, UINT32 offset, UINT32 end) : _data(array), _end(end), _start(offset) {}

	constexpr STREAM_READER() : _data(nullptr), _start(0), _end(0) {}

	UINT32 getPosition() { return _start; }
	UINT32 diffPosition(UINT32 old) { ASSERT(old <= _start); return _start - old; }

	STREAM_READER<T>& rewind()
	{
		this->_start = 0;
		return *this;
	}

	constexpr UINT32 length() const { return this->_data != nullptr ? this->_end - this->_start : 0; }

	STREAM_ITER<T> begin()
	{
		return STREAM_ITER<T>(*this, 0);
	}

	STREAM_ITER<T> end()
	{
		return STREAM_ITER<T>(*this, length());
	}

	T *data(INT32 offset = 0) const
	{
		auto addr = (T*)_data;
		return addr + _start + offset;
	}

	const char* toString(UINT32 offset = 0) const
	{
		auto address = (const T*)_data;
		ASSERT(_start <= _end);
		auto bufEnd = address + _end;
		ASSERT(*bufEnd == 0);
		return (const char*)(address + _start + offset);
	}

	T& shift(INT32 count = 1)
	{
		ASSERT(_start + count <= _end);
		T& value = *this->data();
		this->_start += count;
		return value;
	}

	INT32 getIndex(T& entry)
	{
		auto startAddr = (PUINT8)data();
		auto endAddr = (PUINT8)last();
		auto thisAddr = &entry;

		if (thisAddr >= startAddr && thisAddr <= endAddr)
		{
			return (thisAddr - startAddr) / sizeof(T);
		}
		return -1;
	}

	T& at(INT32 index) const
	{
		return (T&)*data(index);
	}

	T& peek() const
	{
		return at(0);
	}

	T& operator [] (INT32 index) const
	{
		return at(index);
	}

	STREAM_READER<T> readBytes(UINT32 count)
	{
		ASSERT(_start <= _end);
		auto address = this->data();
		this->shift(count);
		return { address, count };
	}

	GUID readGuid()
	{
		ASSERT(length() >= sizeof(GUID));

		GUID result;
		result.Data1 = readBE<UINT32>();
		result.Data2 = readBE<UINT16>();
		result.Data3 = readBE<UINT16>();

		RtlCopyMemory(result.Data4, readBytes(8).data(), 8);

		return result;
	}

	UINT8 readHexChar()
	{
		UINT8 number = 0;
		if (length() >= 2)
		{
			auto first = at(0);
			auto second = at(1);

			if (isHexChar(first) && isHexChar(second))
			{
				shift(2);

				number = ToHexNumber(first) << 4;
				number |= ToHexNumber(second);
			}
			else DBGBREAK();
		}
		else DBGBREAK();
		return number;
	}

	STREAM_READER<T> shrink(UINT32 count = 1)
	{
		ASSERT((this->_end - count) >= this->_start);

		auto address = this->data(this->length() - count);
		this->_end -= count;

		return { address, count };
	}

	void expand(UINT32 count)
	{
		this->_end += count;
	}

	T& last()
	{
		return at(length() - 1);
		//auto address = (const T*)_data;
		//return address[_end - 1]; // ((T * _data) + this->_end - 1);
	}

	template <typename F, typename ... Args>
	void forEach(F func, Args && ... args) const
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			auto value = this->data(i);
			auto toContinue = func(*value, args ...);
			if (toContinue == false)
				break;
		}
	}

	template <typename F, typename ... Args>
	void indexedForEach(F func, Args && ... args) const
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			auto value = this->data(i);
			auto toContinue = func(*value, i, args ...);
			if (toContinue == false)
				break;
		}
	}

	template<typename V>
	INT32 findIndex(V&& arg) const
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			if (at(i) == arg)
			{
				return (INT32)i;
			}
		}
		return -1;
	}

	template<typename V>
	INT32 findIndexReverse(V&& arg) const
	{
		for (UINT32 i = length(); i > 0; i--)
		{
			if (at(i - 1) == arg)
			{
				return (INT32)(i - 1);
			}
		}
		return -1;
	}

	template <typename ... Args>
	T& find(Args && ... args) const
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			if (at(i).match(args ...))
			{
				return at(i);
			}
		}
		return NullRef<T>();
	}

	template<typename V>
	bool exists(V&& arg) const
	{
		return findIndex(arg) != -1;
	}

	template <typename V>
	const V& read()
	{
		ASSERT(_start <= _end);
		return StreamRead<V>(this->data(), this->_start);
	}

	const UINT8 readChar()
	{
		ASSERT(_start <= _end);
		return StreamRead<UINT8>(this->data(), this->_start);
	}

	const UINT8 readByte()
	{
		ASSERT(_start <= _end);
		return readChar();
	}

	template <typename V>
	V readBE()
	{
		ASSERT(_start <= _end);
		auto value = StreamReadBE<V>(this->data(), _start);
		return value;
	}

	UINT64 readUIntBE(UINT32 length)
	{
		UINT64 value = 0;
		ASSERT(this->length() >= length);
		for (UINT32 i = 0; i < length; i++)
		{
			value = (value << 8) | readByte();
		}
		return value;
	}

	UINT64 readVInt()
	{
		auto lengthByte = readByte();
		if (lengthByte == 0)
			return 0;

		UINT64 value;
		UINT32 valueLength = 0;
		for (int i = 0; i < 8; i++)
		{
			UINT8 pattern = 0x80 >> i;
			if (lengthByte & pattern)
			{
				value = lengthByte & ~pattern;
				valueLength = i;
				value <<= (valueLength * 8);
				break;
			}
		}

		for (int i = valueLength - 1; i >= 0; i--)
		{
			UINT64 byte = readByte();
			value |= (byte << (i * 8));
		}
		return value;
	}

	template <typename V>
	V readEnumBE()
	{
		ASSERT(_start <= _end);
		auto value = StreamReadEnumBE<V>(this->data(), _start);
		return value;
	}

	UINT32 copyTo(T * outBuffer, ULONG bufSize)
	{
		ASSERT(_start <= _end);
		auto transferLength = min(this->length(), bufSize);
		RtlCopyMemory((void *)outBuffer, this->data(), transferLength * sizeof(T));
		this->_start += transferLength;
		return transferLength;
	}

	void readString(char *outBuffer, ULONG bufSize)
	{
		ASSERT(_start <= _end);
		auto transferLength = this->readBytes(outBuffer, bufSize);
		if (transferLength < bufSize)
			outBuffer[transferLength] = 0;
	}

	STREAM_READER<T> toBuffer(UINT32 offset, UINT32 length)
	{
		return STREAM_READER<T>((T*)_data, _start + offset, _start + offset + length);
	}

	STREAM_READER<T> clone() const
	{
		return STREAM_READER<T>((T*)_data, _start, _end);
	}
	bool atEnd() const
	{
		return this->_start == this->_end;
	}

	constexpr explicit operator bool() const
	{
		return this->_data == nullptr || this->_start == this->_end ? false : true;
	}

	bool isEmpty() const
	{
		return this->length() == 0;
	}

	STREAM_READER<T> rebase()
	{
		return STREAM_READER<T>(data(), length());
	}

	bool operator == (STREAM_READER<T> other) const
	{
		if (this->length() == other.length())
		{
			if (RtlCompareMemory(this->data(), other.data(), this->length()) == this->length())
			{
				return true;
			}
		}
		return false;
	}

	bool operator != (STREAM_READER<T> other) const
	{
		return !(*this == other);
	}

	template <typename STACK>
	VISUAL_TOKEN readVisualToken()
	{
		if (length() == 0)
			return VISUAL_TOKEN();

		TOKENTYPE tokenType = TOKENTYPE::ERROR;;
		VSIZE size = VSIZE::DEFAULT;
		VSPAN span = VSPAN::DEFAULT;

		auto dataLength = (UINT32)readVInt();
		if (dataLength == 0)
		{
			DBGBREAK();
			ASSERT(_end == 60); // padding
			return VISUAL_TOKEN();
		}

		UINT8 flags = dataLength & 0x03;
		dataLength >>= 2;

		tokenType = (TOKENTYPE)readByte();
		if (flags & VTOKEN_FLAG_SIZE)
		{
			size = (VSIZE)readByte();
		}
		if (flags & VTOKEN_FLAG_SPAN)
		{
			span = (VSPAN)readByte();
		}

		auto token = Null;

		if (tokenType == TOKENTYPE::NUMBER)
		{
			token = CreateNumberHandle<STACK>(dataLength);
		}
		else if (tokenType == TOKENTYPE::CONSTANT)
		{
			token = TOKEN(TOKENTYPE::CONSTANT, dataLength);
		}
		else
		{
			auto data = readBytes(dataLength);
			if (tokenType == TOKENTYPE::BLOB_GUID)
			{
				auto guid = data.readGuid();
				token = CreateGuidHandle<STACK>(guid);
			}
			else if (tokenType == TOKENTYPE::BLOB)
			{
				token = FindBlobHandle<STACK>(TOKENTYPE::BLOB, data);
				if (!token)
				{
					token = CreateBlobHandle<STACK>(data, TOKENTYPE::BLOB);
				}
			}
			else if (tokenType == TOKENTYPE::NAME)
			{
				token = CreateCustomName<STACK>(data);
			}
			else if (tokenType == TOKENTYPE::LITERAL)
			{
				token = String.parseLiteral<STACK>(data);
			}
			else if (tokenType == TOKENTYPE::BLOB_MACADDRESS)
			{
				token = CreateMacAddressHandle<STACK>(data);
			}
			else if (tokenType == TOKENTYPE::OBJECT)
			{
				ASSERT(dataLength == 0);
				token = Null;
			}
			else DBGBREAK();
		}

		return VISUAL_TOKEN(token, size, span);
	}

	char *print()
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			DbgPrint("%c", at(i));
		}
		return (char*)data();
	}
};

using USTRING = STREAM_READER<const UINT8>;
using BUFFER = STREAM_READER<const UINT8>;

constexpr USTRING HexChars = "0123456789ABCDEF";
constexpr USTRING CRLF = "\r\n";
constexpr USTRING ESC_CRLF = "\\r\\n";
constexpr USTRING CRLF_CRLF = "\r\n\r\n";
constexpr USTRING WHITESPACE = " \t\r\n";

constexpr UINT8 ZeroBytesData[128] = { 0 };
constexpr BUFFER ZeroBytes = ZeroBytesData;

constexpr USTRING Spaces = "                                                                                               ";;

template<typename T> 
UINT32 StreamWrite(UINT8* address, T value);

template <typename T>
UINT32 StreamWriteString(T* address, USTRING value, UINT32 length);

template<typename T>
UINT32 StreamWriteBE(UINT8 *address, T value);

template <typename T>
UINT32 StreamWriteEnumBE(UINT8 *address, T value)
{
	auto size = sizeof(T);
	if (size == 1)
	{
		return StreamWriteBE(address, (UINT8)value);
	}
	else if (size == 2)
	{
		return StreamWriteBE(address, (UINT16)value);
	}
	else if (size == 4)
	{
		return StreamWriteBE(address, (UINT32)value);
	}
	else
	{
		DBGBREAK();
		return 0;
	}
}

template <typename T>
UINT32 StreamWriteEnum(UINT8* address, T value)
{
	auto size = sizeof(T);
	if (size == 1)
	{
		return StreamWrite(address, (UINT8)value);
	}
	else if (size == 2)
	{
		return StreamWrite(address, (UINT16)value);
	}
	else if (size == 4)
	{
		return StreamWrite(address, (UINT32)value);
	}
	else
	{
		DBGBREAK();
		return 0;
	}
}

void StreamWriteBytes(PUINT8 destination, const UINT8 * source, ULONG bytes);
int NameToString(TOKEN handle, UINT8 *stringBuffer);
extern PUNICODE_STRING ToUnicodeString(USTRING input);
extern POBJECT_ATTRIBUTES ToObjectAttributes(USTRING path);

constexpr BUFFER Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

extern UINT8 Base64Index[128];

constexpr UINT32 DYNAMIC_MEMORY_MASK = 0x80000000;
//extern BUFFER GetBlobHandleValue(TOKEN handle);
extern GUID GetGuidHandleValue(TOKEN handle);

template <typename STACK>
USTRING GetLiteral(TOKEN name)
{
	USTRING result;
	if (name.getFullType() == TOKENTYPE::LITERAL_LARGE)
	{
		result = GetCurrentStack<STACK>().literals.at(name.getValue() & 0xFFFF);
	}
	else
	{
		name = TOKEN(TOKENTYPE::NAME | name.getMinorType(), name.getValue());
		result = NameToString(name);
	}
	return result;
}

template <typename T, typename ST, UINT32 SZ>
struct STREAM_BUILDER
{
	struct DYNAMIC_CONTEXT
	{
		PUINT8 address;
		UINT32 size;
	};

	UINT32 __count = 0;
	UINT8 staticData[max((SZ * sizeof(T)), (sizeof(DYNAMIC_CONTEXT)))];

	STREAM_BUILDER()
	{
		RtlZeroMemory(staticData, sizeof(staticData));
		this->__count = 0;
	}

	STREAM_BUILDER(STREAM_BUILDER& other) = delete;

	bool isStatic() const { return (__count & DYNAMIC_MEMORY_MASK) == 0; }
	bool isDynamic() const { return (__count & DYNAMIC_MEMORY_MASK) != 0; }
	void setDynamic() { __count |= DYNAMIC_MEMORY_MASK; }
	void setStatic() { __count &= ~DYNAMIC_MEMORY_MASK; }

	auto dynamic() const { return (DYNAMIC_CONTEXT*)staticData; }

	UINT32 count() const
	{ 
		return this->__count & ~DYNAMIC_MEMORY_MASK; 
	}
	
	UINT32 size() const
	{ 
		return isStatic() ? SZ : dynamic()->size; 
	}

	void adjustCount(int by) { this->__count += by; }

	bool adjustCount(UINT32 start, int by)
	{
		UINT32 oldCount = (__count & DYNAMIC_MEMORY_MASK) | (start & ~DYNAMIC_MEMORY_MASK);
		UINT32 newCount = oldCount + by;
		auto result = InterlockedCompareExchange((LONG*)& __count, (LONG)newCount, (LONG)oldCount) == (LONG)oldCount;
		if (result == false)
			DBGBREAK();

		return result;
	}

	void setBuffer(PUINT8 address, ULONG size)
	{
		setDynamic();
		dynamic()->size = size;
		dynamic()->address = address;
	}

	STREAM_BUILDER(T *address, UINT32 size)
	{
		setBuffer((PUINT8)address, size);
	}

	T* address(UINT32 index = 0) const
	{
		ASSERT(index <= count());
		auto addr = (T*)(isStatic() ? staticData : dynamic()->address);
		return addr + (index & ~DYNAMIC_MEMORY_MASK);
	}

	UINT32 reserve(UINT32 reserveCount = 1)
	{
		ASSERT(size() > 0);

		auto newCapacity = count() + reserveCount;
		if (newCapacity > size())
		{
			auto oldAddress = address();
			auto oldSize = size();

			auto newSize = oldSize * 2;
			while (newCapacity > newSize)
				newSize *= 2;

			auto newAddress = (PUINT8)StackAlloc<ST>(newSize * sizeof(T));
			RtlCopyMemory(newAddress, oldAddress, oldSize * sizeof(T));
			setBuffer(newAddress, newSize);
		}
		return count();
	}

	UINT32 availableBytes()
	{
		return size() - count();
	}

	T *end() { return address(count()); }

	template<typename ... Args>
	T &append(Args && ... args)
	{
		auto oldCount = this->reserve();
		auto addr = end();
		new (addr) T(args ...);
		adjustCount(oldCount, 1);
		return *addr;
	}
	
	T &at(UINT32 offset) const
	{
		return *this->address(offset);
	}

	T& last(UINT32 offset = 0) const
	{
		ASSERT(this->count() - offset > 0);
		ASSERT(this->count() > 0);
		return this->at(this->count() - 1 - offset);
	}

	void write(const T* data, ULONG length)
	{
		auto oldCount = this->reserve(length);
		RtlCopyMemory(this->end(), data, length);
		adjustCount(oldCount, length);
	}

	void writeByte(UINT8 value)
	{
		auto oldCount = this->reserve();
		*end() = value;
		adjustCount(oldCount, 1);
	}

	STREAM_READER<const T> writeString(USTRING input)
	{
		return writeString(input, input.length());
	}

	STREAM_READER<const T> writeString(USTRING input, UINT32 length)
	{
		auto position = getPosition();

		auto oldCount = reserve(length + 1);
		auto added = StreamWriteString(this->end(), input, length);
		adjustCount(oldCount, added);
		*this->end() = 0;

		return position.toBuffer();
	}

	STREAM_READER<const T> writeString(UINT16 *data, UINT32 length)
	{
		auto position = getPosition();

		auto oldCount = reserve(length + 1);
		auto address = this->end();
		for (UINT32 i = 0; i < length; i++)
		{
			address[i] = (T)data[i];
		}
		adjustCount(oldCount, length);
		*this->end() = 0;

		return position.toBuffer();
	}

	STREAM_READER<const T> writeString(UNICODE_STRING& unicodeString)
	{
		return writeString(unicodeString.Buffer, unicodeString.Length / sizeof(UINT16));
	}

	STREAM_READER<const T> writeString(UINT64 number, UINT32 base = 10, UINT32 width = 0)
	{
		auto start = count();

		if (number == 0)
		{
			writeByte('0');
		}
		else
		{
			reserve(20);
			for (UINT32 i = 0; i < 20 && number != 0; i++) // 20 digits max
			{
				insert(start);
				writeAt(start, HexChars[number % base]);
				number /= base;
			}
		}

		UINT32 charsWritten = count() - start;
		if (width > 0 && (charsWritten < width))
		{
			width -= charsWritten;
			for (UINT32 i = 0; i < width; i++)
			{
				insert(start);
				writeAt(start, (UINT8)'0');
			}
		}

		*this->end() = 0;
		return toBuffer(start);
	}
	
	STREAM_READER<const T> writeString(UINT32 number, UINT32 base = 10)
	{
		return writeString((UINT64)number, base);
	}

	STREAM_READER<const T> writeString(INT64 number, UINT32 base = 10)
	{
		auto position = count();

		if (number == 0)
		{
			writeByte('0');
		}
		else
		{
			reserve(20);
			if (number < 0)
			{
				writeChar('-');
				number *= -1;
			}
			writeString((UINT64)number, base);
		}
		*this->end() = 0;
		return toBuffer(position);
	}

	STREAM_READER<const T> writeString(INT32 number, UINT32 base = 10)
	{
		return writeString((INT64)number, base);
	}

	template <typename V>
	void writeInt(V value)
	{
		auto oldCount = reserve(sizeof(V));
		auto added = StreamWrite(this->end(), value);
		adjustCount(oldCount, added);
	}

	void writeVInt(UINT64 value)
	{
		if (value <= 0x7F) // 1
		{
			writeByte(0x80 | (UINT8)value);
		}
		else if (value <= 0x3FFF) // 01
		{
			writeByte(0x40 | (UINT8)(value >> 8));
			writeByte((UINT8)(value & 0xFF));
		}
		else if (value <= 0x1FFFFF) // 001
		{
			writeByte(0x20 | (UINT8)(value >> 16));
			writeByte((UINT8)((value & 0xFF00) >> 8));
			writeByte((UINT8)(value & 0xFF));
		}
		else if (value <= 0x0FFFFFFF) // 0001
		{
			writeByte(0x10 | (UINT8)(value >> 24));
			writeByte((UINT8)(value >> 16));
			writeByte((UINT8)(value >> 8));
			writeByte((UINT8)(value));
		}
		else if (value <= 0x07FFFFFFFFFF)
		{
			writeByte(0x08 | (UINT8)(value >> 32));
			writeByte((UINT8)(value >> 24));
			writeByte((UINT8)(value >> 16));
			writeByte((UINT8)(value >> 8));
			writeByte((UINT8)(value));
		}
		else if (value <= 0x03FFFFFFFFFFFF)
		{
			writeByte(0x04 | (UINT8)(value >> 40));
			writeByte((UINT8)(value >> 32));
			writeByte((UINT8)(value >> 24));
			writeByte((UINT8)(value >> 16));
			writeByte((UINT8)(value >> 8));
			writeByte((UINT8)(value));
		}
		else if (value <= 0x01FFFFFFFFFFFFFF)
		{
			writeByte(0x02 | (UINT8)(value >> 48));
			writeByte((UINT8)(value >> 40));
			writeByte((UINT8)(value >> 32));
			writeByte((UINT8)(value >> 24));
			writeByte((UINT8)(value >> 16));
			writeByte((UINT8)(value >> 8));
			writeByte((UINT8)(value));
		}
		else DBGBREAK();
	}

	void writeLengthAt(UINT32 offset)
	{
		LOCAL_STREAM<8> dataStream;
		dataStream.writeVInt(count() - offset);

		insert(offset, dataStream.count());
		RtlCopyMemory(this->address(offset), dataStream.address(), dataStream.count());
	}

	void writeIntBE(UINT64 value, UINT8 byteCount)
	{
		reserve(byteCount);
		for (UINT8 i = byteCount; i > 0; i--)
		{
			auto byte = (UINT8)((value >> ((i - 1) * 8)) & 0xFF);
			writeByte(byte);
		}
	}

	void writeChar(UINT8 c)
	{
		this->writeByte(c);
	}

	BUFFER writeGuid(GUID guid)
	{
		auto offset = getPosition();
		
		auto& subStream = commit(16, STREAM_BUILDER<T, THREAD_STACK, 1>());

		subStream.writeBE<UINT32>(guid.Data1);
		subStream.writeBE<UINT16>(guid.Data2);
		subStream.writeBE<UINT16>(guid.Data3);
		RtlCopyMemory(subStream.end(), guid.Data4, 8);

		return offset.toBuffer();
	}

	STREAM_READER<const T> writeName(TOKEN name)
	{
		ASSERT(name.isString());
		auto nameLength = GetNameLength(name);

		auto oldCount = this->reserve(nameLength + 1);

		auto added = NameToString(name, this->end());
		adjustCount(oldCount, added);
		*this->end() = 0;

		return toBuffer(oldCount);
	}

	void writeString(GUID guid)
	{
		STREAM_BUILDER<UINT8, THREAD_STACK, 16> guidBytes;
		auto buffer = guidBytes.writeGuid(guid);

		auto& subStream = commit(36, STREAM_BUILDER<T, THREAD_STACK, 1>()); // sizeof(GUID) * 2 (2 hex digits), 4 '-'s

		subStream.writeHexString(buffer.readBytes(4));
		subStream.writeString("-");
		subStream.writeHexString(buffer.readBytes(2));
		subStream.writeString("-");
		subStream.writeHexString(buffer.readBytes(2));
		subStream.writeString("-");
		subStream.writeHexString(buffer.readBytes(2));
		subStream.writeString("-");
		subStream.writeHexString(buffer.readBytes(6));
	}

	void writeString(TOKEN handle)
	{
		if (handle.isString())
		{
			writeName(handle);
		}
		else if (handle.isGuid())
		{
			writeString(GetGuidHandleValue(handle));
		}
		else if (handle.isNumber())
		{
			writeString(GetNumberHandleValue(handle));
		}
		else if (handle.isBlob())
		{
			auto blobData = GetBlobData(handle);
			writeHexString(blobData);
		}
		else if (handle == Undefined)
		{
			writeString("undefined");
		}
		else if (handle == True)
		{
			writeString("true");
		}
		else if (handle == False)
		{
			writeString("false");
		}
		else if (handle == Undefined)
		{
			writeString("null");
		}
		else if (handle == Nan)
		{
			writeString("nan");
		}
		else DBGBREAK();
	}

	template <typename ... Args>
	STREAM_READER<const T> writeMany(Args && ... args)
	{
		auto start = this->count();
		int dummy[] = { (this->writeString(args), 0) ... }; dummy;
		return this->toBuffer(start);
	}

	void writeNull()
	{
		reserve();
		*end() = 0;
	}

	UINT32 write(const T& value)
	{
		auto index = this->count();
		auto addr = commit(1);
		RtlCopyMemory(addr, &value, sizeof(T));
		return index;
	}

	void writeAt(UINT32 offset, T value)
	{
		auto addr = this->address(offset);
		new (addr) T(value);
	}

	template <typename V>
	void writeBE(V value)
	{
		auto oldCount = reserve(sizeof(V));
		auto added = StreamWriteBE(this->end(), value);
		adjustCount(oldCount, added);
	}

	void writeUIntBE(UINT32 value, UINT8 byteCount)
	{
		for (UINT8 i = byteCount; i > 0; i--)
		{
			auto byteValue = (UINT8)((value >> (8 * (i - 1))) & 0xFF);
			writeByte(byteValue);
		}
	}

	template <typename V>
	void writeAt(UINT32 offset, V value)
	{
		reserve(sizeof(V));
		StreamWrite(this->address(offset), value);
	}

	template <typename V>
	void writeAtBE(UINT32 offset, V value)
	{
		reserve(sizeof(V));
		StreamWriteBE(this->address(offset), value);
	}

	BUFFER writeBytes(const UINT8* data, UINT32 length)
	{
		BUFFER result;
		while (true)
		{
			auto start = reserve(length);
			RtlCopyMemory(address(start), data, length);

			if (adjustCount(start, length))
			{
				result = BUFFER{ address(start), length };
				break;
			}

			DBGBREAK();
		}
		return result;
	}

	BUFFER writeBytes(STREAM_READER<const UINT8> data, ULONG length)
	{
		return writeBytes(data.data(), length);
	}

	BUFFER writeBytes(STREAM_READER<const UINT8> buffer)
	{
		return writeBytes(buffer.data(), buffer.length());
	}

	T* commit(ULONG length)
	{
		this->reserve(length);
		auto start = this->end();
		adjustCount(length);
		return start;
	}

	template <typename STREAM>
	STREAM& commit(ULONG length, STREAM&& stream)
	{
		auto address = commit(length);
		stream.setBuffer(address, length);
		return stream;
	}

	template <typename V>
	void writeEnumBE(V value)
	{
		reserve(sizeof(V));
		auto added = StreamWriteEnumBE(this->end(), value);
		adjustCount(added);
	}

	UINT32 getIndex(T& current)
	{
		return (UINT32)(((PUINT8)&current - (PUINT8)address()) / sizeof(T));
	}

	UINT32 getIndex(const T& current)
	{
		return (UINT32)(((PUINT8)&current - (PUINT8)address()) / sizeof(T));
	}

	void roundTo32bit()
	{
		this->__count = (this->__count + 3) & 3;
	}

	STREAM_BUILDER<T, ST, SZ>& clear()
	{
		this->__count &= DYNAMIC_MEMORY_MASK;
		return *this;
	}

	STREAM_READER<const T>  remove(UINT32 from, UINT32 removeCount = 1)
	{
		if (from == 0 && removeCount == count())
		{
			clear();
		}
		else
		{
			auto oldCount = count();
			auto moveFrom = from + removeCount;
			if (moveFrom < count())
			{
				auto moveLength = count() - moveFrom;
				RtlMoveMemory(this->address(from), this->address(moveFrom), moveLength * sizeof(T));
			}
			adjustCount(oldCount, -1 * removeCount);
		}
		return STREAM_READER<const T>(this->address(), from, this->count());
	}

	void remove(T& start, UINT32 count = 1)
	{
		this->remove(getIndex(start), count);
	}

	T& trim(UINT32 count = 1)
	{
		auto& result = last();
		adjustCount(-1 * count);
		return result;
	}

	void insert(UINT32 from, UINT32 insertCount = 1)
	{
		auto moveCount = count() - from;
		auto oldCount = this->reserve(insertCount);
		RtlMoveMemory(this->address(from) + insertCount, this->address(from), moveCount * sizeof(T));
		adjustCount(oldCount, insertCount);
	}

	void writeHex(UINT8 letter)
	{
		this->reserve(3);
		this->writeByte(HexChars[(letter & 0xF0) >> 4]);
		this->writeByte(HexChars[letter & 0x0F]);
	}

	void writeHexString(const UINT8 *inputData, UINT32 inputLength)
	{
		auto& subStream = this->commit(inputLength * 2, STREAM_BUILDER<T, THREAD_STACK, 1>());
		for (UINT32 i = 0; i < inputLength; i++)
		{
			auto c = inputData[i];
			subStream.writeByte(HexChars[(c & 0xF0) >> 4]);
			subStream.writeByte(HexChars[c & 0x0F]);
		}
	}

	void writeHexString(BUFFER buffer)
	{
		writeHexString(buffer.data(), buffer.length());
	}

	template <typename STR>
	void readHexString(STR&& hexString)
	{
		while (hexString.length() > 1)
		{
			auto first = hexString.at(0);
			auto second = hexString.at(1);

			if (isHexChar(first) && isHexChar(second))
			{
				hexString.shift(2);

				UINT8 number = ToHexNumber(first) << 4;
				number |= ToHexNumber(second);

				this->writeChar(number);
			}
			else break;
		}
	}

	void writeStream(STREAM_READER<const T> otherStream, UINT32 length)
	{
		auto start = this->commit(length);
		RtlCopyMemory(start, otherStream.data(), length * sizeof(T));
	}

	void writeStream(STREAM_READER<const T> otherStream)
	{
		writeStream(otherStream, otherStream.length());
	}

	template <typename ... Args>
	void sprintf(const char *format, Args && ... args)
	{
		auto oldCount = this->reserve(256);
		auto count = sprintf_s((char *)this->end(), 256, format, args ...);
		adjustCount(oldCount, count);
	}

	NTSTATUS readFile(HANDLE fileHandle, UINT32 byteCount)
	{
		auto oldCount = this->reserve(byteCount);

		IO_STATUS_BLOCK statusBlock;
		auto status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &statusBlock, end(), byteCount, nullptr, nullptr);
		if (NT_SUCCESS(status))
		{
			adjustCount(oldCount, (UINT32)statusBlock.Information);
		}
		return status;
	}

	BUFFER readFile(USTRING filename)
	{
		auto start = count();
		auto status = STATUS_SUCCESS;
		HANDLE fileHandle = nullptr;
		do
		{
			if (filename.peek() != '\\')
			{
				filename = TSTRING_BUILDER().writeMany(DATA_DIRECTORY, filename);
			}

			bool isUtf8 = false, isUnicode = false;

			IO_STATUS_BLOCK statusBlock;
			status = ZwCreateFile(&fileHandle, GENERIC_READ | SYNCHRONIZE, ToObjectAttributes(filename), &statusBlock, NULL,
				FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

			if (!NT_SUCCESS(status))
				break;

			FILE_STANDARD_INFORMATION fileInformation;
			status = ZwQueryInformationFile(fileHandle, &statusBlock, &fileInformation, sizeof(fileInformation), FileStandardInformation);
			VERIFY_STATUS;

			auto fileSize = (UINT32)(fileInformation.EndOfFile.QuadPart + 1);
			reserve(fileSize);

			if (fileSize > 3)
			{
				UINT8 buffer[3];
				status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &statusBlock, buffer, 3, nullptr, nullptr);
				VERIFY_STATUS;

				if (buffer[0] == Utf8Prefix[0 && buffer[1] == Utf8Prefix[1] && buffer[2] == Utf8Prefix[2]])
				{
					isUtf8 = true;
				}
				else if ((buffer[0] == 0xFF && buffer[1] == 0xFE) || (buffer[0] == 0xFE && buffer[1] == 0xFF))
				{
					isUnicode = true;
					writeChar(buffer[2]);
				}
				else
				{
					writeBytes(buffer, 3);
				}
				fileSize -= 3;
			}

			readFile(fileHandle, fileSize);
		} while (false);

		if (fileHandle) ZwClose(fileHandle);

		return { address(start), (UINT32)(count() - start)};
	}

	void encodeBase64(BUFFER inputBuffer)
	{
		auto inputBufferLength = inputBuffer.length();

		auto reminder = inputBufferLength % 3;
		auto fullCount = inputBufferLength - reminder;
		auto byteCount = fullCount * 4 + reminder ? 4 : 0;

		auto& subStream = commit(byteCount, STREAM_BUILDER<T, THREAD_STACK, 1>());

		for (UINT32 i = 0; i < fullCount; i += 3)
		{
			UINT32 data = inputBuffer[i] << 16 | inputBuffer[i + 1] << 8 | inputBuffer[i + 2];
			subStream.writeByte(Base64Chars[((data & 0xFC0000) >> 18)]);
			subStream.writeByte(Base64Chars[((data & 0x03F000) >> 12)]);
			subStream.writeByte(Base64Chars[((data & 0x000FC0) >> 6)]);
			subStream.writeByte(Base64Chars[(data & 0x00003F)]);
		}

		if (reminder == 2)
		{
			UINT32 data = inputBuffer[fullCount] << 16 | inputBuffer[fullCount + 1] << 8;
			subStream.writeByte(Base64Chars[((data & 0xFC0000) >> 18)]);
			subStream.writeByte(Base64Chars[((data & 0x03F000) >> 12)]);
			subStream.writeByte(Base64Chars[((data & 0x000FC0) >> 6)]);
			subStream.writeByte('=');
		}
		else if (reminder == 1)
		{
			UINT32 data = inputBuffer[fullCount] << 16;
			subStream.writeByte(Base64Chars[((data & 0xFC0000) >> 18)]);
			subStream.writeByte(Base64Chars[((data & 0x03F000) >> 12)]);
			subStream.writeByte('=');
			subStream.writeByte('=');
		}

		return;
	}

	void writeUtf8(UINT32 c)
	{
		if (c <= 0x7F)
		{
			writeByte((UINT8)(c & 0x7F));
		}
		else if (c >= 0x80 && c <= 0x7FF)
		{
			writeByte((UINT8)(0xC0 | (c & 0x7C0) >> 6));
			writeByte((UINT8)(0x80 | (c & 0x3F)));
		}
		else if (c > 0x7FF && c < 0xFFFF)
		{
			writeByte((UINT8)(0xE0 | (c & 0xF000) >> 12));
			writeByte((UINT8)(0x80 | (c & 0x0FC0) >> 6));
			writeByte((UINT8)(0x80 | (c & 0x3F)));
		}
		else if (c >= 0xFFFF)
		{
			DBGBREAK();
			writeByte((UINT8)(0xF0 | (c & 0x1C0000) >> 18));
			writeByte((UINT8)(0x80 | (c & 0x3F000) >> 12));
			writeByte((UINT8)(0x80 | (c & 0x0FC0) >> 6));
			writeByte((UINT8)(0x80 | (c & 0x3F)));
		}
	}

	UINT8 base64Index(UINT8 base64Char)
	{
		return base64Char == '=' ? 0 : Base64Index[base64Char];
	}

	void decodeBase64(BUFFER base64String)
	{
		reserve(base64String.length());
		for (UINT32 i = 0; i < base64String.length(); i += 4)
		{
			UINT32 data = (base64Index(base64String[i]) << 18) | (base64Index(base64String[i + 1]) << 12) | (base64Index(base64String[i + 2]) << 6) | base64Index(base64String[i + 3]);

			writeByte((UINT8)((data & 0xFF0000) >> 16));
			writeByte((UINT8)((data & 0xFF00) >> 8));
			writeByte((UINT8)(data & 0xFF));

			if (base64String[i + 2] == '=' && base64String[i + 3] == '=')
			{
				trim(2);
			}
			else if (base64String[i + 3] == '=')
			{
				trim(1);
			}
		}
	}

	void writeVisualToken(const UINT8* address, UINT64 dataLength, TOKENTYPE type, VSIZE size = VSIZE::DEFAULT, VSPAN span = VSPAN::DEFAULT)
	{
		UINT8 flags = 0;
		LOCAL_STREAM<4> typeFlags;

		typeFlags.writeByte((UINT8)type);

		if (size != VSIZE::DEFAULT)
		{
			typeFlags.writeByte((UINT8)size);
			flags |= VTOKEN_FLAG_SIZE;
		}

		if (span != VSPAN::DEFAULT)
		{
			typeFlags.writeByte((UINT8)span);
			flags |= VTOKEN_FLAG_SPAN;
		}

		writeVInt((dataLength << 2) | flags);
		writeBytes(typeFlags.toBuffer());

		if (address)
		{
			writeBytes(address, (UINT32)dataLength);
		}
	}

	template <typename STACK>
	void writeVisualToken(VISUAL_TOKEN visualToken)
	{
		auto token = visualToken.shape;

		BUFFER bytes;
		if (token.isString())
		{
			bytes = GetLiteral<STACK>(token);
			writeVisualToken(bytes.data(), bytes.length(), token.getMajorType(), visualToken.size, visualToken.span);
		}
		else if (token.isBlob())
		{
			bytes = GetBlobData(token);
			writeVisualToken(bytes.data(), bytes.length(), token.getFullType(), visualToken.size, visualToken.span);
		}
		else if (token.isNumber())
		{
			auto number = GetNumberHandleValue(token);
			ASSERT(number < MAXUINT64 / 0xFF);
			writeVisualToken(nullptr, number, TOKENTYPE::NUMBER, visualToken.size, visualToken.span);
		}
		else if (token == Null)
		{
			writeVisualToken(nullptr, 0, TOKENTYPE::OBJECT, visualToken.size, visualToken.span);
		}
		else if (token.isConstant())
		{
			writeVisualToken(nullptr, (UINT64)token.getValue(), TOKENTYPE::CONSTANT, visualToken.size, visualToken.span);
		}
		else DBGBREAK();
	}

	struct OFFSET
	{
		STREAM_BUILDER<UINT8, ST, SZ>& stream;
		UINT32 offset;
		UINT32 lengthBytes;
		bool lengthWritten = false;

		OFFSET(UINT32 countArg, STREAM_BUILDER<UINT8, ST, SZ>& bufferArg) : stream(bufferArg), lengthBytes(countArg)
		{
			offset = stream.count();
			for (UINT32 i = 0; i < lengthBytes; i++)
			{
				stream.writeByte(0);
			}
		}

		void operator = (const OFFSET& other)
		{
			stream = other.stream;
			offset = other.offset;
			lengthBytes = other.lengthBytes;
			lengthWritten = other.lengthWritten;
		}

		UINT32 getLength()
		{
			auto length = (UINT32)(stream.count() - offset);
			length -= lengthBytes;
			return length;
		}

		void writeLength(INT32 adjustLength = 0)
		{
			if (lengthBytes > 0)
			{
				lengthWritten = true;
				auto length = getLength() + adjustLength;
				if (lengthBytes == 2)
				{
					stream.writeAtBE<UINT16>(offset, (UINT16)length);
				}
				else if (lengthBytes == 3)
				{ // ignoring the 1st byte of 3 byte length
					stream.writeAtBE<UINT16>(offset + 1, (UINT16)length);
				}
				else if (lengthBytes == 1)
				{
					stream.writeAtBE<UINT8>(offset, (UINT8)(length & 0xFF));
				}
				else if (lengthBytes == 4)
				{
					stream.writeAtBE<UINT32>(offset, (UINT32)length);
				}
				else DBGBREAK();
			}
		}

		BUFFER toBuffer()
		{
			return { stream.address(offset), getLength() };
		}

		~OFFSET()
		{
			if (!lengthWritten) writeLength();
		}
	};

	OFFSET saveOffset(UINT32 intSize)
	{
		return OFFSET(intSize, *this);
	}

	OFFSET getPosition()
	{
		auto offset = OFFSET(0, *this);
		offset.lengthWritten = true;
		return offset;
	}

	STREAM_READER<const UINT8> toByteBuffer() const
	{
		return STREAM_READER<const UINT8> { (PUINT8)address(), count() * sizeof(T)};
	}

	STREAM_READER<const T> toBuffer(UINT32 start = 0) const
	{
		return STREAM_READER<const T>(this->address(start), count() - start);
	}

	STREAM_READER<T> toBufferNoConst(UINT32 start = 0) const
	{
		return STREAM_READER<T>(this->address(start), count() - start);
	}
};

extern UINT32 GetFileSize(USTRING filename);
extern NTSTATUS CreateDirectory(USTRING name);
extern NTSTATUS WriteFile(USTRING filename, USTRING data);
extern NTSTATUS DeleteFile(USTRING filename);

template <typename STREAM>
USTRING FromUnicodeString(UNICODE_STRING& input, STREAM&& stream)
{
	UINT32 length = input.Length / 2;
	auto outAddress = stream.commit(length + 1);
	for (UINT32 i = 0; i < length; i++)
	{
		outAddress[i] = (UINT8)input.Buffer[i];
	}
	outAddress[length] = 0;
	return { outAddress, length };
}

constexpr USTRING NULL_STRING = USTRING();
constexpr USTRING NULL_BUFFER = USTRING();

constexpr UINT8 Utf8PrefixData[] = { 0xEF, 0xBB, 0xBF };
constexpr USTRING Utf8Prefix = Utf8PrefixData;

template <typename F, typename ... Args>
NTSTATUS ListDirectory(USTRING directoryName, USTRING subDirectoryName, F callback, Args&& ... args)
{
	auto path = subDirectoryName ? GetTempStream().writeMany(directoryName, "\\", subDirectoryName) : directoryName;

	HANDLE directoryHandle;
	//OBJECT_ATTRIBUTES filenameObject;
	//InitializeObjectAttributes(&filenameObject, unicodeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

	IO_STATUS_BLOCK ioStatus;
	auto status = ZwCreateFile(&directoryHandle, FILE_LIST_DIRECTORY | SYNCHRONIZE | GENERIC_READ, ToObjectAttributes(path), &ioStatus, nullptr,
		0, FILE_SHARE_READ, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);

	ASSERT(NT_SUCCESS(status));

	UINT32 fileInfoSize = sizeof(FILE_DIRECTORY_INFORMATION) + 512;
	auto fileInfo = (PFILE_DIRECTORY_INFORMATION) StackAlloc<SCHEDULER_STACK>(fileInfoSize);
	if (NT_SUCCESS(status))
	{
		while (true)
		{
			status = ZwQueryDirectoryFile(directoryHandle, nullptr, nullptr, nullptr, &ioStatus, fileInfo, fileInfoSize, FileDirectoryInformation, TRUE, nullptr, FALSE);
			if (status == STATUS_SUCCESS)
			{
				auto filename = fileInfo->FileName;
				auto nameLength = (UINT32)(fileInfo->FileNameLength / 2);

				if (filename[nameLength -1] == '.')
					continue;

				if (fileInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					auto& subDirectory = GetTempStream();
					if (subDirectoryName)
					{
						subDirectory.writeMany(subDirectoryName, "\\");
					}
					subDirectory.writeString(filename, nameLength);
					ListDirectory(directoryName, subDirectory.toBuffer(), callback, args ...);
				}
				else
				{
					auto& relativeName = GetTempStream(); 
					auto& fullPath = GetTempStream();
					fullPath.writeMany(directoryName, "\\");
					if (subDirectoryName)
					{
						fullPath.writeMany(subDirectoryName, "\\");
						relativeName.writeMany(subDirectoryName, "/");
					}
					fullPath.writeString(filename, nameLength);
					relativeName.writeString(filename, nameLength);

					callback(relativeName.toBuffer(), fullPath.toBuffer(), args ...);
				}
			}
			else if (status == STATUS_NO_MORE_FILES)
			{
				break;
			}
			else
			{
				DBGBREAK();
				break;
			}
		}
	}
	return STATUS_SUCCESS;
}

constexpr UINT32 FILE_READER_BUF_SIZE = 32 * 1024 * 1024;

struct FILE_READER
{
	UINT8* buffer;
	UINT32 readOffset = 0;
	UINT32 bufferEnd = 0;
	HANDLE fileHandle;
	UINT64 fileSize;
	UINT64 readTotal;

	NTSTATUS open(USTRING filename)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			//OBJECT_ATTRIBUTES fileObject;
			//auto unicodeFilename = ToUnicodeString(filename);
			//InitializeObjectAttributes(&fileObject, unicodeFilename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

			IO_STATUS_BLOCK statusBlock;
			status = ZwCreateFile(&fileHandle, GENERIC_READ | SYNCHRONIZE, ToObjectAttributes(filename), &statusBlock, NULL,
				FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
			VERIFY_STATUS;

			FILE_STANDARD_INFORMATION fileInformation;
			status = ZwQueryInformationFile(fileHandle, &statusBlock, &fileInformation, sizeof(fileInformation), FileStandardInformation);
			VERIFY_STATUS;

			fileSize = fileInformation.EndOfFile.QuadPart + 1;

			buffer = (PUINT8) KernelAlloc(FILE_READER_BUF_SIZE);
			if (buffer == nullptr)
			{
				status = STATUS_NO_MEMORY;
				break;
			}

			readOffset = 0;
			auto readCount = (UINT32) min(FILE_READER_BUF_SIZE, fileSize);
			auto status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &statusBlock, buffer, readCount, nullptr, nullptr);
			VERIFY_STATUS;

			readCount = (UINT32)statusBlock.Information;
			readTotal = readCount;
			bufferEnd = readCount;

		} while (false);
		return status;
	}

	void Close()
	{
		ZwClose(fileHandle);
		ExFreePoolWithTag(buffer, POOL_TAG);
		fileHandle = nullptr;
	}

	PUINT8 read(UINT32 count = 1)
	{
		auto availableData = bufferEnd - readOffset;
		if (availableData < count)
		{
			ASSERT(availableData + count < FILE_READER_BUF_SIZE); // increate the buf size

			RtlMoveMemory(buffer, &buffer[readOffset], availableData);
			readOffset = 0;
			bufferEnd = availableData;

			auto readCount = FILE_READER_BUF_SIZE - bufferEnd;
			IO_STATUS_BLOCK statusBlock;
			auto status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &statusBlock, buffer + bufferEnd, readCount, nullptr, nullptr);
			if (NT_SUCCESS(status))
			{
				readCount = (UINT32)statusBlock.Information;
				readTotal += readCount;
				bufferEnd += readCount;
			}
			availableData = bufferEnd - readOffset;
		}

		PUINT8 result = nullptr;
		if (availableData >= count)
		{
			result = &buffer[readOffset];
			readOffset += count;
		}
		return result;
	}

	UINT8 readByte()
	{
		auto data = read();
		return data == NULL ? 0 : *data;
	}
};
