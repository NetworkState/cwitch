// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

#include "pch.h"

#define DBGBREAK()		DbgBreakPoint()
#define VERIFY_STATUS	if (!NT_SUCCESS(status)) { DBGBREAK(); break; }

template <typename ... Args>
void LogError(PCHAR format, Args&& ... args)
{
	DbgPrintEx(DPFLTR_NDIS_ID, DPFLTR_ERROR_LEVEL, format, args ...);
	DbgPrintEx(DPFLTR_NDIS_ID, DPFLTR_ERROR_LEVEL, "\n");
}

struct CLOCK
{
	LARGE_INTEGER startTime;
	LARGE_INTEGER frequency;

	void start()
	{
		startTime = KeQueryPerformanceCounter(&frequency);
	}

	UINT64 elapsedTime() // in milliseconds
	{
		auto currentTime = KeQueryPerformanceCounter(nullptr);

		auto elapsedTime = currentTime.QuadPart - startTime.QuadPart;
		elapsedTime = (elapsedTime * 1000) / frequency.QuadPart;
		return elapsedTime;
	}
};

constexpr auto MS_TO_TIMEUNITS(UINT32 ms) { return LARGE_INTEGER{ -1 * ms * 10000 }; }
constexpr auto SECONDS_TO_TIMEUNITS(UINT32 sec) { return LARGE_INTEGER{ -1 * sec * 10000000 }; }

constexpr UINT32 SYSTEM_TIME_TO_MS = 10000;

extern UINT64 GetStateOsTime();
extern CLOCK SystemClock;

template <typename ... Args>
void LogInfo(PCHAR format, Args&& ... args)
{
	auto elapsedTime = SystemClock.elapsedTime();
	DbgPrintEx(DPFLTR_NDIS_ID, DPFLTR_INFO_LEVEL, "%02d:%02d:%03d ", (elapsedTime / 60000) % 60, (elapsedTime / 1000) % 60, elapsedTime % 1000);
	DbgPrintEx(DPFLTR_NDIS_ID, DPFLTR_INFO_LEVEL, format, args ...);
	DbgPrintEx(DPFLTR_NDIS_ID, DPFLTR_INFO_LEVEL, "\n");
}

constexpr UINT32 ROUND_TO(UINT32 number, UINT32 base) { return (number + base - 1) & ~(base - 1); }

constexpr UINT8 BITCOUNT(UINT32 x) 
{
	for (UINT8 i = 0; i < 32; i++)
	{
		x >>= i;
		if (x == 0)
			return i;
	}
	return 31;
}

template <typename T>
extern T& GetCurrentStack();

#include "Memory.h"

constexpr UINT32 TLS_PORT = 443;
constexpr UINT32 HTTP_PORT = 80;
constexpr UINT32 RTSP_PORT = 554;
constexpr UINT32 RTSPS_PORT = 322;
constexpr UINT32 RTMP_PORT = 1935;

constexpr UINT16 HTONS(UINT16 x) { return (((x >> 8) & 0x00FF) | ((x << 8) & 0xFF00)); }
constexpr UINT32 HTONL(UINT32 x) { return (((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | ((x << 24) & 0xFF000000)); }

#define NULLPTR 0x00000BAD

template <typename T>
constexpr T &NullRef()
{
	return *(T *)NULLPTR;
}

template <typename T>
constexpr bool IsNullRef(T &value)
{
	return &value == (T *)NULLPTR;
}

template <typename T>
constexpr bool IsValidRef(T& value)
{
	return &value != (T*)NULLPTR;
}

enum SEPARATOR : UINT8
{
	SEP_UNKNOWN,
	SEP_LEFT_BRACE,
	SEP_RIGHT_BRACE,
	SEP_LEFT_PARENTHESIS,
	SEP_RIGHT_PARENTHESIS,
	SEP_LEFT_BRACKET,
	SEP_RIGHT_BRACKET,
	SEP_SEMICOLON,
	SEP_DOUBLE_QUOTE,
	SEP_SINGLE_QUOTE,
	SEP_DOT,
	SEP_COMMA,
	SEP_COLON,
	SEP_MAX_COUNT,
};

enum JS_OPERATOR : UINT8
{
	OP_INVALID,
	OP_UNARY_MINUS = 0xF1,
	OP_UNARY_PLUS = 0xF2,
	OP_PLUS_PLUS = 0xF3,
	OP_MINUS_MINUS = 0xF4,
	OP_NOT = 0xF5,
	OP_TILDA = 0xF6,
	OP_DELETE = 0xF7,
	OP_NEW = 0xF8,
	OP_TYPEOF = 0xF9,
	OP_VOID = 0xFA,
	OP_MULTIPLY = 0xE1,
	OP_MOD = 0xE2,
	OP_DIVIDE = 0xE3,
	OP_ADD = 0xD1,
	OP_SUBTRACT = 0xD2,
	OP_LEFT_SHIFT = 0xC1,
	OP_RIGHT_SHIFT = 0xC2,
	OP_RIGHT_SHIFT2 = 0xC3,
	OP_LESS_THAN = 0xB1,
	OP_GREATER_THAN = 0xB2,
	OP_LESS_THAN_EQUAL = 0xB3,
	OP_GREATER_THAN_EQUAL = 0xB4,
	OP_IN = 0xB5,
	OP_INSTANCEOF = 0xB6,
	OP_EQUALS = 0xA1,
	OP_NOT_EQUALS = 0xA2,
	OP_STRICT_EQUALS = 0xA3,
	OP_STRICT_NOT_EQUALS = 0xA4,
	OP_BITWISE_AND = 0x91,
	OP_XOR = 0x81,
	OP_BITWISE_OR = 0x71,
	OP_LOGICAL_AND = 0x61,
	OP_LOGICAL_OR = 0x51,
	OP_QUESTION = 0x41,
	OP_COLON = 0x42,
	OP_ASSIGN = 0x31,
	OP_ADD_ASSIGN = 0x32,
	OP_SUBTRACT_ASSIGN = 0x33,
	OP_MULTIPLY_ASSIGN = 0x34,
	OP_DIVIDE_ASSIGN = 0x35,
	OP_MOD_ASSIGN = 0x36,
	OP_LEFT_SHIFT_ASSIGN = 0x37,
	OP_RIGHT_SHIFT_ASSIGN = 0x38,
	OP_RIGHT_SHIFT_EQUALS2 = 0x39,
	OP_AND_ASSIGN = 0x21,
	OP_OR_ASSIGN = 0x22,
	OP_XOR_ASSIGN = 0x23,
	OP_COMMA = 0x11,
};

enum class TOKENTYPE : UINT8
{
	OBJECT = 0x00,
	NUMBER = 0x10,
	HTML = 0x20,
	CONSTANT = 0x30,
	NAME = 0x40,
	CSS  = 0x50,
	BLOB = 0x60,
	DOUBLE = 0x70,
	LITERAL = 0xA0,
	REGEX = 0xB0,
	STOKEN = 0xC0,
	TASK = 0xD0,
	ERROR = 0xE0,

	STOKEN_EXPRESSION = STOKEN | 0x01,
	STOKEN_ARGS = STOKEN | 0x02,
	STOKEN_SYMBOL = STOKEN | 0x03,
	STOKEN_STATEMENT = STOKEN | 0x04,
	STOKEN_BLOCK = STOKEN | 0x05,
	STOKEN_LOCALS = STOKEN | 0x06,
	STOKEN_JSON = STOKEN | 0x07,
	STOKEN_ARRAY = STOKEN | 0x08,
	STOKEN_KEYWORD = STOKEN | 0x09,
	STOKEN_OPERATOR = STOKEN | 0x0A,
	STOKEN_SEPARATOR = STOKEN | 0x0B,
	STOKEN_SDP = STOKEN | 0x0C,

	MINOR_GLOBAL = 0x00,
	MINOR_SESSION = 0x02,
	MINOR_APP = 0x03,
	MINOR_SCHEDULER = 0x04,

	NAME_GLOBAL = NAME | MINOR_GLOBAL,
	NAME_SESSION = NAME | MINOR_SESSION,
	NAME_APP = NAME | MINOR_APP,
	NAME_SCHEDULER = NAME | MINOR_SCHEDULER,

	LITERAL_GLOBAL = LITERAL | MINOR_GLOBAL,
	LITERAL_SESSION = LITERAL | MINOR_SESSION,
	LITERAL_APP = LITERAL | MINOR_APP,
	LITERAL_LARGE = LITERAL | 0x0F,

	NUMBER_TIMESTAMP = NUMBER | 0x01,
	NUMBER_DATE = NUMBER | 0x02,

	BLOB_GUID = BLOB | 0x01,
	BLOB_MACADDRESS = BLOB | 0x02,
};
DEFINE_ENUM_FLAG_OPERATORS(TOKENTYPE);

struct TOKEN
{
	UINT8 _type;
	UINT8 _value1 = 0;
	UINT8 _value2 = 0;	
	UINT8 _value3 = 0;

	constexpr TOKENTYPE getMajorType() const { return (TOKENTYPE)(_type & 0xF0); }
	constexpr TOKENTYPE getMinorType() const { return (TOKENTYPE)(_type & 0x0F); }
	constexpr bool isScript(TOKENTYPE type) { return( (UINT8)type & 0xF0) == (UINT8)TOKENTYPE::STOKEN; }

	constexpr TOKEN(TOKENTYPE type, UINT32 value = 0, UINT32 length = 1)
		: _type((UINT8)type), 
		_value1(isScript(type) ? (UINT8)value : (UINT8)((value >> 16) & 0xFF)),
		_value2(isScript(type) ? (UINT8)(length >> 8) : (UINT8)((value >> 8) & 0xFF)),
		_value3(isScript(type) ? (UINT8)(length) : (UINT8)(value & 0xFF))
	{
	}

	constexpr TOKEN(UINT32 value)
		: _type((UINT8)((value >> 24) & 0xFF)), _value1((UINT8)((value >> 16) & 0xFF)), _value2((UINT8)((value >> 8) & 0xFF)), _value3((UINT8)(value & 0xFF))
	{
	}

	constexpr TOKEN() : _type((UINT8)TOKENTYPE::OBJECT) {}

	constexpr UINT32 toUInt32() { return (UINT32)_type << 24 | (UINT32)_value1 << 16 | (UINT32)_value2 << 8 | _value3; }
	constexpr bool toBoolean() const;

	explicit operator bool() const { return this->toBoolean(); }

	inline constexpr bool isNotScript() const { return getMajorType() != TOKENTYPE::STOKEN; }
	inline constexpr bool isScript() const { return getMajorType() == TOKENTYPE::STOKEN; }

	inline constexpr TOKENTYPE const getFullType() const { return (TOKENTYPE)_type; }
	inline constexpr UINT32 const getValue() const { return this->isScript() ? (UINT32)_value1 : (UINT32)_value1 << 16 | (UINT32)_value2 << 8 | (UINT32)_value3; }

	constexpr bool isName() const { return this->getMajorType() == TOKENTYPE::NAME; }
	constexpr bool isLiteral() const { return this->getMajorType() == TOKENTYPE::LITERAL; }
	constexpr bool isString() const { return getMajorType() == TOKENTYPE::LITERAL || getMajorType() == TOKENTYPE::NAME; }
	constexpr bool isObject() const { return getValue() != 0 && getMajorType() == TOKENTYPE::OBJECT; }
	constexpr bool isNumber() const { return this->getMajorType() == TOKENTYPE::NUMBER; }
	constexpr bool isDouble() const { return this->getMajorType() == TOKENTYPE::DOUBLE; }
	constexpr bool isBlob() const { return this->getMajorType() == TOKENTYPE::BLOB; }
	constexpr bool isGuid() const { return this->getFullType() == TOKENTYPE::BLOB_GUID; }
	constexpr bool isMacAddress() const { return this->getFullType() == TOKENTYPE::BLOB_MACADDRESS; }
	constexpr bool isTimestamp() const { return this->getFullType() == TOKENTYPE::NUMBER_TIMESTAMP; }
	constexpr bool isRegex() const { return this->getMajorType() == TOKENTYPE::REGEX; }
	constexpr bool isError() const { return this->getMajorType() == TOKENTYPE::ERROR; }
	constexpr bool isConstant() const { return this->getMajorType() == TOKENTYPE::CONSTANT; }

	constexpr auto compareValue() const { return isString() ? (((UINT32)_type & 0x0F) << 24) | ((UINT32)_value2 << 8) | (UINT32)_value3 : getValue(); }

	constexpr bool operator == (TOKEN other) { return this->compareValue() == other.compareValue(); }
	constexpr bool operator != (TOKEN other) { return this->compareValue() != other.compareValue(); }

	constexpr bool operator == (const TOKEN other) const { return this->compareValue() == other.compareValue(); }
	constexpr bool operator != (const TOKEN other) const { return this->compareValue() != other.compareValue(); }
	inline bool isOperator() const { return this->getFullType() == TOKENTYPE::STOKEN_OPERATOR; }
	inline JS_OPERATOR getOperator() const { return (this->isOperator() || this->isExpression()) ? (JS_OPERATOR)this->getValue() : OP_INVALID; }

	inline UINT8 getPrecedence() const { return this->getFullType() == TOKENTYPE::STOKEN_OPERATOR || this->getFullType() == TOKENTYPE::STOKEN_EXPRESSION ? (UINT8)((this->getValue() & 0xF0) >> 16) : 0; }

	bool isSeparator() const { return this->getFullType() == TOKENTYPE::STOKEN_SEPARATOR; };
	inline SEPARATOR getSeparator() const { return this->isSeparator() ? (SEPARATOR)this->getValue() : SEP_UNKNOWN; }

	bool isKeyword() const { return this->getFullType() == TOKENTYPE::STOKEN_KEYWORD; }
	TOKEN getKeyword();

	bool isSdp() const { return this->getFullType() == TOKENTYPE::STOKEN_SDP; }
	TOKEN getSdpName();

	bool isJson() const { return this->getFullType() == TOKENTYPE::STOKEN_JSON; }

	UINT32 getLength() const { return this->isScript() ? (UINT32)_value2 << 8 | (UINT32)_value3 : 1; }
	UINT32 getDataLength() const { return getLength() - 1; }
	void setLength(UINT32 length) { ASSERT(isScript()); _value2 = (UINT8)((length >> 8) & 0xFF); _value3 = (UINT8)(length & 0xFF); }

	constexpr UINT16 getShortName() const { return (UINT16)getValue() & 0xFFFF; }
	bool isExpression() const { return this->getFullType() == TOKENTYPE::STOKEN_EXPRESSION && this->getLength() > 1; }
	bool isSymbol() const { return this->getFullType() == TOKENTYPE::STOKEN_SYMBOL; }
	bool isStatement() const { return this->getFullType() == TOKENTYPE::STOKEN_STATEMENT; }
	bool isArgs() const { return this->getFullType() == TOKENTYPE::STOKEN_ARGS; }
	bool isArray() const { return this->getFullType() == TOKENTYPE::STOKEN_ARRAY; }

	bool isBlockStatement() const { return this->getFullType() == TOKENTYPE::STOKEN_BLOCK; }

	bool isComma() const { return this->isSeparator() && this->getSeparator() == SEP_COMMA; }
	bool isDot() const { return this->isSeparator() && this->getSeparator() == SEP_DOT; }
	bool isSemicolon() const { return this->isSeparator() && this->getSeparator() == SEP_SEMICOLON; }
	bool isColon() const { return this->isSeparator() && this->getSeparator() == SEP_COLON; }
	bool isLeftBrace() const { return this->isSeparator() && this->getSeparator() == SEP_LEFT_BRACE; }
	bool isLeftParenthesis() const { return this->isSeparator() && this->getSeparator() == SEP_LEFT_PARENTHESIS; }
	bool isLeftBracket() const { return this->isSeparator() && this->getSeparator() == SEP_LEFT_BRACKET; }

	bool isRightBrace() const { return this->isSeparator() && this->getSeparator() == SEP_RIGHT_BRACE; }
	bool isRightParenthesis() const { return this->isSeparator() && this->getSeparator() == SEP_RIGHT_PARENTHESIS; }
	bool isRightBracket() const { return this->isSeparator() && this->getSeparator() == SEP_RIGHT_BRACKET; }
};

constexpr auto Undefined = TOKEN(TOKENTYPE::ERROR, 0xFFFFFFF);
constexpr auto TypeError = TOKEN(TOKENTYPE::ERROR, 0x02);
constexpr auto Null = TOKEN(TOKENTYPE::OBJECT, 0x00);
constexpr auto EMPTY_STRING = TOKEN(TOKENTYPE::LITERAL, 0);
constexpr auto NULL_NAME = TOKEN(TOKENTYPE::NAME, 0);

constexpr bool IsEmptyString(TOKEN name)
{
	return (name == Undefined || name == EMPTY_STRING || name == NULL_NAME);
}

constexpr bool IsNonEmptyString(TOKEN name)
{
	return (name != Undefined && name != EMPTY_STRING && name != Null && name != NULL_NAME);
}

constexpr auto Nan = TOKEN(TOKENTYPE::ERROR, 0x03);
constexpr auto False = TOKEN(TOKENTYPE::ERROR, 0x04);

constexpr auto True = TOKEN(TOKENTYPE::CONSTANT, 0x01);
constexpr auto Namespace = TOKEN(TOKENTYPE::CONSTANT, 0x04);

constexpr bool TOKEN::toBoolean() const {
	return (*this == Undefined) || (*this == Null) || (*this == EMPTY_STRING) || (*this == NULL_NAME) || getFullType() == TOKENTYPE::ERROR ? false : true;
}

template <typename T, const UINT32 arraySize>
constexpr INT32 ArrayFind(const T(&array)[arraySize], T value)
{
	for (UINT32 i = 0; i < arraySize; i++)
	{
		if (array[i] == value)
			return i;
	}
	return -1;
}

template <typename T, const UINT32 arraySize>
bool ArrayExists(const T(&array)[arraySize], T value)
{
	return ArrayFind(array, value) != -1;
}

bool IsWhitespace(UINT8 input);

#define UNDEFINED_FLOAT		-9.99f
#define UNDEFINED_UINT16     0xFFFF
#define UNDEFINED_UINT32     0xFFFFFFFF
#define UNDEFINED_BOOL		 0xFF
#define UNDEFINED_NAME		 0xF0000000

struct THREAD_STACK
{
	UINT32 stackSize = 0;
	PUINT8 startAddress = nullptr;
	PUINT8 currentAddress = nullptr;

	UINT32 overflowStackSize = 0;
	PUINT8 overflowStart = nullptr;
	PUINT8 overflowCurrent = nullptr;
};

enum class VSIZE : UINT8
{
	DEFAULT = 0,
	XXSMALL = 0x10,
	XSMALL = 0x20,
	SMALL = 0x30,
	BOLD_SMALL = 0x40,
	MEDIUM = 0x50,
	BOLD_MEDIUM = 0x60,
	LARGE = 0x70,
	BOLD_LARGE = 0x80,
	XLARGE = 0x90,
	XXLARGE = 0xA0,
	JUMBO = 0xB0,
};

enum class VSPAN : UINT8
{
	DEFAULT = 0,
	DOT = 0x01,
	DASH = 0x02,
	COMMA = 0x03,
	COLON = 0x04,
	SEMICOLON = 0x05,
	WORD = 0x06,
	ITEM = 0x07,
	QUOTE = 0x08,
	PARANTHESIS = 0x09,
	SEMICOLON_SENTENCE = 0x0A,
	COMMA_SENTENCE = 0x0B,
	SENTENCE = 0x0C,
	PARAGRAPH = 0x0D,
	SECTION = 0x0E,
	CHAPTER = 0x0F,
};

constexpr UINT8 VTOKEN_FLAG_SIZE = 0x01;
constexpr UINT8 VTOKEN_FLAG_SPAN = 0x02;

struct VISUAL_TOKEN
{
	VSIZE size;
	VSPAN span;
	TOKEN shape;

	constexpr VISUAL_TOKEN(TOKEN inputToken, VSIZE inputSize = VSIZE::DEFAULT, VSPAN inputSpan = VSPAN::DEFAULT)
		: size(inputSize), span(inputSpan), shape(inputToken)
	{
	}

	constexpr VISUAL_TOKEN() : size(VSIZE::DEFAULT), span(VSPAN::DEFAULT), shape(Null) {}

	constexpr bool operator == (VISUAL_TOKEN other) const
	{
		return size == other.size && span == other.span && shape == other.shape;
	}

	explicit operator bool() const { return shape && size != VSIZE::DEFAULT && span != VSPAN::DEFAULT; }
};

#include "Stream.h"

constexpr UINT32 STRING_SIZE = 258;

using STRING_READER = STREAM_READER<const UINT8>;

template <UINT32 SZ>
using LOCAL_STREAM = STREAM_BUILDER<UINT8, THREAD_STACK, SZ>;

using BYTESTREAM = STREAM_BUILDER<UINT8, THREAD_STACK, 1>;

template <typename ST, UINT32 SZ = STRING_SIZE>
using STRING_BUILDER = STREAM_BUILDER<UINT8, ST, SZ>;

template <typename ST, UINT32 SZ = STRING_SIZE>
using WSTRING_BUILDER = STREAM_BUILDER<UINT16, ST, SZ>;

constexpr UINT32 MAX_NAME_LENGTH = 255;
constexpr UINT32 HEADER_DATA_LENGTH = 15;
constexpr UINT32 VARIANT_DATA_LENGTH = 19;

struct NAME_HEADER
{
	UINT8 length;
	UINT8 letter1;
	UINT8 letter2;
	UINT8 letter3;
	UINT32 letter4to7;
	UINT64 letter8to15;
};

struct VARIANT_HEADER
{
	UINT16 index;
	UINT8 variant;
	UINT16 extension;
	UINT8 data[VARIANT_DATA_LENGTH];
};

struct SORT_HEADER
{
	UINT64 header;
	UINT16 name;
	UINT16 extension;
	UINT32 footer;
};

struct EXTENSION_HEADER
{
	UINT16 index;
	UINT8 variant;
	UINT32 data;
};

template<TOKENTYPE ID, typename ST, UINT32 NAMES, UINT32 VARIANTS, UINT32 EXTENSIONS>
struct DICTIONARY
{
	STREAM_BUILDER<SORT_HEADER, ST, NAMES> sortHeaders;
	STREAM_BUILDER<NAME_HEADER, ST, NAMES> nameHeaders;
	STREAM_BUILDER<VARIANT_HEADER, ST, VARIANTS> variantHeaders;
	STREAM_BUILDER<EXTENSION_HEADER, ST, EXTENSIONS> extensionHeaders;

	PUINT8 extensionData;
	INT32 extensionDataWriteOffset;
	TOKENTYPE type;

	DICTIONARY() : type(ID) 
	{
		auto&& zeroHeader = NAME_HEADER();
		RtlZeroMemory(&zeroHeader, sizeof(NAME_HEADER));
		nameHeaders.append(zeroHeader);
	}
};

constexpr USTRING DATA_DIRECTORY = "\\Device\\BootDevice\\ProgramData\\StateOS\\";

struct GLOBAL_STACK
{
	UINT32 stackSize = 64 * 1024 * 1024;
	PUINT8 startAddress;
	PUINT8 currentAddress;

	UINT32 overflowStackSize = 0;
	PUINT8 overflowStart = nullptr;
	PUINT8 overflowCurrent = nullptr;

	STREAM_BUILDER<INT64, GLOBAL_STACK, 256> numberHandles;

	STREAM_BUILDER<UINT8, GLOBAL_STACK, 4096> charStream;
	DICTIONARY<TOKENTYPE::NAME_GLOBAL, GLOBAL_STACK, 6000, 1000, 2000> dictionary;
};

extern GLOBAL_STACK& GlobalStack();

#include "Name.h"
#include "BaseNames.h"
#include "Scheduler.h"

using TBYTESTREAM = STREAM_BUILDER<UINT8, SCHEDULER_STACK, 1>;

using TSTRING_BUILDER = STREAM_BUILDER<UINT8, SCHEDULER_STACK, STRING_SIZE>;

using TSTRING_STREAM = STREAM_BUILDER<USTRING, SCHEDULER_STACK, 16>;

template <UINT32 SZ = STRING_SIZE>
STREAM_BUILDER<UINT8, SCHEDULER_STACK, SZ>& GetTempStream()
{
	return StackAlloc<STREAM_BUILDER<UINT8, SCHEDULER_STACK, SZ>, SCHEDULER_STACK>();
}

using TWSTRING_BUILDER = STREAM_BUILDER<UINT16, SCHEDULER_STACK, STRING_SIZE>;

using BUFFER_BUILDER = STREAM_BUILDER<UINT8, SCHEDULER_STACK, 256>;

template <typename T, typename ... Args>
T& TaskAlloc(Args&& ... args)
{
	return StackAlloc<T, SCHEDULER_STACK>(args ...);
}

template <typename T, UINT32 SZ>
using TSTREAM_BUILDER = STREAM_BUILDER<T, SCHEDULER_STACK, SZ>;

template <UINT32 SZ>
using TBUFFER_BUILDER = STREAM_BUILDER<UINT8, SCHEDULER_STACK, SZ>;

struct SESSION_STACK
{
	UINT32 stackSize = 16 * 1024 * 1024;
	PUINT8 startAddress;
	PUINT8 currentAddress;

	UINT32 overflowStackSize = 0;
	PUINT8 overflowStart = nullptr;
	PUINT8 overflowCurrent = nullptr;

	DICTIONARY<TOKENTYPE::NAME_SESSION, SESSION_STACK, 6000, 1000, 2000> dictionary;

	STREAM_BUILDER<USTRING, SESSION_STACK, 64> literals;
	STREAM_BUILDER<INT64, SESSION_STACK, 256> numberHandles;

	STREAM_BUILDER<TOKEN, SESSION_STACK, 256> blobHandles;
	STREAM_BUILDER<UINT8, SESSION_STACK, 16 * 1024> blobStream;

	STREAM_BUILDER<UINT8, SESSION_STACK, 4096> charStream;
	STREAM_BUILDER<STREAM_BUILDER<TOKEN, SESSION_STACK, 256>, SESSION_STACK, 16> jsTokenStreams;
	STREAM_BUILDER<STREAM_BUILDER<TOKEN, SESSION_STACK, 256>, SESSION_STACK, 32> localVariableArray; // temp array, used by parser
};

template <typename ST>
using TOKEN_BUILDER = STREAM_BUILDER<TOKEN, ST, 256>;

struct SERVICE_STACK
{
	UINT32 stackSize = 32 * 1024 * 1024;
	PUINT8 startAddress = nullptr;
	PUINT8 currentAddress = nullptr;

	UINT32 overflowStackSize = 0;
	PUINT8 overflowStart = nullptr;
	PUINT8 overflowCurrent = nullptr;

	DICTIONARY<TOKENTYPE::NAME_APP, SERVICE_STACK, 6000, 1000, 2000> dictionary;

	STREAM_BUILDER<USTRING, SERVICE_STACK, 64> literals;
	STREAM_BUILDER<INT64, SERVICE_STACK, 256> numberHandles;

	STREAM_BUILDER<TOKEN, SERVICE_STACK, 256> blobHandles;
	STREAM_BUILDER<UINT8, SERVICE_STACK, 16 * 1024> blobStream;

	STREAM_BUILDER<VISUAL_TOKEN, SERVICE_STACK, 2018> visualStream;

	STREAM_BUILDER<UINT8, SERVICE_STACK, 4096> charStream;
	STREAM_BUILDER<STREAM_BUILDER<TOKEN, SERVICE_STACK, 256>, SERVICE_STACK, 16> jsTokenStreams;
	STREAM_BUILDER<STREAM_BUILDER<TOKEN, SERVICE_STACK, 256>, SERVICE_STACK, 32> localVariableArray; // temp array, used by parser
};

struct PROCESSOR_INFO
{
	SERVICE_STACK* appStack;
	SESSION_STACK* sessionStack;
	SCHEDULER_STACK* schedulerStack;
	STASK* currentTask;
	UINT32 currentQueue;
};

struct SYSTEM_INFO
{
	GUID systemId;
	UINT32 hostVersion;

	TOKEN version;
	UINT32 buildNumber;

	UINT32 processorCount;
	UINT64 memorySize;
	UINT64 diskSize;
	UINT64 freeDiskSpace;

	UINT32 nicCount;
	UINT64 txBandwidth;
	UINT64 rxBandwidth; // in Kbits per sec
};

extern SYSTEM_INFO& SystemInfo();

extern PROCESSOR_INFO ProcessorInfo[MAX_PROCESSOR_COUNT];

extern NTSTATUS InitializeLibrary();

UINT32 UpdateCrc32(UINT32 start, const void* buf, size_t len);
constexpr UINT64 TIMEUNITS_PER_SECOND = 10000000;

template<typename T>
UINT32 ComputeCrc32(T&& buffer)
{
	return UpdateCrc32(0, buffer.data(), buffer.length());
}

typedef struct _rgb_color {
	unsigned char r, g, b;    /* Channel intensities between 0 and 255 */
} RGB, * PRGB;

struct HSV
{
	UINT32 value;

	HSV() { this->value = 0xFFFFFFFF; }

	constexpr HSV(UINT32 val) : value(val & 0xFFFFFF) {}
	constexpr HSV(UINT8 hue, UINT8 sat, UINT8 val) : value(hue << 16 | sat << 8 | val) {}

	HSV(HSV& other)
	{
		//ASSERT(other.value != 0xFFFFFFFF);
		this->value = other.value;
	}

	HSV(HSV* other) : HSV(*other) {};

	UINT8 hue() { return (UINT8)((this->value & 0xFF0000) >> 16); };
	UINT8 sat() { return (UINT8)((this->value & 0xFF00) >> 8); };
	UINT8 val() { return (UINT8)(this->value & 0xFF); };

	explicit operator bool() { return this->value != 0xFFFFFFFF; }

	bool operator ==(HSV other)
	{
		return this->value == other.value;
	}
};

HSV RGBtoHSV(RGB rgb);
RGB HSVtoRGB(HSV hsv);

#include "TLS.h"
#include "secp256r1.h"
#include "Crypto.h"
#include "Parser.h"
#include "SDP.h"
#include "X509.h"
#include "Socket.h"
#include "JsParser.h"
#include "Visual.h"

extern bool CompareLiteral(TOKEN first, TOKEN second); // always case sensitive
extern TOKEN FindJson(TOKEN_BUFFER jsonTokens, TOKEN match);

template <typename STACK>
STRING_BUILDER<STACK>& GetStringBuilder()
{
	return StackAlloc<STRING_BUILDER<STACK>, STACK>();
}

struct LANGUAGE_CODE
{
	TOKEN name;
	USTRING code;
};

constexpr LANGUAGE_CODE LanguageCodes[] = {
	{ LANG_Arabic, "ara", },
	{ LANG_Assamese, "asm", },
	{ LANG_Bengali, "ben", },
	{ LANG_Tibetan, "bod", },
	{ LANG_Burmese, "mya", },
	{ LANG_Bulgarian, "bul", },
	{ LANG_Czech, "ces", },
	{ LANG_Chechen, "che", },
	{ LANG_Danish, "dan", },
	{ LANG_German, "deu", },
	{ LANG_Dutch, "nld", },
	{ LANG_Egyptian, "egy", },
	{ LANG_English, "eng", },
	{ LANG_Persian, "fas", },
	{ LANG_Filipino, "fil", },
	{ LANG_French, "fra", },
	{ LANG_Gurajati, "guj", },
	{ LANG_Hindi, "hin", },
	{ LANG_Hebrew, "heb", },
	{ LANG_Hungarian, "hun", },
	{ LANG_Indonesian, "ind", },
	{ LANG_Italian, "ita", },
	{ LANG_Japanese, "jpn", },
	{ LANG_Kannada, "kan", },
	{ LANG_Kashmiri, "kas", },
	{ LANG_Korean, "kor", },
	{ LANG_Malayalam, "mal", },
	{ LANG_Marathi, "mar", },
	{ LANG_Nepali, "nep", },
	{ LANG_Punjabi, "pan", },
	{ LANG_Sanskrit, "san", },
	{ LANG_Sudanese, "sun", },
	{ LANG_Tamil, "tam", },
	{ LANG_Telugu, "tel", },
	{ LANG_Turkish, "tur", },
	{ LANG_Ukranian, "ukr", },
	{ LANG_Vietnamese, "vie", },
	{ LANG_Chinese, "zho", },
	{ LANG_Mandarin, "cmn", },
	{ LANG_Cantonese, "yue", },
};

// 12/12/2012 12:12:12.12
constexpr UINT64 StateOsTimeOrigin = 0x1cdd861ea6e0ac0;

// 01/01/2001 00:00:00
constexpr UINT64 MkvTimeOrigin = 0x1c07385c89dc000;

// 01/01/1970 00:00:00
constexpr UINT64 UnixTimeOrigin = 0x19db1ded53e8000;

constexpr UINT64 MkvToSystemTime(UINT64 mkvTime)
{
	return mkvTime + MkvTimeOrigin;
}

constexpr UINT64 UnixToSystemTime(UINT64 unixTime)
{
	return unixTime + UnixTimeOrigin;
}

constexpr UINT64 SystemToUnixTime(UINT64 systemTime)
{
	return systemTime - UnixTimeOrigin;
}

inline UINT64 GetSystemTime()
{
	LARGE_INTEGER currentTime;
	KeQuerySystemTimePrecise(&currentTime);

	return currentTime.QuadPart;
}

NTSTATUS ParseWebsite(USTRING appName, USTRING url);
void InitWebApps();
