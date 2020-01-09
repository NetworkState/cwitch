// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once
using TOKEN_BUFFER = STREAM_READER<const TOKEN>;

constexpr USTRING DATE_SEPARATOR = ", \t:;";

constexpr GUID NULL_GUID = { 0, 0, 0, {0} };

constexpr UINT8 GetGroupPair(UINT8 first)
{
	return first == '"' ? '"' :
		first == '\'' ? '\'' :
		first == '(' ? ')' :
		first == '[' ? ']' :
		first == '<' ? '>' :
		first == '/' ? '/' :
		first == '{' ? '}' : 0;
}

struct URL_INFO
{
	TOKEN hostname = Undefined;
	TOKEN protocol = Undefined;
	TOKEN path = Undefined;
	UINT32 port = TLS_PORT;

	TOKEN username;
	TOKEN password;

	void clear()
	{
		hostname = protocol = path = Null;
		port = TLS_PORT;
	}

	bool operator == (URL_INFO& other)
	{
		UNREFERENCED_PARAMETER(other);
		auto result = other.hostname == hostname && other.protocol == this->protocol
			&& other.path == path && other.port == port;
		return result;
	}

	URL_INFO(URL_INFO & other)
	{
		this->hostname = other.hostname;
		this->protocol = other.protocol;
		this->path = other.path;
		this->port = other.port;
	}

	URL_INFO() {}
};

template <typename STACK>
TOKENTYPE GetLiteralType();

constexpr UINT32 GUID_STRING_LENGTH = 36;
constexpr UINT32 MACADDRESS_STRING_LENGTH = 17;

struct PARSED_WORD
{
	USTRING separatorBefore;
	USTRING separatorAfter;

	USTRING wordString;
	TOKEN wordName;

	PARSED_WORD(USTRING before, USTRING word, USTRING after) : separatorBefore(before), wordString(word), separatorAfter(after) 
	{
		wordName = FindName(wordString);
	}

	PARSED_WORD(USTRING word) : wordString(word)
	{
		wordName = FindName(wordString);
	}
};

using PARSED_WORDS = STREAM_READER<const PARSED_WORD>;

struct STRINGOPS
{
	bool isGuidString(USTRING text)
	{
		auto result = false;
		if (text.length() == GUID_STRING_LENGTH)
		{
			result = true;
			for (UINT32 i = 0; i < text.length(); i++)
			{
				if (isGuidChar(text.at(i)) == false)
				{
					result = false;
					break;
				}
			}
		}
		return result;
	}

	USTRING splitString(USTRING& input, USTRING pattern)
	{
		auto match = input;
		auto start = input.data();

		while (input)
		{
			if (input.length() >= pattern.length() && memcmp(input.data(), pattern.data(), pattern.length()) == 0)
			{
				match._end = match._start + (UINT32)(input.data() - start);
				input.shift(pattern.length());
				break;
			}
			input.shift();
		}
		return match;
	}

	USTRING splitStringIf(USTRING& input, USTRING pattern)
	{
		auto originalString = input;
		auto subString = splitString(input, pattern);

		if (subString == originalString)
		{
			input = originalString;
			subString = NULL_STRING;
		}
		return subString;
	}

	template <typename STREAM>
	STREAM_READER<USTRING> splitStringToArray(USTRING& input, USTRING pattern, STREAM&& stream)
	{
		while (auto part = splitString(input, pattern))
		{
			stream.append(part);
		}
		return stream.toReader();
	}

	USTRING splitChar(USTRING& inputText, UINT8 separator)
	{
		if (inputText.length() == 0)
		{
			return USTRING();
		}

		auto result = USTRING();

		auto position = inputText.findIndex(separator); // FindChar(inputText, separator);
		ASSERT(position != 0); // separator is the first char, what to do?
		if (position > 0)
		{
			result = USTRING(inputText.data(), position);
			trim(result);
			inputText.shift(position + 1);
		}
		else
		{
			result = inputText;
			inputText.shift(inputText.length());
		}

		return result;
	}

	USTRING splitCharReverse(USTRING inputText, UINT8 seperator)
	{
		if (inputText.length() == 0)
		{
			return USTRING();
		}

		auto result = USTRING();

		auto position = inputText.findIndexReverse(seperator);
		if (position >= 0)
		{
			position++;
			result = USTRING(inputText.data(position), inputText.length() - position);
		}
		return result;
	}

	USTRING splitCharAny(USTRING& input, USTRING separator)
	{
		UINT8 separatorMatch;
		return splitCharAny(input, separator, separatorMatch);
	}

	USTRING splitCharAny(USTRING& input, USTRING separator, UINT8& separatorMatch)
	{
		auto matchText = input;

		const UINT8* match = nullptr;
		separatorMatch = 0;

		for (UINT32 i = 0; i < separator.length(); i++)
		{
			auto sep = separator[i];
			auto nextMatch = (const UINT8*)memchr(input.data(), sep, input.length());
			if (nextMatch != nullptr)
			{
				if (match == nullptr || nextMatch < match)
				{
					match = nextMatch;
					separatorMatch = sep;
				}
			}
		}

		if (match != nullptr)
		{
			auto matchLength = (UINT32)(match - input.data());
			matchText = input.toBuffer(0, matchLength); // ._end = matchText._start + matchLength;
			input.shift(matchLength + 1);
		}
		else
		{
			input.shift(input.length());
		}

		trim(matchText);
		return matchText;
	}

	template <typename STREAM>
	USTRING skipSeparators(USTRING& input, USTRING separator, STREAM&& matchSeparator)
	{
		while (input)
		{
			auto match = (const UINT8*)memchr(separator.data(), input[0], separator.length());
			if (match == nullptr)
			{
				break;
			}
			input.shift();
			matchSeparator.writeChar(*match);
		}
		return matchSeparator.toBuffer();
	}

	template <typename STREAM>
	USTRING splitChar(USTRING& input, USTRING separator, STREAM&& matchSeparator)
	{
		UINT8 separatorFound;
		auto matchText = splitCharAny(input, separator, separatorFound);
		if (separatorFound)
		{
			matchSeparator.writeByte(separatorFound);
			skipSeparators(input, separator, matchSeparator);
		}
		return matchText;
	}

	USTRING splitChar(USTRING& input, USTRING separator)
	{
		return splitChar(input, separator, TSTRING_BUILDER());
	}

	template <typename STREAM>
	STREAM_READER<USTRING> splitCharToArray(USTRING& input, USTRING separator, STREAM&& stream)
	{
		while (auto part = splitChar(input, separator))
		{
			stream.append(part);
		}
		return stream.toBufferNoConst();
	}

	template <typename STREAM>
	USTRING UnescapeHttpString(USTRING inString, STREAM&& stream)
	{
		while (inString)
		{
			auto inChar = inString.shift();
			if (inChar == '%')
			{
				auto hexChar = inString.readHexChar();
				stream.writeByte(hexChar);
			}
			else
			{
				stream.write(inChar);
			}
		}
		return stream.toBuffer();
	}

	template <typename STACK, typename URLINFO>
	URL_INFO& parseUrl(USTRING urlText, URLINFO&& urlInfo)
	{
		urlInfo.clear();

		auto matchString = splitString(urlText, "://");
		if (urlText.length() == 0)
		{
			// no protocol - relative url
			urlInfo.path = CreateCustomName<STACK>(matchString);
		}
		else
		{
			urlInfo.protocol = FindName(matchString);
			ASSERT(urlInfo.protocol);

			urlInfo.port = urlInfo.protocol == HTTP_https ? TLS_PORT : HTTP_http ? 80 : RTSP_rtsp ? 554 : 80;

			UINT8 separator;
			auto match = splitCharAny(urlText, "@/", separator);
			USTRING hostnamePort;
			if (separator == '@')
			{
				// username password
				match = UnescapeHttpString(match, GetTempStream<64>());
				urlInfo.username = CreateCustomName<STACK>(String.splitChar(match, ':'));
				urlInfo.password = CreateCustomName<STACK>(match);

				hostnamePort = String.splitCharAny(urlText, "/");
			}
			else if (separator == '/')
			{
				hostnamePort = match;
			}

			auto first = String.splitCharAny(match, ":", separator);
			if (separator == ':')
			{
				urlInfo.hostname = CreateCustomName<STACK>(first);
				urlInfo.port = toNumber(match);
			}
			else
			{
				urlInfo.hostname = CreateCustomName<STACK>(match);
			}

			urlInfo.path = CreateCustomName<STACK>(urlText);

			//auto&& separatorBuf = GetTempStream();
			//while (urlText.length() > 0)
			//{
			//	auto match = splitChar(urlText, ":/", separatorBuf);
			//	auto separator = separatorBuf.toBuffer();
			//	if (separator == "/")
			//	{
			//		if (urlInfo.hostname)
			//		{
			//			urlInfo.port = toNumber(match);
			//		}
			//		else
			//		{
			//			urlInfo.hostname = CreateName(match);
			//		}
			//		urlInfo.path = CreateName(urlText);
			//		break;
			//	}
			//	else if (separator == ":")
			//	{
			//		urlInfo.hostname = CreateName(match);
			//	}
			//	else
			//	{
			//		DBGBREAK();
			//		ASSERT(urlInfo.hostname);
			//		urlInfo.path = CreateName(match);
			//	}
			//}
		}

		return urlInfo;
	}

	UINT64 parseRfcDate(USTRING dateString)
	{
		TIME_FIELDS timeFields;
		RtlZeroMemory(&timeFields, sizeof(timeFields));

		auto dateParts = splitCharToArray(dateString, DATE_SEPARATOR, TSTRING_STREAM());
		ASSERT(dateParts.length() == 8);

		dateParts.shift(); // ignore day of week.

		timeFields.Day = (UINT16)toNumber(dateParts.shift());
		ASSERT(timeFields.Day > 0);

		auto monthName = FindName(dateParts.shift());
		if (monthName)
		{
			auto index = ArrayFind(MonthNames2, monthName);
			if (index >= 0)
				timeFields.Month = (UINT16)(index + 1);
		}

		timeFields.Year = (UINT16)toNumber(dateParts.shift());

		timeFields.Hour = (UINT16)toNumber(dateParts.shift());
		timeFields.Minute = (UINT16)toNumber(dateParts.shift());
		timeFields.Second = (UINT16)toNumber(dateParts.shift());

		auto timezone = dateParts.shift();
		ASSERT(timezone == "GMT");

		LARGE_INTEGER time;
		RtlTimeFieldsToTime(&timeFields, &time);

		return time.QuadPart;
	}

	template <typename STREAM>
	BUFFER formatHttpDate(STREAM && stream)
	{
		auto offset = stream.getPosition();

		TIME_FIELDS timeFields;
		LARGE_INTEGER elapsedTime;
		KeQuerySystemTime(&elapsedTime);
		RtlTimeToTimeFields(&elapsedTime, &timeFields);
		
		stream.writeMany(DayNames2[timeFields.Weekday], ", ");
		stream.writeMany(timeFields.Day, " ");
		stream.writeMany(MonthNames2[timeFields.Month - 1], " ");
		stream.writeMany(DateYears[timeFields.Year - 1990], " ");

		stream.writeMany(DateHours[timeFields.Hour], ":", DateMinutes[timeFields.Minute], ":", DateSeconds[timeFields.Second], " GMT");
		return offset.toBuffer();
	}


	using IPADDR = UINT32;
	using IPPORT = UINT16;

	constexpr IPADDR parseIPAddress(USTRING ipString) // in big endian
	{
		IPADDR ipAddress = 0;
		ULONG i = 0;
		for (; i < 4; i++)
		{
			auto digitString = splitChar(ipString, '.');
			if (isNumericString(digitString))
			{
				auto number = toNumber(digitString);
				if (number < 255)
				{
					ipAddress |= (number << i * 8);
				}
				else break;
			}
			else break;
		}

		if (i != 4)
			return 0;

		return ipAddress;
	}

	template<typename OUTSTREAM> // address in big endian
	BUFFER formatIPAddress(ULONG ipAddress, OUTSTREAM && stream)
	{
		LogInfo("formatIPddress = 0x%x", ipAddress);
		for (UINT32 i = 0; i < 4; i++)
		{
			auto part = (UINT8)(ipAddress >> (i * 8));
			stream.writeString((UINT64)part);
			if (i != 3) stream.writeString(".");
		}
		return stream.toBuffer();
	}

	template<typename STREAM>
	BUFFER formatIPAddress(SOCKADDR_IN socketAddress, STREAM&& stream)
	{
		auto ipAddress = socketAddress.sin_addr.s_addr;
		return formatIPAddress(ipAddress, stream);
	}

	template <typename STR>
	constexpr UINT32 toHexNumber(STR&& text)
	{
		ASSERT(text.length() <= 8);
		UINT32 number = 0;

		while (text)
		{
			auto digit = text.at(0);
			if (isHexChar(digit))
			{
				digit = ToHexNumber(text.shift());
				number = (number << 4) | (digit & 0x0F);
			}
			else break;
		}
		return number;
	}

	template <typename STR>
	INT32 stringToNumber(STR&& text)
	{
		auto start = text._start;
		auto isNegative = false;
		if (text.peek() == '-')
		{
			isNegative = true;
			text.shift();
		}

		if (startsWith(text, "0x"))
		{
			text.shift(2);
			return toHexNumber(text);
		}

		auto base = 10;
		INT32 number = 0;

		while (text)
		{
			UINT8 c = text.at(0);
			if (!isdigit(c))
				break;

			number *= base;
			number += c - '0';
			text.shift();
		}

		if (isNegative)
		{
			if ((text._start - start) == 1)
			{
				DBGBREAK();
				isNegative = false;
				text._start = start;
			}
		}

		number *= isNegative ? -1 : 1;
		return number;
	}

	INT32 toNumber(const USTRING& text)
	{
		return stringToNumber(text.clone());
	}

	INT32 toNumber(USTRING& text)
	{
		return stringToNumber(text);
	}

	UINT32 toNumber(USTRING& text, USTRING& numberString)
	{
		numberString = text.toBuffer(0, 0);
		auto number = stringToNumber(text);
		numberString._end = text._start;
		return number;
	}

	bool isNumber(USTRING text)
	{
		for (UINT32 i = 0; i < text.length(); i++)
		{
			if (!isdigit(text.at(i)))
				return false;
		}
		return true;
	}

	float toFloat(USTRING& text)
	{
		auto value = (float)toNumber(text);
		if (text.peek() == '.')
		{
			text.shift();
			USTRING numberString;
			auto fraction = (float)toNumber(text, numberString);
			if (fraction > 0)
			{
				value += (1.0f / (pow(10.0f, (int)numberString.length()))) * fraction;
			}
		}
		return value;
	}

	float toFloat(USTRING& text, USTRING& numberString)
	{
		numberString = text.toBuffer(0, 0);
		auto number = toFloat(text);
		numberString._end = text._start;
		return number;
	}

	constexpr bool isNumericString(USTRING input)
	{
		for (UINT32 i = 0; i < input.length(); i++)
		{
			if (isdigit(input.at(i)) == false)
				return false;
		}
		return true;
	}

	UINT8 toUpper(UINT8 c) const
	{
		return (c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c;
	}

	UINT8 toLower(UINT8 c) const
	{
		return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
	}

	void toUpper(USTRING& text)
	{
		auto address = (PUINT8)text.data();
		for (UINT32 i = 0; i < text.length(); i++)
		{
			*(address + i) = (UINT8)toUpper(*(address + i));
		}
	}

	void toLower(USTRING & text)
	{
		auto address = (PUINT8)text.data();
		for (UINT32 i = 0; i < text.length(); i++)
		{
			*(address + i) = (UINT8)toLower(*address);
		}
	}

	bool equals(USTRING first, USTRING second, bool isCaseSensitive = false) const
	{
		if (isCaseSensitive)
			return first == second;

		auto result = false;
		if (first.length() == second.length())
		{
			result = true;
			for (UINT32 i = 0; i < first.length(); i++)
			{
				if (toUpper(first[i]) != toUpper(second[i]))
				{
					result = false;
					break;
				}
			}
		}
		return result;
	}

	bool contains(USTRING text, UINT8 letter)
	{
		letter = toUpper(letter);
		auto result = true;
		for (UINT32 i = 0; i < text.length(); i++)
		{
			if (toUpper(text.at(i)) != letter)
			{
				result = false;
				break;
			}
		}
		return result;
	}

	USTRING& trimStart(USTRING& text)
	{
		while ((text.length() > 0) && IsWhitespace(text[0]))
			text.shift();
		
		return text;
	}

	USTRING& trimEnd(USTRING& text)
	{
		while ((text.length() > 0) && IsWhitespace(text.last()))
			text.shrink();

		return text;
	}

	USTRING& trim(USTRING& text)
	{
		while (text)
		{
			if (IsWhitespace(text.at(0)))
				text.shift();
			else break;
		}
		while (text)
		{
			if (IsWhitespace(text.last()))
				text.shrink();
			else break;
		}
		return text;
	}

	template <typename STACK>
	TOKEN allocLiteral(USTRING inputText)
	{
		if (inputText.length() == 0)
			return 0;

		auto destination = (PUINT8)StackAlloc<STACK>(inputText.length());
		RtlCopyMemory(destination, inputText.data(), inputText.length());

		auto index = GetCurrentStack<STACK>().literals.count();
		GetCurrentStack<STACK>().literals.append(destination, inputText.length());
		return TOKEN(TOKENTYPE::LITERAL_LARGE, index);
	}

	template <typename STACK>
	TOKEN parseLiteral(USTRING text)
	{
		auto value = Undefined;
		do
		{
			if (text.length() == 0)
			{
				value = EMPTY_STRING;
				break;
			}

			if (text.length() > 255)
			{
				value = allocLiteral<STACK>(text);
				break;
			}

			if (isGuidString(text))
			{
				auto guid = parseGuid(text);
				ASSERT(guid != NULL_GUID);
				if (guid != NULL_GUID)
				{
					value = CreateGuidHandle<STACK>(guid);
					break;
				}
			}
			auto name = CreateCustomName<STACK>(text, true);
			value = TOKEN(TOKENTYPE::LITERAL | name.getMinorType(), name.getValue());
		} while (false);
		return value;
	}

	template <typename STACK>
	USTRING getLiteral(TOKEN name)
	{
		USTRING result;
		if (name.getFullType() == TOKENTYPE::LITERAL_LARGE)
		{
			result = GetCurrentStack<STACK>().literals.at(NAME_INDEX(name));
		}
		else
		{
			name = TOKEN(TOKENTYPE::NAME | name.getMinorType(), name.getValue());
			result = NameToString(name);
		}
		return result;
	}

	bool endsWith(USTRING subject, USTRING match) const
	{
		auto result = false;
		if (subject.length() >= match.length())
		{
			auto endPart = subject.shrink(match.length());
			result = equals(endPart, match);
		}
		return result;
	}

	constexpr bool startsWith(USTRING subject, USTRING match)
	{
		auto result = false;
		if (subject.length() >= match.length())
		{
			result = true;
			for (UINT32 i = 0; i < match.length(); i++)
			{
				if (toUpper(subject[i]) != toUpper(match[i]))
				{
					result = false;
					break;
				}
			}
		}
		return result;
	}

	GUID parseGuid(USTRING guidString)
	{
		TSTREAM_BUILDER<USTRING, 8> partsStream;
		auto parts = splitCharToArray(guidString, "-", partsStream);

		if (parts.length() == 5)
		{
			LOCAL_STREAM<16> guidBytes;
			for (auto part : parts)
			{
				guidBytes.readHexString(part);
			}
			return guidBytes.toBuffer().readGuid();
		}

		return NULL_GUID;
	}

	template <typename STACK>
	USTRING copy(USTRING other)
	{
		auto& charStream = GetCurrentStack<STACK>().charStream;
		auto position = charStream.getPosition();
		charStream.writeStream(other);
		return position.toBuffer();
	}

	UINT8 convertEscapeSequence(USTRING& input)
	{
		auto firstChar = input.shift();
		UINT8 newChar = 0;

		if (firstChar == 'r')
		{
			newChar = '\r';
		}
		else if (firstChar == 'n')
		{
			newChar = '\n';
		}
		else if (firstChar == 'x')
		{
			newChar = input.readHexChar();
		}
		else if (firstChar == 't')
		{
			newChar = '\t';
		}
		else
		{
			newChar = firstChar;
		}
		return newChar;
	}

	void splitBlock(USTRING& input, USTRING separators, UINT32 openBraces = 0)
	{
		trim(input);
		ASSERT(separators.length() == 2);
		while (input)
		{
			STRING_BUILDER<SCHEDULER_STACK, 2> separatorStream;
			UINT8 separatorFound;
			auto matchText = splitCharAny(input, separators, separatorFound);
			if (separatorFound == 0)
			{
				DBGBREAK();
				break;
			}

			if (separatorFound == separators.at(0))
			{
				openBraces++;
			}
			else if (separatorFound == separators.at(1))
			{
				ASSERT(openBraces > 0);
				openBraces--;
				if (openBraces == 0)
					break;
			}
		}
	}

	template <typename STREAM>
	USTRING parseQuote(USTRING& input, STREAM&& quoteStream, UINT8 quoteChar = '"')
	{
		STREAM_BUILDER<UINT8, SCHEDULER_STACK, 4> separatorStream;
		auto quoteSeparator = quoteChar == '"' ? "\\\"" : "\\'";
		while (auto part = splitCharAny(input, quoteSeparator, separatorStream))
		{
			quoteStream.writeStream(part);

			auto separator = separatorStream.toBuffer();
			if (separator.peek() == '\\')
			{
				auto newChar = convertEscapeSequence(input);
				quoteStream.writeByte(newChar);
			}
			else if (separator.peek() == quoteChar)
			{
				break;
			}
		}
		return quoteStream.toBuffer();
	}
};

extern STRINGOPS String;

constexpr INT32 INLINE_NUMBER_MAX = (16 * 64 * 1024);
constexpr INT32 INLINE_NUMBER_MIN = -1 * (16 * 64 * 1024);

constexpr UINT32 INLINE_FLAG_NEGATIVE_NUMBER = 0x00100000;
constexpr UINT32 INLINE_FLAG_POSITIVE_NUMBER = 0x00200000;

constexpr UINT32 NUMBER_GLOBAL_STACK = 0x00100000;
constexpr UINT32 NUMBER_SESSION_STACK = 0x00200000;
constexpr UINT32 NUMBER_APP_STACK = 0x00300000;
constexpr UINT32 NUMBER_SCHEDULER_STACK = 0x00400000;

constexpr UINT32 BLOB_GLOBAL_STACK = 0x00100000;
constexpr UINT32 BLOB_SESSION_STACK = 0x00200000;
constexpr UINT32 BLOB_APP_STACK = 0x00300000;
constexpr UINT32 BLOB_SCHEDULER_STACK = 0x00400000;

template <typename STACK>
INT32 FindNumberHandle(INT64 number)
{
	INT32 id = -1;

	auto& numberHandles = GetCurrentStack<STACK>().numberHandles;

	numberHandles.toBuffer().indexedForEach([](const INT64 value, UINT32 index, INT32& id, INT64 match)
		{
			if (value == match)
			{
				id = index;
				return false;
			}
			return true;
		}, id, number);

	return id;
}

constexpr inline bool IsInlineNumber(INT64 number)
{
	return number > INLINE_NUMBER_MIN && number < INLINE_NUMBER_MAX;
}

template <typename STACK>
UINT32 GetNumberStack();

template <typename STACK>
UINT32 GetBlobStack();

template <typename STACK>
constexpr TOKEN CreateNumberHandle(INT64 number, TOKENTYPE tokenType = TOKENTYPE::NUMBER)
{
	TOKEN handle;

	if (number == 0)
		return TOKEN(TOKENTYPE::NUMBER, 0);

	if (IsInlineNumber(number))
	{
		if (number < 0)
		{
			number *= -1;
			number |= INLINE_FLAG_NEGATIVE_NUMBER;
		}
		else
		{
			number |= INLINE_FLAG_POSITIVE_NUMBER;
		}
		handle = TOKEN(tokenType, (UINT32)number);
	}
	else
	{
		auto index = FindNumberHandle<STACK>(number);
		if (index == -1)
		{
			auto id = GetCurrentStack<STACK>().numberHandles.write(number);
			handle = TOKEN(tokenType, id | GetNumberStack<STACK>());
		}
		else
		{
			handle = TOKEN(tokenType, (UINT32)index | GetNumberStack<STACK>());
		}
	}
	return handle;
}

template <typename STACK>
TOKEN CreateTimestampHandle(UINT64 inputNumber)
{
	auto number = (INT64)inputNumber;

	TOKEN handle;
	auto index = FindNumberHandle<STACK>(number);
	if (index != -1)
	{
		handle = TOKEN(TOKENTYPE::NUMBER_TIMESTAMP, (UINT32)index);
	}
	else
	{
		auto id = GetCurrentStack<STACK>().numberHandles.write(number);
		handle = TOKEN(TOKENTYPE::NUMBER_TIMESTAMP, id);
	}
	return handle;
}

template <typename STACK>
UINT64 GetTimestampValue(TOKEN token)
{
	return GetCurrentStack<STACK>().numberHandles.at(token.getValue());
}

extern INT64 GetNumberHandleValue(TOKEN handle);

template <typename STACK>
TOKEN CreateBlobHandle(BUFFER blobData, TOKENTYPE tokenType = TOKENTYPE::BLOB)
{
	auto& stack = GetCurrentStack<STACK>();

	auto position = stack.blobStream.getPosition();
	stack.blobStream.writeVInt(blobData.length());
	stack.blobStream.writeStream(blobData);

	auto token = TOKEN(tokenType, position.offset | GetBlobStack<STACK>());
	stack.blobHandles.append(token);

	return token;
}


template <typename STACK>
TOKEN FindBlobHandle(TOKENTYPE type, BUFFER matchData)
{
	auto& stack = GetCurrentStack<STACK>();
	TOKEN result = Null;
	for (auto token : stack.blobHandles.toBuffer())
	{
		if (token.getFullType() == type)
		{
			auto dataStart = stack.blobStream.toBuffer(token.getValue() & 0xFFFFF);
			if (dataStart.readVInt() == matchData.length())
			{
				if (RtlCompareMemory((PUINT8)dataStart.data(), matchData.data(), matchData.length()) == matchData.length())
				{
					result = token;
					break;
				}
			}
		}
	}

	return result;
}

constexpr UINT32 GUID_LENGTH = 16;

constexpr UINT32 MAC_ADDRESS_LENGTH = 6;
using MACADDRESS = UINT8[MAC_ADDRESS_LENGTH];

constexpr UINT32 MAC_HEADER_LENGTH = 14;

BUFFER GetBlobData(TOKEN token);

template <typename STACK>
TOKEN CreateGuidHandle(GUID guid)
{
	LOCAL_STREAM<GUID_LENGTH> byteStream;
	byteStream.writeGuid(guid);

	auto blobInput = byteStream.toBuffer();
	auto handle = FindBlobHandle<STACK>(TOKENTYPE::BLOB_GUID, blobInput);
	if (!handle)
	{
		handle = CreateBlobHandle<STACK>(blobInput, TOKENTYPE::BLOB_GUID);
	}

	return handle;
}

extern GUID GetGuidHandleValue(TOKEN handle);

template <typename STACK>
TOKEN CreateMacAddressHandle(BUFFER macAddress)
{
	auto handle = FindBlobHandle<STACK>(TOKENTYPE::BLOB_MACADDRESS, macAddress);
	if (!handle)
	{
		handle = CreateBlobHandle<STACK>(macAddress, TOKENTYPE::BLOB_MACADDRESS);
	}
	return handle;
}

template <typename STACK>
BUFFER GetMacAddress(TOKEN token)
{
	return GetBlobData<STACK>(token);
}

enum PT : UINT8
{
	PT_UNKNOWN,
	PT_WORD,
	PT_TERMINATOR,
};

enum PARSER_OPTIONS
{
	PF_NONE,
	PF_COLLAPSE_SPACE = 0x01,
	PF_CASE_SENSITIVE = 0x02,
	PF_CAPTURE_SPACE = 0x04,
	PF_SPLIT_SPACE = 0x08,
	PF_RAW_TEXT = 0x10,
};
DEFINE_ENUM_FLAG_OPERATORS(PARSER_OPTIONS)

struct TPATTERN
{
	PT type = PT_UNKNOWN;
	UINT8 id;
	bool isMatching = true;
	USTRING expression;
	INT32 matchStart = -1;

	TPATTERN() {}

	TPATTERN(PT type, USTRING pattern) : type(type), expression(pattern) {}

	TPATTERN& reset()
	{
		this->isMatching = true;
		this->expression.rewind();
		this->matchStart = -1;
		return *this;
	}

	explicit operator bool()
	{
		return IsNullRef(*this) == false;
	}
};

enum class CONTENT_TYPE
{
	UNKNOWN,
	HTML,
	JSON,
	CSS,
	JAVASCRIPT,
	IMAGE,
	TEXT,
	XML,
	URL,
};

constexpr UINT8 PATTERN_FLAG = 0x80;
constexpr UINT8 PATTERN_FLAG_CHAR_CLASS = 0x81;
constexpr UINT8 PATTERN_FLAG_ZERO_OR_MORE = 0x82;
constexpr UINT8 PATTERN_FLAG_ONE_OR_MORE = 0x84;
constexpr UINT8 PATTERN_FLAG_OPTIONAL = 0x88;

constexpr UINT8 CTRL_Z = '\x1A';

enum CHAR_CLASS : UINT8
{
	CcUnknown,
	CcAlphaNumeric,
	CcNumeric,
	CcAlpha,
	CcUpperAlpha,
	CcLowerAlpha,
	CcUpperNumeric,
	CcLowerNumeric,
	CcHtmlAttribute,
	CcHtmlAttrSeparators,
	CcUrlSeparators,
	CcJsChars,
	CcJsOperators,
	CcJsSeparators,
	CcQuotes,
	CcSingleQuoteChars,
	CcDoubleQuoteChars,
	CcSingleQuoteTerminators,
	CcDoubleQuoteTerminators,
	CcRegexTerminators,
	CcSelectorChars,
	CcSelectorSeparators,
	CcDoubleSelectorSeparators,
	CcSpaceTab,
	CcSelectorCombinators,
	CcSelectorPrefixes,
	CcStyleSeparators,

	CcPropertySeparators,
	CcPropertyChars,
	CcPropertySpecialChars,
	CcPropertySplitters,
	CcPropertyTerminators,
	CcHtmlEntity,
	CcHexChars,
	CcHtmlTextChars,

	CcWordSeparators,
	CcAnyChar,

	CcWhitespace,
	CcStyleWordSeparators,
	CcStyleGroupChars,
	CcStyleTerminators,

	CcMediaSeparators,
	CcMediaTerminators,
	CcMediaGroupChars,

	CcMax
};
static char QuotePattern[] = { PATTERN_FLAG_CHAR_CLASS, CcQuotes};

constexpr UINT8 EscapeSequence[] = { '\\', PATTERN_FLAG_CHAR_CLASS, CcAnyChar };
constexpr UINT8 DoubleQuoteTerminators[] = { PATTERN_FLAG_CHAR_CLASS, CcDoubleQuoteTerminators };
constexpr UINT8 SingleQuoteTerminators[] = { PATTERN_FLAG_CHAR_CLASS, CcSingleQuoteTerminators };
constexpr UINT8 RegexTerminators[] = { PATTERN_FLAG_CHAR_CLASS, CcRegexTerminators };
extern STREAM_READER<USTRING> CharClass();

enum PARSE_EXPRESSION_FLAGS
{
	EF_NONE,
	EF_COMMA_IS_SEPARATOR = 0x01,
	EF_COLON_IS_SEPARATOR = 0x02,
};
DEFINE_ENUM_FLAG_OPERATORS(PARSE_EXPRESSION_FLAGS);

constexpr USTRING BeginCData = "[CDATA[";
constexpr USTRING EndCData = "]]>";

struct PARSER_INFO
{
	CONTENT_TYPE contentType;
	USTRING inputText;
	USTRING revertPoint;

	USTRING matchText;
	USTRING terminatorText;

	UINT8 terminatorBuffer[256];

	TPATTERN* matchingPattern;

	STRING_BUILDER<SCHEDULER_STACK, 256> parsedText;

	bool atEOF = false;

	PARSER_INFO(CONTENT_TYPE type, USTRING inputText) : inputText(inputText), contentType(type)
	{
		parsedText.reserve(inputText.length());
	}

	void revert()
	{
		this->inputText = this->revertPoint;
		this->matchText = this->terminatorText = NULL_STRING;
	}

	USTRING mark()
	{
		return this->inputText;
	}

	void revert(USTRING text)
	{
		this->inputText = text;
		this->matchText = this->terminatorText = NULL_STRING;
	}

	explicit operator bool() { return IsNullRef(*this) == false; };

	void parseBlockComment(USTRING& data)
	{
		while (data.length() > 0)
		{
			auto c = data.readChar();
			if (c == '*' && data.at(0) == '/')
			{
				data.shift();
				break;
			}
		}
	}

	void parseLineComment(USTRING& data)
	{
		while (data.length() > 0)
		{
			auto c = data.readChar();
			if (c == '\n')
			{
				break;
			}
		}
	}

	bool trimComment(PARSER_OPTIONS)
	{
		auto foundComment = false;
		if (this->contentType == CONTENT_TYPE::HTML)
		{
			if (inputText[0] == '<' && inputText[1] == '!')
			{
				inputText.shift(2);
				if (inputText[0] == '-' && inputText[1] == '-')
				{
					inputText.shift(2);
					while (inputText)
					{
						auto c = inputText.readChar();
						if (c == '-' && inputText.at(0) == '-' && inputText.at(1) == '>')
						{
							inputText.shift(2);
							break;
						}
					}
				}
				else if (inputText.at(0) == BeginCData[0] && inputText.at(1) == BeginCData[1] &&
					inputText.at(2) == BeginCData[2] && inputText.at(3) == BeginCData[3] &&
					inputText.at(4) == BeginCData[4] && inputText.at(5) == BeginCData[5] &&
					inputText.at(6) == BeginCData[6])
				{
					inputText.shift(7);
					DBGBREAK(); // XXX trouble!!, recursive call?
								//tokens.writeString(ParseCData2(parseText));
				}
				else
				{
					// preprocessing
					for (auto c = inputText.readChar(); c != '>' && c != 0; c = inputText.readChar());
				}
				String.trim(inputText);
				foundComment = true;
			}
		}
		else if (this->contentType == CONTENT_TYPE::JAVASCRIPT || this->contentType == CONTENT_TYPE::CSS ||
			this->contentType == CONTENT_TYPE::JSON)
		{
			if (inputText[0] == '/' && inputText[1] == '*')
			{
				inputText.shift(2);
				parseBlockComment(inputText);
				foundComment = true;
			}
			else if (inputText[0] == '/' && inputText[1] == '/')
			{
				inputText.shift(2);
				parseLineComment(inputText);
				foundComment = true;
			}
		}
		return foundComment;
	}

	UINT8 getNextChar(PARSER_OPTIONS options)
	{
		UINT8 thisChar = 0;
		if (inputText.length() == 0)
		{
			if (this->atEOF)
			{
				thisChar = 0;
			}
			else
			{
				thisChar = CTRL_Z;
				this->atEOF = true;
			}
		}
		else
		{
			while (inputText.length() > 0)
			{
				if ((options & PF_RAW_TEXT) == 0)
				{
					if (this->trimComment(options))
						continue;
				}
				thisChar = inputText[0];
				break;
			}
		}
		ASSERT(thisChar != 0 || inputText.length() == 0);
		return thisChar;
	}

	bool matchCharClass(UINT8 patternIndex, UINT8 inputChar)
	{
		auto pattern = CharClass()[patternIndex];
		auto negate = false;
		auto found = false;
		for (UINT32 i = 0; i < pattern.length(); i++)
		{
			if (pattern[i] == 1)
			{
				negate = true;
			}
			else if (pattern[i] == 2)
			{
				if (inputChar >= 'a' && inputChar <= 'z')
				{
					found = true;
					break;
				}
			}
			else if (pattern[i] == 3)
			{
				if (inputChar >= 'A' && inputChar <= 'Z')
				{
					found = true;
					break;
				}
			}
			else if (pattern[i] == 4)
			{
				if (inputChar >= '0' && inputChar <= '9')
				{
					found = true;
					break;
				}
			}
			else if (pattern[i] == 5)
			{
				found = true;
			}
			else if (pattern[i] == inputChar)
			{
				found = true;
				break;
			}
		}
		return negate ? !found : found;
	}

	bool matchChar(USTRING& expression, UINT8 inputChar)
	{
		if (inputChar == 0)
			return false;

		auto shiftCount = 0;
		UINT8 patternFlag = expression ? expression[0] & PATTERN_FLAG ? (expression[0] & ~PATTERN_FLAG) : 0 : 0;

		auto charMatched = false;
		if (patternFlag & PATTERN_FLAG_ONE_OR_MORE)
		{
			charMatched = matchCharClass(expression[1], inputChar);
			shiftCount = 2;
		}
		else if (patternFlag & (PATTERN_FLAG_ZERO_OR_MORE | PATTERN_FLAG_OPTIONAL))
		{
			charMatched = matchCharClass(expression[1], inputChar);
			shiftCount = 2;
			if (charMatched == false && expression.length() > 2)
			{
				shiftCount = 0;
				expression.shift(2);
				charMatched = matchChar(expression, inputChar);
			}
		}
		else
		{
			if (patternFlag & PATTERN_FLAG_CHAR_CLASS)
			{
				charMatched = matchCharClass(expression[1], inputChar);
				shiftCount = 2;
			}
			else if (expression)
			{
				charMatched = expression[0] == inputChar;
				shiftCount = 1;
			}
			else
			{
				charMatched = false;
			}
			if (charMatched == false)
			{
				auto patternChar = expression._start >= 2 ? expression.at(-2) : 0;
				if ((patternChar & PATTERN_FLAG) && ((patternChar & ~PATTERN_FLAG) & (PATTERN_FLAG_ONE_OR_MORE | PATTERN_FLAG_ZERO_OR_MORE)))
				{
					charMatched = matchCharClass(expression[-1], inputChar);
					shiftCount = 0;
				}
			}
		}

		if (charMatched)
			expression.shift(shiftCount);

		return charMatched;
	}

	bool isPatternMatchComplete(TPATTERN & pattern)
	{
		auto expression = pattern.expression; // copy
		while (expression.length() > 0)
		{
			auto patternChar = expression[0];
			if (((patternChar & PATTERN_FLAG_ZERO_OR_MORE) == PATTERN_FLAG_ZERO_OR_MORE)
				|| ((patternChar & PATTERN_FLAG_OPTIONAL) == PATTERN_FLAG_OPTIONAL))
			{
				expression.shift(2);
			}
			else break;
		}
		return expression.length() == 0;
	}

	USTRING parseQuote(UINT8 quoteChar)
	{
		auto&& parser = *this;

		auto quoteStart = parser.parsedText.count();

		TPATTERN escapePattern{ PT_TERMINATOR, EscapeSequence };
		TPATTERN endPattern;
		endPattern.type = PT_TERMINATOR;
		if (quoteChar == '"')
			endPattern.expression = DoubleQuoteTerminators;
		else if (quoteChar == '\'')
			endPattern.expression = SingleQuoteTerminators;
		else if (quoteChar == '/')
			endPattern.expression = RegexTerminators;

		while (auto & capture = parser.match(PF_RAW_TEXT, escapePattern, endPattern))
		{
			if (capture.id == 1)
			{
				break;
			}
			else if (capture.id == 0)
			{
				auto escapeChar = parser.terminatorText[1];

				if (escapeChar <= 0x1F)
					continue;

				auto newChar = escapeChar;
				if (escapeChar >= '0' && escapeChar <= '9')
					newChar = escapeChar - '0';
				else if (escapeChar == 'r')
					newChar = '\r';
				else if (escapeChar == 'n')
					newChar = '\n';
				else if (escapeChar == 'x')
				{
					ASSERT(parser.inputText.length() >= 2);
					auto firstHex = parser.inputText[0];
					auto secondHex = parser.inputText[1];
					if (isxdigit(firstHex) && isxdigit(secondHex))
					{
						newChar = ToHexNumber(firstHex) << 4 | ToHexNumber(secondHex);
						parser.inputText.shift(2);
					}
				}
				else if (escapeChar == 'u')
				{
					DBGBREAK();
				}
				parser.parsedText.writeChar(newChar);
			}
		}

		parser.matchText = parser.parsedText.toBuffer(quoteStart);
		return parser.matchText;
	}

	template <typename ... PatternArgs>
	TPATTERN& match(PARSER_OPTIONS options, PatternArgs&& ... patternArgs)
	{
		if (this->atEOF)
		{
			ASSERT(inputText.length() == 0);
			return NullRef<TPATTERN>();
		}

		TPATTERN* patternList[] = { (&patternArgs) ... };
		for (int i = 0; i < ARRAYSIZE(patternList); i++)
		{
			auto& pattern = *patternList[i];
			pattern.id = (UINT8)i;
			pattern.reset();
		}
		bool collapseWhitespace = options & PF_COLLAPSE_SPACE;
		bool splitWhitespace = options & PF_SPLIT_SPACE;

		if (collapseWhitespace || splitWhitespace)
		{
			while (this->inputText.length() > 0)
			{
				String.trimStart(inputText);
				if (trimComment(options))
					continue;
				break;
			}
		}

		if (this->inputText.length() == 0)
		{
			this->atEOF = true;
			return NullRef<TPATTERN>();
		}

		this->revertPoint = this->inputText;

		this->matchingPattern = nullptr;

		auto parserTextStart = this->parsedText.count();

		UINT8 thisChar = 0, previousChar = 0;
		while (true)
		{
			previousChar = thisChar;
			thisChar = getNextChar(options);
			if (thisChar == 0)
				break;

			if (collapseWhitespace && IsWhitespace(thisChar))
			{
				if (IsWhitespace(previousChar))
				{
					DBGBREAK(); // XXX what is the logic here?
					inputText.shift(1);
					continue;
				}
				else if (previousChar == 0)
				{
					String.trimStart(inputText);
					thisChar = 0;
					continue;
				}
				thisChar = ' ';
			}

			auto shouldContinue = false;
			for (auto patternPtr : patternList)
			{
				auto& pattern = *patternPtr;
				if (pattern.isMatching)
				{
					auto charMatched = matchChar(pattern.expression, (UINT8)tolower(thisChar));
					if (charMatched)
					{
						if (pattern.type == PT_TERMINATOR && pattern.matchStart < 0)
						{
							pattern.matchStart = this->parsedText.count();
						}
						shouldContinue = true;
					}
					else
					{
						if (pattern.type == PT_WORD)
						{
							pattern.isMatching = false;
							if (isPatternMatchComplete(pattern))
							{
								this->matchingPattern = &pattern;
								break;
							}
						}
						else if (pattern.type == PT_TERMINATOR)
						{
							if (isPatternMatchComplete(pattern))
							{
								this->matchingPattern = &pattern;
								shouldContinue = false;
								break;
							}
							else
							{
								shouldContinue = true;
								pattern.matchStart = -1;
								pattern.expression.rewind();
							}
						}
					}
				}
			}
			if (shouldContinue == false)
			{
				break;
			}
			if (thisChar != CTRL_Z)
			{
				parsedText.writeChar(thisChar);
				inputText.shift(1);
			}
		}

		if (this->atEOF && this->matchingPattern == nullptr)
		{
			for (auto pattern : patternList)
			{
				if (isPatternMatchComplete(*pattern))
				{
					this->matchingPattern = pattern;
					break;
				}
			}
		}

		if (this->matchingPattern != nullptr)
		{
			if (this->matchingPattern->type == PT_TERMINATOR)
			{
				ASSERT(this->matchingPattern->matchStart >= 0);  // match is the terminator text...
				auto terminatorLength = this->parsedText.count() - this->matchingPattern->matchStart;
				ASSERT(terminatorLength < sizeof(terminatorBuffer));
				RtlCopyMemory(this->terminatorBuffer, this->parsedText.address(this->matchingPattern->matchStart), terminatorLength);
				this->terminatorText = USTRING{ (const UINT8*)this->terminatorBuffer, 0, terminatorLength };

				if (this->terminatorText.length() > 1)
					String.trim(this->terminatorText);

				this->parsedText.trim(this->parsedText.count() - this->matchingPattern->matchStart);
			}
			else
			{
				this->terminatorText = NULL_STRING;
			}
			this->matchText = this->parsedText.toBuffer(parserTextStart);
		}
		else
		{
			this->matchText = this->terminatorText = NULL_STRING;
			this->inputText = this->revertPoint;  // restore input
		}

		//ASSERT(this->matchingPattern != nullptr || atEOF);
		return this->matchingPattern ? *this->matchingPattern : NullRef<TPATTERN>();
	}

	template <typename ... PatternArgs>
	USTRING matchWord(PatternArgs&& ... patternArgs)
	{
		TPATTERN quotePattern{ PT_TERMINATOR, QuotePattern };

		auto options = PF_COLLAPSE_SPACE;
		auto wordStart = this->parsedText.count();

		this->matchText = NULL_STRING;

		while (auto& pattern = this->match(options, quotePattern, (patternArgs) ...))
		{
			options = PF_NONE;
			if (pattern.id == 0)
			{
				auto quoteChar = this->terminatorText[0];
				parseQuote(quoteChar);
			}
			else
			{
				this->matchText = this->parsedText.toBuffer(wordStart);
				break;
			}
		}

		return this->matchText;
	}

	USTRING matchBlock(USTRING beginTag, USTRING endTag, bool insideBlock = true)
	{
		TPATTERN beginPattern{ PT_TERMINATOR, beginTag };
		TPATTERN endPattern{ PT_TERMINATOR, endTag };

		UINT32 recursiveCount = insideBlock ? 1 : 0;
		//if (insideBlock == false)
		//{
		//	auto tagMatch = match(PF_COLLAPSE_SPACE, beginPattern);
		//	ASSERT(tagMatch);
		//}
		auto matchStart = parsedText.count();

		while (auto& pattern = match(PF_COLLAPSE_SPACE, beginPattern, endPattern))
		{
			if (pattern.id == 0)
			{
				recursiveCount++;
			}
			else if (pattern.id == 1)
			{
				if (--recursiveCount == 0)
				{
					break;
				}
			}
		}
		return parsedText.toBuffer(matchStart);
	}

	template <typename STREAM>
	USTRING parseWords(USTRING wordSeparators, USTRING groupChars, USTRING terminators, STREAM&& wordStream)
	{
		USTRING separatorBefore, separatorAfter;

		if (match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, wordSeparators }))
		{
			String.trim(matchText);
			separatorBefore = matchText;
		}

		for (;;)
		{
			if (auto& capture = match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, groupChars }, TPATTERN{ PT_TERMINATOR, wordSeparators }, TPATTERN{ PT_TERMINATOR, terminators }))
			{
				auto lineEnd = false;
				USTRING wordString;
				if (capture.id == 0)
				{
					auto quoteChar = String.trim(matchText).last();
					if (quoteChar == '\'' || quoteChar == '"')
					{
						wordString = parseQuote(quoteChar);
					}
					else
					{
						UINT8 pairString[] = { GetGroupPair(quoteChar) };
						if (match(PF_COLLAPSE_SPACE, TPATTERN{ PT_TERMINATOR, pairString }))
						{
							wordString = matchText;
						}
						else DBGBREAK();
					}

					separatorAfter = NULL_STRING;
					if (match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, wordSeparators }))
					{
						separatorAfter = String.trim(matchText);
					}
				}
				else if (capture.id == 1)
				{
					wordString = String.trim(matchText);
					separatorAfter = String.trim(terminatorText);
				}
				else if (capture.id == 2)
				{
					separatorAfter = String.trim(terminatorText);
					wordString = String.trim(matchText);
					lineEnd = true;
				}

				if (wordString)
				{
					wordStream.append(separatorBefore, wordString, separatorAfter);
					separatorBefore = separatorAfter;
				}

				if (lineEnd)
					break;
			}
			else DBGBREAK();
		}
		ASSERT(separatorAfter || atEOF);
		return separatorAfter;
	}

	//template <typename STREAM>
	//auto parseWords(USTRING wordSepartors, USTRING lineSeparators, USTRING blockSeparators, STREAM&& wordStream)
	//{
	//	USTRING separatorBefore, separatorAfter;
	//	USTRING quoteSeparators = "'\"";

	//	if (match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, wordSepartors }))
	//	{
	//		separatorBefore = matchText;
	//	}

//	if (match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, blockSepartors }))
//	{
//		return NULL_STRING;
//	}

//	for (;;)
//	{
//		USTRING wordString;
//		auto lastWord = false;
//		if (match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, quoteSeparators }))
//		{
//			wordString = parseQuote(matchText.last());
//			if (auto& capture = match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, wordSepartors }, TPATTERN{ PT_WORD, lineSeparators }, TPATTERN{ PT_WORD, blockSeparators }))
//			{
//				separatorAfter = matchText;
//				lastWord = capture.id == 1 || capture.id == 2;
//			}
//			else DBGBREAK();
//		}
//		else
//		{
//			if (auto& capture = match(PF_COLLAPSE_SPACE, TPATTERN{ PT_TERMINATOR, wordSepartors }, TPATTERN{ PT_TERMINATOR, lienSeparators }, TPATTERN{ PT_TERMINATOR, blockSEparators }))
//			{
//				wordString = matchText;
//				separatorAfter = terminatorText;
//				lastWord = capture.id == 1 || capture.id == 2;
//			}
//			else DBGBREAK();
//		}

//		if (wordString)
//		{
//			wordStream.append(separatorBefore, wordString, separatorAfter);
//			separatorBefore = separatorAfter;
//		}
//		if (lastWord)
//			break;
//	}

//	return separatorAfter;
//}
};

static auto UserAgent = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36\r\n";
constexpr USTRING HTTP_HEADER_NAME_PATTERN = ": \t";
constexpr USTRING WHITESPACE_PATTERN = " \t";
constexpr USTRING HTTP_HEADERS_DELIMITER = "\r\n\r\n";

constexpr USTRING COOKIE_PARAM_SEPARATOR = " \t;";
constexpr USTRING COOKIE_NAME_SEPARATOR = " \t-";

struct HTTP_COOKIE
{
	TOKEN name;
	TOKEN value;

	UINT64 expires;
	TOKEN path = HTTP_SLASH;
	TOKEN domain;

	explicit operator bool() const { return IsValidRef(*this); }
	HTTP_COOKIE(TOKEN nameArg) : name(nameArg) {};
};

constexpr TOKEN HttpProtocols[] = { HTTP_http, RTSP_rtsp };

constexpr USTRING HttpHeaderPairDelimiters = "=;\"";
constexpr USTRING HttpHeaderListDelimiters = ",\"";

struct HTTP_OPS
{
	struct HEADER_PAIR
	{
		USTRING Name;
		USTRING value;
	};

	USTRING getResponseHeaders(BUFFER& socketData)
	{
		auto headers = String.splitStringIf(socketData, HTTP_HEADERS_DELIMITER);
		return headers;
	}

	template <typename FUNC, typename ... ARGS>
	void parseHeaders(USTRING headers, FUNC callback, ARGS&& ... args)
	{
		String.splitString(headers, CRLF); // get past the status line!

		while (auto line = String.splitString(headers, CRLF))
		{
			auto nameString = String.splitChar(line, HTTP_HEADER_NAME_PATTERN);
			auto name = FindName(nameString);

			callback(name, line, args ...);
		}
	}

	template <typename STREAM, typename FUNC, typename ... ARGS>
	void parseHeaderValuePairs(USTRING headerText, STREAM&& valueStream, FUNC callback, ARGS&& ... args)
	{
		UINT8 separator;
		while (auto name = String.splitCharAny(headerText, "=;,", separator))
		{
			USTRING valueStart = valueStream.getPosition();
			if (separator == '=')
			{
				while (auto part = String.splitCharAny(headerText, ";\"", separator))
				{
					valueStream.writeStream(part);
					if (separator == '"')
					{
						part = String.parseQuote(headerText, valueStream);
						valueStream.writeStream(part);
					}
					else if (separator == ';' || separator == 0)
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

			auto shouldContinue = callback(name, valueStream.toBuffer(valueStart), args ...);
			if (shouldContinue == false)
				break;
		}
	}

	template <typename STREAM, typename FUNC, typename ... ARGS>
	void parseHeaderValueList(USTRING headerText, STREAM&& valueStream, FUNC callback, ARGS&& ... args)
	{
		UINT8 separator;
		USTRING valueStart = valueStream.getPosition();
		while (auto name = String.splitCharAny(headerText, ",\";=", separator))
		{
			valueStream.writeStream(part);
			if (separator == '"')
			{
				String.parseQuote(headerText, valueStream);
			}
			else if (separator == ',' || separator == 0)
			{
				auto shouldContinue = callback(name, valueStream.toBuffer(valueStart), args ...);
				valueStart = valueStream.getPosition();
				if (shouldContinue == false)
					break;
			}
			else
			{
				DBGBREAK();
			}
		}
	}

	template <typename STREAM>
	USTRING parseHeaderValue(USTRING headerText, STREAM&& valueStream)
	{
		UINT8 separator;
		USTRING valueStart = valueStream.getPosition();
		while (auto name = String.splitCharAny(headerText, ",\";=", separator))
		{
			valueStream.writeStream(part);
			if (separator == '"')
			{
				String.parseQuote(headerText, valueStream);
			}
			else break;
		}
		return valueStream.toBuffer(valueStart);
	}

	USTRING findHeader(USTRING headers, TOKEN name)
	{
		USTRING returnValue;

		parseHeaders(headers, [](TOKEN headerName, USTRING headerValue, TOKEN matchName, USTRING& returnValue)
			{
				if (headerName == matchName)
				{
					returnValue = headerValue;
				}
			}, name, returnValue);

		return returnValue;
	}

	bool isRequest(USTRING headers)
	{
		auto result = false;
		auto firstLine = String.splitString(headers, CRLF);
		auto version = String.splitChar(firstLine, WHITESPACE_PATTERN);

		if (String.startsWith(version, "HTTP") || String.startsWith(version, "RTSP"))
		{
			result = true;
		}
		return result;
	}

	bool isResponse(USTRING headers)
	{
		return !isRequest(headers);
	}

	TOKEN getMethod(USTRING headers)
	{
		ASSERT(isRequest(headers));

		auto firstLine = String.splitString(headers, CRLF);
		auto methodString = String.splitChar(firstLine, WHITESPACE_PATTERN);

		return FindName(methodString);
	}

	TOKEN getStatus(USTRING headers)
	{
		ASSERT(isResponse(headers));

		auto firstLine = String.splitString(headers, CRLF);

		String.splitChar(firstLine, WHITESPACE_PATTERN); // version
		auto status = String.splitChar(firstLine, WHITESPACE_PATTERN);

		ASSERT(status);
		return FindName(status);
	}

};

extern HTTP_OPS Http;

template <typename HT>
void Utf8Decode(USTRING& input, WSTRING_BUILDER<HT>& output)
{
	wchar_t unicode = 0;
	int byteSequence = 1;
	while (input.length() > 0)
	{
		auto c = input.readChar();
		if (c <= 0x7F)
		{
			ASSERT(byteSequence == 1);
			unicode = (wchar_t)c;
			output.writeChar((wchar_t)c);
		}
		else if (c >= 0x80 && c <= 0xBF)
		{
			ASSERT(byteSequence > 0);
			unicode <<= 6;
			unicode |= (c & 0x3F);
			if (--byteSequence == 1)
			{
				output.writeChar(unicode);
			}
		}
		else if (c >= 0xC2 && c <= 0xDF)
		{
			byteSequence = 2;
			unicode = c & 0x1F;
		}
		else if (c >= 0xE0 && c <= 0xEF)
		{
			byteSequence = 3;
			unicode = c & 0x0F;
		}
		else if (c >= 0xF0 && c <= 0xFF)
		{
			byteSequence = 4;
			unicode = c & 0x07;
		}
	}
}

enum SELECTOR_TYPE
{
	SEL_NONE,
	SEL_DESCENDANT,
	SEL_CHILD,
	SEL_SIBLING,
	SEL_ADJACENT_SIBLING,
	SEL_ATTR,
	SEL_ATTR_EQUALS,
	SEL_ATTR_CONTAINS,
	SEL_ATTR_BEGINS_WITH,
	SEL_ATTR_ENDS_WITH,
	SEL_ATTR_SPACED,
	SEL_ATTR_HYPHENATED,
	SEL_PSEUDO_CLASS,
	SEL_PSEUDO_ELEMENT,
};

struct SELECTOR_MAP
{
	SELECTOR_TYPE type;
	USTRING text;
};

SELECTOR_MAP SelectorMap[];

enum CSS_SEPARATOR
{
	CSEP_NONE,
	CSEP_DESCENDANT,
	CSEP_CHILD,
	CSEP_SIBLING,
	CSEP_ADJ_SIBLING,
	CSEP_ATTR_START,
	CSEP_ATTR_END,
	CSEP_ATTR_EQUALS,
	CSEP_ATTR_CONTAINS,
	CSEP_ATTR_BEGINS_WITH,
	CSEP_ATTR_ENDS_WITH,
	CSEP_ATTR_SPACED,
	CSEP_ATTR_HYPHENATED,
	CSEP_PSEUDO_CLASS,
	CSEP_PSEUDO_ELEMENT,
	CSEP_COMMA,
	CSEP_VALUE_START,
	CSEP_PARENTHESIS,
};

struct CSS_SEPARATOR_MAP
{
	CSS_SEPARATOR separator;
	USTRING text;
};

