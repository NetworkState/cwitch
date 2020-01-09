#include "pch.h"
#include "..\UMLibrary\Types.h"

#include "Tls.h"
#include "tls12.h"

// For testing TLS 1.2 handshake, don't use in production.  (Use TLS 1.3 instead)

static auto UserAgent = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36\r\n";
struct NAME_VALUE_PAIR
{
	RTHANDLE name;
	USTRING value;
};

using HEADER_TABLE = STREAM_BUILDER<NAME_VALUE_PAIR, STACK_TYPE::GLOBAL, 8>;

static USTRING HTTP_HEADER_NAME_PATTERN = ": \t";
static USTRING WHITESPACE_PATTERN = " \t";
static USTRING HTTP_HEADERS_DELIMITER = "\r\n\r\n";

template <typename T>
static auto ParseHeader(USTRING headerString, T&& headers)
{
	headers.clear();
	while (auto line = SplitString(headerString, CRLF))
	{
		auto header = SplitChar(line, HTTP_HEADER_NAME_PATTERN);
		auto headerName = FindName(header);
		if (headerName)
		{
			NAME_VALUE_PAIR pair{ headerName, line };
			headers.write(pair);
		}
	}
	return headers.toBuffer();
}

static USTRING DATE_SEPARATOR = ", \t:;";
static RTHANDLE DayNames1[] = { DATE_SUNDAY, DATE_MONDAY, DATE_TUESDAY, DATE_WEDNESDAY, DATE_THURSDAY, DATE_FRIDAY, DATE_SATURDAY };
static RTHANDLE DayNames2[] = { DATE_SUN, DATE_MON, DATE_TUE, DATE_WED, DATE_THU, DATE_FRI, DATE_SAT };

static RTHANDLE MonthNames1[] = { DATE_JANUARY, DATE_FEBRUARY, DATE_MARCH, DATE_APRIL, DATE_MAY, DATE_JUNE, DATE_JULY, DATE_AUGUST, DATE_SEPTEMBER, DATE_OCTOBER, DATE_NOVEMBER, DATE_DECEMBER };
static RTHANDLE MonthNames2[] = { DATE_JAN, DATE_FEB, DATE_MAR, DATE_APR, DATE_MAY, DATE_JUN, DATE_JUL, DATE_AUG, DATE_SEP, DATE_OCT, DATE_NOV, DATE_DEC };

static RTHANDLE DateYears[] = { DATE_1990, DATE_1991, DATE_1992, DATE_1993, DATE_1994, DATE_1995, DATE_1996, DATE_1997, DATE_1998, DATE_1999, DATE_2000, DATE_2001, DATE_2002, DATE_2003, DATE_2004, DATE_2005, DATE_2006, DATE_2007, DATE_2008, DATE_2009, DATE_2010, DATE_2011, DATE_2012, DATE_2013, DATE_2014, DATE_2015, DATE_2016, DATE_2017, DATE_2018, DATE_2019, };

static RTHANDLE DateHours[] = { NAME_00, NAME_01, NAME_02, NAME_03, NAME_04, NAME_05, NAME_06, NAME_07, NAME_08, NAME_09, NAME_10, NAME_11, NAME_12, NAME_13, NAME_14, NAME_15, NAME_16, NAME_17, NAME_18, NAME_19, NAME_20, NAME_21, NAME_22, NAME_23 };
static RTHANDLE DateMinutes[] = { NAME_00, NAME_01, NAME_02, NAME_03, NAME_04, NAME_05, NAME_06, NAME_07, NAME_08, NAME_09, NAME_10, NAME_11, NAME_12, NAME_13, NAME_14, NAME_15, NAME_16, NAME_17, NAME_18, NAME_19, NAME_20, NAME_21, NAME_22, NAME_23, NAME_24, NAME_25, NAME_26, NAME_27, NAME_28, NAME_29, NAME_30, NAME_31, NAME_33, NAME_33, NAME_34, NAME_35, NAME_36, NAME_37, NAME_38, NAME_39, NAME_40, NAME_41, NAME_42, NAME_43, NAME_44, NAME_45, NAME_46, NAME_47, NAME_48, NAME_49, NAME_50, NAME_51, NAME_52, NAME_53, NAME_54, NAME_55, NAME_56, NAME_57, NAME_58, NAME_59, };
static RTHANDLE DateSeconds[] = { NAME_00, NAME_01, NAME_02, NAME_03, NAME_04, NAME_05, NAME_06, NAME_07, NAME_08, NAME_09, NAME_10, NAME_11, NAME_12, NAME_13, NAME_14, NAME_15, NAME_16, NAME_17, NAME_18, NAME_19, NAME_20, NAME_21, NAME_22, NAME_23, NAME_24, NAME_25, NAME_26, NAME_27, NAME_28, NAME_29, NAME_30, NAME_31, NAME_33, NAME_33, NAME_34, NAME_35, NAME_36, NAME_37, NAME_38, NAME_39, NAME_40, NAME_41, NAME_42, NAME_43, NAME_44, NAME_45, NAME_46, NAME_47, NAME_48, NAME_49, NAME_50, NAME_51, NAME_52, NAME_53, NAME_54, NAME_55, NAME_56, NAME_57, NAME_58, NAME_59, };

//template <unsigned int arraySize>
//int ArrayFindName(RTHANDLE const (&arr)[arraySize], RTHANDLE name)
//{
//	auto index = -1;
//	for (uint32_t i = 0; i < arraySize; i++)
//	{
//		if (COMPARE_NAME(arr[i], name))
//		{
//			index = i;
//			break;
//		}
//	}
//	return index;
//}

static void ParseDate(USTRING text)
{
	struct tm time;
	FillMemory(&time, sizeof(time), 0xFF);

	TSTRING_BUILDER separatorBuf;
	while (auto match = SplitChar(text, DATE_SEPARATOR, separatorBuf))
	{
		auto separator = separatorBuf.toBuffer();
		auto name = FindName(match);
		ASSERT(name);

		Trim(separator);

		if (separator.length() > 0)
		{
			if (separator[0] == ',')
			{
				auto dayIndex = ArrayFind(DayNames1, name);
				if (dayIndex == -1)
					dayIndex = ArrayFind(DayNames2, name);
				ASSERT(dayIndex >= 0);
			}
			else if (separator[0] == ':')
			{

			}
		}
		else
		{
			if (time.tm_mday == -1)
			{
				auto value = StringToNumber(match); // strtol(match.addr(), &endPtr, 10);
				if (value > 0)
				{
					ASSERT(value <= 31);
					time.tm_mday = value;
				}
				else DBGBREAK();
			}
			else if (time.tm_mon == -1)
			{
				auto monthIndex = ArrayFind(MonthNames1, name);
				if (monthIndex == -1)
				{
					monthIndex = ArrayFind(MonthNames2, name);
				}

				ASSERT(monthIndex >= 0);
				time.tm_mon = monthIndex;
			}
			else if (time.tm_year)
			{
				auto value = StringToNumber(match);
			}
		}
		if (separator[0] == ',')
		{
			continue;
		}
		else if (separator)
			for (auto& dateNames : DateParts)
			{
				if (dateNames == name)
				{

				}
			}
	}
}

const USTRING COOKIE_PARAM_SEPARATOR = " \t;";
const USTRING COOKIE_NAME_SEPARATOR = " \t-";

static void ParseCookie(USTRING text)
{
	auto domain = Undefined;
	auto name = Undefined;
	auto path = Undefined;
	USTRING value;

	auto nameValuePair = SplitChar(text, ";");
	Trim(nameValuePair);

	auto nameText = SplitChar(nameValuePair, "=");
	Trim(nameText);

	name = CreateAppName(nameText);

	//value = nameValuePair.trim();

	while (auto param = SplitChar(text, ";"))
	{
		Trim(param);

		auto nameText = SplitChar(param, "=");
		auto name = CreateAppName(nameText);
		Trim(param);

		if (name == HTTP_Expires)
		{
			ParseDate(param);
		}
		else if (name == HTTP_Domain)
		{
			domain = CreateAppName(param);
		}
		else if (name == HTTP_Path)
		{
			path = CreateAppName(param);
		}
	}
}

static void SetCookie(USTRING text)
{
	auto domain = Undefined;
	auto name = Undefined;
	auto path = HTTP_SLASH;
	USTRING value;

	auto nameValuePair = SplitChar(text, ";");
	Trim(nameValuePair);

	auto nameText = SplitChar(nameValuePair, "=");
	Trim(nameText);

	name = CreateAppName(nameText);

	value = nameValuePair;
	Trim(value);

	while (auto param = SplitChar(text, ";"))
	{
		Trim(param);

		auto nameText = SplitChar(param, "=");
		auto name = CreateAppName(nameText);
		Trim(param);

		if (name == HTTP_Expires)
		{
			ParseDate(param);
		}
		else if (name == HTTP_Domain)
		{
			domain = CreateAppName(param);
		}
		else if (name == HTTP_Path)
		{
			path = CreateAppName(param);
		}
		else if (name == HTTP_Max_Age)
		{

		}
	}
}

struct CHUNK_TRANSFER
{
	bool chunkSizeKnown = false;

	UINT32 chunkSize = 0;
	UINT32 chunkStart = 0;

	bool processData(TSTRING_BUILDER& recvBuffer)
	{
		auto transferComplete = false;

		if (chunkSizeKnown)
		{
			auto chunkBytesReceived = recvBuffer.count() - chunkStart;
			if (chunkBytesReceived > chunkSize)
			{
				chunkStart += chunkSize;
				chunkSizeKnown = false;
			}
		}

		if (chunkSizeKnown == false)
		{
			auto chunkString = BUFFER{ recvBuffer.address(chunkStart), recvBuffer.count() - chunkStart };
			if (chunkString.length() > 2)
			{
				auto delimiter = SplitString(chunkString, CRLF);
				auto lineString = SplitString(chunkString, CRLF);
				Trim(lineString);

				if (lineString)
				{
					auto sizeString = SplitChar(lineString, ';');
					if (sizeString)
					{
						chunkSize = HexStringToNumber(sizeString);

						auto bytesShifted = chunkString._start;

						chunkStart += bytesShifted;
						recvBuffer.remove(chunkStart, bytesShifted);
					}
				}

				if (chunkSize == 0)
				{
					transferComplete = true;
				}
			}
		}

		return transferComplete;
	}

};

struct TLS12_DOWNLOAD
{
	TLS12_HANDSHAKE<TLS12_DOWNLOAD> handshake;
	URL_INFO url;

	TSTRING_BUILDER recvBuffer;

	CHUNK_TRANSFER chunkState;

	UINT32 contentLength = 0;
	bool chunkTransfer = false;
	bool isKeepAlive = false;
	bool headersParsed = false;

	bool waitingForHeaders = true;
	bool downloadComplete = false;

	TLS12_DOWNLOAD() : handshake(*this) {}

	void parseResponseHeaders(USTRING responseString)
	{
		if (auto headerString = SplitString(responseString, HTTP_HEADERS_DELIMITER))
		{
			waitingForHeaders = false;

			auto title = SplitString(headerString, CRLF);
			auto httpVersion = SplitChar(title, WHITESPACE_PATTERN);
			auto httpStatus = SplitChar(title, WHITESPACE_PATTERN);

			while (auto line = SplitString(headerString, CRLF))
			{
				auto header = SplitChar(line, HTTP_HEADER_NAME_PATTERN);
				auto headerName = FindName(header);
				if (headerName == HTTP_Content_Length)
				{
					contentLength = StringToNumber(line);
				}
				else if (headerName == HTTP_Transfer_Encoding)
				{
					chunkTransfer = StringEquals(line, "chunked");
				}
				else if (headerName == HTTP_Connection)
				{
					isKeepAlive = StringEquals(line, "keep-alive");
				}
			}
		}
	}

	void sendRequest()
	{
		handshake.sendData([](DATA_BUFFER & buffer, TLS12_DOWNLOAD & download)
			{
				buffer.writeMany("GET /", download.url.path, " HTTP/1.1", CRLF);
				buffer.writeMany("Host: ", download.url.hostname, CRLF);
				buffer.writeString(UserAgent);
				buffer.writeMany("Accept: */*", CRLF);
				buffer.writeMany("Connection: Keep-Alive", CRLF);
				buffer.writeString(CRLF);
			}, *this);
	}

	void receiveData(BUFFER dataBuffer)
	{
		recvBuffer.writeStream(dataBuffer);
		auto transferComplete = false;

		if (waitingForHeaders)
		{
			parseResponseHeaders(recvBuffer.toBuffer());
		}
		else
		{
			if (chunkTransfer)
			{
				transferComplete = chunkState.processData(recvBuffer);
			}
			else if (contentLength > 0)
			{
				if (recvBuffer.count() >= contentLength)
				{
					transferComplete = true;
				}
			}
		}
		LogInfo("Received %d bytes", dataBuffer.length());
	}

	NTSTATUS download(USTRING urlString)
	{
		auto status = STATUS_SUCCESS;
		do
		{
			recvBuffer.reserve(256 * 1024);

			ParseUrl(urlString, url);

			status = handshake.startClient(url);
			VERIFY_STATUS;

		} while (false);
		return status;
	}
};

void TestTLS12()
{
	TLS12_DOWNLOAD download;
	download.download("https://www.google.com/");
}
