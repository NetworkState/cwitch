// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#include "pch.h"
#include "Types.h"

template <>
TOKENTYPE GetLiteralType<GLOBAL_STACK>() { return TOKENTYPE::LITERAL_GLOBAL; }

template <>
TOKENTYPE GetLiteralType<SERVICE_STACK>() { return TOKENTYPE::LITERAL_APP; }

template <>
TOKENTYPE GetLiteralType<SESSION_STACK>() { return TOKENTYPE::LITERAL_SESSION; }

bool CompareLiteral(TOKEN first, TOKEN second) // always case sensitive
{
	ASSERT(first.isString() && second.isString());

	if (first.getValue() == second.getValue())
		return true;

	auto firstString = NameToString(first);
	auto secondString = NameToString(second);

	if (firstString == secondString)
		return true;

	return false;
}

bool IsWhitespace(UINT8 input)
{
	return WHITESPACE.exists(input);
}

template <> UINT32 GetNumberStack<SCHEDULER_STACK>() { return NUMBER_SCHEDULER_STACK; }
template <> UINT32 GetNumberStack<GLOBAL_STACK>() { return NUMBER_GLOBAL_STACK; }
template <> UINT32 GetNumberStack<SERVICE_STACK>() { return NUMBER_APP_STACK; }
template <> UINT32 GetNumberStack<SESSION_STACK>() { return NUMBER_SESSION_STACK; }

template <> UINT32 GetBlobStack<SCHEDULER_STACK>() { return BLOB_SCHEDULER_STACK; }
template <> UINT32 GetBlobStack<GLOBAL_STACK>() { return BLOB_GLOBAL_STACK; }
template <> UINT32 GetBlobStack<SERVICE_STACK>() { return BLOB_APP_STACK; }
template <> UINT32 GetBlobStack<SESSION_STACK>() { return BLOB_SESSION_STACK; }

INT64 GetNumberHandleValue(TOKEN handle)
{
	auto id = handle.getValue();

	if (id == 0)
		return 0;

	INT64 number = -1;
	auto flag = id & 0x00F00000;
	if (flag == INLINE_FLAG_POSITIVE_NUMBER)
	{
		number = id & 0x000FFFFF;
	}
	else if (flag == INLINE_FLAG_NEGATIVE_NUMBER)
	{
		number = id & 0xFFFFF;
		number *= -1;
	}
	else
	{
		auto stackId = handle.getValue() & 0x00F00000;
		if (stackId == NUMBER_GLOBAL_STACK)
			number = GetCurrentStack<GLOBAL_STACK>().numberHandles.at(handle.getValue() & 0xFFFFF);
		else if (stackId == NUMBER_SCHEDULER_STACK)
			number = GetCurrentStack<SCHEDULER_STACK>().numberHandles.at(handle.getValue() & 0xFFFFF);
		else if (stackId == NUMBER_SESSION_STACK)
			number = GetCurrentStack<SESSION_STACK>().numberHandles.at(handle.getValue() & 0xFFFFF);
		else if (stackId == NUMBER_APP_STACK)
			number = GetCurrentStack<SERVICE_STACK>().numberHandles.at(handle.getValue() & 0xFFFFF);
	}
	return number;
}

BUFFER GetBlobData(TOKEN token)
{
	BUFFER streamData;

	auto stack = token.getValue() & 0x00F00000;
	if (stack == BLOB_SCHEDULER_STACK)
		streamData = GetCurrentStack<SCHEDULER_STACK>().blobStream.toBuffer(token.getValue() & 0xFFFFF);
	else if (stack == BLOB_APP_STACK)
		streamData = GetCurrentStack<SERVICE_STACK>().blobStream.toBuffer(token.getValue() & 0xFFFFF);
	else DBGBREAK();

	auto blobLength = (UINT32)streamData.readVInt();

	ASSERT(blobLength <= streamData.length());
	return BUFFER{ streamData.data(), blobLength };
}

GUID GetGuidHandleValue(TOKEN handle)
{	
	auto blob = GetBlobData(handle);
	return blob.readGuid();
}

