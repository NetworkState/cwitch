// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

#include "Types.h"

#define NAME_INDEX(_x) (UINT16)(_x.getValue() & 0xFFFF)
#define VARIANT_INDEX(_x)  (UINT8)((_x.getValue() & 0x00FF0000) >> 16)

constexpr INT32 INT_NAME_MIN = -25;
constexpr INT32 INT_NAME_MAX = 500;

template <typename STACK>
TOKENTYPE GetNameType();

struct PARSED_NAME
{
	USTRING variantText = NULL_STRING;
	USTRING normalizedString;
	bool isCaseSensitive = false;
	TOKEN normalizedName = Undefined;

	PARSED_NAME(USTRING input, bool isCaseSensitive = false) : isCaseSensitive(isCaseSensitive)
	{
		stringData.clear();
		for (UINT32 i = 0; i < input.length(); i++)
		{
			if (input[i] >= 'A' && input[i] <= 'Z')
			{
				this->variantText = input;
				this->stringData.writeChar(input[i] + 0x20);
			}
			else
			{
				this->stringData.writeChar(input[i]);
			}
		}
		this->normalizedString = this->stringData.toBuffer();
	}

	LOCAL_STREAM<STRING_SIZE> stringData;
};

template<typename DICT>
VARIANT_HEADER* AddVariant(DICT&& dictionary, UINT16 index, USTRING& string)
{
	index &= 0xFFFF;
	UINT8 variantFound = 0;

	for (auto& variant : dictionary.variantHeaders.toBuffer())
	{
		if (variant.index == index)
			variantFound = max(variant.variant, variantFound);
	}

	variantFound++;
	auto& variant = dictionary.variantHeaders.append();

	variant.index = index;
	string.copyTo((UINT8*)variant.data, VARIANT_DATA_LENGTH);
	variant.variant = variantFound;

	if (string.length() > 0)
	{
		AddExtension(dictionary, index, variantFound, string);
	}

	return &variant;
}

template<typename DICT>
const VARIANT_HEADER* FindVariant(DICT&& dictionary, UINT16 index, USTRING& variant)
{
	index &= 0xFFFF;
	for (auto& variantHeader : dictionary.variantHeaders.toBuffer())
	{
		if (variantHeader.index == index)
		{
			if (memcmp(variantHeader.data, variant.data(), variant.length()) == 0)
			{
				return  &variantHeader;
			}
		}
	}
	return nullptr;
}

template<typename DICT>
int FindVariant(DICT&& dictionary, UINT16 index, UINT8 variant)
{

	index &= 0xFFFF;
	for (auto& variantHeader : dictionary.variantHeaders.toBuffer())
	{
		if (variantHeader.index == index && variantHeader.variant == variant)
		{
			return dictionary.variantHeaders.getIndex(variantHeader);
		}
	}
	return -1;
}

#define EXTENSION_DATA_SIZE		(2 * 1024 * 1024)

template<typename DICT>
UINT16 AddExtension(DICT&& dictionary, UINT16 index, UINT8 variant, USTRING& string)
{
	if (dictionary.extensionData == nullptr)
	{
		dictionary.extensionData = (PUINT8)KernelAlloc(EXTENSION_DATA_SIZE);
		dictionary.extensionDataWriteOffset = 0;
	}

	ASSERT((dictionary.extensionDataWriteOffset + string.length()) < EXTENSION_DATA_SIZE);

	UINT16 extension = (UINT16)dictionary.extensionHeaders.reserve();
	auto& extensionHeader = dictionary.extensionHeaders.append();

	extensionHeader.data = dictionary.extensionDataWriteOffset;
	extensionHeader.index = index;
	extensionHeader.variant = variant;

	RtlCopyMemory(dictionary.extensionData + extensionHeader.data, string.data(), string.length());
	dictionary.extensionDataWriteOffset += string.length();

	return extension;
}

template<typename DICT>
PUINT8 FindExtension(DICT&& dictionary, UINT16 index, UINT8 variant)
{
	for (auto& extensionHeader : dictionary.extensionHeaders.toBuffer())
	{
		if (extensionHeader.index == index && extensionHeader.variant == variant)
		{
			return dictionary.extensionData + extensionHeader.data;
		}
	}
	return nullptr;
}

template<typename DICT>
bool CompareExtension(DICT&& dictionary, UINT16 index, UINT8 variant, const UINT8* string, int length)
{
	auto extensionData = FindExtension(dictionary, index, variant);
	if (extensionData)
	{
		return memcmp(extensionData, string, length) == 0;
	}
	return false;
}

template <typename DICT>
bool CompareExtension(DICT&& dictionary, UINT32 extension, const UINT8* string, int length)
{
	auto& extensionHeader = dictionary.extensionHeaders.at(extension);
	auto extensionData = extensionHeader.data + dictionary.extensionData;
	return memcmp(extensionData, string, length) == 0;
}

int CompareSortData(SORT_HEADER& sortData, UINT64 header, UINT32 footer);

template<typename DICT, typename NAME>
TOKEN FindNameInternal(DICT&& dictionary, NAME&& parsedName)
{
	auto normalizedString = parsedName.normalizedString.data();
	auto length = (UINT8)parsedName.normalizedString.length();
	auto& normalizedName = parsedName.normalizedName;

	UINT64 headerPattern = 0, dataPattern = 0;
	UINT32 footerPattern = 0;

	auto patternPointer = (char*)&headerPattern;
	patternPointer[0] = length;
	RtlCopyMemory(&patternPointer[1], normalizedString, min(length, 7));

	patternPointer = (char*)& footerPattern;
	auto footerCount = min(3, length);
	RtlCopyMemory(&patternPointer[1], &normalizedString[length - footerCount], footerCount);

	if (length > 7)
	{
		patternPointer = (char*)& dataPattern;
		RtlCopyMemory(patternPointer, &normalizedString[7], min(length, 15) - 7);
	}

	auto normalizedIndex = -1;

	auto begin = 0ul;
	UINT32 end = dictionary.sortHeaders.count();

	auto middle = 0ul;
	auto partialMatch = false;

	while (begin < end)
	{
		middle = (begin + end) / 2;
		auto comparison = CompareSortData(dictionary.sortHeaders.at(middle), headerPattern, footerPattern);
		if (comparison > 0 && end != middle)
		{
			end = middle;
		}
		else if (comparison < 0 && begin != middle)
		{
			begin = middle;
		}
		else
		{
			partialMatch = true;
			break;
		}
	}

	for (UINT32 i = middle; i < dictionary.sortHeaders.count(); i++)
	{
		auto& sortedData = dictionary.sortHeaders.at(i);
		if (CompareSortData(sortedData, headerPattern, footerPattern) != 0)
			break;

		if (length <= 7 || dictionary.nameHeaders.at(sortedData.name).letter8to15 == dataPattern)
		{
			auto indexFound = sortedData.name;
			if (length <= HEADER_DATA_LENGTH || CompareExtension(dictionary, sortedData.extension, &normalizedString[HEADER_DATA_LENGTH], (length - HEADER_DATA_LENGTH)))
			{
				normalizedIndex = indexFound;
				break;
			}
		}
	}

	if (normalizedIndex == -1 && length > 7 && partialMatch)
	{
		for (UINT32 i = begin; i < end; i++)
		{
			auto& sortedData = dictionary.sortHeaders.at(i);
			if (CompareSortData(sortedData, headerPattern, footerPattern) == 0 && dictionary.nameHeaders.at(sortedData.name).letter8to15 == dataPattern)
			{
				auto indexFound = sortedData.name;
				if (length <= HEADER_DATA_LENGTH || CompareExtension(dictionary, sortedData.extension, &normalizedString[HEADER_DATA_LENGTH], (length - HEADER_DATA_LENGTH)))
				{
					normalizedIndex = indexFound;
					break;
				}
			}
		}
	}

	if (normalizedIndex == -1)
		return Undefined;

	normalizedName = MakeName(dictionary.type, (UINT16)normalizedIndex, 0);
	UINT8 variantIndex = 0;
	if (parsedName.variantText)
	{
		auto variantData = FindVariant(dictionary, (UINT16)normalizedIndex, parsedName.variantText);
		if (variantData == nullptr)
		{
			variantData = AddVariant(dictionary, (UINT16)normalizedIndex, parsedName.variantText);
		}
		variantIndex = variantData->variant;

		//variantIndex = variantData ? variantData->variant : 0;
	}

	return parsedName.isCaseSensitive && parsedName.variantText && variantIndex == 0 ? Undefined : MakeName(dictionary.type, (UINT16)normalizedIndex, variantIndex);
}

template <typename DICT>
void SortName(DICT&& dictionary, UINT16 name, UINT8 variant, UINT16 extension, const UINT8* nameString, UINT8 nameLength)
{
	SORT_HEADER sortData;
	RtlZeroMemory(&sortData, sizeof(SORT_HEADER));

	auto headerPtr = (UINT8*)&sortData.header;
	headerPtr[0] = nameLength;
	RtlCopyMemory(&headerPtr[1], nameString, min(nameLength, 7));

	auto footerPtr = (UINT8*)&sortData.footer;
	footerPtr[0] = variant;
	auto copyCount = min(nameLength, 3);
	RtlCopyMemory(&footerPtr[1], &nameString[nameLength - copyCount], copyCount);

	sortData.name = name;
	sortData.extension = extension;

	UINT32 begin = 0;
	auto end = dictionary.sortHeaders.count();

	while (begin < end)
	{
		auto middle = (begin + end) / 2;
		auto comparison = CompareSortData(dictionary.sortHeaders.at(middle), sortData.header, sortData.footer);
		if (comparison > 0 && end != middle) // don't loop
		{
			end = middle;
		}
		else if (comparison < 0 && begin != middle)
		{
			begin = middle;
		}
		else
		{
			begin = end = middle;
			break;
		}
	}

	for (; begin < dictionary.sortHeaders.count(); begin++)
	{
		auto& sortHeader = dictionary.sortHeaders.at(begin);
		if (CompareSortData(sortHeader, sortData.header, sortData.footer) >= 0)
		{
			break;
		}
	}

	dictionary.sortHeaders.insert(begin, 1);

	dictionary.sortHeaders.at(begin) = sortData;
}

template <typename DICT>
static UINT16 AddNameEntry(DICT&& dictionary, USTRING& nameString)
{
	NAME_HEADER header;
	RtlZeroMemory(&header, sizeof(NAME_HEADER));

	header.length = (UINT8)nameString.length();
	nameString.copyTo(&header.letter1, HEADER_DATA_LENGTH);
	return (UINT16)dictionary.nameHeaders.write(header);
}

template <typename DICT, typename NAME>
TOKEN CreateNameInternal(DICT&& dictionary, NAME&& parsedName)
{
	auto nameStart = parsedName.normalizedString.data();
	auto nameLength = (UINT8)parsedName.normalizedString.length();

	if (nameLength == 0)
		return NULL_NAME;
	auto nameHandle = FindNameInternal(dictionary, parsedName);
	if (nameHandle)
		return nameHandle;

	UINT8 variantIndex = 0;
	UINT16 nameIndex = NAME_INDEX(parsedName.normalizedName);
	if (!parsedName.normalizedName)
	{
		nameIndex = AddNameEntry(dictionary, parsedName.normalizedString);
		UINT16 extension = 0;
		if (parsedName.normalizedString.length() > 0)
		{
			extension = AddExtension(dictionary, nameIndex, 0, parsedName.normalizedString);
		}

		SortName(dictionary, nameIndex, 0, extension, nameStart, nameLength);
	}
	else
	{
		ASSERT(dictionary.nameHeaders.at(nameIndex & 0xFFFF).length == nameLength);
	}

	if (parsedName.variantText)
	{
		auto variantData = FindVariant(dictionary, nameIndex, parsedName.variantText);
		ASSERT(variantData == nullptr);
		if (variantData == nullptr)
		{
			variantData = AddVariant(dictionary, nameIndex, parsedName.variantText);
		}
		variantIndex = variantData->variant;
		ASSERT(variantIndex > 0);
	}

	return MakeName(dictionary.type, nameIndex, variantIndex);
}

template <typename ST>
TOKEN CreateName(USTRING nameString)
{
	if (nameString.length() == 0)
		return NULL_NAME;

	ASSERT(nameString.length() <= MAX_NAME_LENGTH);
	if (nameString.length() > MAX_NAME_LENGTH) return Undefined;

	return CreateNameInternal(GetCurrentStack<ST>().dictionary, PARSED_NAME(nameString, true));
}

template <typename DICT>
int NameToString(DICT&& dictionary, UINT16 name, UINT8 variant, UINT8* stringBuffer)
{
	int stringLength = 0;
	if (name == 0)
		return 0;

	auto& nameHeader = dictionary.nameHeaders.at(name);
	ASSERT(nameHeader.length > 0);
	if (variant == 0)
	{
		stringLength = nameHeader.length;
		RtlCopyMemory(stringBuffer, &nameHeader.letter1, 7);
		RtlCopyMemory(&stringBuffer[7], &nameHeader.letter8to15, 8);

		if (nameHeader.length > HEADER_DATA_LENGTH)
		{
			PUINT8 extension = FindExtension(dictionary, name, variant);
			RtlCopyMemory(&stringBuffer[HEADER_DATA_LENGTH], extension, nameHeader.length - HEADER_DATA_LENGTH);
		}
	}
	else
	{
		int variantIndex = FindVariant(dictionary, name, variant);
		ASSERT(variantIndex != -1);
		if (variantIndex != -1)
		{
			stringLength = nameHeader.length;
			RtlCopyMemory(stringBuffer, dictionary.variantHeaders.at(variantIndex).data, min(stringLength, VARIANT_DATA_LENGTH));
			if (stringLength > VARIANT_DATA_LENGTH)
			{
				PUINT8 extension = FindExtension(dictionary, name, variant);
				ASSERT(extension != nullptr);
				RtlCopyMemory(&stringBuffer[VARIANT_DATA_LENGTH], extension, stringLength - VARIANT_DATA_LENGTH);
			}
		}
	}
	stringBuffer[stringLength] = 0;
	return stringLength;
}

template <typename DICT>
UINT32 GetNameLength(DICT&& dictionary, TOKEN handle)
{
	auto name = NAME_INDEX(handle);
	auto& nameHeader = dictionary.nameHeaders.at(name);
	return nameHeader.length;
}

template<typename DICT>
TOKEN FindOrCreateName(DICT&& dictionary, USTRING nameString, bool isCaseSensitive)
{
	if (nameString.length() == 0)
		return NULL_NAME;

	ASSERT(nameString.length() <= MAX_NAME_LENGTH);
	if (nameString.length() > MAX_NAME_LENGTH) return Undefined;

	auto name = FindNameInternal(dictionary, PARSED_NAME(nameString, true));
	if (!name)
	{
		name = CreateNameInternal(dictionary, PARSED_NAME(nameString));
	}
	return name;
}

template <typename DICT>
TOKEN FindName(DICT&& dictionary, USTRING input, bool isCaseSensitive = false)
{
	return FindNameInternal(dictionary, PARSED_NAME(input, isCaseSensitive));
}

template <typename ST>
TOKEN FindCustomName(USTRING input, bool isCaseSensitive = false)
{
	auto&& parsedName = PARSED_NAME(input, isCaseSensitive);

	auto name = FindNameInternal(GlobalStack().dictionary, parsedName);
	if (!name)
	{
		name = FindNameInternal(GetCurrentStack<ST>().dictionary, parsedName);
	}
	return name;
}

template<typename ST>
TOKEN CreateCustomName(USTRING nameString, bool caseSensitive = false)
{
	auto&& parsedName = PARSED_NAME(nameString, caseSensitive);

	auto name = FindNameInternal(GlobalStack().dictionary, parsedName);
	if (!name)
	{
		if (parsedName.normalizedName)
		{
			ASSERT(caseSensitive);
			name = CreateNameInternal(GlobalStack().dictionary, parsedName);
		}
		else
		{
			name = CreateNameInternal(GetCurrentStack<ST>().dictionary, parsedName);
		}
	}
	return name;
}


template<unsigned int arraySize>
bool MatchName(TOKEN const (&nameArray)[arraySize], TOKEN match, int& index)
{
	auto isMatch = false;
	index = -1;
	do
	{
		if (IsEmptyString(match))
			break;

		for (auto i = 0; i < ARRAYSIZE(nameArray); i++)
		{
			auto name = nameArray[i];
			if (name == match)
			{
				isMatch = true;
				index = i;
				break;
			}
		}

	} while (false);
	return isMatch;
}

//template<typename DICT>
//void InitializeDictionary(DICT&& dictionary)
//{
//	new (&dictionary) DICT();
//
//	auto &&zeroHeader = NAME_HEADER();
//	RtlZeroMemory(&zeroHeader, sizeof(NAME_HEADER));
//
//	dictionary.nameHeaders.append(zeroHeader);
//}

#define LITERAL_NAME_PREFIX 0x0F
#define IS_LITERAL_NAME(_name_) (((_name_._type) & LITERAL_NAME_PREFIX) == LITERAL_NAME_PREFIX)

enum class NAME_MATCH
{
	EQUAL,
	STARTS_WITH,
	ENDS_WITH,
	CONTAINS,
};

bool CompareName(TOKEN name, TOKEN prefix, NAME_MATCH comparisonType = NAME_MATCH::EQUAL);
TOKEN FindName(USTRING input, bool isCaseSensitive = false);

constexpr auto MakeName(TOKENTYPE tokenType, UINT16 name, UINT8 variant) { return TOKEN(tokenType, (((UINT32)variant & 0xFF) << 16) | (name & 0xFFFF)); }
constexpr auto MakeName(UINT16 value) { return TOKEN(TOKENTYPE::NAME_GLOBAL, (UINT32)value); }
#define NAME_HANDLE(_x_) TOKEN(_x_)
extern TOKEN CreateName(USTRING input, bool isCaseSensitive = false);
extern USTRING NameToString(TOKEN name);

template <typename T>
USTRING NameToString(TOKEN name, T&& stream)
{
	if (IsEmptyString(name))
		return USTRING();

	return stream.writeName(name);
}
