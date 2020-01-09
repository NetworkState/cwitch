// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

#include "pch.h"
#include "Types.h"

STREAM_READER<USTRING> *CharClassPtr;
STREAM_READER<USTRING> CharClass()
{
	return *CharClassPtr;
}

void ParserInitialize()
{
	auto&& charClassStream = StackAlloc<STREAM_BUILDER<USTRING, GLOBAL_STACK, 64>, GLOBAL_STACK>();
	auto&& charClass = StackAlloc<STREAM_READER<USTRING>, GLOBAL_STACK>();

	CharClassPtr = &charClass;

	// 2:'a-z', 3: 'A-Z', 4:'0-9' 1:'not' 5:'any'
	charClassStream.commit(CcMax);

	charClassStream.at(CcAlphaNumeric) = "\2\3\4";
	charClassStream.at(CcNumeric) = "\4";
	charClassStream.at(CcAlpha) = "\2\3";
	charClassStream.at(CcUpperAlpha) = "\3";
	charClassStream.at(CcLowerAlpha) = "\2";
	charClassStream.at(CcUpperNumeric) = "\3\4";
	charClassStream.at(CcLowerNumeric) = "\2\4";
	charClassStream.at(CcHtmlAttribute) = "\1=/'\"> ";
	charClassStream.at(CcHtmlAttrSeparators) = "= ";
	charClassStream.at(CcUrlSeparators) = "://?# \t\r\n";
	charClassStream.at(CcQuotes) = "\"'";
	charClassStream.at(CcSingleQuoteChars) = "\1'\\\r\n";
	charClassStream.at(CcDoubleQuoteChars) = "\1\"\\\r\n";
	charClassStream.at(CcDoubleQuoteTerminators) = "\"\r\n";
	charClassStream.at(CcSingleQuoteTerminators) = "'\r\n";
	charClassStream.at(CcRegexTerminators) = "/\r\n";
	charClassStream.at(CcJsChars) = "\2\3\4$_";
	charClassStream.at(CcJsSeparators) = "{}[]().,;:\"'";
	charClassStream.at(CcJsOperators) = "<>=!+-%/*&^~?|";
	charClassStream.at(CcSpaceTab) = " \t";
	charClassStream.at(CcWordSeparators) = " \t\x1A";
	charClassStream.at(CcSelectorSeparators) = ">~+[]=*^$|:(){,";
	charClassStream.at(CcDoubleSelectorSeparators) = "=:";
	charClassStream.at(CcSelectorPrefixes) = ".#@*\2_-";
	charClassStream.at(CcSelectorCombinators) = " \t>+~";
	charClassStream.at(CcSelectorChars) = "\2\3\4-_";
	charClassStream.at(CcStyleSeparators) = ":;";

	charClassStream.at(CcPropertyChars) = "\2\3\4-_%+.$#!";
	charClassStream.at(CcPropertySpecialChars) = "\"'([";
	charClassStream.at(CcPropertySplitters) = " ,";
	charClassStream.at(CcPropertyTerminators) = ";";

	charClassStream.at(CcHtmlTextChars) = "\1<";
	charClassStream.at(CcHtmlEntity) = "\2\3\4-_";
	charClassStream.at(CcHexChars) = "\4abcdefABCDEF";

	charClassStream.at(CcPropertySeparators) = " ,;([!}\x1A";
	charClassStream.at(CcAnyChar) = "\5";
	charClassStream.at(CcWhitespace) = " \r\t\n";

	charClassStream.at(CcStyleWordSeparators) = " \r\t\n:,!";
	charClassStream.at(CcStyleTerminators) = ";}\x1A";
	charClassStream.at(CcStyleGroupChars) = "\"'([";

	charClassStream.at(CcMediaSeparators) = " \r\t\n:,()";
	charClassStream.at(CcMediaTerminators) = "{";
	charClassStream.at(CcMediaGroupChars) = "\"'";

	charClass = charClassStream.toBufferNoConst();
}
constexpr USTRING AttrDelimiter = "\0";

//TOKEN FindJson(TOKEN_BUFFER jsonTokens, TOKEN match)
//{
//	TOKEN result = Null;
//	ASSERT(jsonTokens.at(0).isJson());
//	if (jsonTokens.at(0).isJson())
//		jsonTokens.shift();
//
//	while (jsonTokens)
//	{
//		auto name = jsonTokens.shift();
//		auto value = jsonTokens.at(0);
//
//		ASSERT(name.isLiteral());
//		if (CompareLiteral(name, match))
//		{
//			result = jsonTokens.shift();
//			break;
//		}
//		else
//		{
//			jsonTokens.shift(value.getLength());
//		}
//	}
//	return result;
//}

TOKEN FindJson(TOKEN_BUFFER jsonTokens, TOKEN match)
{
	TOKEN result = Null;
	FindJson(jsonTokens, match, [](TOKEN_BUFFER matchFound, TOKEN& result)
		{
			auto first = matchFound.at(0);
			ASSERT(first.isJson() == false);
			result = matchFound.at(0);
			return false;
		}, result);
	return result;
}

TOKEN TOKEN::getKeyword() { return this->isKeyword() ? KeywordNames[getValue()] : Undefined; }
