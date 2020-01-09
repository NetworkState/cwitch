// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once
#include "Types.h"
#include "Css.h"
#include "HttpClient.h"

constexpr UINT8 HtmlTextChars[] = { PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcHtmlTextChars};

constexpr UINT8 WordSeparators[] = { PATTERN_FLAG_CHAR_CLASS, CcWordSeparators };

struct PARSE_HTML_CONTEXT
{
	STREAM_BUILDER<TOKEN, SERVICE_STACK, 32> elementStack;
};

constexpr UINT8 BeginTagPattern[] = { '<', PATTERN_FLAG_CHAR_CLASS, CcAlpha, PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ZERO_OR_MORE, CcAlphaNumeric};

constexpr UINT8 EndTagPattern[] = { '<', '/', PATTERN_FLAG_CHAR_CLASS, CcAlpha, PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ZERO_OR_MORE, CcAlphaNumeric};

constexpr UINT8 AttributeChars[] = { PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcHtmlAttribute};
constexpr UINT8 AttributeSeparators[] = { PATTERN_FLAG_CHAR_CLASS, CcHtmlAttrSeparators};
constexpr UINT8 AttributeQuotes[] = { PATTERN_FLAG_CHAR_CLASS, CcQuotes};

constexpr UINT8 UrlSeparators[] = { PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcUrlSeparators};

constexpr UINT8 SelectorChars[] = { PATTERN_FLAG_CHAR_CLASS , CcSelectorPrefixes, PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ZERO_OR_MORE, CcSelectorChars};

constexpr UINT8 SelectorSeparators[] = { PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ZERO_OR_MORE, CcWhitespace,
	PATTERN_FLAG_CHAR_CLASS, CcSelectorSeparators,
	PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_OPTIONAL, CcDoubleSelectorSeparators};

constexpr CSS_SEPARATOR_MAP CssSeparatorMap[] = { { CSEP_DESCENDANT, " " },{ CSEP_CHILD, ">" },{ CSEP_SIBLING, "~" },
{ CSEP_ADJ_SIBLING, "+" },{ CSEP_ATTR_START, "[" },{ CSEP_ATTR_END, "]" },{ CSEP_ATTR_EQUALS, "=" },
{ CSEP_ATTR_CONTAINS, "*=" }, { CSEP_ATTR_BEGINS_WITH, "^=" },{ CSEP_ATTR_ENDS_WITH, "$=" },
{ CSEP_ATTR_SPACED, "~=" }, { CSEP_ATTR_HYPHENATED, "|=" },{ CSEP_PSEUDO_CLASS, ":" },
{ CSEP_PSEUDO_ELEMENT, "::" },{ CSEP_COMMA, "," }, { CSEP_VALUE_START, "{" },{ CSEP_PARENTHESIS, "(" }, };

constexpr UINT8 PropertyChars[] = { PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcPropertyChars};
constexpr UINT8 PropertySpecialChars[] = { PATTERN_FLAG_CHAR_CLASS, CcPropertySpecialChars};
constexpr UINT8 PropertySplitters[] = { PATTERN_FLAG_CHAR_CLASS, CcPropertySplitters};
constexpr UINT8 PropertyTerminators[] = { PATTERN_FLAG_CHAR_CLASS, CcPropertyTerminators};

constexpr UINT8 PropertySeparators[] = { PATTERN_FLAG_CHAR_CLASS, CcPropertySeparators};

constexpr TOKEN NoContentElements[] = { ELEMENT_meta, ELEMENT_text, ELEMENT_hr, ELEMENT_link, ELEMENT_img, ELEMENT_br,
ELEMENT_base, ELEMENT_wbr, ELEMENT_embed, ELEMENT_param, ELEMENT_source, ELEMENT_track,
ELEMENT_area, ELEMENT_col, ELEMENT_input, ELEMENT_keygen, ELEMENT_menuitem };

constexpr TOKEN  NoFlowContentElements[] = { ELEMENT_script, ELEMENT_style };

constexpr TOKEN  NoSelfChildElements[] = { ELEMENT_p, ELEMENT_li, ELEMENT_dt, ELEMENT_dd, ELEMENT_td, ELEMENT_tr, ELEMENT_th,
ELEMENT_thead, ELEMENT_tbody, };

constexpr TOKEN  BlockElements[] = { ELEMENT_address, ELEMENT_article, ELEMENT_aside, ELEMENT_blockquote, ELEMENT_details,
ELEMENT_dialog, ELEMENT_div, ELEMENT_dl, ELEMENT_fieldset, ELEMENT_figcaption, ELEMENT_figure, ELEMENT_footer,
ELEMENT_header, ELEMENT_menu, ELEMENT_nav, ELEMENT_ol, ELEMENT_p, ELEMENT_section, ELEMENT_summary, ELEMENT_ul,
ELEMENT_dd, ELEMENT_dt, ELEMENT_h1, ELEMENT_h2, ELEMENT_h3, ELEMENT_h4, ELEMENT_h5, ELEMENT_h6, ELEMENT_body };

constexpr TOKEN InlineElements[] = { ELEMENT_a, ELEMENT_span, ELEMENT_br, ELEMENT_label, ELEMENT_b, ELEMENT_s, ELEMENT_strong,
ELEMENT_sub, ELEMENT_sup, ELEMENT_i, ELEMENT_em, ELEMENT_u, ELEMENT_q, ELEMENT_var, ELEMENT_code, ELEMENT_time, ELEMENT_abbr,
ELEMENT_samp, ELEMENT_data, ELEMENT_rp, ELEMENT_rt, };

enum class HTOKEN : UINT8
{
	UNKNOWN,
	CLASS,
	ID,
	ELEMENT,
	STYLE,
	CHILD,
	SIBLING,
	ATTR_NAME,
	ATTR_VALUE,
	TEXT,
	END,
};

struct HTML_TOKEN
{
	HTOKEN type;
	TOKEN value;

	HTML_TOKEN(HTOKEN typeArg, TOKEN valueArg) : type(typeArg), value(valueArg) {}
};

enum class CTOKEN : UINT8
{
	UNKNOWN,
	DESCENDANT,
	CHILD,
	SIBLING,
	ADJACENT_SIBLING,
	WITHIN,
	ATTR_EXISTS,
	ATTR_EQUALS,
	ATTR_CONTAINS,
	ATTR_BEGINS_WITH,
	ATTR_ENDS_WITH,
	ATTR_SPACED,
	ATTR_HYPHENATED,
	VALUE,
	PSEUDO_CLASS,
	PSEUDO_ELEMENT,
	PROPERTIES,
	END,
};

struct CSS_TOKEN
{
	CTOKEN type;
	TOKEN value;

	CSS_TOKEN(CTOKEN typeArg, TOKEN valueArg) : type(typeArg), value(valueArg) {}
};

template <typename STREAM>
void WriteHtmlToken(STREAM&& stream, HTOKEN type, TOKEN value)
{
	stream.append(type, value);
}

template <typename STREAM>
void WriteCssToken(STREAM&& stream, CTOKEN type, TOKEN value)
{
	stream.append(type, value);
}
//
//TOKEN HtmlToken(TOKEN name, UINT32 index)
//{
//	return TOKEN(TOKENTYPE::HTML, GetElementId(name) << 16 | index);
//}

bool IsNoContentElement(TOKEN elementName)
{
	return ArrayExists(NoContentElements, elementName);
}

bool IsNoSelfChildElement(TOKEN elementName)
{
	return ArrayExists(NoSelfChildElements, elementName);
}

template <typename SERVICE>
struct WEBPAGE_PARSER
{
	SERVICE& service;

	WEBPAGE_PARSER(SERVICE& inService) : service(inService){}

	PARSER_INFO* htmlParser;

	bool runtimeInitialized = false;

	CSS_STREAM cssPropertyStream;
	STREAM_BUILDER<CSS_TOKEN, SERVICE_STACK, 64> cssSelectorStream;
	STREAM_BUILDER<HTML_TOKEN, SERVICE_STACK, 512> htmlTokenStream;

	auto& getScheduler() { return service.scheduler; }

	struct HTML_PARSE_INFO
	{
		TOKEN  doc = Undefined;
		TOKEN  head = Undefined;
		TOKEN  body = Undefined;
		TOKEN  html = Undefined;
		USTRING htmlText = USTRING();
	};

	CSS_SEPARATOR findCssSeparator(USTRING& text)
	{
		for (auto& map : CssSeparatorMap)
		{
			if (map.text == text)
				return map.separator;
		}
		DBGBREAK();
		return CSEP_DESCENDANT;
	}

	TOKEN getNextTag(PARSER_INFO& parser, bool& isEndTag)
	{
		auto elementName = Undefined;
		if (auto& match = parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, BeginTagPattern },
			TPATTERN{ PT_WORD, EndTagPattern }))
		{
			if (match.id == 0)
			{
				isEndTag = false;
				parser.matchText.shift(1);
				elementName = FindName(parser.matchText);
			}
			else if (match.id == 1)
			{
				isEndTag = true;
				parser.matchText.shift(2);
				elementName = FindName(parser.matchText);
				parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, ">" });
			}
			else DBGBREAK();
		}
		return elementName;
	}

	bool ignoreAttributes(PARSER_INFO& parser)
	{
		TPATTERN separatorPattern{ PT_TERMINATOR, AttributeSeparators };
		TPATTERN endTagPattern1{ PT_TERMINATOR, "/>" };
		TPATTERN endTagPattern2{ PT_TERMINATOR, ">" };
		while (true)
		{
			auto&& match = parser.matchWord(separatorPattern, endTagPattern1, endTagPattern2);
			if (!match)
				break;

			if (parser.terminatorText == ">" || parser.terminatorText == "/>")
			{
				break;
			}
		}
		return parser.terminatorText == "/>";
	}

	bool getClosingTag(PARSER_INFO& parser)
	{
		ASSERT(parser.terminatorText == ">" || parser.terminatorText == "/>");
		return parser.terminatorText == "/>";
	}

	template <typename STREAM>
	USTRING getContent(TOKEN parentName, PARSER_INFO& parser, STREAM&& contentHtml, PARSER_OPTIONS options)
	{
		do
		{
			if (getClosingTag(parser))
			{
				break;
			}

			auto&& startTag = TSTRING_BUILDER().writeMany("<", parentName);
			auto&& endTag = TSTRING_BUILDER().writeMany("</", parentName);

			auto startTagPattern = TPATTERN{ PT_TERMINATOR, startTag };
			auto endTagPattern = TPATTERN{ PT_TERMINATOR, endTag };

			auto recursiveElemets = 1;
			while (auto& match = parser.match(options, startTagPattern, endTagPattern))
			{
				contentHtml.writeString(parser.matchText);
				if (match.id == 1)
				{
					if (--recursiveElemets == 0)
						break;
				}
				else if (match.id == 0)
				{
					DBGBREAK(); // debug!
					recursiveElemets++;
				}
			}

			parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, ">" });
		} while (false);

		parser.parsedText.clear();

		return contentHtml.toBuffer();
	}

	CTOKEN getCssTokenType(CSS_SEPARATOR sep)
	{
		auto cssType = CTOKEN::WITHIN;

		if (sep == CSEP_NONE)
			cssType = CTOKEN::WITHIN;
		else if (sep == CSEP_DESCENDANT)
			cssType = CTOKEN::DESCENDANT;
		else if (sep == CSEP_CHILD)
			cssType = CTOKEN::CHILD;
		else if (sep == CSEP_SIBLING)
			cssType = CTOKEN::SIBLING;
		else if (sep == CSEP_ATTR_EQUALS)
			cssType = CTOKEN::ATTR_EQUALS;
		else if (sep == CSEP_ATTR_BEGINS_WITH)
			cssType = CTOKEN::ATTR_BEGINS_WITH;
		else if (sep == CSEP_ATTR_CONTAINS)
			cssType = CTOKEN::ATTR_CONTAINS;
		else if (sep == SEL_ATTR_ENDS_WITH)
			cssType = CTOKEN::ATTR_ENDS_WITH;
		else if (sep == SEL_ATTR_SPACED)
			cssType = CTOKEN::ATTR_SPACED;
		else if (sep == SEL_ATTR_HYPHENATED)
			cssType = CTOKEN::ATTR_HYPHENATED;
		else if (sep == CSEP_PARENTHESIS)
			cssType = CTOKEN::VALUE;
		else if (sep == CSEP_PSEUDO_CLASS || sep == CSEP_PSEUDO_ELEMENT)
			cssType = CTOKEN::PSEUDO_CLASS;
		else if (sep == CSEP_PSEUDO_ELEMENT)
			cssType = CTOKEN::PSEUDO_ELEMENT;
		else
			DBGBREAK();

		return cssType;
	}

	template <typename TOKENSTREAM>
	void parseSelectorAttribute(PARSER_INFO& parser, TOKENSTREAM&& tokenBuffer)
	{
		TPATTERN charPattern{ PT_WORD, SelectorChars };
		TPATTERN separatorPattern{ PT_WORD, SelectorSeparators };

		auto& nameCapture = parser.match(PF_COLLAPSE_SPACE, charPattern);
		if (nameCapture)
		{
			auto name = CreateCustomName<SERVICE_STACK>(parser.matchText);

			auto& separatorCapture = parser.match(PF_COLLAPSE_SPACE, separatorPattern);
			ASSERT(separatorCapture);

			auto separator = findCssSeparator(parser.matchText);
			if (separator == CSEP_ATTR_END)
			{
				WriteCssToken(tokenBuffer, CTOKEN::ATTR_EXISTS, name);
			}
			else
			{
				WriteCssToken(tokenBuffer, getCssTokenType(separator), name);

				TPATTERN terminatorPattern{ PT_TERMINATOR, "]" };
				auto valueText = parser.matchWord(terminatorPattern);
				if (valueText)
				{
					WriteCssToken(tokenBuffer, CTOKEN::VALUE, String.parseLiteral<SERVICE_STACK>(valueText));
				}
				else DBGBREAK();
			}
		}
		else DBGBREAK();
	}

	template <typename STREAM>
	CSS_TOKEN parseCssProperties(PARSER_INFO& parser, STREAM&& cssStream)
	{
		auto propertyOffset = cssStream.count();

		UINT8 wordSeparators[] = { PATTERN_FLAG_ONE_OR_MORE, CcStyleWordSeparators };
		UINT8 groupChars[] = { PATTERN_FLAG_CHAR_CLASS, CcStyleGroupChars };
		UINT8 terminators[] = { PATTERN_FLAG_ZERO_OR_MORE, CcWhitespace, PATTERN_FLAG_CHAR_CLASS, CcStyleTerminators };

		STREAM_BUILDER<PARSED_WORD, SCHEDULER_STACK, 8> wordStream;
		for (;;)
		{
			auto terminatorText = parser.parseWords(wordSeparators, groupChars, terminators, wordStream.clear());

			auto words = wordStream.toBuffer();
			if (words)
			{
				auto propertyName = words.shift().wordName;
				ParseCssProperty(cssStream, propertyName, words);
			}
			else
			{
				ASSERT(String.contains(terminatorText, '}') || parser.atEOF);
			}
			if (String.contains(terminatorText, '}') || parser.atEOF)
				break;
		}

		return CSS_TOKEN{ CTOKEN::PROPERTIES, CreateNumberHandle<SERVICE_STACK>((propertyOffset << 16) | (cssStream.count() - propertyOffset)) };
	}
	
	template <typename TOKENSTREAM>
	void parsePseudoClass(PARSER_INFO& parser, TOKENSTREAM&& tokenStream)
	{
		TPATTERN charPattern{ PT_WORD, SelectorChars };

		auto& nameCapture = parser.match(PF_COLLAPSE_SPACE, charPattern);
		if (nameCapture)
		{
			auto name = FindName(parser.matchText);
			WriteCssToken(tokenStream, CTOKEN::PSEUDO_CLASS, name);
			if (name == STYLE_not || name == STYLE_nth_child || name == STYLE_nth_last_child || name == STYLE_nth_last_of_type || name == STYLE_nth_of_type)
			{
				if (parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_TERMINATOR, ")" }))
				{
					auto param = parser.matchText;
					param.shift();
				}
				else DBGBREAK();
			}
		}
		else DBGBREAK();
	}

	template <typename TOKENSTREAM>
	void parsePsuedoElement(PARSER_INFO& parser, TOKENSTREAM&& tokenStream)
	{
		TPATTERN charPattern{ PT_WORD, SelectorChars };

		auto& nameCapture = parser.match(PF_COLLAPSE_SPACE, charPattern);
		if (nameCapture)
		{
			auto name = FindName(parser.matchText);
			WriteCssToken(tokenStream, CTOKEN::PSEUDO_ELEMENT, name);
		}
		else DBGBREAK();
	}

	template <typename STREAM>
	bool parseSupports(PARSER_INFO& parser, STREAM&& selectorStream)
	{
		UINT8 wordSeparators[] = { PATTERN_FLAG_ONE_OR_MORE, CcMediaSeparators };
		UINT8 groupChars[] = { PATTERN_FLAG_CHAR_CLASS, CcMediaGroupChars };
		UINT8 terminators[] = { PATTERN_FLAG_ZERO_OR_MORE, CcWhitespace,  PATTERN_FLAG_CHAR_CLASS, CcMediaTerminators };

		STREAM_BUILDER<PARSED_WORD, SCHEDULER_STACK, 4> wordStream;

		parser.parseWords(wordSeparators, groupChars, terminators, wordStream);
		auto parsedWords = wordStream.toBuffer();

		auto isNot = false;
		if (parsedWords.peek().wordName == STYLE_not)
		{
			parsedWords.shift();
			isNot = true;
		}

		auto isValid = isNot ? false : true;

		if (isValid)
		{
			for (;;)
			{
				if (parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, "}" }))
					break;

				parseSelector(parser, selectorStream);
			}
		}
		else
		{
			parser.matchBlock("{", "}");
		}
		return isValid;
	}

	template <typename STREAM>
	bool parseKeyframes(PARSER_INFO& parser, STREAM&& selectorStream)
	{
		UINT8 wordSeparators[] = { PATTERN_FLAG_ONE_OR_MORE, CcMediaSeparators };
		UINT8 groupChars[] = { PATTERN_FLAG_CHAR_CLASS, CcMediaGroupChars };
		UINT8 terminators[] = { PATTERN_FLAG_ZERO_OR_MORE, CcWhitespace,  PATTERN_FLAG_CHAR_CLASS, CcMediaTerminators };

		STREAM_BUILDER<PARSED_WORD, SCHEDULER_STACK, 4> wordStream;

		parser.parseWords(wordSeparators, groupChars, terminators, wordStream);
		auto parsedWords = wordStream.toBuffer();

		auto isValid = false;

		if (isValid)
		{
			for (;;)
			{
				if (parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, "}" }))
					break;

				parseSelector(parser, selectorStream);
			}
		}
		else
		{
			parser.matchBlock("{", "}");
		}
		return isValid;
	}

	template <typename STREAM>
	bool parseMedia(PARSER_INFO& parser, STREAM&& selectorStream)
	{
		UINT8 wordSeparators[] = { PATTERN_FLAG_ONE_OR_MORE, CcMediaSeparators };
		UINT8 groupChars[] = { PATTERN_FLAG_CHAR_CLASS, CcMediaGroupChars };
		UINT8 terminators[] = { PATTERN_FLAG_ZERO_OR_MORE, CcWhitespace,  PATTERN_FLAG_CHAR_CLASS, CcMediaTerminators };

		STREAM_BUILDER<PARSED_WORD, SCHEDULER_STACK, 4> wordStream;

		parser.parseWords(wordSeparators, groupChars, terminators, wordStream);
		auto parsedWords = wordStream.toBuffer();

		auto isNot = false;
		if (parsedWords.peek().wordName == STYLE_not)
		{
			parsedWords.shift();
			isNot = true;
		}

		auto isValid = true;
		do
		{
			auto nextWord = parsedWords.peek();
			if (nextWord.wordName == STYLE_all || nextWord.wordName == STYLE_screen)
			{
				parsedWords.shift();
			}
			else if (nextWord.wordString == "print" || nextWord.wordString == "speech")
			{
				isValid = false;
				break;
			}

			while (parsedWords)
			{
				auto parsedWord = parsedWords.shift();
				if (parsedWord.wordName == STYLE_and)
					continue;

				if (String.contains(parsedWord.separatorAfter, ':'))
				{
					ASSERT(parsedWords);
					auto nextWord = parsedWords.shift();

					if (parsedWord.wordName == STYLE_min_width)
					{
						auto value = String.toNumber(nextWord.wordString);
						if (value > 1600)
						{
							isValid = false;
							break;
						}
					}
					else if (parsedWord.wordName == STYLE_min_height)
					{
						auto value = String.toNumber(nextWord.wordString);
						if (value > 1080)
						{
							isValid = false;
							break;
						}
					}
					else DBGBREAK();
				}
				else
				{
					if (parsedWord.wordName == STYLE_monochrome)
					{
						isValid = false;
						break;
					}
				}
			}
		} while (false);

		if (isNot)
		{
			DBGBREAK();
			isValid = !isValid;
		}

		if (isValid)
		{
			for (;;)
			{
				if (parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, "}" }))
					break;

				parseSelector(parser, selectorStream);
			}
		}
		else
		{
			parser.matchBlock("{", "}");
		}
		return isValid;
	}

	template <typename TOKENSTREAM>
	CSS_TOKEN parseSelector(PARSER_INFO& parser, TOKENSTREAM&& tokenStream)
	{
		auto separator = CSEP_DESCENDANT;
		TPATTERN charPattern{ PT_WORD, SelectorChars };
		TPATTERN separatorPattern{ PT_WORD, SelectorSeparators };

		auto valueToken =  CSS_TOKEN(CTOKEN::PROPERTIES, Null);
		while (auto& capture = parser.match(PF_COLLAPSE_SPACE, charPattern, separatorPattern))
		{
			if (capture.id == 0)
			{
				if (parser.matchText == "@media")
				{
					parseMedia(parser, tokenStream);
					break;
				}
				if (parser.matchText == "@supports")
				{
					parseSupports(parser, tokenStream);
					break;
				}
				else if (parser.matchText == "@-webkit-keyframes" || parser.matchText == "@keyframes")
				{
					parseKeyframes(parser, tokenStream);
					break;
				}
				else
				{
					ASSERT(parser.matchText[0] != '@');
					auto name = CreateCustomName<SERVICE_STACK>(parser.matchText);
					WriteCssToken(tokenStream, getCssTokenType(separator), name);
				}
			}
			else
			{
				auto sepText = parser.matchText;
				if (sepText)
				{
					if (sepText.length() > 1)
						String.trim(sepText);

					if (sepText == "*")
					{
						DBGBREAK();
						auto name = CreateCustomName<SERVICE_STACK>(sepText);
						WriteCssToken(tokenStream, getCssTokenType(separator), name);
						continue;
					}

					separator = findCssSeparator(sepText);
					if (separator == CSEP_COMMA)
					{
						auto valueOffset = tokenStream.commit(1);
						valueToken = parseSelector(parser, tokenStream);
						*valueOffset = valueToken;
						break;
					}
					else if (separator == CSEP_VALUE_START)
					{
						valueToken = parseCssProperties(parser, cssPropertyStream);
						tokenStream.append(valueToken);
						break;
					}
					else if (separator == CSEP_ATTR_START)
					{
						parseSelectorAttribute(parser, tokenStream);
						separator = CSEP_DESCENDANT;
					}
					else if (separator == CSEP_PSEUDO_CLASS)
					{
						parsePseudoClass(parser, tokenStream);
					}
					else if (separator == CSEP_PSEUDO_ELEMENT)
					{
						parsePsuedoElement(parser, tokenStream);
					}
					else if (separator == CSEP_PARENTHESIS)
					{
						DBGBREAK();
						auto& valueCapture = parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_TERMINATOR, ")" });
						if (valueCapture)
						{
							tokenStream.append(CTOKEN::VALUE, String.parseLiteral<SERVICE_STACK>(parser.matchText));
						}

					}
				}
				else DBGBREAK();
			}
		}
		return valueToken;
	}

	void parseCSS(USTRING cssText)
	{
		auto& parser = TaskAlloc<PARSER_INFO>(CONTENT_TYPE::CSS, cssText);

		while (parser.inputText.length() > 0)
		{
			parseSelector(parser, cssSelectorStream);
		}
	}

	template <typename LAMBDA, typename ... ARGS>
	void parseAttribute(PARSER_INFO& parser, LAMBDA callback, ARGS&& ... args)
	{
		TOKEN attrName = Undefined;
		USTRING valueText;
		TPATTERN separatorPattern{ PT_TERMINATOR, AttributeSeparators };
		TPATTERN endTagPattern1{ PT_TERMINATOR, "/>" }; // both patterns match a self closing tag, keep this first.
		TPATTERN endTagPattern2{ PT_TERMINATOR, ">" };

		for (;;)
		{
			parser.matchWord(separatorPattern, endTagPattern1, endTagPattern2);
			if (parser.terminatorText[0] == '=')
			{
				ASSERT(!attrName);
				attrName = CreateCustomName<SERVICE_STACK>(parser.matchText);
				continue;
			}

			if (parser.matchText.length() > 0)
			{
				if (attrName)
					valueText = parser.matchText;
				else
					attrName = CreateCustomName<SERVICE_STACK>(parser.matchText);
			}
			else
			{
				ASSERT(parser.terminatorText == " " ||
					parser.terminatorText == ">" || parser.terminatorText == "/>");
			}

			if (attrName)
			{
				callback(attrName, valueText, args ...);
			}

			attrName = Null;
			valueText = NULL_STRING;

			if (parser.terminatorText == ">" || parser.terminatorText == "/>")
			{
				break;
			}
		}
	}

	bool parseControlElement(TOKEN name, PARSER_INFO& parser)
	{
		auto handled = true;

		if (name == ELEMENT_script)
		{
			auto externalScript = false;
			parseAttribute(parser, [](TOKEN name, USTRING value, WEBPAGE_PARSER<SERVICE>& pageParser, bool& externalScript)
				{
					if (name == ATTR_src)
					{
						externalScript = true;

						pageParser.service.download(value, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
							{
								auto& pageParser = *(WEBPAGE_PARSER<SERVICE>*) context;
								UNREFERENCED_PARAMETER(pageParser);

								auto contentString = argv.read<USTRING>();
								UNREFERENCED_PARAMETER(contentString);

								if (NT_SUCCESS(status))
								{
									// parseScript(contentString);
								}
							}, &pageParser));
					}
					// Download external script.
				}, *this, externalScript);

			if (externalScript == false)
			{
				auto scriptText = getContent(name, parser, TSTRING_BUILDER(), PF_NONE);
				//ParseScript(scriptText);
			}
			else
			{
				if (getClosingTag(parser) == false)
				{
					getContent(name, parser, TSTRING_BUILDER(), PF_NONE);
				}
			}
		}
		else if (name == ELEMENT_link)
		{
			auto isStyleSheet = true;
			UNREFERENCED_PARAMETER(isStyleSheet);
			parseAttribute(parser, [](TOKEN name, USTRING value, bool& isStyleSheet, WEBPAGE_PARSER<SERVICE>& pageParser)
				{
					if (name == ATTR_rel)
					{
						if (FindName(value) != ATTR_stylesheet)
							isStyleSheet = false;
					}
					else if (name == ATTR_type)
					{
						if (FindName(value) != ATTR_text_css)
						{
							isStyleSheet = false;
						}
					}
					else if (name == ATTR_href)
					{
						if (isStyleSheet)
						{
							pageParser.service.download(value, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
								{
									auto& parser = *(WEBPAGE_PARSER<SERVICE>*)context;
									auto htmlString = argv.read<USTRING>();
									parser.parseCSS(htmlString);
								}, &pageParser));
						}
					}
				}, isStyleSheet, *this);
			auto endTagFound = getClosingTag(parser);
			ASSERT(endTagFound);
		}
		else if (name == ELEMENT_style)
		{
			ignoreAttributes(parser);
			auto styleText = getContent(name, parser, TSTRING_BUILDER(), PF_NONE);
			parseCSS(styleText);
		}
		else
		{
			handled = false;
		}
		return handled;
	}

	void parseHead(PARSER_INFO& parser)
	{
		auto selfClosing = ignoreAttributes(parser);
		ASSERT(selfClosing == false);

		auto isEndTag = false;
		while (auto name = getNextTag(parser, isEndTag))
		{
			if (isEndTag)
				break;

			if (parseControlElement(name, parser) == false)
			{
				selfClosing = ignoreAttributes(parser);
				if (selfClosing == false && (IsNoContentElement(name) == false))
				{
					getContent(name, parser, TSTRING_BUILDER(), PF_NONE);
				}
			}
		}
	}

	template <typename TOKENSTREAM>
	void parseChildElement(PARSE_HTML_CONTEXT& context, TOKEN thisElement, PARSER_INFO& parser,
		TOKENSTREAM&& tokenBuffer)
	{
		context.elementStack.append(thisElement);
		parseHtmlElement(context, parser, tokenBuffer);
		context.elementStack.trim();
	}

	bool isAncestor(PARSE_HTML_CONTEXT& context, TOKEN elementName)
	{
		auto found = false;
		for (UINT32 i = 0; i < context.elementStack.count(); i++)
		{
			if (context.elementStack.last(i) == elementName)
			{
				found = true;
				break;
			}
		}
		return found;
	}

	USTRING parseTextElement(USTRING& input)
	{
		TSTRING_BUILDER textStream;

		auto& parser = TaskAlloc<PARSER_INFO>(CONTENT_TYPE::TEXT, input);

		UINT8 EntityChars[] = { '&', PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcHtmlEntity, ';'};
		UINT8 UnicodeEscapeChars[] = { '\\', 'u', PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcHexChars };
		UINT8 EofChars[] = { CTRL_Z };

		TPATTERN entityPattern{ PT_TERMINATOR, EntityChars };
		TPATTERN unicodeCharPattern{ PT_TERMINATOR, UnicodeEscapeChars };
		TPATTERN eofPattern{ PT_TERMINATOR, EofChars };

		while (auto& match = parser.match(PF_COLLAPSE_SPACE, entityPattern, unicodeCharPattern, eofPattern))
		{
			textStream.writeStream(parser.matchText);

			if (match.id == 0)
			{
				auto& entity = parser.terminatorText;
				ASSERT(entity.length() > 2 && entity.length() < 10);
				entity.shrink();
				entity.shift();

				auto name = FindName(entity);
				if (name)
				{
					UINT32 unicode = 0;
					for (auto& entityMap : EntityMap)
					{
						if (entityMap.name == name)
						{
							unicode = entityMap.letter;
							break;
						}
					}
					ASSERT(unicode != 0);
					textStream.writeUtf8(unicode);
				}
				else if (entity[0] == '#')
				{
					entity.shift();
					UINT32 unicode = 0;
					if (entity[0] == 'x' || entity[0] == 'X')
					{
						unicode = String.toHexNumber(entity);
					}
					else
					{
						unicode = String.toNumber(entity);
					}
					ASSERT(unicode != 0);
					textStream.writeUtf8(unicode);
				}
			}
			else if (match.id == 1)
			{
				UINT32 unicode = 0;
				auto& hex = parser.terminatorText;
				ASSERT(hex.length() == 6);

				hex.shift(2);
				unicode = String.toHexNumber(hex);
			}
			else if (match.id == 2)
			{
				break;
			}
			else DBGBREAK();
		}

		if (parser.inputText)
		{
			DBGBREAK();
			textStream.writeStream(parser.inputText);
		}

		return textStream.toBuffer();
	}

	template <typename TOKENSTREAM>
	void parseHtmlElement(PARSE_HTML_CONTEXT& context, PARSER_INFO& parser, TOKENSTREAM&& htmlStream)
	{
		auto elementName = context.elementStack.last();

		if (parseControlElement(elementName, parser))
		{
			return;
		}

		auto elementId = htmlStream.count();
		do
		{
			UINT32 childCount = 0;

			WriteHtmlToken(htmlStream, HTOKEN::ELEMENT, elementName); // HtmlToken(elementName, elementId));
			parseAttribute(parser, [](TOKEN name, USTRING value, WEBPAGE_PARSER<SERVICE>& parser)
				{
					if (name == ATTR_id)
					{
						auto idName = CreateCustomName<SERVICE_STACK>(TSTRING_BUILDER().writeMany("#", value));
						WriteHtmlToken(parser.htmlTokenStream, HTOKEN::ID, idName);
					}
					else if (name == ATTR_class)
					{
						auto& classParser = TaskAlloc<PARSER_INFO>(CONTENT_TYPE::TEXT, value);
						TPATTERN charPattern{ PT_TERMINATOR, WordSeparators };
						while (auto& match = classParser.match(PF_COLLAPSE_SPACE, charPattern))
						{
							auto className = CreateCustomName<SERVICE_STACK>(TSTRING_BUILDER().writeMany(".", classParser.matchText));
							WriteHtmlToken(parser.htmlTokenStream, HTOKEN::CLASS, className);
						}
					}
					else if (name == ATTR_style)
					{
						auto& propertyBuffer = parser.cssPropertyStream;
						auto propertyOffset = propertyBuffer.count();

						auto& styleParser = TaskAlloc<PARSER_INFO>(CONTENT_TYPE::CSS, value);
						parser.parseCssProperties(styleParser, propertyBuffer);
						WriteHtmlToken(parser.htmlTokenStream, HTOKEN::STYLE, CreateNumberHandle<SCHEDULER_STACK>((propertyOffset << 8) | (propertyBuffer.count() - propertyOffset)));
					}
					else
					{
						WriteHtmlToken(parser.htmlTokenStream, HTOKEN::ATTR_NAME, name);
						WriteHtmlToken(parser.htmlTokenStream, HTOKEN::ATTR_VALUE, String.parseLiteral<SERVICE_STACK>(value));
					}
				}, *this);

			if (getClosingTag(parser) == true)
			{
				break;
			}

			if (IsNoContentElement(elementName))
			{
				break;
			}

			if (elementName == ELEMENT_svg || elementName == ELEMENT_img)
			{
				getContent(elementName, parser, TSTRING_BUILDER(), PF_NONE);
				break;
			}

			TPATTERN startTag{ PT_WORD, BeginTagPattern };
			TPATTERN endTag{ PT_WORD, EndTagPattern };
			TPATTERN textElementTag{ PT_WORD, HtmlTextChars };

			while (auto& match = parser.match(PF_COLLAPSE_SPACE, startTag, endTag, textElementTag))
			{
				if (match.id == 0)
				{
					parser.matchText.shift();
					auto childName = FindName(parser.matchText);
					ASSERT(childName);

					if (childName == elementName && IsNoSelfChildElement(elementName))
					{
						DBGBREAK();
						break;
					}
					WriteHtmlToken(htmlTokenStream, childCount++ == 0 ? HTOKEN::CHILD : HTOKEN::SIBLING, CreateNumberHandle<SERVICE_STACK>(elementId));
					parseChildElement(context, childName, parser, htmlStream);
				}
				else if (match.id == 1)
				{
					parser.matchText.shift(2);
					auto tagElementName = FindName(parser.matchText);
					if (elementName == tagElementName)
					{
						parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, ">" });
						break;
					}
					else if (isAncestor(context, tagElementName))
					{
						parser.revert();
						break;
					}
					else
					{
						parser.match(PF_COLLAPSE_SPACE, TPATTERN{ PT_WORD, ">" });
					}
				}
				else if (match.id == 2)
				{
					auto text = parseTextElement(parser.matchText);
					auto textToken = String.allocLiteral<SCHEDULER_STACK>(text);
					WriteHtmlToken(htmlTokenStream, HTOKEN::TEXT, textToken);
					continue;
				}
			}
		} while (false);

		WriteHtmlToken(htmlStream, HTOKEN::END, CreateNumberHandle<SCHEDULER_STACK>(elementId));
		parser.parsedText.clear();
	}

	void parseBody(PARSER_INFO& parser)
	{
		ignoreAttributes(parser);

		PARSE_HTML_CONTEXT context;
		context.elementStack.append(ELEMENT_body);
		auto isEndTag = false;
		while (auto name = getNextTag(parser, isEndTag))
		{
			if (isEndTag)
				break;
			parseChildElement(context, name, parser, htmlTokenStream);
		}
	}

	void parseHtml(USTRING htmlText)
	{
		htmlParser = &TaskAlloc<PARSER_INFO>(CONTENT_TYPE::HTML, htmlText);

		auto status = KeExpandKernelStackAndCalloutEx([](PVOID param)
			{
				auto& self = *(WEBPAGE_PARSER<SERVICE>*)param;
				auto isEndTag = false;
				auto name = self.getNextTag(*self.htmlParser, isEndTag);
				if (name == ELEMENT_html)
				{
					self.ignoreAttributes(*self.htmlParser);
					name = self.getNextTag(*self.htmlParser, isEndTag);
					if (name == ELEMENT_head)
					{
						self.parseHead(*self.htmlParser);
					}
					else DBGBREAK();
					name = self.getNextTag(*self.htmlParser, isEndTag);
					if (name == ELEMENT_body)
					{
						self.parseBody(*self.htmlParser);
					}
					else DBGBREAK();
				}
				else DBGBREAK();
			}, this, 64 * 1024, FALSE, nullptr);
		ASSERT(NT_SUCCESS(status));
	}

};

struct WEBSITE_PARSER
{
	SERVICE_STACK stack;
	SCHEDULER_INFO<WEBSITE_PARSER> scheduler;
	WEBPAGE_PARSER<WEBSITE_PARSER> pageParser;

	URL_INFO appUrl;

	STREAM_BUILDER<HTTP_CLIENT<WEBSITE_PARSER>, SERVICE_STACK, 4> httpClientStream;

	STREAM_BUILDER<HTTP_COOKIE, SERVICE_STACK, 8> cookieTable;

	WEBSITE_PARSER() : scheduler(*this), pageParser(*this) 
	{
		auto status = InitializeStack(stack, 32 * 1024 * 1024, 0);
		ASSERT(NT_SUCCESS(status));

		status = scheduler.initialize();
		ASSERT(NT_SUCCESS(status));
	}

	auto& getScheduler() { return scheduler; }

	STREAM_READER<const HTTP_COOKIE> getCookieTable()
	{
		return cookieTable.toBuffer();
	}
	
	HTTP_COOKIE& findCookie(TOKEN name)
	{
		for (auto& cookie : cookieTable.toBufferNoConst())
		{
			if (cookie.name == name)
			{
				return cookie;
			}
		}
		return NullRef<HTTP_COOKIE>();
	}

	HTTP_COOKIE& setCookie(TOKEN name, TOKEN value)
	{
		auto& cookieFound = findCookie(name);
		auto& cookie = cookieFound ? cookieFound : cookieTable.append(name);

		cookie.value = value;
		return cookie;
	}

	auto& getHttpClient()
	{
		//for (auto& client : httpClientStream.toBufferNoConst())
		//{
		//	if (client.downloadComplete)
		//	{
		//		new (&client) HTTP_CLIENT<WEBSITE_PARSER>(*this);
		//		return client;
		//	}
		//}
		return httpClientStream.append(*this);
	}

	NTSTATUS parse(USTRING url)
	{
		scheduler.runTask(0, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto& parser = *(WEBSITE_PARSER*)context;
				auto urlString = argv.read<USTRING>();

				String.parseUrl<SERVICE_STACK>(urlString, parser.appUrl);

				auto& httpClient = parser.getHttpClient();
				httpClient.download(parser.appUrl, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
					{
						DBGBREAK();
						auto& parser = *(WEBSITE_PARSER*)context;

						auto& httpClient = *argv.read<HTTP_CLIENT<WEBSITE_PARSER>*>();
						httpClient.close();

						if (NT_SUCCESS(status))
						{
							auto htmlString = argv.read<USTRING>();
							parser.pageParser.parseHtml(htmlString);
						}
					}, &parser, &httpClient));
			}, this, url));

		return STATUS_SUCCESS;
	}

	NTSTATUS download(USTRING urlString, STASK completionTask)
	{
		URL_INFO urlInfo;
		String.parseUrl<SERVICE_STACK>(urlString, urlInfo);

		if (!urlInfo.protocol)
		{
			urlInfo.protocol = appUrl.protocol;
			urlInfo.port = appUrl.port;
			urlInfo.hostname = appUrl.hostname;
		}

		auto taskId = scheduler.queueTask(SOCKET_RECV_PRIORITY - 1, completionTask);
		auto& httpClient = getHttpClient();

		auto status = httpClient.download(urlInfo, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
			{
				auto& parser = *(WEBSITE_PARSER*)context;
				auto taskId = argv.read<TASK_ID>();

				auto& httpClient = *argv.read<HTTP_CLIENT<WEBSITE_PARSER>*>();
				httpClient.close();

				auto htmlString = argv.read<USTRING>();
				parser.scheduler.updateTask(taskId, status, htmlString);
			}, this, taskId, &httpClient));

		return status;
	}
};
