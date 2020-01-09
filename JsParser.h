// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

INT32 KeywordIndex(TOKEN name);
constexpr TOKEN KeywordHandle(TOKEN name)
{
	if (IsEmptyString(name))
		return Undefined;

	for (auto i = 0; i < ARRAYSIZE(KeywordNames); i++)
	{
		if (KeywordNames[i] == name)
			return TOKEN(TOKENTYPE::STOKEN_KEYWORD, i);
	}
	return Undefined;
}

DEFINE_ENUM_FLAG_OPERATORS(JS_OPERATOR);

constexpr UINT8 JsChars[] = { PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcJsChars };
constexpr UINT8 JsSeparators[] = { PATTERN_FLAG_CHAR_CLASS, CcJsSeparators };
constexpr UINT8 JsOperators[] = { PATTERN_FLAG_CHAR_CLASS | PATTERN_FLAG_ONE_OR_MORE, CcJsOperators };

constexpr UINT8 GetPrecedence(JS_OPERATOR op) { return op & 0xF0; }

constexpr UINT8 PRECEDENCE_UNARY = OP_NEW & 0xF0;
constexpr UINT8 PRECEDENCE_ADD = OP_ADD & 0xF0;
constexpr UINT8 PRECEDENCE_MULTIPLY = OP_MULTIPLY & 0xF0;
constexpr UINT8 PRECEDENCE_ASSIGN = OP_ASSIGN & 0xF0;
constexpr UINT8 PRECEDENCE_LOGICAL_ASSIGN = OP_AND_ASSIGN & 0xF0;
constexpr UINT8 PRECEDENCE_LOGICAL_OR = OP_LOGICAL_OR & 0xF0;
constexpr UINT8 PRECEDENCE_LOGICAL_AND = OP_LOGICAL_AND & 0xF0;
constexpr UINT8 PRECEDENCE_EQUALS = OP_EQUALS & 0xF0;
constexpr UINT8 PRECEDENCE_LOGICAL = OP_GREATER_THAN & 0xF0;

struct OPERATOR_INFO
{
	JS_OPERATOR id;
	bool leftToRight;
	USTRING string;
};

struct SEPARATOR_INFO
{
	SEPARATOR id;
	UINT8 letter;
};

constexpr SEPARATOR_INFO Separators[] = {
	{ SEP_LEFT_BRACE, '{' },
	{ SEP_RIGHT_BRACE, '}' },
	{ SEP_LEFT_PARENTHESIS, '(' },
	{ SEP_RIGHT_PARENTHESIS, ')' },
	{ SEP_LEFT_BRACKET, '[' },
	{ SEP_RIGHT_BRACKET, ']' },
	{ SEP_SEMICOLON, ';' },
	{ SEP_DOUBLE_QUOTE, '"' },
	{ SEP_SINGLE_QUOTE, '\'' },
	{ SEP_DOT, '.' },
	{ SEP_COMMA, ',' },
	{ SEP_COLON, ':'},
};

constexpr OPERATOR_INFO Operators[] = {
	{ OP_LESS_THAN, true, "<" },
	{ OP_GREATER_THAN, true, ">" },
	{ OP_LESS_THAN_EQUAL, true, "<=" },
	{ OP_GREATER_THAN_EQUAL, true, ">=" },
	{ OP_EQUALS, true, "==" },
	{ OP_NOT_EQUALS, true, "!=" },
	{ OP_STRICT_EQUALS, true, "===" },
	{ OP_STRICT_NOT_EQUALS, true, "!==" },
	{ OP_ADD, true, "+" },
	{ OP_SUBTRACT, true, "-" },
	{ OP_MULTIPLY, true, "*" },
	{ OP_MOD, true, "%" },
	{ OP_DIVIDE, true, "/" },
	{ OP_COMMA, true, "," },
	{ OP_UNARY_MINUS, true, "-" },
	{ OP_UNARY_PLUS, true, "+" },
	{ OP_PLUS_PLUS, true, "++" },
	{ OP_MINUS_MINUS, true, "--" },
	{ OP_LEFT_SHIFT, true, "<<" },
	{ OP_RIGHT_SHIFT, true, ">>" },
	{ OP_RIGHT_SHIFT2, true, ">>>" },
	{ OP_BITWISE_AND, true, "&" },
	{ OP_BITWISE_OR, true, "|" },
	{ OP_XOR, true, "^" },
	{ OP_NOT, true, "!" },
	{ OP_TILDA, true, "~" },
	{ OP_LOGICAL_AND, true, "&&" },
	{ OP_LOGICAL_OR, true, "||" },
	{ OP_QUESTION, true, "?" },
	{ OP_COLON, true, ":" },
	{ OP_ASSIGN, true, "=" },
	{ OP_ADD_ASSIGN, true, "+=" },
	{ OP_SUBTRACT_ASSIGN, true, "-=" },
	{ OP_MULTIPLY_ASSIGN, true, "*=" },
	{ OP_DIVIDE_ASSIGN, true, "/=" },
	{ OP_MOD_ASSIGN, true, "%=" },
	{ OP_LEFT_SHIFT_ASSIGN, true, "<<=" },
	{ OP_RIGHT_SHIFT_ASSIGN, true, ">>=" },
	{ OP_RIGHT_SHIFT_EQUALS2, true, ">>>=" },
	{ OP_AND_ASSIGN, true, "&=" },
	{ OP_OR_ASSIGN, true, "|=" },
	{ OP_XOR_ASSIGN, true, "^=" },
	{ OP_DELETE, true, "delete" },
	{ OP_NEW, true, "new" },
	{ OP_IN, true, "in" },
	{ OP_TYPEOF, true, "typeof" },
	{ OP_VOID, true, "void" },
	{ OP_INSTANCEOF, true, "instanceof" },
};

constexpr auto ElseToken = KeywordHandle(KEYWORD_else);

template<typename STACK, typename TOKENSTREAM>
struct JSTOKEN_PARSER
{
	TOKENSTREAM& tokenStream;
	UINT32 streamStart;
	PARSER_INFO& textParser;

	JSTOKEN_PARSER(PARSER_INFO& parser, TOKENSTREAM&& stream) : tokenStream(stream), textParser(parser)
	{
		this->streamStart = this->tokenStream.count();
	}

	JSTOKEN_PARSER(PARSER_INFO& parser, TOKENSTREAM&& stream, TOKENTYPE type,
		UINT32 value) : tokenStream(stream), textParser(parser)
	{
		this->streamStart = this->tokenStream.count();
		this->tokenStream.append(TOKEN(type, value));
	}

	JSTOKEN_PARSER(PARSER_INFO& parser, TOKENSTREAM&& stream, TOKEN token) : tokenStream(stream), textParser(parser)
	{
		this->streamStart = this->tokenStream.count();
		this->tokenStream.append(token);
	}

	JSTOKEN_PARSER(PARSER_INFO& parser, TOKENSTREAM&& stream, UINT32 start) : tokenStream(stream), textParser(parser)
	{
		this->streamStart = start;
	}

	JSTOKEN_PARSER(PARSER_INFO& parser, TOKENSTREAM& buffer, UINT32 start,
		TOKENTYPE type, UINT32 value = 0) : tokenStream(buffer), streamStart(start), textParser(parser)
	{
		this->tokenStream.insert(start, 1);
		this->tokenStream.writeAt(start, TOKEN(type, value));
	}

	bool isNotEmpty() { return !textParser.atEOF; }

	void writeLength(UINT32 offset = 0)
	{
		offset += this->streamStart;
		auto length = this->tokenStream.count() - offset;
		ASSERT(length < 64 * 1024);

		auto& token = this->tokenStream.at(offset);
		token.setLength(length); // = (token._value & 0xFFFF0000) | (length & 0xFFFF);
	}

	auto& header() { return this->tokenStream.at(this->streamStart); }
	bool isEmpty() { return (this->tokenStream.count() - this->streamStart) <= 1; }

	UINT32 write(TOKEN token)
	{
		auto offset = this->tokenStream.count() - this->streamStart;
		this->tokenStream.append(token);
		return offset;
	}

	TOKEN read()
	{
		return ParseJsToken(this->textParser);
	}

	JSTOKEN_PARSER subStream(TOKENTYPE subType, UINT32 value)
	{
		return JSTOKEN_PARSER(this->textParser, this->tokenStream, subType, value);
	}

	JSTOKEN_PARSER subStreamAt(UINT32 offset, TOKENTYPE subType, UINT32 value)
	{
		return JSTOKEN_PARSER(this->textParser, this->tokenStream, offset, subType, value);
	}

	JSTOKEN_PARSER subStreamAt(UINT32 offset)
	{
		return JSTOKEN_PARSER(this->textParser, this->tokenStream, offset);
	}

	JSTOKEN_PARSER keywordStream(TOKEN keywordName)
	{
		return JSTOKEN_PARSER(this->textParser, this->tokenStream, KeywordHandle(keywordName));
	}

	UINT32 dataLength()
	{
		ASSERT(this->tokenStream.count() > this->streamStart);
		return (this->tokenStream.count() - this->streamStart) - 1;
	}

	TOKEN getData(int offset = 0)
	{
		return this->tokenStream.at(this->streamStart + 1 + offset);
	}

	void revert()
	{
		this->tokenStream.trim(tokenStream.count() - streamStart);
	}

	static JS_OPERATOR GetOperator(USTRING& text)
	{
		for (auto&& op : Operators)
		{
			if (String.equals(op.string, text))
			{
				return op.id;
			}
		}
		return OP_INVALID;
	}

	static SEPARATOR GetScriptSeparator(UINT8 letter)
	{
		for (auto&& separator : Separators)
		{
			if (separator.letter == letter)
			{
				return separator.id;
			}
		}
		return SEP_UNKNOWN;
	}

	static TOKEN KeywordToOp(TOKEN token)
	{
		JS_OPERATOR op = OP_INVALID;
		auto keyword = token.getKeyword();
		if (keyword == KEYWORD_new)
		{
			op = OP_NEW;
		}
		else if (keyword == KEYWORD_in)
		{
			op = OP_IN;
		}
		else if (keyword == KEYWORD_typeof)
		{
			op = OP_TYPEOF;
		}
		else if (keyword == KEYWORD_void)
		{
			op = OP_VOID;
		}
		else if (keyword == KEYWORD_delete)
		{
			op = OP_DELETE;
		}
		else if (keyword == KEYWORD_instanceof)
		{
			op = OP_INSTANCEOF;
		}
		return op != OP_INVALID ? TOKEN(TOKENTYPE::STOKEN_OPERATOR, op) : token;
	}

	static TOKEN ParseRegex(PARSER_INFO& parser)
	{
		auto scriptMarker = parser.inputText;

		TPATTERN pattern{ PT_TERMINATOR, "/" };

		auto regexText = parser.parseQuote('/');
		//auto ptr = regexText.data();

		auto validRegex = false;
		//try
		//{
		//	std::regex reg(ptr);
		//}
		//catch (...)
		//{
		//	DBGBREAK();
		//	validRegex = false;
		//}

		if (validRegex)
		{
			auto literalHandle = String.parseLiteral<STACK>(regexText); // parser.matchText);
			return TOKEN(TOKENTYPE::REGEX, literalHandle.getValue());
		}
		else
		{
			parser.inputText = scriptMarker;
			return Undefined;
		}
	}

	static TOKEN ParseLiteral(SEPARATOR separator, PARSER_INFO& parser)
	{
		ASSERT(separator == SEP_DOUBLE_QUOTE || separator == SEP_SINGLE_QUOTE);

		parser.parseQuote(separator == SEP_DOUBLE_QUOTE ? '"' : '\'');

		ASSERT(parser.matchText.last() != '\\');
		return String.parseLiteral<STACK>(parser.matchText);
	}

	static TOKEN ParseJsToken(PARSER_INFO& parser)
	{
		TOKEN token;

		TPATTERN charPattern{ PT_WORD, JsChars };
		TPATTERN separatorPattern{ PT_WORD, JsSeparators };
		TPATTERN operatorPattern{ PT_WORD, JsOperators };

		auto& wordMatch = parser.match(PF_COLLAPSE_SPACE, charPattern);

		if (wordMatch)
		{
			if (wordMatch.id == 0)
			{
				auto number = ParseNumber(parser.matchText);
				if (number)
				{
					token = number;
				}
				else
				{
					auto name = CreateCustomName<STACK>(parser.matchText, true);
					auto keywordIndex = KeywordIndex(name);
					if (keywordIndex >= 0)
					{
						token = TOKEN(TOKENTYPE::STOKEN_KEYWORD, keywordIndex);
						token = KeywordToOp(token);
					}
					else
					{
						if (name == RUNTIME_null)
							token = Null;
						else if (name == RUNTIME_undefined)
							token = Undefined;
						else if (name == RUNTIME_true)
							token = True;
						else if (name == RUNTIME_false)
							token = False;
						else token = name;
					}
				}
			}
			else DBGBREAK();
		}
		else
		{
			auto& match = parser.match(PF_RAW_TEXT, separatorPattern, operatorPattern);
			if (match)
			{
				if (match.id == 0)
				{
					auto separator = GetScriptSeparator(parser.matchText[0]);
					if (separator == SEP_DOUBLE_QUOTE || separator == SEP_SINGLE_QUOTE)
					{
						token = ParseLiteral(separator, parser);
					}
					else
					{
						token = TOKEN(TOKENTYPE::STOKEN_SEPARATOR, separator);
					}
				}
				else if (match.id == 1)
				{
					auto op = SplitScriptOperator(parser.matchText, parser.inputText);
					token = TOKEN(TOKENTYPE::STOKEN_OPERATOR, op);
				}
				else DBGBREAK();
			}
			else if (parser.atEOF == false) DBGBREAK();
		}
		return token;
	}

	static bool ParseMatchingJsToken(PARSER_INFO& parser, TOKEN matchToken)
	{
		auto token = ParseJsToken(parser);
		auto isMatch = (token == matchToken);
		if (!isMatch)
		{
			parser.revert();
		}
		return isMatch;
	}

	static UINT8 SplitScriptOperator(USTRING opText, USTRING& scriptText)
	{
		// opText may have multiple operators!
		while (opText.length() > 0)
		{
			auto op = GetOperator(opText);
			if (op != OP_INVALID)
			{
				return op;
			}
			opText.shrink(1);
			scriptText.shift(-1);
		}
		return OP_INVALID;
	}

	using PARSE_FUNCTION = JSTOKEN_PARSER & (*) (JSTOKEN_PARSER& tokenStream, TOKEN& token);

	struct PARSE_FUNCTION_INFO
	{
		UINT8 tokenType;
		UINT32 tokenValue;
		PARSE_FUNCTION handler;
	};

	static TOKEN ParseNumber(USTRING& script)
	{
		auto number = String.toNumber(script);
		return CreateNumberHandle<STACK>(number);
	}

	static auto&& GetLocalVariables()
	{
		return GetCurrentStack<STACK>().localVariableArray;
	}

	static void AddLocalVariable(TOKEN name)
	{
		auto& array = GetLocalVariables().last();
		array.append(name);
	}

	static void InitializeLocalVariables()
	{
		GetLocalVariables().reserve();
	}

	static void WriteLocalVariables(JSTOKEN_PARSER& functionStream)
	{
		auto&& varTokensStream = GetLocalVariables().last();
		auto varTokens = varTokensStream.toBuffer();

		GetLocalVariables().trim();

		if (varTokens.length() > 0)
		{
			auto varOffset = functionStream.streamStart + 1;

			functionStream.tokenStream.insert(varOffset, varTokens.length() + 1);

			functionStream.tokenStream.writeAt(varOffset++, TOKEN(TOKENTYPE::STOKEN_LOCALS, 0, varTokens.length() + 1));
			for (auto&& varToken : varTokens)
			{
				functionStream.tokenStream.writeAt(varOffset++, varToken);
			}
		}
	}

	static void ParseArgs(JSTOKEN_PARSER& parentStream)
	{
		auto tokenStream = parentStream.subStream(TOKENTYPE::STOKEN_ARGS, 0);

		while (true)
		{
			auto token = ParseExpression(tokenStream, Undefined, EF_COMMA_IS_SEPARATOR);
			if (token.isRightParenthesis())
			{
				break;
			}
			else if (token.isComma())
			{
				continue;
			}
			else DBGBREAK();
		}
		tokenStream.writeLength();
	}

	template <typename T>
	static TOKEN ParseSymbol(TOKEN inputToken, T&& symbolStream)
	{
		ASSERT(symbolStream.header().isSymbol());

		auto token = inputToken;
		while (token)
		{
			if (token.isNotScript())
			{
				symbolStream.write(token);
				token = symbolStream.read();
			}
			else if (token.isSeparator())
			{
				auto separator = token.getSeparator();
				if (separator == SEP_LEFT_PARENTHESIS)
				{
					ParseArgs(symbolStream);
					token = symbolStream.read();
				}
				else if (separator == SEP_LEFT_BRACKET)
				{
					ParseArray(symbolStream);
					token = symbolStream.read();
				}
				else if (separator == SEP_RIGHT_BRACE || separator == SEP_SEMICOLON || separator == SEP_RIGHT_PARENTHESIS || separator == SEP_RIGHT_BRACKET || separator == SEP_COMMA)
				{
					break;
				}
				else if (separator == SEP_DOT)
				{
					symbolStream.write(token);
					token = symbolStream.read();
				}
				else if (separator == SEP_COLON)
				{
					break;
				}
				else DBGBREAK();
			}
			else if (token.isOperator())
			{
				if (token.getPrecedence() == PRECEDENCE_UNARY)
				{
					symbolStream.write(token);
					token = symbolStream.read();
				}
				else
				{
					break;
				}
			}
			else if (token.isKeyword())
			{
				auto keyword = token.getKeyword();
				if (keyword == KEYWORD_function)
				{
					ParseFunctionStatement(symbolStream);
					//ASSERT(token.isRightBrace());
					token = symbolStream.read();
				}
				else DBGBREAK();
			}
			else DBGBREAK();
		}

		symbolStream.writeLength();
		ASSERT(symbolStream.dataLength() > 0);
		if (symbolStream.getData().getLength() == symbolStream.dataLength())
		{
			symbolStream.tokenStream.remove(symbolStream.streamStart, 1);
		}
		return token;
	}

	static TOKEN_BUFFER& GetPrevToken(JSTOKEN_PARSER& tokenStream, TOKEN_BUFFER&& tokenSegment)
	{
		tokenSegment._end = tokenSegment._start = 0;

		auto&& tokenBuffer = tokenStream.tokenStream;
		for (UINT32 i = tokenStream.streamStart + 1; i < tokenBuffer.count(); )
		{
			auto token = tokenBuffer.at(i);
			tokenSegment._start = i;
			tokenSegment._end = token.getLength();
			i += token.getLength();
		}
		return tokenSegment._end > 0 ? tokenSegment : NullRef<TOKEN_BUFFER>();
	}

	static void ParseArray(JSTOKEN_PARSER& parentStream)
	{
		auto&& arrayStream = parentStream.subStream(TOKENTYPE::STOKEN_ARRAY, 0);
		auto rightBracketSeen = false;
		while (parentStream.isNotEmpty())
		{
			auto token = parentStream.read();
			if (token.isRightBracket())
			{
				rightBracketSeen = true;
				break;
			}
			token = ParseExpression(arrayStream, token, EF_COMMA_IS_SEPARATOR);
			if (token.isComma())
			{
				continue;
			}
			else if (token.isRightBracket())
			{
				rightBracketSeen = true;
				break;
			}
		}
		ASSERT(rightBracketSeen);
		arrayStream.writeLength();
	}

	static void ParseJson(JSTOKEN_PARSER& parentStream)
	{
		auto&& jsonStream = parentStream.subStream(TOKENTYPE::STOKEN_JSON, 0);
		auto rightBraceSeen = false; // for debugging
		while (jsonStream.isNotEmpty())
		{
			auto token = jsonStream.read();
			if (token.isString())
			{
				jsonStream.write(token);
				token = jsonStream.read();

				if (token.isColon())
				{
					token = ParseExpression(jsonStream, Undefined, EF_COMMA_IS_SEPARATOR);
					if (token.isRightBrace())
					{
						rightBraceSeen = true;
						break;
					}
				}
			}
			else if (token.isRightBrace())
			{
				rightBraceSeen = true;
				break;
			}
			else if (token.isComma())
			{
				continue;
			}
			else
			{
				DBGBREAK();
			}
		}
		ASSERT(rightBraceSeen);
		jsonStream.writeLength();
	}

	template <typename T>
	static TOKEN ParseThisExpression(T&& expressionStream, TOKEN inputToken, PARSE_EXPRESSION_FLAGS flags)
	{
		auto token = inputToken ? inputToken : expressionStream.read();
		if (expressionStream.isEmpty() && token.isOperator() && token.getOperator() == OP_DIVIDE)
		{
			if (auto regexToken = ParseRegex(expressionStream.textParser))
			{
				token = regexToken;
			}
		}

		auto basePrecedence = expressionStream.header().getPrecedence();

		UINT32 lastScriptOffset = 0; // for loop detection
		while (token)
		{
			if (expressionStream.textParser.inputText._start == lastScriptOffset)
				DBGBREAK();

			lastScriptOffset = expressionStream.textParser.inputText._start;

			if (token.isColon())
			{
				if (flags & EF_COLON_IS_SEPARATOR)
					break;

				token = TOKEN(TOKENTYPE::STOKEN_OPERATOR, OP_COLON);
			}
			else if (token.isComma())
			{
				if (flags & EF_COMMA_IS_SEPARATOR)
					break;

				token = TOKEN(TOKENTYPE::STOKEN_OPERATOR, OP_COMMA);
			}

			if (token.isOperator())
			{
				if (token.getPrecedence() == PRECEDENCE_UNARY)
				{
					token = ParseSymbol(token, expressionStream.subStream(TOKENTYPE::STOKEN_SYMBOL, 0));
				}
				else if (token.getPrecedence() > basePrecedence)
				{
					auto&& tokenSegment = GetPrevToken(expressionStream, expressionStream.tokenStream.toBuffer());
					if (tokenSegment)
					{
						auto lastToken = tokenSegment.last();
						if (lastToken.isSymbol() || lastToken.isExpression() || lastToken.isNotScript())
						{
							auto&& subStream = expressionStream.subStreamAt(tokenSegment._start, TOKENTYPE::STOKEN_EXPRESSION, token.getValue());
							token = ParseThisExpression(subStream, token, flags);
						}
						else if (lastToken.isOperator())
						{
							// unary operator
							if (token.getOperator() == OP_ADD)
								token = TOKEN(TOKENTYPE::STOKEN_OPERATOR, OP_UNARY_PLUS);
							else if (token.getOperator() == OP_SUBTRACT)
								token = TOKEN(TOKENTYPE::STOKEN_OPERATOR, OP_UNARY_MINUS);
							token = ParseThisExpression(expressionStream.subStream(TOKENTYPE::STOKEN_EXPRESSION, token.getValue()), token, flags);
						}
						else DBGBREAK();
					}
					else
					{
						token = ParseThisExpression(expressionStream.subStream(TOKENTYPE::STOKEN_EXPRESSION, token.getValue()), token, flags);
					}
				}
				else if (token.getPrecedence() < basePrecedence)
				{
					break;
				}
				else
				{
					expressionStream.write(token);
					token = expressionStream.read();
				}
			}
			else if (token.isDot())
			{
				auto&& lastSegment = GetPrevToken(expressionStream, expressionStream.tokenStream.toBuffer());
				if (lastSegment)
				{
					auto header = lastSegment.at(0);
					if (header.isSymbol())
					{
						auto&& symbolStream = expressionStream.subStreamAt(lastSegment._start);
						token = ParseSymbol(token, symbolStream);
					}
					else if (header.isExpression() || header.isArray())
					{
						auto&& symbolStream = expressionStream.subStreamAt(lastSegment._start, TOKENTYPE::STOKEN_SYMBOL, 0);
						token = ParseSymbol(token, symbolStream);
					}
					else DBGBREAK();
				}
				else DBGBREAK();
			}
			else if (token.isNotScript())
			{
				token = ParseSymbol(token, expressionStream.subStream(TOKENTYPE::STOKEN_SYMBOL, 0));
			}
			else if (token.isSeparator())
			{
				auto separator = token.getSeparator();
				if (separator == SEP_SEMICOLON || separator == SEP_RIGHT_BRACE)
				{
					break;
				}
				else if (separator == SEP_LEFT_PARENTHESIS)
				{
					auto&& lastSegment = GetPrevToken(expressionStream, expressionStream.tokenStream.toBuffer());
					if (lastSegment)
					{
						auto header = lastSegment.at(0);
						if (header.isExpression()|| header.isKeyword())
						{
							auto&& symbolStream = expressionStream.subStreamAt(lastSegment._start, TOKENTYPE::STOKEN_SYMBOL, 0);
							token = ParseSymbol(token, symbolStream);
						}
						else
						{
							token = ParseExpression(expressionStream, Undefined, flags);
							ASSERT(token.isRightParenthesis());
							token = expressionStream.read();
						}
					}
					else
					{
						token = ParseExpression(expressionStream, Undefined, flags);
						ASSERT(token.isRightParenthesis());
						token = expressionStream.read();
					}
				}
				else if (separator == SEP_RIGHT_PARENTHESIS || separator == SEP_RIGHT_BRACKET)
				{
					break;
				}
				else if (separator == SEP_LEFT_BRACE)
				{
					ParseJson(expressionStream);
					token = expressionStream.read();
				}
				else if (separator == SEP_LEFT_BRACKET)
				{
					ParseArray(expressionStream);
					token = expressionStream.read();
				}
				else if (separator == SEP_COMMA)
				{
					break;
				}
				else DBGBREAK();
			}
			else if (token.isKeyword())
			{
				auto keyword = token.getKeyword();
				if (keyword == KEYWORD_function)
				{
					ParseFunctionStatement(expressionStream);
					//ASSERT(token.isRightBrace());
					token = expressionStream.read();
				}
				else DBGBREAK();
			}
			else DBGBREAK();
		}

		expressionStream.writeLength();
		if (expressionStream.dataLength() == 0)
		{
			expressionStream.revert();
		}
		else
		{
			auto dataToken = expressionStream.getData();
			if (dataToken.getLength() == expressionStream.dataLength())
			{
				expressionStream.tokenStream.remove(expressionStream.streamStart, 1);
			}
		}
		return token;
	}

	static TOKEN ParseExpression(JSTOKEN_PARSER& parentStream, TOKEN inputToken = Undefined,
		PARSE_EXPRESSION_FLAGS flags = EF_NONE)
	{
		auto&& expressionStream = parentStream.subStream(TOKENTYPE::STOKEN_EXPRESSION, (UINT32)OP_INVALID);
		auto token = ParseThisExpression(expressionStream, inputToken, flags);
		return token;
	}

	static auto WriteKeyword(TOKENSTREAM&& tokenBuffer, TOKEN keyword)
	{
		auto offset = tokenBuffer.reserve();
		tokenBuffer.writeAt(offset, KeywordHandle(keyword));
		return offset;
	}

	static TOKEN ParseBlockStatement(TOKEN inputToken, JSTOKEN_PARSER& parentStream, bool writeVars = false)
	{
		auto token = inputToken;
		ASSERT(token.isLeftBrace());

		auto&& statementStream = parentStream.subStream(TOKENTYPE::STOKEN_BLOCK, 0);

		while (token = statementStream.read())
		{
			if (token.isRightBrace())
				break;

			token = ParseScriptLine(token, statementStream);

			if (token.isRightBrace())
				break;
		}

		if (writeVars)
		{
			WriteLocalVariables(statementStream);
		}

		statementStream.writeLength();

		return Undefined;
	}

	static TOKEN ParseScriptLine(TOKEN inputToken, JSTOKEN_PARSER& parentStream)
	{
		auto token = inputToken ? inputToken : parentStream.read();
		if (token.isLeftBrace())
		{
			ParseBlockStatement(token, parentStream);
			token = Undefined;
		}
		else
		{
			if (token.isName() && ParseMatchingJsToken(parentStream.textParser, TOKEN(TOKENTYPE::STOKEN_SEPARATOR, SEP_COLON)))
			{
				parentStream.write(TOKEN(TOKENTYPE::STOKEN_OPERATOR, OP_COLON));
				parentStream.write(token);
				token = ParseScriptLine(Undefined, parentStream);
			}
			else if (token.isKeyword())
			{
				token = ParseStatement(token, parentStream);
				if (token.isRightBrace())
					DBGBREAK();
			}
			else if (token.isSemicolon() || token.isRightBrace() || token.isRightParenthesis())
			{
				//DBGBREAK();
				//WriteControlToken(tokenBuffer, STOKEN_EXPRESSION);
			}
			else
			{
				token = ParseExpression(parentStream, token);
				if (token.isRightBrace())
					DBGBREAK();
			}

			if (token.isRightBrace())
			{
				//DBGBREAK();
				token = Undefined;
			}
		}
		return token;
	}

	static TOKEN ParseIfStatement(JSTOKEN_PARSER& parentStream)
	{
		auto&& statementStream = parentStream.keywordStream(KEYWORD_if);

		auto token = parentStream.read();
		if (token.isLeftParenthesis())
		{
			token = ParseExpression(statementStream);
			ASSERT(token.isRightParenthesis());
		}
		else DBGBREAK();

		token = ParseScriptLine(Undefined, statementStream);
		if (ParseMatchingJsToken(statementStream.textParser, ElseToken))
		{
			statementStream.write(ElseToken);
			token = ParseScriptLine(Undefined, statementStream);
		}

		statementStream.writeLength();

		return token;
	}

	static TOKEN ParseWhileStatement(JSTOKEN_PARSER& parentStream)
	{
		auto&& statementStream = parentStream.keywordStream(KEYWORD_while);

		auto token = statementStream.read();
		ASSERT(token.isLeftParenthesis());

		token = ParseExpression(statementStream);
		ASSERT(token.isRightParenthesis());

		token = ParseScriptLine(Undefined, statementStream);

		statementStream.writeLength();

		return token;
	}

	static TOKEN ParseFunctionStatement(JSTOKEN_PARSER& parentStream)
	{
		InitializeLocalVariables();

		auto&& statementStream = parentStream.keywordStream(KEYWORD_function);

		auto token = parentStream.read();

		if (token.isName())
		{
			statementStream.write(token);

			token = statementStream.read();
		}

		if (token.isLeftParenthesis())
		{
			auto&& argsStream = parentStream.subStream(TOKENTYPE::STOKEN_ARGS, 0);

			while (token = statementStream.read())
			{
				if (token.isRightParenthesis())
					break;

				if (token.isName())
				{
					argsStream.write(token);
				}
				else if (token.isComma())
				{
					continue;
				}
				else DBGBREAK();
			}

			argsStream.writeLength();
		}
		else DBGBREAK();

		token = statementStream.read();
		if (token.isLeftBrace())
		{
			token = ParseBlockStatement(token, statementStream, true);
		}
		else DBGBREAK();

		statementStream.writeLength();

		return Undefined;
	}

	static TOKEN ParseForStatement(JSTOKEN_PARSER& parentStream)
	{
		auto&& statementStream = parentStream.keywordStream(KEYWORD_for);

		auto token = parentStream.read();

		if (token.isLeftParenthesis())
		{
			auto mark = parentStream.textParser.mark();
			auto token1 = parentStream.read();
			auto token2 = parentStream.read();
			auto token3 = parentStream.read();

			if (token2.isOperator() && token2.getOperator() == OP_IN)
			{
				statementStream.write(token1);
				statementStream.write(token2);
				token = ParseExpression(statementStream, token3);
			}
			else if (token1.isKeyword() && token1.getKeyword() == KEYWORD_var && token3.isOperator() && token3.getOperator() == OP_IN)
			{
				statementStream.write(token2);
				statementStream.write(token3);
				token = ParseExpression(statementStream);
			}
			else
			{
				parentStream.textParser.revert(mark);

				token = ParseScriptLine(Undefined, statementStream);
				ASSERT(token.isSemicolon());

				token = ParseExpression(statementStream);
				ASSERT(token.isSemicolon());

				token = ParseExpression(statementStream);
				ASSERT(token.isRightParenthesis());
			}
		}
		else DBGBREAK();

		token = ParseScriptLine(Undefined, statementStream);

		statementStream.writeLength();

		return token;
	}

	static TOKEN ParseVarStatement(JSTOKEN_PARSER& parentStream)
	{
		TOKEN token;
		TOKEN nameToken;
		while (token = parentStream.read())
		{
			if (token.isName())
			{
				AddLocalVariable(token);
				nameToken = token;
			}
			else if (token.isComma())
			{
				continue;
			}
			else if (token.isSemicolon() || token.isRightBrace())
			{
				break;
			}
			else if (token.isOperator())
			{
				if (token.getOperator() == OP_ASSIGN)
				{
					ASSERT(nameToken);
					auto&& expressionStream = parentStream.subStream(TOKENTYPE::STOKEN_EXPRESSION, OP_ASSIGN);
					expressionStream.write(nameToken);

					token = ParseThisExpression(expressionStream, token, EF_COMMA_IS_SEPARATOR);
					if (token.isSemicolon() || token.isRightBrace())
					{
						break;
					}
				}
				else DBGBREAK();
			}
			else DBGBREAK();
		}
		return token;
	}

	static TOKEN ParseThrowStatement(JSTOKEN_PARSER& parentStream)
	{
		auto&& statementStream = parentStream.keywordStream(KEYWORD_throw);

		auto token = ParseExpression(statementStream);
		ASSERT(token.isSemicolon() || token.isRightBrace());

		statementStream.writeLength();

		return token;
	}

	static TOKEN ParseReturnStatement(JSTOKEN_PARSER& parentStream)
	{
		auto&& statementStream = parentStream.keywordStream(KEYWORD_return);

		auto token = ParseExpression(statementStream);
		ASSERT(token.isSemicolon() || token.isRightBrace());

		statementStream.writeLength();

		return token;
	}

	static TOKEN ParseTryStatement(JSTOKEN_PARSER& parentStream)
	{
		auto&& statementStream = parentStream.keywordStream(KEYWORD_try);

		auto token = statementStream.read();
		ASSERT(token.isLeftBrace());

		ParseBlockStatement(token, statementStream);

		token = statementStream.read();
		ASSERT(token.isKeyword());

		ASSERT(token.getKeyword() == KEYWORD_catch);

		WriteKeyword(statementStream.tokenStream, KEYWORD_catch);

		token = statementStream.read();
		ASSERT(token.isLeftParenthesis());

		if (token.isLeftParenthesis())
		{
			token = statementStream.read();
			ASSERT(token.isName());

			statementStream.write(token);

			token = statementStream.read();
			ASSERT(token.isRightParenthesis());
		}

		token = statementStream.read();
		ASSERT(token.isLeftBrace());
		ParseBlockStatement(token, statementStream);

		statementStream.writeLength();

		return Undefined;
	}

	static TOKEN ParseSwitchStatement(JSTOKEN_PARSER& parentStream)
	{
		DBGBREAK(); // XXX debug
		auto&& statementStream = parentStream.keywordStream(KEYWORD_switch);

		auto token = statementStream.read();
		if (token.isLeftParenthesis())
		{
			ParseExpression(statementStream);
		}
		else DBGBREAK();

		token = statementStream.read();

		if (token.isLeftBrace())
		{
			while (token = statementStream.read())
			{
				//if ((token = statementStream.read()).isInvalid())
				//	break;

				if (token.isRightBrace())
					break;

				if (token.isKeyword())
				{
					auto keyword = token.getKeyword();
					if (keyword == KEYWORD_case)
					{
						statementStream.write(token);
						token = ParseExpression(statementStream, Undefined, EF_COLON_IS_SEPARATOR);
					}
					else if (keyword == KEYWORD_default)
					{
						statementStream.write(token);
						token = statementStream.read();
						if (token.isColon())
						{
							// do nothing?
						}
						else DBGBREAK();
					}
					else if (keyword == KEYWORD_break)
					{
						statementStream.write(token);
					}
				}
				else
				{
					ParseScriptLine(token, statementStream);
				}
			}
		}

		statementStream.writeLength();

		return token;
	}

	static TOKEN ParseDebuggerStatement(JSTOKEN_PARSER& tokenStream)
	{
		DBGBREAK();
		auto token = tokenStream.read();
		ASSERT(token.isSemicolon());

		if (token.isSemicolon())
		{
			token = Undefined;
		}
		return token;
	}

	static TOKEN ParseStatement(TOKEN inputToken, JSTOKEN_PARSER& tokenStream)
	{
		auto token = inputToken;
		ASSERT(token.isKeyword());

		auto keyword = token.getKeyword();
		if (keyword == KEYWORD_if)
			token = ParseIfStatement(tokenStream);

		else if (keyword == KEYWORD_var)
			token = ParseVarStatement(tokenStream);

		else if (keyword == KEYWORD_function)
			token = ParseFunctionStatement(tokenStream);

		else if (keyword == KEYWORD_switch)
			token = ParseSwitchStatement(tokenStream);

		else if (keyword == KEYWORD_for)
			token = ParseForStatement(tokenStream);

		else if (keyword == KEYWORD_while)
			token = ParseWhileStatement(tokenStream);

		else if (keyword == KEYWORD_do)
			DBGBREAK();

		else if (keyword == KEYWORD_try)
			token = ParseTryStatement(tokenStream);

		else if (keyword == KEYWORD_catch)
			DBGBREAK();

		else if (keyword == KEYWORD_finally)
			DBGBREAK();

		else if (keyword == KEYWORD_debugger)
			ParseDebuggerStatement(tokenStream);

		else if (keyword == KEYWORD_with)
			DBGBREAK();

		else if (keyword == KEYWORD_return)
			token = ParseReturnStatement(tokenStream);

		else if (keyword == KEYWORD_throw)
			token = ParseThrowStatement(tokenStream);

		else if (keyword == KEYWORD_break)
		{
			tokenStream.write(token);
				token = tokenStream.read();
				if (token.isName())
				{
					tokenStream.write(token);
						token = tokenStream.read();
				}
			ASSERT(token.isSemicolon());
		}
		else {
			DBGBREAK();
		}
		return token;
	}
};
//
//template <typename T, typename STACK> // USTRING
//TOKEN_BUFFER ParseScript(T&& scriptText)
//{
//	auto&& scriptParser = StackAlloc<PARSER_INFO, SCHEDULER_STACK>(CONTENT_TYPE::JAVASCRIPT, scriptText);
//
//	auto&& tokenBuffer = GetCurrentStack<STACK>().jsTokenStreams.at(0);
//
//	auto&& scriptStream = JSTOKEN_PARSER(scriptParser, tokenBuffer, TOKENTYPE::STOKEN_BLOCK);
//	JSTOKEN_PARSER::ParseExpression(scriptStream);
//
//	scriptStream.writeLength();
//
//	return tokenBuffer.toBuffer();
//}

template <typename STACK, typename TOKENSTREAM>
TOKEN_BUFFER ParseJson(TOKENSTREAM&& tokenStream, USTRING jsonString)
{
	auto&& scriptParser = StackAlloc<PARSER_INFO, SCHEDULER_STACK>(CONTENT_TYPE::JAVASCRIPT, jsonString);
	//auto&& tokenStream = GetCurrentStack<STACK>().jsTokenStreams.at(0).clear();
	auto&& scriptStream = JSTOKEN_PARSER<STACK, TOKENSTREAM>(scriptParser, tokenStream);

	auto token = scriptStream.read();
	if (token.isSeparator() && token.getSeparator() == SEP_LEFT_BRACE)
	{
		JSTOKEN_PARSER<STACK, TOKENSTREAM>::ParseJson(scriptStream);
	}
	else DBGBREAK();

	//auto tokens = tokenStream.toBuffer();
	//tokens.shift();
	//token = tokens.shift();
	//if (token.isJson())
	//{
	//	tokens = tokens.toBuffer(0, token.getLength());
	//}
	//else DBGBREAK();
	return tokenStream.toBuffer();
}

template <typename STREAM>
void FormatOperator(JS_OPERATOR op, STREAM&& stringBuffer)
{
	for (auto&& opInfo : Operators)
	{
		if (opInfo.id == op)
		{
			stringBuffer.writeString(opInfo.string);
			return;
		}
	}
	DBGBREAK();
}

template <typename STREAM>
void FormatSeparator(SEPARATOR separator, STREAM&& stringBuffer)
{
	for (auto&& separatorInfo : Separators)
	{
		if (separatorInfo.id == separator)
		{
			stringBuffer.writeChar(separatorInfo.letter);
			return;
		}
	}
	DBGBREAK();
}

template <typename TOKENSTREAM>
void WriteJson(TOKENSTREAM&& tokenStream, TOKEN name, TOKEN value)
{
	tokenStream.write(name);
	tokenStream.write(value);
}

template <typename TOKENSTREAM, typename FUNC, typename ... ARGS>
TOKEN_BUFFER WriteJson(TOKENSTREAM&& tokenStream, FUNC callback, ARGS&& ... args)
{
	auto start = tokenStream.count();
	tokenStream.write(TOKEN(TOKENTYPE::STOKEN_JSON));
	callback(tokenStream, args ...);
	tokenStream.at(start).setLength(tokenStream.count() - start);

	return tokenStream.toBuffer(start);
}

template <typename STACK, typename STREAM>
USTRING FormatJson(TOKEN_BUFFER tokenBuffer, STREAM&& charStream, UINT32 indent = 0)
{
	auto token = tokenBuffer.at(0);
	ASSERT(token.isJson());

	if (token.isJson())
	{
		tokenBuffer = tokenBuffer.readBytes(token.getLength());
		tokenBuffer.shift();
		charStream.writeString("{\r\n");
		indent += 4;
	}

	while (tokenBuffer)
	{
		token = tokenBuffer.shift();
		ASSERT(token.isString());

		charStream.writeString(Spaces, indent);
		charStream.writeMany("\"", token, "\" : ");

		token = tokenBuffer.at(0);

		if (token.isJson())
		{
			FormatJson<STACK>(tokenBuffer.readBytes(token.getLength()), charStream, indent);
		}
		else if (token.isNumber())
		{
			tokenBuffer.shift();
			charStream.writeMany(token, ",\r\n");
		}
		else 
		{
			tokenBuffer.shift();
			charStream.writeMany("\"", token, "\",\r\n");
		}
	}

	charStream.writeString(Spaces, indent);
	charStream.writeString("}\r\n");
	indent -= 4;
	return charStream.toBuffer();
}

template <typename FUNC, typename ... ARGS>
void FindJson(TOKEN_BUFFER jsonTokens, TOKEN match, FUNC callback, ARGS&& ... args)
{
	if (jsonTokens.at(0).isJson())
		jsonTokens.shift();

	while (jsonTokens)
	{
		auto name = jsonTokens.shift();
		auto valueLength = jsonTokens.at(0).getLength();
		ASSERT(name.isString());
		if (name == match) // (CompareLiteral(name, match))
		{
			TOKEN_BUFFER value { jsonTokens.data(), valueLength };
			auto shouldContinue = callback(value, args ...);
			if (shouldContinue == false)
				break;
		}
		jsonTokens.shift(valueLength);
	}
}


template <typename TOKENSTREAM>
struct JSON_STREAM
{
	TOKENSTREAM& tokenStream;
	UINT32 start;

	JSON_STREAM(TOKENSTREAM& inStream) : tokenStream(inStream)
	{
		start = inStream.count();
		inStream.append(TOKEN(TOKENTYPE::STOKEN_JSON));
	}

	TOKEN_BUFFER close()
	{
		auto length = tokenStream.count() - start;
		ASSERT(length < 64 * 1024);

		auto& token = tokenStream.at(start);
		token.setLength(length);

		return tokenStream.toBuffer();
	}

	void write(TOKEN name, TOKEN value)
	{
		tokenStream.append(name);
		tokenStream.append(value);
	}

	JSON_STREAM subStream(TOKEN name)
	{
		tokenStream.append(name);
		return JSON_STREAM(tokenStream);
	}
};

constexpr UINT8 NODE_FLAG_DELETED = 0x01;

template <typename STACK, typename TOKENSTREAM>
struct JSON_OBJECT
{
	enum class JSON_COMMAND_TYPE : UINT8
	{
		NONE,
		UPDATE,
		APPEND,
		REMOVE,
	};

	struct JSON_COMMAND
	{
		JSON_COMMAND_TYPE type;
		STREAM_BUILDER<UINT8, SCHEDULER_STACK, 6> pathStream;
		UINT16 offset;

		STREAM_BUILDER<TOKEN, SCHEDULER_STACK, 6> tokenStream;
		UINT16 count;
	};

	struct JSON_NODE
	{
		STREAM_BUILDER<UINT8, STACK, 5> path;
		UINT16 offset;
		UINT32 checksum = 0;
		UINT8 flags = 0;
		UINT16 childCount = 0;

		explicit JSON_NODE(UINT32 offsetArg) : offset((UINT16)offsetArg) {}
		explicit operator bool() const { return IsValidRef(*this); }
	};

	TOKENSTREAM& tokenStream;
	STREAM_BUILDER<JSON_NODE, STACK, 16> nodeStream;

	JSON_OBJECT(TOKENSTREAM& inStream) : tokenStream(inStream)
	{
		buildIndex(nodeStream.append(0));
	}

	TOKEN& getToken(JSON_NODE& node, UINT32 offset)
	{
		return tokenStream.at(node.offset + offset);
	}

	UINT32 getLength(JSON_NODE& node)
	{
		return tokenStream.at(node.offset).getLength();
	}

	void setLength(JSON_NODE& node, UINT32 length)
	{
		tokenStream.at(node.offset).setLength(length);
	}

	JSON_NODE& findParent(JSON_NODE& node)
	{
		auto parentPath = node.path.toBuffer().shrink();
		auto index = nodeStream.getIndex(node);

		for (UINT32 i = index - 1; i < index; i--)
		{
			auto& parent = nodeStream.at(i);
			if (parent.path.toBuffer() == parentPath)
			{
				return parent;
			}
		}

		return NullRef<JSON_NODE>();
	}

	void updateParentLength(JSON_NODE& parent, INT32 change)
	{
		if (parent)
		{
			auto& token = getToken(parent, 0);
			token.setLength(token.getLength() + change);
			updateParentLength(findParent(parent), change);
		}
	}

	void updateLength(JSON_NODE& node, INT32 change)
	{
		updateParentLength(node, change);
		auto index = nodeStream.getIndex(node);

		for (UINT32 i = index; i < nodeStream.count(); i++)
		{
			nodeStream.at(i).offset += change;
		}
	}

	JSON_NODE& findNode(BUFFER path)
	{
		for (auto& node : nodeStream.toBufferNoConst())
		{
			if (node.path.count() == path.length())
			{
				if (node.path.toBuffer() == path)
				{
					return node;
				}
			}
		}
		return NullRef<JSON_NODE>();
	}

	UINT32 buildIndex(JSON_NODE& node)
	{
		UINT64 checksum = 0;

		auto token = tokenStream.at(node.offset);
		ASSERT(token.isJson());
		TOKEN_BUFFER tokens{ tokenStream.address(), (UINT32)node.offset + 1, (UINT32)node.offset + token.getLength() };

		while (tokens)
		{
			auto name = tokens.shift();
			checksum += name.toUInt32();
			checksum *= (tokens.length() + 1);

			ASSERT(tokens);

			auto value = tokens.at(0);
			if (value.isJson())
			{
				auto& childNode = nodeStream.append(tokens._start);
				childNode.path.writeBytes(node.path.toBuffer());
				childNode.path.writeByte((UINT8)++node.childCount);
				checksum += buildIndex(childNode);
				tokens.shift(value.getLength());
			}
			else
			{
				tokens.shift();
				checksum += value.toUInt32();
			}
			checksum *= (tokens.length() + 1);
		}

		node.checksum = (UINT32)checksum;
		node.checksum += (UINT32)(checksum >> 32);
		return node.checksum;
	}

	void append(BUFFER path, UINT32 offset, TOKEN_BUFFER appendData)
	{
		auto& node = findNode(path);
		ASSERT(node);

		if (node)
		{
			auto streamOffset = node.offset + offset;
			tokenStream.insert(streamOffset, appendData.length());
			RtlCopyMemory(tokenStream.address(streamOffset), appendData.data(), appendData.length() * sizeof(TOKEN));

			updateLength(node, appendData.length());
		}
	}

	void remove(BUFFER path, UINT32 offset, UINT32 count)
	{
		auto& node = findNode(path);
		ASSERT(node);

		if (node)
		{

		}
	}

	void deleteNode(JSON_NODE& node)
	{
		node.flags |= NODE_FLAG_DELETED;
		auto& parent = findParent(node);
		if (parent)
		{
			parent.childCount--;
		}
	}

	JSON_NODE& getLeafNode()
	{
		for (UINT32 i = 0; i < nodeStream.count(); i++)
		{
			auto& node = nodeStream.at(i);
			if (node.flags & NODE_FLAG_DELETED)
				continue;

			if (node.childCount == 0)
				return node;
		}
		return NullRef<JSON_NODE>();
	}

	static void doDiff(JSON_OBJECT& first, JSON_OBJECT& second)
	{
		auto firstHash = ComputeHash(first.tokenStream.toByteBuffer());
		auto secondHash = ComputeHash(second.tokenStream.toByteBuffer());

		if (firstHash != secondHash)
		{
			while (auto& firstNode = first.getLeafNode())
			{
				auto& secondNode = second.findNode(firstNode.path.toBuffer());
				if (secondNode)
				{
					if (firstNode.checksum == secondNode.checksum)
					{
						first.deleteNode(firstNode);
						second.deleteNode(secondNode);
					}
					else
					{
						auto firstLength = first.getLength(firstNode);
						auto secondLength = second.getLength(secondNode);

						if (firstLength == secondLength)
						{
							UINT32 updateStart = 0, updateLength = 0;
							for (UINT32 i = 1; i < firstLength; i += 2)
							{
								auto nameMatch = first.getToken(firstNode, i) == second.getToken(secondNode, i);
								auto valueMatch = first.getToken(firstNode, i + 1) == second.getToken(secondNode, i + 1);

								if (!nameMatch || !valueMatch)
								{
									updateStart = i; updateLength = firstLength - i;
									for (UINT32 j = firstLength - 1; j > updateStart; j -= 2)
									{
										nameMatch = first.getToken(firstNode, j - 1) == second.getToken(secondNode, j - 2);
										valueMatch = first.getToken(firstNode, j) == second.getToken(secondNode, j);

										if (nameMatch && valueMatch)
											updateLength -= 2;
									}
								}
							}
						}
					}
				}
			}
		}

	}

	explicit operator bool() const { return IsValidRef(tokenStream); }
};

template <typename FUNC, typename ... ARGS>
void FindJson(TOKEN_BUFFER json, TOKEN_BUFFER matchTokens, TOKEN matchValue, FUNC callback, ARGS&& ... args)
{

}
//extern SEPARATOR GetScriptSeparator(char letter);
//extern UINT8 SplitScriptOperator(USTRING opText, USTRING& scriptText);
