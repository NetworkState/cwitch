// Copyright(C) 2018 Amalraj Antonysamy, All rights reserved.
#include "pch.h"

#define FILE_ID  0x22

#include "Types.h"
#include "css.h"
#include <time.h>
#include <math.h>

//#define CSS_ENCODE_NAME(x_) *(float *) &x_
//#define CSS_ENCODE_COLOR(x_) *(float *) &x_
//#define CSS_DECODE_COLOR(x_) HSV((HSV *)&x_)

CSS_GLOBALS* CssGlobalsPtr;
CSS_GLOBALS& CssGlobals()
{
	return *CssGlobalsPtr;
}

auto& DefaultStyle()
{
	return CssGlobals().defaultSyle;
}

struct CORNER_PROPERTIES
{
	int count = 0;
	CSS_PROPERTY top;
	CSS_PROPERTY right;
	CSS_PROPERTY bottom;
	CSS_PROPERTY left;
};

template <typename STR>
HSV ParseHexColorString(STR&& colorString)
{
	ASSERT(colorString.peek() == '#');
	colorString.shift();

	if (colorString.peek() == '#') // for buggy sites that send ## prefix
		colorString.shift();

	auto length = colorString.length();
	auto hex = String.toHexNumber(colorString);
	auto hexChars = length - colorString.length();

	RGB rgb;
	if (hexChars == 3)
	{
		rgb.r = (UINT8)((hex & 0x0F00) >> 8);
		rgb.r |= rgb.r << 4;
		rgb.g = (UINT8)((hex & 0x00F0) >> 4);
		rgb.g |= rgb.g << 4;
		rgb.b = (UINT8)(hex & 0x0F);
		rgb.b |= rgb.b << 4;
	}
	else if (hexChars == 6)
	{
		rgb.r = (UINT8)((hex & 0x00FF0000) >> 16);
		rgb.g = (UINT8)((hex & 0x0000FF00) >> 8);
		rgb.b = (UINT8)(hex & 0x000000FF);
	}
	else
	{
		DBGBREAK();
		return HSV();
	}

	return RGBtoHSV(rgb);
}

typedef struct _NAME_MAP
{
	TOKEN fromName;
	TOKEN toName;
} NAME_MAP;

template <unsigned int arraySize>
static void MapName(CSS_PROPERTY &property, NAME_MAP const (&mapTable)[arraySize])
{
	if (property.scale == CSS_SCALE_NAME)
	{
		auto propertyName = CSS_DECODE_NAME(property.value); // MakeName((UINT16)property.value);
		for (auto &map : mapTable)
		{
			if (map.fromName == propertyName)
			{
				property.value = CSS_ENCODE_NAME(map.toName);
			}
		}
	}
}

CSS_PROPERTY &StyleFindProperty(CSS_STREAM &style, CSS_PROPERTY_NAME name)
{
	for (auto &prop : style.toBufferNoConst())
	{
		if (prop.name == name)
			return prop;
	}
	return NullRef<CSS_PROPERTY>();

}

TOKEN DisplayNameToString(CSS_DISPLAY display)
{
	for (auto &map : StyleDisplayMap)
	{
		if (map.display == display)
		{
			return map.name;
		}
	}
	DBGBREAK();
	return Undefined;
}

USTRING FormatCssValue(CSS_PROPERTY &property, TSTRING_BUILDER &formatBuffer)
{
	if (property.scale == CSS_SCALE_PIXEL)
	{
		formatBuffer.sprintf("%.1fpx", property.value);
	}
	else if (property.scale == CSS_SCALE_EM)
	{
		formatBuffer.sprintf("%.1fem", property.value);
	}
	else if (property.scale == CSS_SCALE_NAME)
	{
		auto value = CSS_DECODE_NAME(property.value); // MakeName((UINT16)property.value);
		ASSERT(value);
		formatBuffer.writeName(value);
	}
	else if (property.scale == CSS_SCALE_INHERIT)
	{
		formatBuffer.writeString("inherit");
	}
	else if (property.scale == CSS_SCALE_AUTO)
	{
		formatBuffer.writeString("auto");
	}
	else if (property.scale == CSS_SCALE_COLOR)
	{
		auto color = CSS_DECODE_COLOR(property.value);
		if (!color)
		{
			formatBuffer.writeString("null");
		}
		else
		{
			formatBuffer.sprintf("%02x:%02x:%02x", color.hue(), color.sat(), color.val());
		}
	}
	else if (property.scale == CSS_SCALE_DISPLAY)
	{
		auto display = (CSS_DISPLAY)(int)property.value;
		formatBuffer.writeName(DisplayNameToString(display));
	}
	else if (property.scale == CSS_SCALE_PERCENT)
	{
		formatBuffer.sprintf("%.1f%%", property.value * 100);
	}
	else DBGBREAK();

	return formatBuffer.toBuffer();
}

CSS_PROPERTY_NAME StyleMapName(TOKEN nameString)
{
	ASSERT(nameString.isName());
	for (auto &nameMap : PropertyNames)
	{
		if (nameMap.name == nameString)
		{
			return nameMap.property;
		}
	}
	return CSS_PROPERTY_INVALID;
}

void StyleSetProperty(CSS_STREAM& style, CSS_PROPERTY &newProperty)
{
	if (newProperty.scale == CSS_SCALE_NAME)
	{
		auto name = CSS_DECODE_NAME(newProperty.value);
		ASSERT(name);
	}

	style.append(newProperty);
}

void SetProperty(CSS_STREAM& style, CSS_PROPERTY_NAME name, CSS_SCALE scale, float value, CSS_FLAGS flags)
{
	CSS_PROPERTY property;

	property.name = name;
	property.scale = scale;
	property.value = value;
	property.flags = flags;

	StyleSetProperty(style, property);
}

HSV StyleGetColorValue(CSS_STREAM &style, CSS_PROPERTY_NAME propertyName)
{
	auto &property = StyleFindProperty(style, propertyName);
	if (property)
	{
		return CSS_DECODE_COLOR(property.value);
	}
	else return HSV();
}

HSV StyleGetBackgroundColor(CSS_STREAM &style)
{
	auto &property = StyleFindProperty(style, CSS_PROPERTY_BACKGROUND_COLOR);
	if (property)
	{
		return CSS_DECODE_COLOR(property.value);
	}
	else return HSV();
}

TOKEN StyleGetBackgroundImage(CSS_STREAM &style)
{
	TOKEN name = Undefined;

	auto &property = StyleFindProperty(style, CSS_PROPERTY_BACKGROUND_IMAGE);
	if (property)
	{
		name = CSS_DECODE_NAME(property.value);
	}
	return name;
}

UINT32 StyleGetBorderWidth(CSS_STREAM &style, CSS_PROPERTY_NAME propertyName)
{
	INT32 widthValue = 0;

	auto &property = StyleFindProperty(style, propertyName);
	if (property)
	{
		if (property.scale == CSS_SCALE_PIXEL)
		{
			widthValue = (INT32) property.value;
		}
		else if (property.scale == CSS_SCALE_NAME)
		{
			auto name = CSS_DECODE_NAME(property.value); // MakeName((UINT16)property.value);
			if (name == STYLE_thin)
				widthValue = 1;
			else if (name == STYLE_thick)
				widthValue = 5;
			else if (name == STYLE_medium)
				widthValue = 3;
			else if (name == STYLE_transparent)
				widthValue = 0;
			else DBGBREAK();
		}
		else DBGBREAK();
	}

	return widthValue;
}

constexpr CSS_PROPERTY_NAME BorderWidthProperties [] = { CSS_PROPERTY_BORDER_TOP_WIDTH, CSS_PROPERTY_BORDER_RIGHT_WIDTH, CSS_PROPERTY_BORDER_BOTTOM_WIDTH, CSS_PROPERTY_BORDER_LEFT_WIDTH};
UINT32 StyleGetBorderWidth(CSS_STREAM &style)
{
	auto widthValue = StyleGetBorderWidth(style, CSS_PROPERTY_BORDER_WIDTH);
	if (widthValue <= 0)
	{
		INT32 values[4];
		for (auto i = 0; i < ARRAYSIZE(BorderWidthProperties); i++)
		{
			values[i] = StyleGetBorderWidth(style, BorderWidthProperties[i]);
		}
		if (values[0] > 0 && values[0] == values[1] && values[0] == values[2] && values[0] == values[3])
		{
			widthValue = values[0];
		}
	}
	return widthValue;
}

constexpr CSS_PROPERTY_NAME BorderColorProperties[] = { CSS_PROPERTY_BORDER_TOP_COLOR, CSS_PROPERTY_BORDER_RIGHT_COLOR, CSS_PROPERTY_BORDER_BOTTOM_COLOR, CSS_PROPERTY_BORDER_LEFT_COLOR};
HSV StyleGetBorderColor(CSS_STREAM &style)
{
	auto colorValue = StyleGetColorValue(style, CSS_PROPERTY_BORDER_COLOR);
	if (!colorValue)
	{
		HSV values[4];
		for (auto i = 0; i < ARRAYSIZE(BorderColorProperties); i++)
		{
			values[i] = StyleGetColorValue(style, BorderColorProperties[i]);
		}
		if (values[0] && values[0] == values[1] && values[0] == values[2] && values[0] == values[3])
		{
			colorValue = values[0];
		}
	}
	return colorValue;
}

float StyleGetWidth(CSS_STREAM &style)
{
	auto clientWidth = 0.0f;
	auto &widthProperty = StyleFindProperty(style, CSS_PROPERTY_WIDTH);
	if (widthProperty)
	{
		widthProperty = StyleFindProperty(style, CSS_PROPERTY_MIN_WIDTH);
	}
	if (widthProperty)
	{
		if (widthProperty.scale == CSS_SCALE_PIXEL)
		{
			auto &maxWidthProperty = StyleFindProperty(style, CSS_PROPERTY_MAX_WIDTH);
			if (maxWidthProperty)
			{
				clientWidth = min(widthProperty.value, maxWidthProperty.value);
			}
			else
			{
				clientWidth = widthProperty.value;
			}
		}
		else
		{
			ASSERT(widthProperty.scale == CSS_SCALE_AUTO);
		}
	}

	return clientWidth;
}

float StyleGetHeight(CSS_STREAM &style)
{
	float clientHeight = 0;
	auto &heightProperty = StyleFindProperty(style, CSS_PROPERTY_HEIGHT);
	if (!heightProperty)
	{
		heightProperty = StyleFindProperty(style, CSS_PROPERTY_MIN_HEIGHT);
	}
	else if (heightProperty.value == 0 && heightProperty.scale == CSS_SCALE_PIXEL)
	{
		DBGBREAK();
		return 1.f; // XXX, hack, 0 is considered an undefined value.
	}

	if (heightProperty && heightProperty.scale == CSS_SCALE_PIXEL)
	{
		auto &maxHeightProperty = StyleFindProperty(style, CSS_PROPERTY_MAX_HEIGHT);
		if (maxHeightProperty)
		{
			clientHeight = min(maxHeightProperty.value, heightProperty.value);
		}
		else
		{
			clientHeight = heightProperty.value;
		}
	}

	return clientHeight;
}

CSS_DISPLAY StyleGetDisplay(CSS_STREAM &style)
{
	auto display = DISPLAY_INVALID;
	auto &property = StyleFindProperty(style, CSS_PROPERTY_DISPLAY);
	if (property && property.scale == CSS_SCALE_DISPLAY)
	{
		display = (CSS_DISPLAY) (UINT8) ceil(property.value);
	}
	ASSERT(display != DISPLAY_INVALID);
	return display;
}

void StyleSetDisplay(CSS_STREAM &style, CSS_DISPLAY display)
{
	auto &property = StyleFindProperty(style, CSS_PROPERTY_DISPLAY);
	if (property && property.scale == CSS_SCALE_DISPLAY)
	{
		property.value = (float) (int) display;
	}
	else DBGBREAK();
}

HSV FindColorByName(TOKEN colorName)
{
	HSV retunValue;
	for (auto& color : CssGlobals().colorTable.toBuffer())
	{
		if (color.name == colorName)
		{
			retunValue = color.hsv;
		}
	}
	return retunValue;
}

CSS_PROPERTY ParseCssName(PARSED_WORD param)
{
	CSS_PROPERTY property;

	auto parseResult = false;
	auto name = param.wordName;
	if (name)
	{
		parseResult = true;
		if (name == STYLE_auto)
		{
			property.scale = CSS_SCALE_AUTO;
			property.value = 0;
		}
		else if (name == STYLE_inherit)
		{
			property.scale = CSS_SCALE_INHERIT;
			property.value = 0;
		}
		else
		{
			property.scale = CSS_SCALE_NAME;
			property.value = CSS_ENCODE_NAME(name);
		}
	}
	return property;
}

constexpr UINT8 ColorSeparators[] = ", \t";
constexpr UINT8 RgbPrefix[] = "rgb(";
constexpr UINT8 RgbaPrefix[] = "rgba(";

HSV ParseRgbColor(USTRING colorString)
{
	RGB rgb;
	HSV hsv;

	auto colorParts = String.splitCharToArray(colorString, " ,", TSTRING_STREAM());
	if (colorParts.length() >= 3)
	{
		rgb.r = (UINT8)String.toNumber(colorParts.shift());
		rgb.g = (UINT8)String.toNumber(colorParts.shift());
		rgb.b = (UINT8)String.toNumber(colorParts.shift());

		hsv = RGBtoHSV(rgb);
	}
	return hsv;
}

HSV ParseColorValue(PARSED_WORD firstParam, PARSED_WORDS& paramStream)
{
	HSV hsv;

	do
	{
		if (firstParam.wordString == "rgb" || firstParam.wordString == "rgba")
		{
			ASSERT(paramStream);
			hsv = ParseRgbColor(paramStream.shift().wordString);
			break;
		}

		auto knownName = firstParam.wordName;
		if (knownName)
		{
			if (knownName == STYLE_transparent)
			{
				break;
			}
			else
			{
				hsv = FindColorByName(knownName);
				if (hsv)
				{
					break;
				}
			}
		}

		if (firstParam.wordString[0] == '#')
		{
			hsv = ParseHexColorString(firstParam.wordString);
			break;
		}

	} while (false);

	return hsv;
}

bool ParseColorValue(PARSED_WORDS& paramStream, CSS_PROPERTY &colorProperty)
{
	auto firstParam = paramStream.shift();
	auto hsv = ParseColorValue(firstParam, paramStream);
	if (hsv)
	{
		colorProperty.scale = CSS_SCALE_COLOR;
		colorProperty.value = CSS_ENCODE_COLOR(hsv);
	}
	return hsv ? true : false;
}

bool ParseFontFamily(CSS_STREAM &style, USTRING fontName, CSS_FLAGS flags)
{
	auto fontFamily = Undefined;
	if (String.equals(fontName, "sans-serif") == true)
	{
		fontFamily = STYLE_sans_serif;
	}
	else if (String.equals(fontName, "serif") == true)
	{
		fontFamily = STYLE_serif;
	}
	else if (String.equals(fontName, "monospace") == true)
	{
		fontFamily = STYLE_monospace;
	}
	else if (String.equals(fontName, "fantasy") == true)
	{
		fontFamily = STYLE_fantasy;
	}
	else if (String.equals(fontName, "cursive") == true)
	{
		fontFamily = STYLE_cursive;
	}
	if (fontFamily)
	{
		SetProperty(style, CSS_PROPERTY_FONT_FAMILY, CSS_SCALE_NAME, CSS_ENCODE_NAME(fontFamily), flags);
		return true;
	}
	return false;
}

bool ParseFontFamily(CSS_STREAM& style, PARSED_WORDS& paramStream, CSS_FLAGS flags)
{
	auto returnValue = false;
	while (paramStream.length() > 0)
	{
		auto param = paramStream.shift();
		if (ParseFontFamily(style, param.wordString, flags))
			returnValue = true;
	}
	return returnValue;
}

bool ParseCssLength(PARSED_WORD param, float& cssLength, CSS_SCALE& scale, CSS_SCALE defaultScale)
{
	scale = defaultScale;
	auto parseSuccessful = false;
	auto lengthString = param.wordString;
	USTRING floatString;
	cssLength = String.toFloat(lengthString, floatString);
	if (floatString)
	{
		parseSuccessful = true;
		if (lengthString == "px")
		{
			scale = CSS_SCALE_PIXEL;
		}
		else if (lengthString == "pt")
		{
			scale = CSS_SCALE_POINT;
		}
		else if (lengthString == "em")
		{
			scale = CSS_SCALE_EM;
		}
		else if (lengthString == "rem")
		{
			scale = CSS_SCALE_EM;
		}
		else if (lengthString == "ex")
		{
			cssLength *= 0.5f;
			scale = CSS_SCALE_EM;
		}
		else if (lengthString == "%" || lengthString == "vw" || lengthString == "vh" || lengthString == "vmin" || lengthString == "vmax")
		{
			cssLength /= 100.0f;
			scale = CSS_SCALE_PERCENT;
		}
		else if (lengthString == "fr")
		{
			scale = CSS_SCALE_GRID;
		}
		else
		{
			if (cssLength == 0)
			{
				scale = CSS_SCALE_PIXEL;
			}
			else DBGBREAK();
		}
	}
	else if (auto property = ParseCssName(param))
	{
		cssLength = property.value;
		scale = property.scale;
		parseSuccessful = true;
	}
	return parseSuccessful;
}

CSS_PROPERTY ParseCssLength(PARSED_WORD param, CSS_SCALE defaultScale)
{
	CSS_PROPERTY value;
	auto result =  ParseCssLength(param, value.value, value.scale, defaultScale);
	return result ? value : CSS_PROPERTY();
}

float ToPoints(float number, CSS_SCALE scale)
{
	auto points = 0.0f;
	if (scale == CSS_SCALE_PIXEL)
	{
		points = number * 0.95f;
	}
	else if (scale == CSS_SCALE_POINT)
	{
		points = number;
	}
	else if (scale == CSS_SCALE_EM)
	{
		points = number * 12;
	}
	else if (scale == CSS_SCALE_PERCENT)
	{
		points = 12.0f * number;
	}
	else DBGBREAK();

	return points;
}

template<unsigned int arraySize>
float ToNumberUnit(NUMBER_UNIT_PAIR const (&unitMap)[arraySize], float referenceValue, float thisValue)
{
	auto diffUnit = 1.0f;
	do
	{
		float refUnit;
		if (FindNumberUnit(unitMap, referenceValue, refUnit) == false)
		{
			DBGBREAK();
			break;
		}

		float thisUnit;
		if (FindNumberUnit(unitMap, thisValue, thisUnit) == false)
		{
			break;
		}

		diffUnit = 1.0f + (thisUnit - refUnit);
	} while (false);
	return diffUnit;
}

float ToFontSizeUnit(float reference, float fontSize)
{
	return ToNumberUnit(FontSizeUnits, reference, fontSize);
}

float ToFontWeightUnit(TOKEN fontWeight)
{
	auto& nameUnit = BackgroundRepeatUnits.find(fontWeight);
	return nameUnit ? nameUnit.unit : 1.0f;
}

float ToNameUnit(STREAM_READER<NAME_UNIT_PAIR> unitMap, TOKEN referenceValue, TOKEN thisValue)
{
	auto diffUnit = 1.0f;
	do
	{
		if (!referenceValue || !thisValue)
			break;

		if (auto& refUnit = unitMap.find(referenceValue))
		{
			if (auto& thisUnit = unitMap.find(thisValue))
			{
				diffUnit = 1.0f + (thisUnit.unit - refUnit.unit);
			}
		}
	} while (false);
	return diffUnit;
}

float ToFontWeightUnit(TOKEN referenceWeight, TOKEN thisWeight)
{
	return ToNameUnit(FontWeightUnits, referenceWeight, thisWeight);
}

float ToFontStyleUnit(TOKEN fontStyle)
{
	auto& nameUnit = FontStyleUnits.find(fontStyle);
	return nameUnit ? nameUnit.unit : 1.0f;
}

float ToFontStyleUnit(TOKEN referenceStyle, TOKEN thisStyle)
{
	return ToNameUnit(FontStyleUnits, referenceStyle, thisStyle);
}

float StyleGetFontSize(CSS_STREAM& style)
{
	auto fontSize = 0.0f;
	auto& property = StyleFindProperty(style, CSS_PROPERTY_FONT_SIZE);
	ASSERT(property);
	if (property)
	{
		ASSERT(property.scale == CSS_SCALE_PIXEL);
		fontSize = property.value;
	}
	return fontSize;
}

TOKEN StyleGetNameValue(CSS_STREAM& style, CSS_PROPERTY_NAME propertyName)
{
	TOKEN nameValue = Undefined;
	auto& property = StyleFindProperty(style, propertyName);
	if (property)
	{
		ASSERT(property.scale == CSS_SCALE_NAME);
		nameValue = CSS_DECODE_NAME(property.value); // MakeName((UINT16)property.value);
	}
	return nameValue;
}

void GetTextStyleUnits(CSS_STREAM &referenceStyle, CSS_STREAM &thisStyle, float &fontSize, float &fontWeight, float &fontStyle)
{
	auto referenceFontSize = StyleGetFontSize(referenceStyle);

	fontSize = ToFontSizeUnit(referenceFontSize, StyleGetFontSize(thisStyle));
	fontWeight = 1.0f;
	fontStyle = 1.0f;

	auto fontWeightName = StyleGetNameValue(thisStyle, CSS_PROPERTY_FONT_WEIGHT);
	if (fontWeightName)
	{
		fontWeight = ToFontWeightUnit(fontWeightName);
	}

	auto fontStyleName = StyleGetNameValue(thisStyle, CSS_PROPERTY_FONT_STYLE);
	if (fontStyleName)
	{
		fontStyle = ToFontStyleUnit(fontStyleName);
	}
}

bool ToFontSizeUnit(PARSED_WORD param, float &unit)
{
	CSS_SCALE scale;
	float number;
	if (ParseCssLength(param, number, scale, CSS_SCALE_PIXEL) == false)
	{
		return false;
	}

	auto points = ToPoints(number, scale);
	unit = FindNumberUnit(FontSizeUnits, points);
	return unit != UNDEFINED_FLOAT;
}

float CompareColors(HSV color1, HSV color2)
{
	auto diff = abs(color1.val() - color2.val());
	auto unit = diff < 8 ? 1.0f :
		diff < 16 ? 0.9f :
		diff < 32 ? 0.7f :
		diff < 48 ? 0.5f :
		diff < 64 ? 0.3f :
		diff < 76 ? 0.2f : 0.0f;
	return unit;
}

float GetColorVal(HSV color)
{
	auto val = ((float)color.val()) / 255.0f;
	//val *= 2;

	auto sat = ((float)color.sat()) / 255.0f;
	sat *= 0.2f;

	return val - sat;
}

float GetColorUnit(HSV firstColor, HSV secondColor)
{
	auto backgroundVal = GetColorVal(firstColor);
	auto foregroundVal = GetColorVal(secondColor);

	auto diff = abs(foregroundVal - backgroundVal) + 1.f; // *2;

	return diff;
}

float GetColorContrast(HSV firstColor, HSV secondColor)
{
	auto foregroundVal = GetColorVal(firstColor);
	auto backgroundVal = GetColorVal(secondColor);

	return backgroundVal - foregroundVal;
}

void ParseLineHeight(CSS_STREAM &style, PARSED_WORD param, CSS_FLAGS flags)
{
	float number;
	auto scale = CSS_SCALE_INVALID;

	if (param.wordString.length() <= 0)
		return;

	auto name = param.wordName;
	if (name == STYLE_normal)
	{
		number = 1.2f;
		scale = CSS_SCALE_EM;
		SetProperty(style, CSS_PROPERTY_LINE_HEIGHT, scale, number, flags);
	}
	else
	{
		if (ParseCssLength(param, number, scale, CSS_SCALE_EM) == true)
		{
			SetProperty(style, CSS_PROPERTY_LINE_HEIGHT, scale, number, flags);
		}
	}
}

bool ParseFontSize(CSS_STREAM &style, PARSED_WORD param, CSS_FLAGS flags)
{
	bool isSuccessful = false;
	float sizeValue; CSS_SCALE scale;
	if (ParseCssLength(param, sizeValue, scale, CSS_SCALE_PIXEL))
	{
		SetProperty(style, CSS_PROPERTY_FONT_SIZE, scale, sizeValue, flags);
		isSuccessful = true;
	}

	ParseLineHeight(style, param, flags);
	return isSuccessful;
}

void ParseFont(CSS_STREAM &style, PARSED_WORDS& param, CSS_FLAGS flags)
{
	while (param)
	{
		auto parsedWord = param.shift();
		auto fontToken = parsedWord.wordString;
		auto tokenName = parsedWord.wordName;
		if (tokenName)
		{
			if (auto& nameUnit = FontWeightUnits.find(tokenName))
			{
				SetProperty(style, CSS_PROPERTY_FONT_WEIGHT, CSS_SCALE_NAME, CSS_ENCODE_NAME(tokenName), flags);
				continue;
			}

			if (auto& nameUnit = FontSizeNameUnits.find(tokenName))
			{
				SetProperty(style, CSS_PROPERTY_FONT_SIZE, CSS_SCALE_NAME, CSS_ENCODE_NAME(tokenName), flags);
				continue;
			}

			if (auto& nameUnit = FontStyleUnits.find(tokenName))
			{
				SetProperty(style, CSS_PROPERTY_FONT_STYLE, CSS_SCALE_NAME, CSS_ENCODE_NAME(tokenName), flags);
				continue;
			}

			if (auto& nameUnit = FontVariantUnits.find(tokenName))
			{
				SetProperty(style, CSS_PROPERTY_FONT_VARIANT, CSS_SCALE_NAME, CSS_ENCODE_NAME(tokenName), flags);
				continue;
			}
		}

		if (String.isNumber(fontToken) && ParseFontSize(style, parsedWord, flags))
		{
			continue;
		}

		if (ParseFontFamily(style, fontToken, flags))
		{
			continue;
		}
	}
}

void ParseFontStyle(CSS_STREAM &style, PARSED_WORD fontLine, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(fontLine))
	{
		SetProperty(style, CSS_PROPERTY_FONT_STYLE, property.scale, property.value, flags);
	}
}

void ParseFontVariant(CSS_STREAM &style, PARSED_WORD fontLine, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(fontLine))
	{
		SetProperty(style, CSS_PROPERTY_FONT_VARIANT, property.scale, property.value, flags);
	}
}

constexpr NAME_MAP FontWeightMap [] = { { STYLE_normal, STYLE_400 }, { STYLE_bold, STYLE_600 }, { STYLE_bolder, STYLE_800 }, { STYLE_lighter, STYLE_200 }, };
void ParseFontWeight(CSS_STREAM &style, PARSED_WORD fontLine, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(fontLine))
	{
		MapName(property, FontWeightMap);
		SetProperty(style, CSS_PROPERTY_FONT_WEIGHT, property.scale, property.value, flags);
	}
}

void ParseForegroundColor(CSS_STREAM &style, PARSED_WORDS& colorString, CSS_FLAGS flags)
{
	CSS_PROPERTY colorProperty;
	if (ParseColorValue(colorString, colorProperty))
	{
		SetProperty(style, CSS_PROPERTY_COLOR, colorProperty.scale, colorProperty.value, flags);
	}
}

TOKEN ParseUrl(PARSED_WORDS& paramStream)
{
	auto name = Null;
	if ((paramStream.peek().wordString == "url") && paramStream.length() >= 2)
	{
		name = CreateCustomName<SERVICE_STACK>(paramStream.shift(2).wordString);
	}
	return name;
}

void ParseBackgroundImage(CSS_STREAM &style, PARSED_WORDS& valueLine, CSS_FLAGS flags)
{
	auto name = ParseUrl(valueLine);
	if (name)
	{
		SetProperty(style, CSS_PROPERTY_BACKGROUND_IMAGE, CSS_SCALE_NAME, CSS_ENCODE_NAME(name), flags);
	}
}

void ParseBackground(CSS_STREAM &style, PARSED_WORDS& paramStream, CSS_FLAGS flags)
{
	while (paramStream)
	{
		do
		{
			CSS_PROPERTY colorProperty;
			if (ParseColorValue(paramStream, colorProperty) == true)
			{
				SetProperty(style, CSS_PROPERTY_BACKGROUND_COLOR, colorProperty.scale, colorProperty.value, flags);
				break;
			}

			auto name = ParseUrl(paramStream);
			if (name)
			{
				SetProperty(style, CSS_PROPERTY_BACKGROUND_IMAGE, CSS_SCALE_NAME, CSS_ENCODE_NAME(name), flags);
				break;
			}

			name = paramStream.peek().wordName;
			if (name)
			{
				if (auto& nameUnit = BackgroundRepeatUnits.find(name))
				{
					paramStream.shift();
					SetProperty(style, CSS_PROPERTY_BACKGROUND_REPEAT, CSS_SCALE_NAME, CSS_ENCODE_NAME(name), flags);
					break;
				}
			}
		} while (false);
	}
}

void ParseBackgroundRepeat(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	if (param.wordName == STYLE_inherit)
	{
		SetProperty(style, CSS_PROPERTY_BACKGROUND_REPEAT, CSS_SCALE_INHERIT, 0.0f, flags);
	}
	if (param.wordName)
	{
		if (auto& nameUnit = BackgroundRepeatUnits.find(param.wordName))
		{
			SetProperty(style, CSS_PROPERTY_BACKGROUND_REPEAT, CSS_SCALE_NAME, CSS_ENCODE_NAME(param.wordName), flags);
		}
	}
}

void ParseBackgroundColor(CSS_STREAM &style, PARSED_WORDS& valueLine, CSS_FLAGS flags)
{
	CSS_PROPERTY color;
	if (ParseColorValue(valueLine, color) == true)
	{
		SetProperty(style, CSS_PROPERTY_BACKGROUND_COLOR, color.scale, color.value, flags);
	}
}

void ParseDisplay(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	CSS_DISPLAY display = DISPLAY_INVALID;
	for (auto displayNamePair : StyleDisplayMap)
	{
		if (displayNamePair.name == param.wordName)
		{
			display = displayNamePair.display;
			break;
		}
	}
	ASSERT(display != DISPLAY_INVALID);
	//style->display = display;
	if (display != DISPLAY_INVALID)
	{
		SetProperty(style, CSS_PROPERTY_DISPLAY, CSS_SCALE_DISPLAY, display, flags);
	}
}

void ParseVisibility(CSS_STREAM &style, PARSED_WORD param, CSS_FLAGS)
{
	if (param.wordName == STYLE_hidden || param.wordName == STYLE_collapse)
	{
		StyleSetDisplay(style, DISPLAY_NONE);
	}
}

void ParseFloat(CSS_STREAM &style, PARSED_WORD valueLine, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(valueLine))
	{
		SetProperty(style, CSS_PROPERTY_FLOAT, property.scale, property.value, flags);
	}
}

void SetCornerProperty(CORNER_PROPERTIES &edge, CSS_PROPERTY &property)
{
	auto count = ++edge.count;
	if (count == 1)
	{
		edge.top = edge.right = edge.bottom = edge.left = property;
	}
	else if (count == 2)
	{
		edge.right = edge.left = property;
	}
	else if (count == 3)
	{
		edge.bottom = property;
	}
	else if (count == 4)
	{
		edge.left = property;
	}
	else DBGBREAK();
}

void ParsePadding(CSS_STREAM &style, PARSED_WORDS paramStream, CSS_FLAGS flags)
{
	CORNER_PROPERTIES padding;
	for(auto& param: paramStream)
	{
		if (auto property = ParseCssLength(param, CSS_SCALE_PIXEL))
		{
			SetCornerProperty(padding, property);
		}
		else DBGBREAK();
	}

	SetProperty(style, CSS_PROPERTY_PADDING_TOP, padding.top.scale, padding.top.value, flags);
	SetProperty(style, CSS_PROPERTY_PADDING_RIGHT, padding.right.scale, padding.right.value, flags);
	SetProperty(style, CSS_PROPERTY_PADDING_BOTTOM, padding.bottom.scale, padding.bottom.value, flags);
	SetProperty(style, CSS_PROPERTY_PADDING_LEFT, padding.left.scale, padding.left.value, flags);
}

void ParseMargin(CSS_STREAM &style, PARSED_WORDS& paramStream, CSS_FLAGS flags)
{
	auto margin = CORNER_PROPERTIES();
	CSS_PROPERTY property;
	for (auto& param: paramStream)
	{
		if (auto property = ParseCssLength(param, CSS_SCALE_PIXEL))
		{
			SetCornerProperty(margin, property);
		}
		else DBGBREAK();
	}

	SetProperty(style, CSS_PROPERTY_MARGIN_TOP, margin.top.scale, margin.top.value, flags);
	SetProperty(style, CSS_PROPERTY_MARGIN_RIGHT, margin.right.scale, margin.right.value, flags);
	SetProperty(style, CSS_PROPERTY_MARGIN_BOTTOM, margin.bottom.scale, margin.bottom.value, flags);
	SetProperty(style, CSS_PROPERTY_MARGIN_LEFT, margin.left.scale, margin.left.value, flags);
}

void ParseBorderColor(CSS_STREAM &style, PARSED_WORDS& valueLine, CSS_PROPERTY_NAME propertyName, CSS_FLAGS flags)
{
	CORNER_PROPERTIES borderColor;
	CSS_PROPERTY colorProperty;
	USTRING token;
	while (valueLine.length() > 0)
	{
		auto isColor = ParseColorValue(valueLine, colorProperty);
		if (isColor)
		{
			SetCornerProperty(borderColor, colorProperty);
		}
		else break;
	}

	if (propertyName == CSS_PROPERTY_BORDER_COLOR)
	{
		SetProperty(style, CSS_PROPERTY_BORDER_TOP_COLOR, borderColor.top.scale, borderColor.top.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_RIGHT_COLOR, borderColor.right.scale, borderColor.right.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_BOTTOM_COLOR, borderColor.bottom.scale, borderColor.bottom.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_LEFT_COLOR, borderColor.left.scale, borderColor.left.value, flags);
	}
	else
	{
		SetProperty(style, propertyName, borderColor.top.scale, borderColor.top.value, flags);
	}
}

void ParseBorderStyle(CSS_STREAM &style, PARSED_WORDS& paramStream, CSS_PROPERTY_NAME propertyName, CSS_FLAGS flags)
{
	CORNER_PROPERTIES borderStyle;
	CSS_PROPERTY styleProperty;
	for(auto& param: paramStream)
	{
		if (auto stylePropery = ParseCssName(param))
		{
			SetCornerProperty(borderStyle, styleProperty);
		}
	}

	if (propertyName == CSS_PROPERTY_BORDER_STYLE)
	{
		SetProperty(style, CSS_PROPERTY_BORDER_TOP_STYLE, borderStyle.top.scale, borderStyle.top.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_RIGHT_STYLE, borderStyle.right.scale, borderStyle.right.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_BOTTOM_STYLE, borderStyle.bottom.scale, borderStyle.bottom.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_LEFT_STYLE, borderStyle.left.scale, borderStyle.left.value, flags);
	}
	else
	{
		SetProperty(style, propertyName, borderStyle.top.scale, borderStyle.top.value, flags);
	}
}

void ParseBorderWidth(CSS_STREAM &style, PARSED_WORDS& paramStream, CSS_PROPERTY_NAME propertyName, CSS_FLAGS flags)
{
	CORNER_PROPERTIES borderWidth;
	CSS_PROPERTY widthValue;
	for (auto& param: paramStream)
	{
		if (widthValue = ParseCssLength(param, CSS_SCALE_PIXEL))
		{
			SetCornerProperty(borderWidth, widthValue);
		}
		else if (widthValue = ParseCssName(param))
		{
			SetCornerProperty(borderWidth, widthValue);
		}
	}

	if (borderWidth.count == 0)
		return;

	if (propertyName == CSS_PROPERTY_BORDER_WIDTH)
	{
		SetProperty(style, CSS_PROPERTY_BORDER_TOP_WIDTH, borderWidth.top.scale, borderWidth.top.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_RIGHT_WIDTH, borderWidth.right.scale, borderWidth.right.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_BOTTOM_WIDTH, borderWidth.bottom.scale, borderWidth.bottom.value, flags);
		SetProperty(style, CSS_PROPERTY_BORDER_LEFT_WIDTH, borderWidth.left.scale, borderWidth.left.value, flags);
	}
	else
	{
		SetProperty(style, propertyName, borderWidth.top.scale, borderWidth.top.value, flags);
	}
}

struct BORDER_PROPERTIES
{
	CSS_PROPERTY_NAME borderType;
	CSS_PROPERTY_NAME borderColor;
	CSS_PROPERTY_NAME borderWidth;
	CSS_PROPERTY_NAME borderStyle;
};

constexpr BORDER_PROPERTIES BorderProperties [] = {
	{ CSS_PROPERTY_BORDER_TOP, CSS_PROPERTY_BORDER_TOP_COLOR, CSS_PROPERTY_BORDER_TOP_WIDTH, CSS_PROPERTY_BORDER_TOP_STYLE },
	{ CSS_PROPERTY_BORDER_RIGHT, CSS_PROPERTY_BORDER_RIGHT_COLOR, CSS_PROPERTY_BORDER_RIGHT_WIDTH, CSS_PROPERTY_BORDER_RIGHT_STYLE },
	{ CSS_PROPERTY_BORDER_BOTTOM, CSS_PROPERTY_BORDER_BOTTOM_COLOR, CSS_PROPERTY_BORDER_BOTTOM_WIDTH, CSS_PROPERTY_BORDER_BOTTOM_STYLE },
	{ CSS_PROPERTY_BORDER_LEFT, CSS_PROPERTY_BORDER_LEFT_COLOR, CSS_PROPERTY_BORDER_LEFT_WIDTH, CSS_PROPERTY_BORDER_LEFT_STYLE },
};

void ParseBorder(CSS_STREAM &style, PARSED_WORDS& paramStream, CSS_PROPERTY_NAME propertyName, CSS_FLAGS flags)
{
	CSS_PROPERTY borderStyle, borderWidth, borderColor;

	while (paramStream)
	{
		auto firstParam = paramStream.shift();

		auto name = firstParam.wordName;
		if (name == STYLE_none)
		{
			borderWidth.value = 0.0f;
			borderWidth.scale = CSS_SCALE_PIXEL;
		}
		else if (auto& nameUnit = BorderStyleUnits.find(name))
		{
			borderStyle.value = CSS_ENCODE_NAME(name);
			borderStyle.scale = CSS_SCALE_NAME;
		}
		else if (auto& nameUnit = BorderWidthNameUnits.find(name))
		{
			borderWidth.value = CSS_ENCODE_NAME(name);
			borderWidth.scale = CSS_SCALE_NAME;
		}
		else if (auto hsv = ParseColorValue(firstParam, paramStream))
		{
			borderColor.scale = CSS_SCALE_COLOR;
			borderColor.value = CSS_ENCODE_COLOR(hsv);
		}
		else if (auto property = ParseCssLength(firstParam, CSS_SCALE_PIXEL))
		{
			borderWidth = property;
		}
		else
		{
			DBGBREAK();
		}
	}

	for (auto &borderProperties : BorderProperties)
	{
		if (borderProperties.borderType == propertyName || propertyName == CSS_PROPERTY_BORDER)
		{
			if (borderColor)
				SetProperty(style, borderProperties.borderColor, borderColor.scale, borderColor.value, flags);

			if (borderWidth)
				SetProperty(style, borderProperties.borderWidth, borderWidth.scale, borderWidth.value, flags);

			if (borderStyle)
				SetProperty(style, borderProperties.borderStyle, CSS_SCALE_NAME, borderStyle.value, flags);
		}
	}
}

void ParseTextDecoration(CSS_STREAM &style, PARSED_WORD param, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(param))
	{
		SetProperty(style, CSS_PROPERTY_TEXT_DECORATION, property.scale, property.value, flags);
	}
	else DBGBREAK();
}

void ParseTextAlign(CSS_STREAM &style, PARSED_WORD param, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(param))
	{
		SetProperty(style, CSS_PROPERTY_TEXT_ALIGN, property.scale, property.value, flags);
	}
	else DBGBREAK();
}

void ParseTextTransform(CSS_STREAM &style, PARSED_WORD param, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(param))
	{
		SetProperty(style, CSS_PROPERTY_TEXT_TRANSFORM, property.scale, property.value, flags);
	}
	else DBGBREAK();
}

void ParseTextIndent(CSS_STREAM &style, PARSED_WORD param, CSS_FLAGS flags)
{
	if (auto property = ParseCssLength(param, CSS_SCALE_PIXEL))
	{
		SetProperty(style, CSS_PROPERTY_TEXT_INDENT, property.scale, property.value, flags);
	}
	else DBGBREAK();
	// not now
}

void ParseHeight(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	ParseCssLength(param, length, scale, CSS_SCALE_PIXEL);
	SetProperty(style, CSS_PROPERTY_HEIGHT, scale, length, flags);
}

void ParseMinHeight(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	ParseCssLength(param, length, scale, CSS_SCALE_PIXEL);
	SetProperty(style, CSS_PROPERTY_MIN_HEIGHT, scale, length, flags);
}

void ParseMaxHeight(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	ParseCssLength(param, length, scale, CSS_SCALE_PIXEL);
	SetProperty(style, CSS_PROPERTY_MAX_HEIGHT, scale, length, flags);
}

void ParseWidth(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	ParseCssLength(param, length, scale, CSS_SCALE_PIXEL);
	SetProperty(style, CSS_PROPERTY_WIDTH, scale, length, flags);
}

void ParseMinWidth(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	ParseCssLength(param, length, scale, CSS_SCALE_PIXEL);
	SetProperty(style, CSS_PROPERTY_MIN_WIDTH, scale, length, flags);
}

void ParseMaxWidth(CSS_STREAM &style, PARSED_WORD& valueLine, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	ParseCssLength(valueLine, length, scale, CSS_SCALE_PIXEL);
	SetProperty(style, CSS_PROPERTY_MAX_WIDTH, scale, length, flags);
}

void ParsePosition(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(param))
	{
		SetProperty(style, CSS_PROPERTY_POSITION, property.scale, property.value, flags);
	}
	else DBGBREAK();
}

void ParseTop(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	if (ParseCssLength(param, length, scale, CSS_SCALE_PIXEL) == true)
	{
		SetProperty(style, CSS_PROPERTY_TOP, scale, length, flags);
	}
}

void ParseLeft(CSS_STREAM &style, PARSED_WORD&  param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	if (ParseCssLength(param, length, scale, CSS_SCALE_PIXEL) == true)
	{
		SetProperty(style, CSS_PROPERTY_LEFT, scale, length, flags);
	}
}

void ParseRight(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	if (ParseCssLength(param, length, scale, CSS_SCALE_PIXEL) == true)
	{
		SetProperty(style, CSS_PROPERTY_RIGHT, scale, length, flags);
	}
}

void ParseBottom(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	float length; CSS_SCALE scale;
	if (ParseCssLength(param, length, scale, CSS_SCALE_PIXEL) == true)
	{
		SetProperty(style, CSS_PROPERTY_BOTTOM, scale, length, flags);
	}
}

void ParseClear(CSS_STREAM &style, PARSED_WORD& param, CSS_FLAGS flags)
{
	if (auto property = ParseCssName(param))
	{
		SetProperty(style, CSS_PROPERTY_CLEAR, property.scale, property.value, flags);
	}
	else DBGBREAK();
}

//template<unsigned int arraySize>
//bool EndsInKeyword(USTRING &value, char const (&keyword)[arraySize])
//{
//	if (value.length() < arraySize)
//		return false;
//
//	auto patternLength = arraySize - 1;
//	auto index = FindChar(value, keyword[0]);
//	if (index > 0 && (value.length() - index) == patternLength)
//	{
//		if (strncmp(value.addr(index), keyword, patternLength) == 0)
//		{
//			value.truncate(patternLength);
//			Trim(value);
//			return true;
//		}
//	}
//	return false;
//}

void ParseCssProperty(CSS_STREAM &style, TOKEN name, PARSED_WORDS& paramStream)
{
	auto flags = CSS_FLAG_NONE;
	if (paramStream.last().wordName == STYLE_important)
	{
		paramStream.shrink();
		flags = CSS_FLAG_IMPORTANT;
	}

	float number;
	CSS_SCALE scale;
	auto firstParam = paramStream.peek();
	switch (name.getValue())
	{
	case STYLE_font.getValue():
		ParseFont(style, paramStream, flags);
		break;

	case STYLE_font_family.getValue():
		ParseFontFamily(style, paramStream, flags);
		break;

	case STYLE_font_size.getValue():
		ParseFontSize(style, firstParam, flags);
		break;

	case STYLE_font_weight.getValue():
		ParseFontWeight(style, firstParam, flags);
		break;

	case STYLE_font_variant.getValue():
		ParseFontVariant(style, firstParam, flags);
		break;

	case STYLE_font_style.getValue():
		ParseFontStyle(style, firstParam, flags);
		break;

	case STYLE_display.getValue():
		ParseDisplay(style, firstParam, flags);
		break;

	case STYLE_color.getValue():
		ParseForegroundColor(style, paramStream, flags);
		break;

	case STYLE_background_color.getValue():
		ParseBackgroundColor(style, paramStream, flags);
		break;

	case STYLE_background_repeat.getValue():
		ParseBackgroundRepeat(style, firstParam, flags);
		break;

	case STYLE_background.getValue():
		ParseBackground(style, paramStream, flags);
		break;

	case STYLE_background_image.getValue():
		ParseBackgroundImage(style, paramStream, flags);
		break;

	case STYLE_width.getValue():
		ParseWidth(style, firstParam, flags);
		break;

	case STYLE_height.getValue():
		ParseHeight(style, firstParam, flags);
		break;

	case STYLE_float.getValue():
		ParseFloat(style, firstParam, flags);
		break;

	case STYLE_clear.getValue():
		ParseClear(style, firstParam, flags);
		break;

	case STYLE_padding.getValue():
		ParsePadding(style, paramStream, flags);
		break;

	case STYLE_padding_left.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_PADDING_LEFT, scale, number, flags);
		}
		break;

	case STYLE_padding_right.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_PADDING_RIGHT, scale, number, flags);
		}
		break;

	case STYLE_padding_top.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_PADDING_TOP, scale, number, flags);
		}
		break;

	case STYLE_padding_bottom.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_PADDING_BOTTOM, scale, number, flags);
		}
		break;

	case STYLE_margin.getValue():
		ParseMargin(style, paramStream, flags);
		break;

	case STYLE_margin_left.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_MARGIN_LEFT, scale, number, flags);
		}
		break;

	case STYLE_margin_right.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_MARGIN_RIGHT, scale, number, flags);
		}
		break;

	case STYLE_margin_top.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_MARGIN_TOP, scale, number, flags);
		}
		break;

	case STYLE_margin_bottom.getValue():
		if (ParseCssLength(firstParam, number, scale, CSS_SCALE_PIXEL) == true)
		{
			SetProperty(style, CSS_PROPERTY_MARGIN_BOTTOM, scale, number, flags);
		}
		break;

	case STYLE_border.getValue():
		ParseBorder(style, paramStream, CSS_PROPERTY_BORDER, flags);
		break;

	case STYLE_border_top.getValue():
		ParseBorder(style, paramStream, CSS_PROPERTY_BORDER_TOP, flags);
		break;

	case STYLE_border_bottom.getValue():
		ParseBorder(style, paramStream, CSS_PROPERTY_BORDER_BOTTOM, flags);
		break;

	case STYLE_border_left.getValue():
		ParseBorder(style, paramStream, CSS_PROPERTY_BORDER_LEFT, flags);
		break;

	case STYLE_border_right.getValue():
		ParseBorder(style, paramStream, CSS_PROPERTY_BORDER_RIGHT, flags);
		break;

	case STYLE_border_top_color.getValue():
		ParseBorderColor(style, paramStream, CSS_PROPERTY_BORDER_TOP_COLOR, flags);
		break;

	case STYLE_border_bottom_color.getValue():
		ParseBorderColor(style, paramStream, CSS_PROPERTY_BORDER_BOTTOM_COLOR, flags);
		break;

	case STYLE_border_left_color.getValue():
		ParseBorderColor(style, paramStream, CSS_PROPERTY_BORDER_LEFT_COLOR, flags);
		break;

	case STYLE_border_right_color.getValue():
		ParseBorderColor(style, paramStream, CSS_PROPERTY_BORDER_RIGHT_COLOR, flags);
		break;

	case STYLE_border_color.getValue():
		ParseBorderColor(style, paramStream, CSS_PROPERTY_BORDER_COLOR, flags);
		break;

	case STYLE_border_top_style.getValue():
		ParseBorderStyle(style, paramStream, CSS_PROPERTY_BORDER_TOP_STYLE, flags);
		break;

	case STYLE_border_bottom_style.getValue():
		ParseBorderStyle(style, paramStream, CSS_PROPERTY_BORDER_BOTTOM_STYLE, flags);
		break;

	case STYLE_border_left_style.getValue():
		ParseBorderStyle(style, paramStream, CSS_PROPERTY_BORDER_LEFT_STYLE, flags);
		break;

	case STYLE_border_right_style.getValue():
		ParseBorderStyle(style, paramStream, CSS_PROPERTY_BORDER_RIGHT_STYLE, flags);
		break;

	case STYLE_border_style.getValue():
		ParseBorderStyle(style, paramStream, CSS_PROPERTY_BORDER_STYLE, flags);
		break;

	case STYLE_border_top_width.getValue():
		ParseBorderWidth(style, paramStream, CSS_PROPERTY_BORDER_TOP_WIDTH, flags);
		break;

	case STYLE_border_bottom_width.getValue():
		ParseBorderWidth(style, paramStream, CSS_PROPERTY_BORDER_BOTTOM_WIDTH, flags);
		break;

	case STYLE_border_left_width.getValue():
		ParseBorderWidth(style, paramStream, CSS_PROPERTY_BORDER_LEFT_WIDTH, flags);
		break;

	case STYLE_border_right_width.getValue():
		ParseBorderWidth(style, paramStream, CSS_PROPERTY_BORDER_RIGHT_WIDTH, flags);
		break;

	case STYLE_border_width.getValue():
		ParseBorderWidth(style, paramStream, CSS_PROPERTY_BORDER_WIDTH, flags);
		break;

	case STYLE_text_decoration.getValue():
		ParseTextDecoration(style, firstParam, flags);
		break;

	case STYLE_text_align.getValue():
		ParseTextAlign(style, firstParam, flags);
		break;

	case STYLE_text_indent.getValue():
		ParseTextIndent(style, firstParam, flags);
		break;

	case STYLE_text_transform.getValue():
		ParseTextTransform(style, firstParam, flags);
		break;

	case STYLE_line_height.getValue():
		ParseLineHeight(style, firstParam, flags);
		break;

	case STYLE_font_size_adjust.getValue():
	case STYLE_font_stretch.getValue():
	case STYLE_border_image.getValue():
	case STYLE_border_collapse.getValue():
	case STYLE_border_spacing.getValue():
	case STYLE_vertical_align.getValue():
	case STYLE_overflow.getValue():
	case STYLE_list_style_image.getValue():
	case STYLE_list_style_position.getValue():
	case STYLE_list_style_type.getValue():
	case STYLE_white_space.getValue():
	case STYLE_background_attachment.getValue():
	case STYLE_background_position.getValue():
	case STYLE_cursor.getValue():
	case STYLE_letter_spacing.getValue():
	case STYLE_opacity.getValue():
	case STYLE_z_index.getValue():
	case STYLE_resize.getValue():
	case STYLE_zoom.getValue():
	case STYLE_text_shadow.getValue():
	case STYLE_clip.getValue():
	case STYLE_word_spacing.getValue():
	case STYLE_text_overflow.getValue():
	case STYLE_filter.getValue():
	case STYLE_list_style.getValue():
	case STYLE_word_wrap.getValue():
	case STYLE_table_layout.getValue():
		break;

	case STYLE_visibility.getValue():
		ParseVisibility(style, firstParam, flags);
		break;

	case STYLE_position.getValue():
		ParsePosition(style, firstParam, flags);
		break;

	case STYLE_top.getValue():
		ParseTop(style, firstParam, flags);
		break;

	case STYLE_bottom.getValue():
		ParseBottom(style, firstParam, flags);
		break;

	case STYLE_left.getValue():
		ParseLeft(style, firstParam, flags);
		break;

	case STYLE_right.getValue():
		ParseRight(style, firstParam, flags);
		break;

	case STYLE_min_height.getValue():
		ParseMinHeight(style, firstParam, flags);
		break;

	case STYLE_min_width.getValue():
		ParseMinWidth(style, firstParam, flags);
		break;

	case STYLE_max_height.getValue():
		ParseMaxHeight(style, firstParam, flags);
		break;

	case STYLE_max_width.getValue():
		ParseMaxWidth(style, firstParam, flags);
		break;

	default:
		break;
	}
}

CSS_STREAM& GetDefaultStyle(TOKEN elementName)
{
	auto& styleMap = DefaultStyle().toBufferNoConst().find(elementName); // .find2(offsetof(ELEMENT_DISPLAY_STYLE, name), elementName);
	ASSERT(styleMap);
	return styleMap ? styleMap.style : NullRef<CSS_STREAM>();
}

TOKEN PropertyNameToString(CSS_PROPERTY_NAME property)
{
	for (auto &map : PropertyNames)
	{
		if (map.property == property)
			return map.name;
	}
	return Undefined;
}

USTRING PrintStyle(CSS_STREAM &style)
{
	auto& formatStream = GetTempStream();

	for (UINT32 i = 0; i < style.count(); i++)
	{
		auto &property = style.at(i);
		ASSERT(property && property.name);
		formatStream.writeName(PropertyNameToString(property.name));
		formatStream.writeString(": ");

		FormatCssValue(property, formatStream);
		formatStream.writeString("\n");
	}
	return formatStream.toBuffer();
}

CSS_STREAM &GetStyle(TOKEN)
{
	return NullRef<CSS_STREAM>();
	// XXX return GetStyle(GetHtmlElement(elementIndex));
}

USTRING PrintStyle(TOKEN element)
{
	return PrintStyle(GetStyle(element));
}

INT32 StyleGetMargin(CSS_STREAM &style, CSS_PROPERTY_NAME propertyName)
{
	auto marginValue = 0.0f;
	auto &property = StyleFindProperty(style, propertyName);
	if (!property)
	{
		property = StyleFindProperty(style, CSS_PROPERTY_MARGIN);
	}
	if (property)
	{
		if (property.scale == CSS_SCALE_PERCENT)
			marginValue = (StyleGetWidth(style) * property.value);
		else if (property.scale == CSS_SCALE_EM)
			marginValue = (StyleGetFontSize(style) * property.value);
		else if (property.scale == CSS_SCALE_PIXEL)
			marginValue = property.value;
		else if (property.scale == CSS_SCALE_AUTO)
			marginValue = 0; // XXX compute margin based on width
		else DBGBREAK();
	}
	return (INT32) marginValue;
}

INT32 StyleGetPadding(CSS_STREAM &style, CSS_PROPERTY_NAME propertyName)
{
	auto paddingValue = 0.0f;
	auto &property = StyleFindProperty(style, propertyName);
	if (!property)
	{
		property = StyleFindProperty(style, CSS_PROPERTY_PADDING);
	}
	if (property)
	{
		if (property.scale == CSS_SCALE_PERCENT)
			paddingValue = StyleGetWidth(style) * property.value;
		else if (property.scale == CSS_SCALE_EM)
			paddingValue = StyleGetFontSize(style) * property.value;
		else if (property.scale == CSS_SCALE_PIXEL)
			paddingValue = property.value;
		else DBGBREAK();
	}
	return (INT32) paddingValue;
}

INT32 StyleGetPixelValue(CSS_STREAM &style, CSS_PROPERTY_NAME propertyName)
{
	INT32 value = MININT;
	auto &property = StyleFindProperty(style, propertyName);
	if (property)
	{
		if (property.scale == CSS_SCALE_EM)
		{
			auto fontSize = StyleGetFontSize(style);
			value = (INT32)(property.value * fontSize);
		}
		else if (property.scale == CSS_SCALE_PIXEL)
		{
			value = (INT32) property.value;
		}
		else if (property.scale == CSS_SCALE_AUTO)
		{
			value = MININT;
		}
		else DBGBREAK();
	}
	return value;
}

bool StyleGetPixelValue(CSS_STREAM &style, CSS_PROPERTY_NAME propertyName, INT32 &value)
{
	auto tempValue = StyleGetPixelValue(style, propertyName);
	if (tempValue != MININT)
		value = tempValue;

	return tempValue != MININT;
}

void StyleSetNameValue(CSS_STREAM &style, CSS_PROPERTY_NAME name, TOKEN value)
{
	CSS_PROPERTY property;
	property.name = name;
	property.value = CSS_ENCODE_NAME(value);
	property.scale = CSS_SCALE_NAME;

	StyleSetProperty(style, property);
}

void StyleSetPixelValue(CSS_STREAM &style, CSS_PROPERTY_NAME name, float value)
{
	CSS_PROPERTY property;
	property.name = name;
	property.value = value;
	property.scale = CSS_SCALE_PIXEL;

	StyleSetProperty(style, property);
}

float StyleToUnits(CSS_STREAM &style)
{
	UNREFERENCED_PARAMETER(style);
	return 0.0f;
}

void HandleAtDirective(USTRING &cssText)
{
	UNREFERENCED_PARAMETER(cssText);
}

static void InitializeDefaultStyle()
{
	for (auto &elementMap : ElementDisplayMap)
	{
		auto &nameMap = DefaultStyle().append();
		nameMap.name = elementMap.name;
		SetProperty(nameMap.style, CSS_PROPERTY_DISPLAY, CSS_SCALE_DISPLAY, elementMap.display, CSS_FLAG_NONE);
	}

	for (auto &property : DefaultStyleProperties)
	{
		auto &style = GetDefaultStyle(property.elementName);
		SetProperty(style, property.propertyName, property.scale, property.value, CSS_FLAG_NONE);
	}
}

constexpr DOCUMENT_PROPERTY DocumentProperties [] = {
	{ CSS_PROPERTY_MIN_WIDTH, CSS_SCALE_PIXEL, 1600.0f },
	{ CSS_PROPERTY_MIN_HEIGHT, CSS_SCALE_PIXEL, 800.0f },
	{ CSS_PROPERTY_FONT_SIZE, CSS_SCALE_PIXEL, 14.0f },
	{ CSS_PROPERTY_FONT_WEIGHT, CSS_SCALE_NAME, CSS_ENCODE_NAME(STYLE_400) },
};

static void InitializeDocumentStyle()
{
	auto &style = CssGlobals().documentStyle;

	for (auto &property : DocumentProperties)
	{
		SetProperty(style, property.name, property.scale, property.value, CSS_FLAG_NONE);
	}
	auto foreground = FindColorByName(STYLE_black);
	auto background = FindColorByName(STYLE_white);
	SetProperty(style, CSS_PROPERTY_COLOR, CSS_SCALE_COLOR, CSS_ENCODE_COLOR(foreground), CSS_FLAG_NONE);
	SetProperty(style, CSS_PROPERTY_BACKGROUND_COLOR, CSS_SCALE_COLOR, CSS_ENCODE_COLOR(background), CSS_FLAG_NONE);
}

CSS_STREAM &GetDocumentStyle()
{
	return CssGlobals().documentStyle;
}

void CssInitialize()
{
	CssGlobalsPtr = &KernelAlloc<CSS_GLOBALS>();

	for (auto string : RgbColors)
	{
		COLOR_INFO& color = CssGlobals().colorTable.append(); // &ColorTable[ColorTableCount++];
		color.name = CreateName(string);

		String.splitChar(string, "(");

		RGB rgb;
		rgb.r = (UINT8)String.toNumber(String.splitChar(string, ",)"));
		rgb.g = (UINT8)String.toNumber(String.splitChar(string, ",)"));
		rgb.b = (UINT8)String.toNumber(String.splitChar(string, ",)"));

		color.hsv = RGBtoHSV(rgb);
	}

	for (auto &standardColor : StandardColors)
	{
		COLOR_INFO& color = CssGlobals().colorTable.append();
		auto string = standardColor.color;

		color.hsv = ParseHexColorString(string.clone());
		color.name = CreateName(string);

		CssGlobals().colorTable.append(standardColor.name, color.hsv);
	}

	for (auto string : SizeStrings)
	{
		auto name = CreateName(string);

		auto& fontSize = CssGlobals().fontSizeTable.append(); // &FontSizeUnitsTable[FontSizeUnitsTableCount++];

		fontSize.name = name; 
		ToFontSizeUnit(PARSED_WORD(string), fontSize.unit);
	}

	InitializeDefaultStyle();

	InitializeDocumentStyle();
}
