#pragma once

constexpr VISUAL_TOKEN SizeVisual(VSIZE size) { return VISUAL_TOKEN(Null, size); }
constexpr VISUAL_TOKEN SpanVisual(VSPAN span) { return VISUAL_TOKEN(Null, VSIZE::DEFAULT, span); }

using VISUALBUFFER = STREAM_READER<const VISUAL_TOKEN>;

template <typename STACK, typename BSTREAM>
void FormatVisual(VISUALBUFFER visualBuffer, BSTREAM&& byteStream)
{
	for (auto& token : visualBuffer)
	{
		byteStream.writeVisualToken<STACK>(token);
	}
}

template <typename STACK, typename VSTREAM>
VISUALBUFFER ParseVisual(VSTREAM&& stream, BUFFER dataBuffer)
{
	auto position = stream.count();
	while (dataBuffer)
	{
		auto visual = dataBuffer.readVisualToken<STACK>();
		stream.append(visual);
	}
	return stream.toBuffer(position);
}

template <typename STACK, UINT32 SIZE = 64>
struct VISUALSTREAM
{
	STREAM_BUILDER<VISUAL_TOKEN, STACK, SIZE> stream;

	void writeValue(TOKEN value, VSIZE size = VSIZE::MEDIUM, VSPAN span = VSPAN::WORD)
	{
		stream.append(value, size, span);
	}

	void writeAttr(TOKEN value, VSIZE size = VSIZE::SMALL, VSPAN span = VSPAN::COLON)
	{
		stream.append(value, size, span);
	}
	
	template <typename ... ARGS>
	void writeValueAttr(TOKEN value, ARGS&& ... args)
	{
		writeValue(value);
		int dummy[] = { (this->writeAttr(args), 0) ... }; dummy;
	}

	void writeSpan(VSPAN span)
	{
		stream.append(Null, VSIZE::DEFAULT, span);
	}

	template <typename STREAM>
	void format(STREAM&& byteStream)
	{
		FormatVisual<STACK>(stream.toBuffer(), byteStream);
	}

	STREAM_READER<const VISUAL_TOKEN> parse(BUFFER dataBuffer)
	{
		return ParseVisual<STACK>(stream, dataBuffer);
	}

	VISUALBUFFER toBuffer() { return stream.toBuffer(); }
};

extern VISUALBUFFER DiffBot(VISUALBUFFER firstVisual, VISUALBUFFER secondVisual);
