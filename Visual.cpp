#include "Types.h"

VISUALBUFFER FindVisual(BUFFER path, VISUALBUFFER parent)
{
	while (parent && path)
	{
		auto visualToken = parent.shift();
		if ((UINT8)visualToken.span >= path.at(0))
		{
			path.shift();
		}
	}
	
	auto child = parent;
	auto currentSpan = (UINT8)parent.at(0).span;
	while (parent)
	{
		if ((UINT8)parent.at(0).span >= currentSpan)
		{
			break;
		}
		parent.shift();
	}

	child._end = parent._start;
	return child;
}

constexpr auto KEEP_TOKEN = VISUAL_TOKEN(TOKEN(TOKENTYPE::CONSTANT, 21));
constexpr auto REMOVE_TOKEN = VISUAL_TOKEN(TOKEN(TOKENTYPE::CONSTANT, 22));
constexpr auto INSERT_TOKEN = VISUAL_TOKEN(TOKEN(TOKENTYPE::CONSTANT, 23));
constexpr auto REPLACE_TOKEN = VISUAL_TOKEN(TOKEN(TOKENTYPE::CONSTANT, 24));

VISUALBUFFER getVisual(VISUALBUFFER& parent)
{
	auto child = parent;
	if (parent)
	{
		auto span = (UINT8)parent.shift().span;

		while (parent)
		{
			if ((UINT8)parent.at(0).span >= span)
				break;

			parent.shift();
		}

		child._end = parent._start;
	}
	return child;
}

template <typename STREAM>
STREAM_READER<const VISUALBUFFER> getAllVisuals(VISUALBUFFER parent, STREAM&& visualStream)
{
	while (auto visual = getVisual(parent))
	{
		visualStream.append(visual);
	}
	return visualStream.toBuffer();
}

float CompareVisual(VISUALBUFFER firstVisual, VISUALBUFFER secondVisual)
{
	auto byteCount = firstVisual.length() * sizeof(VISUAL_TOKEN);
	if (RtlCompareMemory((PUINT8)firstVisual.data(), (PUINT8)secondVisual.data(), byteCount) == byteCount)
	{
		return 1.0;
	}
	else
	{
		float matches = 0;
		for (UINT32 i = 0; i < firstVisual.length(); i++)
		{
			if (secondVisual.length() >= i && firstVisual.at(i) == secondVisual.at(i))
			{
				matches++;
			}
		}
		return matches / max(firstVisual.length(), secondVisual.length());
	}
}

float matchVisual(STREAM_READER<const VISUALBUFFER> visualList, VISUALBUFFER match, UINT32& matchIndex)
{
	float highScore = 0;
	matchIndex = 0;

	for (UINT32 i = 0; i < visualList.length(); i++)
	{
		auto visual = visualList.at(i);
		auto score = CompareVisual(visual, match);
		if (score > highScore)
		{
			matchIndex = i;
			highScore = score;
		}
	}
	return highScore;
}

template <typename STREAM>
void writeTokens(STREAM&& stream, VISUAL_TOKEN token, UINT32 count)
{
	for (UINT32 i = 0; i < count; i++)
	{
		stream.append(token);
	}
}

template <typename STREAM>
void DiffBot(VISUALBUFFER firstVisual, VISUALBUFFER secondVisual, STREAM&& firstStream, STREAM&& secondStream)
{
	ASSERT(firstVisual && secondVisual);

	if (firstVisual.at(0) == secondVisual.at(0))
	{
		firstStream.append(KEEP_TOKEN);
		secondStream.append(KEEP_TOKEN);

		firstVisual.shift();
		secondVisual.shift();

		while (auto visual = getVisual(firstVisual))
		{
			if (secondVisual)
			{
				auto secondVisualList = getAllVisuals(secondVisual, STREAM_BUILDER<VISUALBUFFER, SCHEDULER_STACK, 4>());
				UINT32 matchIndex;
				auto score = matchVisual(secondVisualList, visual, matchIndex);
				if (score == 1.0)
				{
					if (matchIndex == 0)
					{
						writeTokens(firstStream, KEEP_TOKEN, visual.length());
						writeTokens(secondStream, KEEP_TOKEN, visual.length());
						secondVisual.shift(visual.length());
					}
					else
					{
						for (UINT32 i = 0; i < matchIndex; i++)
						{
							auto thisVisual = secondVisualList.at(i);
							writeTokens(firstStream, INSERT_TOKEN, thisVisual.length());
							secondStream.writeStream(thisVisual);
							secondVisual.shift(thisVisual.length());
						}
						writeTokens(firstStream, KEEP_TOKEN, visual.length());
						writeTokens(secondStream, KEEP_TOKEN, visual.length());
						secondVisual.shift(visual.length());
					}
				}
				else
				{
					DiffBot(visual, secondVisualList.at(0), firstStream, secondStream);
					secondVisual.shift(secondVisualList.at(0).length());
				}
			}
			else
			{
				firstStream.writeStream(visual);
				writeTokens(secondStream, INSERT_TOKEN, visual.length());
			}
		}
		if (secondVisual)
		{
			writeTokens(firstStream, INSERT_TOKEN, secondVisual.length());
		}
	}
	else
	{
		firstStream.writeStream(firstVisual);
		writeTokens(secondStream, INSERT_TOKEN, firstVisual.length());

		writeTokens(firstStream, INSERT_TOKEN, secondVisual.length());
		secondStream.writeStream(secondVisual);
	}
}

VISUALBUFFER DiffBot(VISUALBUFFER firstVisual, VISUALBUFFER secondVisual)
{
	STREAM_BUILDER<VISUAL_TOKEN, SCHEDULER_STACK, 1> firstStream, secondStream;
	firstStream.reserve(firstVisual.length() * 2);
	secondStream.reserve(secondVisual.length() * 2);

	DiffBot(getVisual(firstVisual), getVisual(secondVisual), firstStream, secondStream);

	auto firstDiff = firstStream.toBuffer();
	auto secondDiff = secondStream.toBuffer();

	ASSERT(firstDiff.length() == secondDiff.length());

	STREAM_BUILDER<VISUAL_TOKEN, SCHEDULER_STACK, 1> mergeStream;
	mergeStream.reserve(firstVisual.length() * 2);

	while (firstDiff)
	{
		auto firstToken = firstDiff.shift();
		auto secondToken = secondDiff.shift();

		if (firstToken == KEEP_TOKEN)
		{
			ASSERT(secondToken == KEEP_TOKEN);
			UINT32 keepCount = 1;
			while (firstDiff.at(0) == KEEP_TOKEN && secondDiff.at(0) == KEEP_TOKEN)
			{
				keepCount++;
				firstDiff.shift();
				secondDiff.shift();
			}

			mergeStream.append(KEEP_TOKEN);
			mergeStream.append(CreateNumberHandle<SCHEDULER_STACK>(keepCount));
		}
		else if (firstToken == INSERT_TOKEN)
		{
			mergeStream.append(INSERT_TOKEN);
			mergeStream.append(secondToken);
			while (firstDiff.at(0) == INSERT_TOKEN)
			{
				mergeStream.append(secondDiff.shift());
				firstDiff.shift();
			}
		}
		else if (secondToken == INSERT_TOKEN)
		{
			mergeStream.append(REMOVE_TOKEN);
			UINT32 removeCount = 1;
			while (secondDiff.at(0) == INSERT_TOKEN)
			{
				removeCount++;
				secondDiff.shift();
				firstDiff.shift();
			}
			mergeStream.append(CreateNumberHandle<SCHEDULER_STACK>(removeCount));
		}
	}

	return mergeStream.toBuffer();
}
