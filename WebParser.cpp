#include "Types.h"
#include "WebParser.h"


struct WEBAPP_INFO
{
	USTRING appName;
	WEBSITE_PARSER appParser;

	bool match(USTRING name) { return appName == name; }
	explicit operator bool() const { return IsValidRef(*this); }
};

using WEBAPP_STREAM = STREAM_BUILDER<WEBAPP_INFO, GLOBAL_STACK, 4>;

struct CACHE_INFO
{
	USTRING path;
	UINT32 size;

	bool match(USTRING name) const { return path == name; }
	constexpr explicit operator bool() const { return IsValidRef(*this); }
};

struct WEBAPP_GLOBALS
{
	WEBAPP_STREAM webApps;
	STREAM_BUILDER<CACHE_INFO, GLOBAL_STACK, 128> downloadCache;
};

WEBAPP_GLOBALS* WebAppGlobalsPtr;
WEBAPP_GLOBALS& WebAppGlobals() { return *WebAppGlobalsPtr; }

NTSTATUS ParseWebsite(USTRING appName, USTRING url)
{
	auto& appFound = WebAppGlobals().webApps.toBufferNoConst().find(appName);
	auto& webApp = appFound ? appFound : WebAppGlobals().webApps.append();

	webApp.appParser.parse(url);

	return STATUS_SUCCESS;
}

UINT32 ReadDownloadCache(USTRING path)
{
	auto& cacheEntry = WebAppGlobals().downloadCache.toBuffer().find(path);
	return cacheEntry ? cacheEntry.size : 0;
}

void InitDownloadCache()
{
	auto directory = TSTRING_BUILDER().writeMany(DATA_DIRECTORY, CACHE_DIRECTORY);
	ListDirectory(directory, USTRING(), [](USTRING relativePath, USTRING fullPath)
		{
			UNREFERENCED_PARAMETER(relativePath);
			auto& entry = WebAppGlobals().downloadCache.append();
			entry.size = GetFileSize(fullPath);

			String.splitString(fullPath, DATA_DIRECTORY);
			fullPath = String.copy<GLOBAL_STACK>(fullPath);
			entry.path = fullPath;
		});
}

void InitWebApps()
{
	WebAppGlobalsPtr = &StackAlloc<WEBAPP_GLOBALS, GLOBAL_STACK>();
	DBGBREAK();
	InitDownloadCache();
	CssInitialize();
	//ParseWebsite("nytimes", "https://www.nytimes.com/");
}

void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, WEBSITE_PARSER& parser)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	processorInfo.appStack = &parser.stack;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = &schedulerStack;
}

void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, HTTP_CLIENT<WEBSITE_PARSER>& httpClient)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	processorInfo.appStack = &httpClient.context.stack;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = &schedulerStack;
}
