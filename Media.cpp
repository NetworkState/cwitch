// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#include "pch.h"
#include "Types.h"
#include "Signaling.h"
#include "Webrtc.h"
#include "MkvParser.h"

struct CACHE_CONTENT
{
	USTRING filename;
	USTRING fileContent;
	TOKEN contentType;

	bool match(USTRING name) const { return filename == name; }
	constexpr explicit operator bool() const { return IsValidRef(*this); }
};

auto SERVER_CERTIFICATE =
"MIICRzCCAe2gAwIBAgIURuwRzHE2YdcGgxqEVHCUqhm1t0wwCgYIKoZIzj0EAwIw"
"XDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdQdWxsbWFuMRYw"
"FAYDVQQKDA1OZXR3b3JrIFN0YXRlMRYwFAYDVQQDDA1OZXR3b3JrIFN0YXRlMB4X"
"DTE5MDYxMDE2MTExN1oXDTIyMDMwNjE2MTExN1oweTELMAkGA1UEBhMCVVMxCzAJ"
"BgNVBAgMAk1EMRAwDgYDVQQHDAdQdWxsbWFuMRYwFAYDVQQKDA1OZXR3b3JrIFN0"
"YXRlMRIwEAYDVQQDDAltZWRpYXNydjExHzAdBgkqhkiG9w0BCQEWEHRlc3RAZXhh"
"bXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATpOMmO4ROs0waD6ESO"
"XZmMZRGKedUaYq8vnci5YChiQpkKQOBOfkbL/dUaWy4K/0qP8cPnKw5LZX0F4Mdj"
"glzUo3AwbjAdBgNVHQ4EFgQU6wK3rm/rSZO2PsePNJ9LWovpsXAwHwYDVR0jBBgw"
"FoAUnzurX5pboo6FoKNFaJh/huLJUt4wCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAw"
"FAYDVR0RBA0wC4IJbWVkaWFzcnYxMAoGCCqGSM49BAMCA0gAMEUCIQDlnWYSwOrn"
"6UYVF7To+ut11d9p3/Eos9vOAiwCtlupYwIgZwzToDyg81QH33Lv4JS3XGkMiUqh"
"vK7ksMzi8xoJ+ho=";

auto SERVER_KEY =
"MHcCAQEEIG3dCF2nFMKDShTNdsKtl2X7t/nGNgCnOKZ3o/59AJsboAoGCCqGSM49"
"AwEHoUQDQgAE6TjJjuETrNMGg+hEjl2ZjGURinnVGmKvL53IuWAoYkKZCkDgTn5G"
"y/3VGlsuCv9Kj/HD5ysOS2V9BeDHY4Jc1A==";

constexpr USTRING HTML_DIRECTORY = "html";
struct MEDIA_SERVICE
{
	struct SESSION_MAP
	{
		BUFFER cookie;
		HTTP_CONNECTION<MEDIA_SERVICE>& connection;
		MEDIA_SESSION<MEDIA_SERVICE>& session;

		SESSION_MAP(BUFFER cookieArg, MEDIA_SESSION<MEDIA_SERVICE>& sessionArg, HTTP_CONNECTION<MEDIA_SERVICE>& connectionArg) 
			: cookie(cookieArg), session(sessionArg), connection(connectionArg) {}

		bool match(BUFFER other) const { return cookie == other; }
		constexpr explicit operator bool() const { return IsValidRef(*this); }
	};

	SERVICE_STACK stack;
	LISTEN_SOCKET<MEDIA_SERVICE, HTTP_CONNECTION<MEDIA_SERVICE>::TLS13_HANDSHAKE> listener;
	SCHEDULER_INFO<MEDIA_SERVICE> scheduler;
	STREAM_BUILDER<UINT8, SERVICE_STACK, 4096> charStream;
	STREAM_BUILDER<CACHE_CONTENT, SERVICE_STACK, 256> htmlCacheStream;
	STREAM_READER<const CACHE_CONTENT> htmlCache;

	CERTIFICATE serverCertificate;
	BCRYPT_KEY_HANDLE certificateKey;
	STREAM_BUILDER<UINT8, SERVICE_STACK, 2048> certificateByteStream;
	BUFFER certificateBytes;
	TOKEN hostname;
	SIGNATURE_SCHEME signatureAlgorithm;

	STREAM_BUILDER<SESSION_MAP, SERVICE_STACK, 16> sessionTable;
	STREAM_READER<const SESSION_MAP> getSessionTable() { return sessionTable.toBuffer(); }

	MEDIA_SERVICE() : listener(*this), scheduler(*this) 
	{
		InitializeStack(stack, 32 * 1024 * 1024, 0);
	}

	auto& getCertificateBytes() { return certificateBytes; }
	auto& getCertificateKey() { return certificateKey; }
	constexpr auto isServer() { return true; }
	constexpr auto isClient() { return false; }
	auto getServerName() { return hostname; }
	auto getSignatureAlgorithm() { return signatureAlgorithm; }

	NTSTATUS initialize()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			status = cacheHtmlFiles(HTML_DIRECTORY);
			VERIFY_STATUS;

			status = scheduler.initialize();
			VERIFY_STATUS;

			certificateByteStream.decodeBase64(SERVER_CERTIFICATE);
			certificateBytes = certificateByteStream.toBuffer();

			ParseX509(certificateBytes, serverCertificate);
			signatureAlgorithm = SIGNATURE_SCHEME::ecdsa_secp256r1_sha256;

			BUFFER_BUILDER byteStream;
			byteStream.decodeBase64(SERVER_KEY);
			ParsePrivateKey(byteStream.toBuffer(), certificateKey);

		} while (false);
		return status;
	}

	void TestECDH()
	{
		LOCAL_STREAM<ECDH_KEY_SIZE> privateKey1;
		LOCAL_STREAM<ECDH_KEY_SIZE*2> publicKey1;

		LOCAL_STREAM<ECDH_KEY_SIZE> privateKey2;
		LOCAL_STREAM<ECDH_KEY_SIZE*2> publicKey2;

		LOCAL_STREAM<ECDH_KEY_SIZE*2> sharedSecret;

		auto status = STATUS_SUCCESS;
		do
		{
			status = ECDH256_GenPrivateKey(privateKey1);
			VERIFY_STATUS;

			status = ECDH256_GetPublicKey(privateKey1.toBuffer(), publicKey1);
			VERIFY_STATUS;

			status = ECDH256_GenPrivateKey(privateKey2);
			VERIFY_STATUS;

			status = ECDH256_GetPublicKey(privateKey2.toBuffer(), publicKey2);
			VERIFY_STATUS;

			status = ECDH256_GetSharedSecret(privateKey1.toBuffer(), publicKey2.toBuffer(), sharedSecret);
			VERIFY_STATUS;

		} while (false);

	}

	NTSTATUS start()
	{
		auto status = STATUS_SUCCESS;
		do
		{
			hostname = CreateCustomName<SERVICE_STACK>("mediasrv1");

			status = listener.listen(TLS_PORT, STASK([](PVOID, NTSTATUS status, STASK_PARAMS)
				{
					ASSERT(NT_SUCCESS(status));
				}, this));
			VERIFY_STATUS;

			// XXX test code, remove it soon!!
			LogInfo("TEST: creating a test session");
			auto&& session = StackAlloc<MEDIA_SESSION<MEDIA_SERVICE>, SERVICE_STACK>(*this); // XXX
			session.initialize(); // XXX

		} while (false);
		return status;
	}

	TOKEN getContentType(USTRING filename)
	{
		auto contentType = HTTP_text_html;
		auto extension = String.splitCharReverse(filename, '.');
		if (extension)
		{
			if (extension == "html")
				contentType = HTTP_text_html;
			else if (extension == "js")
				contentType = HTTP_application_javascript;
			else if (extension == "css")
				contentType = HTTP_text_css;
			else if (extension == "ico")
				contentType == HTTP_image_x_icon;
			else if (extension == "png")
				contentType == HTTP_image_x_png;
			else DBGBREAK();
		}

		return contentType;
	}

	NTSTATUS cacheHtmlFiles(USTRING relativePath)
	{
		auto path = GetTempStream().writeMany(DATA_DIRECTORY, relativePath);
		auto status = ListDirectory(path, USTRING(), [](USTRING relativeName, USTRING fullPath, MEDIA_SERVICE& server)
			{
				auto filename = server.charStream.writeString(relativeName);
				auto contentType = server.getContentType(filename);
				auto fileContent = server.charStream.readFile(fullPath);

				CACHE_CONTENT cache{ filename, fileContent, contentType };
				server.htmlCacheStream.write(cache);

			}, *this);
		htmlCache = htmlCacheStream.toBuffer();
		return status;
	}

	const SESSION_MAP& getSessionMap(HTTP_CONNECTION<MEDIA_SERVICE>& connection)
	{
		if (connection.sessionName)
		{
			return sessionTable.toBuffer().find(connection.sessionName);
		}
		else
		{
			auto&& session = StackAlloc<MEDIA_SESSION<MEDIA_SERVICE>, SERVICE_STACK>(*this);
			session.initialize();

			connection.sessionName = session.cookie.toBuffer();
			return sessionTable.append(session.cookie.toBuffer(), session, connection);
		}
	}
	
	void onSignalingStart(HTTP_CONNECTION<MEDIA_SERVICE>& connection)
	{
		getSessionMap(connection); // create session, if needed.
	}

	void onSignalingReceive(HTTP_CONNECTION<MEDIA_SERVICE>& connection, BUFFER recvData)
	{
		auto&& sessionMap = getSessionMap(connection);
		connection.recvSyncTask = connection.scheduler.queueTask(SIGNALING_RECV_PRIORITY + 1, STASK());
		sessionMap.session.scheduler.runTask(SIGNALING_RECV_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto&& sessionMap = *(SESSION_MAP*)context;
				BUFFER recvData = argv.read<BUFFER>();
				sessionMap.session.onSignalingReceive(recvData);
				sessionMap.connection.scheduler.updateTask(sessionMap.connection.recvSyncTask);
			}, (PVOID)&sessionMap, recvData));
	}

	void sendSignalingData(MEDIA_SESSION<MEDIA_SERVICE>& session, BUFFER sendData)
	{
		auto sessionName = session.cookie.toBuffer();
		if (auto&& entry = sessionTable.toBuffer().find(sessionName))
		{
			entry.connection.sendWebsocketData(sendData, WEBSOCKET_OPCODE::TEXT_FRAME, STASK());
		}
		else DBGBREAK();
	}

	void onRequest(HTTP_CONNECTION<MEDIA_SERVICE>& connection, TOKEN verb, USTRING urlPath, HEADER_TABLE& headers, USTRING content)
	{
		if (urlPath == "/")
		{
			urlPath = "/index.html";
		}
		LogInfo("OnRequest: Url:%s", GetTempStream().writeString(urlPath).toString());

		ASSERT(urlPath.at(0) == '/');
		urlPath.shift();
		auto& mediaSession = getSessionMap(connection);
		UNREFERENCED_PARAMETER(mediaSession);

		if (verb == HTTP_GET)
		{
			auto& contentEntry = this->htmlCache.find(urlPath);
			if (contentEntry)
			{
				connection.sendResponse(HTTP_200, HTTP_OK, contentEntry.contentType, contentEntry.fileContent);
			}
			else
			{
				connection.sendResponse(HTTP_404, HTTP_NOT_FOUND, NULL_NAME, NULL_STRING);
			}
		}
		else if (verb == HTTP_POST)
		{
			auto&& contentFound = headers.find(HTTP_Content_Type);
			auto contentType = contentFound ? FindName(contentFound.value) : NULL_NAME;
			ASSERT(contentType == HTTP_application_json);

			STREAM_BUILDER<TOKEN, SCHEDULER_STACK, 16> jsonStream;
			auto json = ParseJson<SERVICE_STACK>(jsonStream, content);
			connection.sendResponse(HTTP_200, HTTP_OK, NULL_NAME, NULL_STRING);
		}
		else DBGBREAK();
	}

	SCHEDULER_INFO<MEDIA_SERVICE>& getScheduler() { return scheduler; }

	// Not called from a scheduler, outside a synchronization context!
	auto& onNewConnection(PWSK_SOCKET acceptHandle, SOCKADDR_IN* localAddress, SOCKADDR_IN* remoteAddress)
	{
		UNREFERENCED_PARAMETER(localAddress);
		UNREFERENCED_PARAMETER(remoteAddress);
		auto& connection = KernelAlloc<HTTP_CONNECTION<MEDIA_SERVICE>>(*this, acceptHandle);
		getScheduler().runTask(SOCKET_CONTROL_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
			{
				auto& connection = *(HTTP_CONNECTION<MEDIA_SERVICE>*)context;
				connection.start();
			}, &connection));
		return connection.handshake.socket;
	}

	void onClose(HTTP_CONNECTION<MEDIA_SERVICE>* connection)
	{
		LogInfo("Server closing connection, freeing memory");
		ExFreePoolWithTag(connection, POOL_TAG);
	}
};

MEDIA_SERVICE* CurrentServer;

void MediaServer()
{
	auto&& server = KernelAlloc<MEDIA_SERVICE>();
	CurrentServer = &server;

	auto status = server.initialize();
	ASSERT(NT_SUCCESS(status));

	server.getScheduler().runTask(SOCKET_CONTROL_PRIORITY, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
		{
			auto&& server = *(MEDIA_SERVICE*)context;
			server.start();

		}, &server));
}

template<>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, MEDIA_SERVICE& server)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];

	processorInfo.appStack = &server.stack;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = &schedulerStack;
}

void ResetCurrentScheduler()
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];

	processorInfo.schedulerStack->clear();

	processorInfo.appStack = nullptr;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = nullptr;
}

template<>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, MEDIA_SESSION<MEDIA_SERVICE>& connection)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];

	processorInfo.appStack = &connection.server.stack;
	processorInfo.sessionStack = &connection.sessionStack;
	processorInfo.schedulerStack = &schedulerStack;
}

template<>
void SetCurrentScheduler(SCHEDULER_STACK& schedulerStack, HTTP_CONNECTION<MEDIA_SERVICE>& connection)
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];

	processorInfo.appStack = &connection.server.stack;
	processorInfo.sessionStack = nullptr;
	processorInfo.schedulerStack = &schedulerStack;
}

template<>
SCHEDULER_STACK& GetCurrentStack<SCHEDULER_STACK>()
{
	if (KeGetCurrentIrql() == PASSIVE_LEVEL)
	{
		return SystemScheduler().GetCurrentStack();
	}
	else
	{
		auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
		ASSERT(processorInfo.schedulerStack != nullptr);
		return *processorInfo.schedulerStack;
	}
}

template<>
SESSION_STACK& GetCurrentStack<SESSION_STACK>()
{
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	if (processorInfo.sessionStack)
	{
		return *processorInfo.sessionStack;
	}
	else
	{
		DBGBREAK();
		return NullRef<SESSION_STACK>();
	}
}

template<>
SERVICE_STACK& GetCurrentStack<SERVICE_STACK>()
{
	ASSERT(KeGetCurrentIrql() != PASSIVE_LEVEL);
	auto&& processorInfo = ProcessorInfo[KeGetCurrentProcessorNumber()];
	ASSERT(processorInfo.appStack);
	return processorInfo.appStack ? *processorInfo.appStack : NullRef<SERVICE_STACK>();
}
