// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once
#include "Types.h"

constexpr USTRING RTSP_UA = "MediaSwitch V0.4";

template <typename CONTEXT>
struct RTSP_SESSION
{
	TCP_SOCKET<RTSP_SESSION> socket;
	URL_INFO connectUrl;
	UINT32 cSeqNo = 0;
	STASK requestCompletionTask;
	STASK redirectTask;
	SCHEDULER_INFO<RTSP_SESSION> scheduler;
	SESSION_STACK stack;
	CONTEXT& context;
	SDP_STREAM sdpStream;

	TOKEN authType;
	STREAM_BUILDER<UINT8, SESSION_STACK, 64> authA1;
	STREAM_BUILDER<UINT8, SESSION_STACK, 64> authA2;
	BCRYPT_ALG_HANDLE authAlgortithm;
	UINT32 authHashLength;
	STREAM_BUILDER<UINT8, SESSION_STACK, 64> authNonce;
	STREAM_BUILDER<UINT8, SESSION_STACK, 64> authCnonce;
	STREAM_BUILDER<UINT8, SESSION_STACK, 64> authRealm;
	STREAM_BUILDER<UINT8, SESSION_STACK, 64> authOpaque;
	UINT32 authNC;

	STREAM_BUILDER<UINT8, SESSION_STACK, 64> sessionId;
	STREAM_BUILDER<UINT8, SESSION_STACK, 2048> socketSendStream;
	STREAM_BUILDER<UINT8, SESSION_STACK, 2048> socketRecvStream;

	RTSP_SESSION(CONTEXT& contextArg) : socket(*this), scheduler(*this), context(contextArg)
	{
		scheduler.initialize();
		InitializeStack(stack, 2 * 1024 * 1024, 0);
	}

	auto& getScheduler() { return scheduler; }

	NTSTATUS sendMessage(BUFFER sendData, STASK onComplete)
	{
		requestCompletionTask = onComplete;
		return socket.send(sendData, STASK());
	}

	void handleSetupAudioResponse(USTRING headers, USTRING body)
	{
		UNREFERENCED_PARAMETER(headers);
		UNREFERENCED_PARAMETER(body);
	}

	void handleSetupVideoResponse(USTRING headers, USTRING body)
	{
		UNREFERENCED_PARAMETER(body);
		do
		{
			ASSERT(Http.getStatus(headers) == HTTP_200);

			auto session = Http.findHeader(headers, RTSP_Session);
			ASSERT(session);
			sessionId.writeStream(session);

			auto audioData = Sdp.findSdpStream(SDP_audio, sdpStream.toBuffer());
			if (!audioData)
				break;

			auto controlData = Sdp.findSdpStream(SDP_control, audioData);
			if (!controlData)
				break;

			auto trackIndex = controlData.findIndex(SDP_trackId);
			if (trackIndex == -1)
				break;

			auto trackId = (UINT32)GetNumberHandleValue(controlData.at(trackIndex + 1));
			
			initMessage(socketSendStream, RTSP_SETUP, TSTRING_BUILDER().writeMany("/trackId=", trackId));
			socketSendStream.writeMany("Session: ", session, CRLF);
			socketSendStream.writeMany("Require: play.basic", CRLF);
			socketSendStream.writeMany("Accept-Ranges: npt, smpte, clock", CRLF);
			socketSendStream.writeString(CRLF);

			sendMessage(socketSendStream.toBuffer(), STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
				{
					auto& session = *(RTSP_SESSION*)context;
					if (NT_SUCCESS(status))
					{
						auto headers = argv.read<USTRING>();
						auto body = argv.read<USTRING>();

						session.handleSetupAudioResponse(headers, body);
					}
				}, this));

		} while (false);
	}

	void setupVideo(TOKEN_BUFFER sdpStream, TOKEN_BUFFER videoStream)
	{
		UNREFERENCED_PARAMETER(sdpStream);
		UNREFERENCED_PARAMETER(videoStream);

		do
		{
			auto controlData = Sdp.findSdpStream(SDP_control, videoStream);
			if (!controlData)
				break;

			auto trackIndex = controlData.findIndex(SDP_trackId);
			if (trackIndex == -1)
				break;

			auto trackId = (UINT32)GetNumberHandleValue(controlData.at(trackIndex + 1));

			initMessage(socketSendStream, RTSP_SETUP, TSTRING_BUILDER().writeMany("/trackId=", trackId));
			socketSendStream.writeMany("Require: play.basic", CRLF);
			socketSendStream.writeMany("Accept-Ranges: npt, smpte, clock", CRLF);
			socketSendStream.writeString(CRLF);

			sendMessage(socketSendStream.toBuffer(), STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
				{
					auto& session = *(RTSP_SESSION*)context;
					if (NT_SUCCESS(status))
					{
						auto headers = argv.read<USTRING>();
						auto body = argv.read<USTRING>();

						session.handleSetupVideoResponse(headers, body);
					}
				}, this));
		} while (false);
	}

	template <typename STREAM>
	void getAuthResponse(TOKEN method, STREAM&& messageStream)
	{
		do
		{
			if (!(authType == HTTP_Basic || authType == HTTP_Digest))
				break;

			if (!(connectUrl.username || authNonce.count() == 0))
				break;

			TSTRING_BUILDER outStream;
			if (authType == HTTP_Basic)
			{
				outStream.writeMany(connectUrl.username, ":", connectUrl.password);
				messageStream.writeString("Authorization: Basic ");
				messageStream.encodeBase64(outStream.toBuffer());
				messageStream.writeString(CRLF);
			}
			else
			{
				outStream.writeMany(connectUrl.username, ":", authRealm.toBuffer(), ":", connectUrl.password);

				auto status = BCryptHash(authAlgortithm, nullptr, 0, outStream.address(), outStream.count(), authA1.commit(authHashLength), authHashLength);
				ASSERT(NT_SUCCESS(status));

				outStream.clear();
				outStream.writeMany(method, ":/", connectUrl.path);
				status = BCryptHash(authAlgortithm, nullptr, 0, outStream.address(), outStream.count(), authA2.commit(authHashLength), authHashLength);
				ASSERT(NT_SUCCESS(status));

				outStream.clear();
				outStream.writeHexString(authA1.toBuffer());
				outStream.writeMany(":", authNonce.toBuffer(), ":");
				outStream.writeString(++authNC, 16, 8);
				outStream.writeMany(":", authCnonce.toBuffer(), ":", HTTP_auth, ":");
				outStream.writeHexString(authA2.toBuffer());

				LOCAL_STREAM<SHA256_HASH_LENGTH> hashOutput;
				status = BCryptHash(authAlgortithm, nullptr, 0, outStream.address(), outStream.count(), hashOutput.commit(authHashLength), authHashLength);
				ASSERT(NT_SUCCESS(status));

				messageStream.writeMany("Authorization: Digest username=\"", connectUrl.username, "\", ");
				messageStream.writeMany("realm=\"", authRealm.toBuffer(), "\", ");
				messageStream.writeMany("uri=\"", connectUrl.path, "\", ");
				messageStream.writeMany("algorithm=\"", authAlgortithm == Algorithms.md5 ? HTTP_MD5 : HTTP_SHA_256, "\", ");
				messageStream.writeMany("nonce=\"", authNonce.toBuffer(), "\", ");
				messageStream.writeString("nc=\"");
				messageStream.writeString(authNC, 16, 8);
				messageStream.writeString("\", ");
				messageStream.writeMany("cnonce=\"", authCnonce.toBuffer(), "\", ");
				messageStream.writeMany("qop=\"", "auth\", ");
				messageStream.writeMany("response=\"");
				messageStream.writeHexString(hashOutput.toBuffer());
				messageStream.writeString( "\", ");
				messageStream.writeMany("opaque=\"", authOpaque.toBuffer(), "\"", CRLF);
			}
		} while (false);
	}

	void addAuthentication(USTRING headers)
	{
		auto authString = Http.findHeader(headers, HTTP_WWW_Authenticate);
		ASSERT(authString);

		Http.parseHeaderValuePairs(headers, [](USTRING nameString, USTRING value, RTSP_SESSION<CONTEXT>& session)
			{
				if (auto name = FindName(nameString))
				{
					if (name == HTTP_Basic || HTTP_Digest)
					{
						session.authType = name;
					}
					else if (name == HTTP_realm)
					{
						session.authRealm.writeStream(value);
					}
					else if (name == HTTP_algorithm)
					{
						session.authAlgortithm = name == HTTP_MD5 ? Algorithms.md5 : Algorithms.hashSha256;
						session.authHashLength = name == HTTP_MD5 ? MD5_HASH_LENGTH : SHA256_HASH_LENGTH;
					}
					else if (name == HTTP_nonce)
					{
						session.authNonce.writeStream(value);
						LOCAL_STREAM<32> randomData;
						Random.generateRandom(randomData, 32);
						session.authCnonce.writeHexString(randomData.toBuffer());

					}
					else if (name == HTTP_qop)
					{
						ASSERT(name == HTTP_auth);
					}
					else if (name == HTTP_opaque)
					{
						session.authOpaque.writeStream(value);
					}
					else DBGBREAK();
				}
			}, *this);
	}

	template <typename TASK>
	void redirect(USTRING headers, TASK&& task)
	{
		redirectTask = task;
		auto urlText = Http.findHeader(headers, RTSP_Location);
		socket.close(STASK([](PVOID context, NTSTATUS, STASK_PARAMS argv)
			{
				auto& session = *(RTSP_SESSION<CONTEXT>*)context;
				auto urlText = argv.read<USTRING>();
				session.connect(urlText);
			}, this, urlText));
	}

	bool isRedirect(TOKEN status) { return status == RTSP_301 || status == RTSP_302 || status == RTSP_303 || status == RTSP_305; }

	void handleDescribeResponse(USTRING headers, USTRING body)
	{
		auto status = Http.getStatus(headers);
		if (isRedirect(status))
		{
			redirect(headers, STASK([](PVOID context, NTSTATUS, STASK_PARAMS)
				{
					auto& session = *(RTSP_SESSION<CONTEXT>*)context;
					session.sendDescribe();
				}, this));
		}
		else if (status == RTSP_401)
		{

		}
		else
		{
			Sdp.parseSdp(body, sdpStream);

			auto video = Sdp.findSdpStream(SDP_video, sdpStream.toBuffer());
			if (video)
			{
				setupVideo(sdpStream.toBuffer(), video);
			}
		}
	}

	template <typename STREAM>
	void initMessage(STREAM&& messageStream, TOKEN method, USTRING pathExt = NULL_STRING)
	{
		messageStream.clear();
		messageStream.writeMany(method, " rtsp://", connectUrl.hostname, "/", connectUrl.path, pathExt, " RTSP/1.0", CRLF);
		messageStream.writeMany("CSeq: ", ++cSeqNo, CRLF);
		messageStream.writeMany("User-Agent: ", RTSP_UA, CRLF);
		getAuthResponse(method, messageStream);
	}

	void sendDescribe()
	{
		initMessage(socketSendStream, RTSP_DESCRIBE);
		socketSendStream.writeMany("Accept: ", "application/sdp", CRLF);
		socketSendStream.writeString(CRLF);
		
		sendMessage(socketSendStream.toBuffer(), STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
			{
				auto& session = *(RTSP_SESSION*)context;
				if (NT_SUCCESS(status))
				{
					auto headers = argv.read<USTRING>();
					auto body = argv.read<USTRING>();

					session.handleDescribeResponse(headers, body);
				}
			}, this));
	}

	void onConnect()
	{
		if (redirectTask)
		{
			requestCompletionTask.run();
		}
		else
		{
			sendDescribe();
		}
	}

	void onDescribe(USTRING headers, USTRING body)
	{
		UNREFERENCED_PARAMETER(headers);
		UNREFERENCED_PARAMETER(body);
	}

	void parseMessage(USTRING headers, USTRING body)
	{
		if (Http.isRequest(headers))
		{
			auto method = Http.getMethod(headers);
			UNREFERENCED_PARAMETER(method);

			if (method == RTSP_DESCRIBE)
			{
				onDescribe(headers, body);
			}
		}
		else
		{
			requestCompletionTask.AddArg(headers, body);
			requestCompletionTask.run();
			//ASSERT(requestTaskId != INVALID_TASKID);
			//auto status = Http.getStatus(headers);

			//scheduler.updateTask(requestTaskId, STATUS_SUCCESS, headers, body);
		}
	}

	void onReceive(BUFFER recvData)
	{
		socketRecvStream.writeStream(recvData);
		auto messageData = socketRecvStream.toBuffer();

		auto headers = String.splitStringIf(messageData, CRLF_CRLF);
		if (headers)
		{
			auto headerValue = Http.findHeader(headers, RTSP_Content_Length);
			UINT32 contentLength = headerValue ? String.toNumber(headerValue) : 0;

			if (contentLength == 0 || messageData.length() >= contentLength)
			{
				auto body = messageData.readBytes(contentLength);
				parseMessage(headers, body);

				socketRecvStream.remove(0, messageData.getPosition());
			}
		}
	}

	void connect(USTRING urlText)
	{
		String.parseUrl<SESSION_STACK>(urlText, connectUrl);
		socket.connect(connectUrl, STASK([](PVOID context, NTSTATUS status, STASK_PARAMS argv)
			{
				UNREFERENCED_PARAMETER(status);
				UNREFERENCED_PARAMETER(argv);
				auto& session = *(RTSP_SESSION<RTSP_SERVICE>*)context;
				session.onConnect();
			}, this));
	}

	void onClose()
	{

	}
};

struct RTSP_SERVICE
{
	SERVICE_STACK stack;

	RTSP_SERVICE()
	{
		InitializeStack(stack, 2 * 1024 * 1024, 0);
	}

	void startClient(USTRING url)
	{
		auto& rtspSession = StackAlloc<RTSP_SESSION<RTSP_SERVICE>, SESSION_STACK>(*this);
		rtspSession.connect(url);
	}
};