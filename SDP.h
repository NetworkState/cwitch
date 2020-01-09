// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once

enum class ICE_TYPE : UINT8
{
	UNKNOWN = 0,
	HOST = 126,
	PEER_REFLX = 110,
	SERVER_REFLX = 100,
	RELAYED = 0,
};

constexpr UINT32 LOCAL_PREFERENCE = 65535;
constexpr UINT32 COMPONENT_ID = 1;

struct ICE_CANDIDATE
{
	ICE_TYPE type = ICE_TYPE::UNKNOWN;
	SOCKADDR_IN candidate = { AF_INET, 0 };
	SOCKADDR_IN base = { AF_INET, 0 };
	UINT64 foundation = 0;
	UINT32 priority = 0;

	ICE_CANDIDATE(SOCKADDR_IN candidateArg)
	{
		type = ICE_TYPE::HOST;
		candidate = candidateArg;
		foundation = ((UINT64)type << 32) | candidate.sin_addr.s_addr;;
		priority = ((UINT32)type << 24) | LOCAL_PREFERENCE << 8 | (256 - COMPONENT_ID); // RFC8445 5.1.2.1
	}

	ICE_CANDIDATE(ICE_TYPE typeArg, SOCKADDR_IN candidateArg, SOCKADDR_IN baseArg, UINT64 foundationArg, UINT32 priorityArg)
	{
		type = typeArg;
		base = baseArg;
		candidate = candidateArg;

		foundation = foundationArg;
		priority = priorityArg;
	}

	constexpr explicit operator bool() const { return IsValidRef(*this); }
};

struct SDP_LINE
{
	TOKEN name;
	TSTREAM_BUILDER<USTRING, 16> params;

	constexpr explicit operator bool() const { return IsValidRef(*this); }
};
constexpr TOKEN SDP_KEYWORDS[] = {
	SDP_video, SDP_audio, SDP_application, SDP_group, SDP_rtcp, SDP_ice_ufrag, SDP_ice_pwd, SDP_ice_options,
	SDP_extmap, SDP_rtcp_mux, SDP_rtpmap, SDP_rtcp_fb, SDP_fmtp, SDP_ssrc, SDP_setup, SDP_mid,
	SDP_msid, SDP_ssrc_group, SDP_msid_semantic, SDP_BUNDLE, SDP_fingerprint, SDP_sendrecv, SDP_rtcp_rsize, SDP_codec,
	SDP_sctpmap, SDP_rtx, SDP_candidate, SDP_end_of_candidates, SDP_controlled };

constexpr INT32 SdpKeywordIndex(TOKEN keyword)
{
	auto result = ArrayFind(SDP_KEYWORDS, keyword);
	ASSERT(result != -1);
	return result;
}

constexpr TOKEN SdpKeyword(UINT8 index)
{
	ASSERT(index < ARRAYSIZE(SDP_KEYWORDS));
	return SDP_KEYWORDS[index];
}

constexpr bool IsSdpKeyword(TOKEN name)
{
	return SdpKeywordIndex(name) != -1;
}
using SDP_STREAM = STREAM_BUILDER<TOKEN, SESSION_STACK, 16>;
using SDP_BUFFER = STREAM_READER<const TOKEN>;

struct SDP_OPS
{
	template <typename STREAM>
	UINT32 writeKeyword(STREAM&& outStream, TOKEN name)
	{
		auto offset = outStream.count();
		outStream.append(TOKEN(TOKENTYPE::STOKEN_SDP, (UINT8)SdpKeywordIndex(name), 0));
		return offset;
	}

	template <typename STREAM>
	void writeLength(STREAM&& outStream, UINT32 offset)
	{
		auto&& token = outStream.at(offset);
		auto length = outStream.count() - offset;
		if (length > 1)
		{
			token.setLength(length);
		}
		else
		{
			DBGBREAK();
			outStream.trim();
		}
	}

	template <typename STREAM, typename ... Args>
	void writeSdpStream(STREAM&& outStream, TOKEN keyName, Args&& ... args)
	{
		auto lengthOffset = writeKeyword(outStream, keyName);
		int dummy[] = { (outStream.write(args), 0) ... }; dummy;
		writeLength(outStream, lengthOffset);
	}

	template <typename STREAM, typename T>
	void writeSdpStream(STREAM&& outStream, TOKEN name, STREAM_READER<T> args)
	{
		auto lengthOffset = writeKeyword(outStream, name);
		for (auto& string : args)
		{
			outStream.write(CreateCustomName<SERVICE_STACK>(string));
		}
		writeLength(outStream, lengthOffset);
	}

	TOKEN parseSdpLine(USTRING line, SDP_LINE& sdpLine, UINT8 type = 0)
	{
		sdpLine.name = NULL_NAME;
		sdpLine.params.clear();

		if (type == 0)
		{
			type = line.shift();
			ASSERT(line.shift() == '=');
		}
		auto params = String.splitCharToArray(line, " ", sdpLine.params);

		if (type == 'm')
		{
			auto mtype = params.shift();
			if (mtype == "audio")
				sdpLine.name = SDP_audio;
			else if (mtype == "video")
				sdpLine.name = SDP_video;
			else if (mtype == "application")
				sdpLine.name = SDP_application;
			else DBGBREAK();
		}
		else if (type == 'a')
		{
			auto nameString = String.splitChar(params.at(0), ':');
			auto name = FindName(nameString);

			if (IsSdpKeyword(name))
				sdpLine.name = name;
		}
		return sdpLine.name;
	}

	bool isMediaLine(SDP_LINE& line)
	{
		return line.name == SDP_video || line.name == SDP_audio || line.name == SDP_application;
	}

	const SDP_LINE& findSdpLine(STREAM_READER<SDP_LINE> sdpLines, TOKEN name)
	{
		for (auto& line : sdpLines)
		{
			if (line.name == name)
				return line;
		}
		return NullRef<SDP_LINE>();
	}

	template <typename F, typename ... Args>
	void findSdpLine(STREAM_READER<SDP_LINE> sdpLines, TOKEN name, F func, Args&& ... args)
	{
		for (auto& line : sdpLines)
		{
			if (line.name == name)
				func(line, args ...);
		}
	}

	template <typename SDP>
	TOKEN_BUFFER findSdpStream(TOKEN name, SDP&& tokenStream)
	{
		TOKEN_BUFFER result;
		auto keyword = SdpKeywordIndex(name);
		ASSERT(keyword != -1);
		while (tokenStream)
		{
			auto token = tokenStream.at(0);
			if (token.getSdpName() == name)
			{
				tokenStream.shift();
				ASSERT(token.getLength() > 1);
				auto length = token.getLength() - 1;
				result = TOKEN_BUFFER(tokenStream.data(), length);
				tokenStream.shift(length);
				break;
			}
			else tokenStream.shift(token.getLength());
		}
		return result;
	}

	template <typename STREAM>
	void addExtmap(STREAM&& extmapStream, TOKEN id, TOKEN url)
	{
		auto buffer = extmapStream.toBuffer();
		auto exists = false;
		for (UINT32 i = 0; i < buffer.length(); i += 2)
		{
			if (buffer.at(i) == id)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			extmapStream.append(id);
			extmapStream.append(url);
		}
	}

	template <typename EXTMAP, typename SDPSTREAM>
	void parseSdp(STREAM_READER<SDP_LINE> sdpLines, EXTMAP&& extmapStream, SDPSTREAM&& sdpStream)
	{
		auto sdpLinesCopy = sdpLines;
		auto&& firstLine = sdpLines.at(0);
		TSTREAM_BUILDER<TOKEN, 4> ssrcStream;

		if (isMediaLine(firstLine))
		{
			sdpLines.shift();
			auto ssrcLength = writeKeyword(ssrcStream, SDP_ssrc);
			findSdpLine(sdpLines, SDP_ssrc, [](const SDP_LINE& sdpLine, TSTREAM_BUILDER<TOKEN, 4>& ssrcStream)
				{
					auto value = String.toNumber(sdpLine.params.at(0));
					auto handle = CreateNumberHandle<SESSION_STACK>(value);
					if (ssrcStream.toBuffer().exists(handle) == false)
					{
						ssrcStream.write(handle);
					}
				}, ssrcStream);
			writeLength(ssrcStream, ssrcLength);
		}

		while (sdpLines)
		{
			auto&& sdp = sdpLines.shift();
			auto params = sdp.params.toBuffer();
			auto name = sdp.name;

			if (name == SDP_extmap)
			{
				auto id = CreateNumberHandle<SESSION_STACK>(String.toNumber(params.shift()));
				auto url = FindName(params.shift());
				ASSERT(url);
				addExtmap(extmapStream, id, url);
			}
			else if (name == SDP_group)
			{
				if (params.shift() == "BUNDLE")
				{
					writeSdpStream(sdpStream, SDP_BUNDLE, params);
				}
				else DBGBREAK();
			}
			else if (name == SDP_rtpmap)
			{
				TOKEN currentMid = NULL_NAME;
				auto packetType = String.toNumber(params.shift());
				auto codecString = params.shift();

				auto codecParams = String.splitCharToArray(codecString, "/", TSTREAM_BUILDER<USTRING, 4>());
				auto codecType = codecParams.at(0);

				if (codecType == "opus" || codecType == "H264")
				{
					if (auto&& midLine = findSdpLine(sdpLinesCopy, SDP_mid))
					{
						auto bundleConfig = findSdpStream(SDP_BUNDLE, sdpStream.toBuffer());
						ASSERT(bundleConfig);
						currentMid = CreateCustomName<SERVICE_STACK>(midLine.params.at(0));
						if (currentMid == bundleConfig.at(0))
						{
							if (auto&& iceLine = findSdpLine(sdpLinesCopy, SDP_ice_ufrag))
							{
								//if (context.remoteIceUfrag.count() == 0) // XXX move this logic to WebRTC code
								//	context.remoteIceUfrag.writeStream(iceLine.params.at(0));

								writeSdpStream(sdpStream, SDP_ice_ufrag, CreateCustomName<SERVICE_STACK>(iceLine.params.at(0)));
							}
							if (auto&& iceLine = findSdpLine(sdpLinesCopy, SDP_ice_pwd))
							{
								//if (context.remoteIcePassword.count() == 0) // XXX move this logic to WebRTC code
								//	context.remoteIcePassword.writeStream(iceLine.params.at(0));

								writeSdpStream(sdpStream, SDP_ice_pwd, CreateCustomName<SERVICE_STACK>(iceLine.params.at(0)));
							}
							if (auto&& fingerprint = findSdpLine(sdpLinesCopy, SDP_fingerprint))
							{
								TBUFFER_BUILDER<64> hexString;
								auto&& inputString = fingerprint.params.at(1);
								while (inputString)
								{
									hexString.readHexString(String.splitChar(inputString, ':'));
								}
								writeSdpStream(sdpStream, SDP_fingerprint, String.parseLiteral<SERVICE_STACK>(fingerprint.params.at(0)),
									String.parseLiteral<SERVICE_STACK>(hexString.toBuffer()));
							}
						}
					}

					auto mediaLength = writeKeyword(sdpStream, firstLine.name); // SDP_VIDEO or SDP_AUDIO

					writeSdpStream(sdpStream, SDP_mid, currentMid);
					writeSdpStream(sdpStream, SDP_rtpmap, CreateNumberHandle<SESSION_STACK>(packetType));
					writeSdpStream(sdpStream, SDP_codec, codecParams);

					sdpStream.writeStream(ssrcStream.toBuffer());

					auto rtcpLength = writeKeyword(sdpStream, SDP_rtcp_fb);
					findSdpLine(sdpLines, SDP_rtcp_fb, [](const SDP_LINE& sdpLine, SDP_STREAM& config, UINT32 packetType)
						{
							auto params = sdpLine.params.toBuffer();
							auto typeString = params.shift();
							if (String.toNumber(typeString) == (INT32)packetType)
							{
								auto&& type1 = params.shift();
								auto&& type2 = params ? params.shift() : "";

								auto typeName = NULL_NAME;
								if (type1 == "nack")
								{
									typeName = SDP_nack;
									if (type2 == "pli") typeName = SDP_nack_pli;
									else if (type2 == "sli") typeName = SDP_nack_sli;
									else if (type2 == "rpsi") typeName = SDP_nack_rpsi;
									else if (type2) DBGBREAK();
								}
								else if (type1 == "ccm")
								{
									if (type2 == "fir") typeName = SDP_ccm_fir;
									else if (type2 == "tmmbr") typeName = SDP_ccm_tmmbr;
									else if (type2 == "tstr") typeName = SDP_ccm_tstr;
									else DBGBREAK();
								}
								else
								{
									typeName = CreateCustomName<SERVICE_STACK>(type1);
								}
								config.append(typeName);
							}
						}, sdpStream, packetType);
					writeLength(sdpStream, rtcpLength);

					findSdpLine(sdpLines, SDP_fmtp, [](const SDP_LINE& sdpLine, SDP_STREAM& config, UINT32 packetType)
						{
							auto params = sdpLine.params.toBuffer();
							auto fmtpType = String.toNumber(params.shift());
							auto pairsString = params.shift();
							if (fmtpType == (INT32)packetType)
							{
								auto fmtpLength = Sdp.writeKeyword(config, SDP_fmtp);
								while (pairsString)
								{
									auto&& pair = String.splitChar(pairsString, ';');
									auto&& pairName = String.splitChar(pair, '=');

									config.append(CreateCustomName<SERVICE_STACK>(pairName));
									auto value = String.toHexNumber(pair);
									config.append(CreateNumberHandle<SESSION_STACK>(value));
								}
								Sdp.writeLength(config, fmtpLength);
							}
							else
							{
								while (pairsString)
								{
									auto&& pair = String.splitChar(pairsString, ';');
									auto&& pairName = String.splitChar(pair, '=');

									if (pairName == "apt")
									{
										if (String.toNumber(pair) == (INT32)packetType)
										{
											Sdp.writeSdpStream(config, SDP_rtx, CreateNumberHandle<SESSION_STACK>(fmtpType));
										}
									}
								}
							}
						}, sdpStream, packetType);

					writeLength(sdpStream, mediaLength);
				}
			}
			else if (name == SDP_candidate)
			{
				parseIceCandidate(sdp);
			}
			else if (name == SDP_control) 
			{
				auto lengthOffset = writeKeyword(sdpStream, SDP_control);
				auto pairsString = params.shift();
				while (pairsString)
				{
					auto&& pair = String.splitChar(pairsString, ';');
					auto&& pairName = String.splitChar(pair, '=');

					sdpStream.append(CreateCustomName<SERVICE_STACK>(pairName));

					if (pair)
					{
						auto value = String.toHexNumber(pair);
						sdpStream.append(CreateNumberHandle<SESSION_STACK>(value));
					}
					else
					{
						sdpStream.append(Null);
					}
				}
				writeLength(sdpStream, lengthOffset);
			}
		}
	}

	template <typename STREAM>
	void parseSdp(USTRING sdpString, STREAM&& sdpStream)
	{
		TSTREAM_BUILDER<TOKEN, 16> extmapStream;
		TSTREAM_BUILDER<SDP_LINE, 64> sdpLines;
		sdpStream.clear();
		while (sdpString)
		{
			SDP_LINE sdpLine;
			auto line = String.splitString(sdpString, CRLF);
			if (line)
			{
				parseSdpLine(line, sdpLine);
				if (sdpLine.name)
				{
					if (isMediaLine(sdpLine))
					{
						parseSdp(sdpLines.toBufferNoConst(), extmapStream, sdpStream);
						sdpLines.clear().write(sdpLine);
					}
					else
					{
						sdpLines.write(sdpLine);
					}
				}
			}
		}
		parseSdp(sdpLines.toBufferNoConst(), extmapStream, sdpStream);
		auto lengthOffset = writeKeyword(sdpStream, SDP_extmap);
		sdpStream.writeStream(extmapStream.toBuffer());
		writeLength(sdpStream, lengthOffset);
	}

	template <typename BUFFER>
	TOKEN_BUFFER getSdp(BUFFER&& configStream, TOKEN name)
	{
		TOKEN_BUFFER result;
		for (UINT32 i = 0; i < configStream.length(); i++)
		{
			auto token = configStream.at(i);
			if (token.isSdp() && token.getSdpName() == name)
			{
				result = TOKEN_BUFFER(configStream.data(), i, token.getLength() - 1);
			}
		}
		return result;
	}

	template <typename STREAM>
	USTRING formatIceCandidate(STREAM& outString, const ICE_CANDIDATE& candidate)
	{
		auto streamOffset = outString.getPosition();
		outString.writeMany("a=candidate:", candidate.foundation, " ", COMPONENT_ID, " udp ", candidate.priority, " ");
		auto addrString = String.formatIPAddress(candidate.candidate, outString);
		LogInfo("formatIce: address: ");
		addrString.print();
		outString.writeMany(" ", HTONS(candidate.candidate.sin_port), " typ ",
			candidate.type == ICE_TYPE::HOST ? "host" :
			candidate.type == ICE_TYPE::SERVER_REFLX ? "srflx" : "prflx");

		if (candidate.type == ICE_TYPE::SERVER_REFLX || candidate.type == ICE_TYPE::PEER_REFLX)
		{
			outString.writeString(" raddr ");
			String.formatIPAddress(candidate.base, outString);
			outString.writeMany(" rport ", HTONS(candidate.base.sin_port));
		}
		outString.writeString(ESC_CRLF);
		return streamOffset.toBuffer();
	}

	ICE_CANDIDATE parseIceCandidate(SDP_LINE& sdpLine)
	{
		// candidate:3328707334 1 udp 2113937151 172.18.10.126 53478 typ host generation 0 ufrag wzJ+ network-cost 999
		auto&& parts = sdpLine.params.toBuffer();

		auto foundation = String.toNumber(parts.shift());
		auto componentId = String.toNumber(parts.shift());
		ASSERT(componentId == 1);

		auto protocol = parts.shift();
		ASSERT(protocol == "udp");

		auto priority = String.toNumber(parts.shift());

		SOCKADDR_IN candidate;
		auto ipAddress = String.parseIPAddress(parts.shift());
		candidate.sin_addr.s_addr = HTONL(ipAddress);

		auto port = (UINT16)String.toNumber(parts.shift());
		candidate.sin_port = HTONS(port);

		parts.shift();
		auto typeString = parts.shift();

		auto type = typeString == "host" ? ICE_TYPE::HOST
			: typeString == "srflx" ? ICE_TYPE::SERVER_REFLX
			: ICE_TYPE::PEER_REFLX;

		SOCKADDR_IN base = { AF_INET, 0 };
		if (parts)
		{
			// wrong, handles prefix raddr, rport and such.
			auto ipAddress = String.parseIPAddress(parts.shift());
			base.sin_addr.s_addr = HTONL(ipAddress);

			auto port = (UINT16)String.toNumber(parts.shift());
			base.sin_port = HTONS(port);
		}

		return ICE_CANDIDATE(type, candidate, base, foundation, priority);
	}
};

extern SDP_OPS Sdp;
