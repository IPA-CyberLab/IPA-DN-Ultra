// IPA-DN-Ultra Library Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA CYBERLAB, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
// OR OTHER SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY
// KIND OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE IPA CYBERLAB HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// daiyuu.securityreport [at] dnobori.jp
// 
// Thank you for your cooperation.


// WtGate.c
// WideTunnel Gate

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

#define g_show_debug_protocol	false

// WebApp のためのプロキシ (Standalone mode 用)
void WtgHttpProxyForWebApp(WT* wt, SOCK* s, HTTP_HEADER* first_header)
{
	if (wt == NULL || s == NULL || first_header == NULL)
	{
		return;
	}

	// base url
	char base_url[MAX_PATH] = CLEAN;
	StrCpy(base_url, sizeof(base_url), "https://127.0.0.1:7002/");
	URL_DATA url = CLEAN;
	ParseUrl(&url, base_url, false, NULL);

	StrCpy(url.Target, sizeof(url.Target), first_header->Target);

	// ログとる
	char log_prefix[128] = CLEAN;
	Format(log_prefix, sizeof(log_prefix), "ProxyForWebApp/ClientIP=%r/ClientPort=%u/ServerIP=%r/ServerPort=%u", &s->RemoteIP, s->RemotePort, &s->LocalIP, s->LocalPort);

	SOCK* s2 = NULL;

	UINT num = 0;

	while (true)
	{
		HTTP_HEADER* h = NULL;
		if (num == 0)
		{
			h = first_header;
		}
		num++;

		if (h == NULL)
		{
			h = RecvHttpHeader(s, WTG_HTTP_PROXY_FOR_WEBAPP_MAX_HTTP_LINE_SIZE, WTG_HTTP_PROXY_FOR_WEBAPP_MAX_HTTP_LINE_SIZE);
		}

		if (h == NULL)
		{
			break;
		}

		//if (StrCmpi(h->Version, "HTTP/1.1") == 0)
		//{
		//	//Free(h->Version);
		//	//h->Version = CopyStr("HTTP/1.0");
		//}

		DeleteHttpHeaderValue(h, "Accept-Encoding");

		//DebugHttpHeader(h);

		if (StrCmpi(h->Method, "POST") == 0 || StrCmpi(h->Method, "GET") == 0 || StrCmpi(h->Method, "HEAD") == 0)
		{
			// Supported method
			HTTP_HEADER* h2;
			char* http_version = h->Version;
			UINT i;
			bool err = false;
			BUF* post_buf = NULL;
			char original_host[64];

			Zero(original_host, sizeof(original_host));
			Format(original_host, sizeof(original_host), "%r:%u", &s->LocalIP, s->LocalPort);

			if (StrCmpi(h->Method, "POST") == 0)
			{
				// Receive POST data also in the case of POST
				UINT content_len = GetContentLength(h);
				UINT buf_size = 65536;
				UCHAR* buf = Malloc(buf_size);

				content_len = MIN(content_len, WG_PROXY_MAX_POST_SIZE);

				post_buf = NewBuf();

				while (true)
				{
					UINT recvsize = MIN(buf_size, content_len - post_buf->Size);
					UINT size;

					if (recvsize == 0)
					{
						break;
					}

					size = Recv(s, buf, buf_size, true);
					if (size == 0)
					{
						// Disconnected
						break;
					}

					WriteBuf(post_buf, buf, size);
				}

				Free(buf);
			}

			h2 = NewHttpHeaderEx(h->Method, h->Target, h->Version, true);

			// Copy the request header
			for (i = 0;i < LIST_NUM(h->ValueList);i++)
			{
				HTTP_VALUE* v = LIST_DATA(h->ValueList, i);

				if (StartWith(v->Name, "X-Forwarded-") == false)
				{
					if (StrCmpi(v->Name, "HOST") == 0)
					{
						StrCpy(original_host, sizeof(original_host), v->Data);
						AddHttpValue(h2, NewHttpValue(v->Name, url.HeaderHostName));
					}
					else
					{
						AddHttpValue(h2, NewHttpValue(v->Name, v->Data));
					}
				}
			}

			WtLogEx(wt, log_prefix, "Proxying: [https://%s%s] --> [https://%s%s]", original_host, h->Target,
				url.HeaderHostName, h->Target);

			// Add a special header
			if (true)
			{
				char tmp[MAX_SIZE];

				if (IsIP6(&s->RemoteIP))
				{
					Format(tmp, sizeof(tmp), "[%r]:%u", &s->RemoteIP, s->RemotePort);
				}
				else
				{
					Format(tmp, sizeof(tmp), "%r:%u", &s->RemoteIP, s->RemotePort);
				}
				AddHttpValue(h2, NewHttpValue("X-Forwarded-For", tmp));

				AddHttpValue(h2, NewHttpValue("X-Forwarded-Host", original_host));
				AddHttpValue(h2, NewHttpValue("X-Forwarded-Proto", "https"));
			}

			// Connect to the destination server
			if (s2 == NULL)
			{
				WtLogEx(wt, log_prefix, "Connecting to [%s]:%u ...", url.HostName, url.Port);

				s2 = ConnectEx2(url.HostName, url.Port, 0, NULL);

				if (s2 != NULL)
				{
					WtLogEx(wt, log_prefix, "Establishing SSL. StartSSLEx2(): SniString='%s'", url.SniString);
					if (StartSSLEx(s2, NULL, NULL, true, 0, url.SniString) == false)
					{
						WtLogEx(wt, log_prefix, "StartSSLEx2() failed.");
						Disconnect(s2);
						ReleaseSock(s2);
						s2 = NULL;
					}
					else
					{
						WtLogEx(wt, log_prefix, "SSL Established OK.");
					}

					SetTimeout(s2, WG_PROXY_TCP_TIMEOUT_SERVER);
				}
			}

			if (s2 == NULL)
			{
				// Failed to connect to the destination server
				char* text = "--- Thin Telework System Controller Reverse Proxy for HTML5 Web Gateway ---\r\n\r\n"
					"Error: Hello! Failed to connect to the Thin Telework HTML5 Web Gateway server running on [%s]:%u.\r\n"
					"Please make sure that the Thin Telework HTML5 Web Gateway server process is running and its initial configuration is already done correctly.\r\n\r\n"
					"For details please refer to the manual.\r\n\r\nBye bye!\n";

				char tmp[MAX_SIZE] = CLEAN;
				Format(tmp, sizeof(tmp), text, url.HostName, url.Port);
				
				HttpSendBody(s, tmp, StrLen(tmp), "text/plain");
			}
			else
			{
				HTTP_HEADER* r2;

				//DebugHttpHeader(h2);

				// Send a request to the destination server
				WtLogEx(wt, log_prefix, "Sending HTTP request to the server...");
				PostHttpEx(s2, h2, (post_buf == NULL ? NULL : post_buf->Buf), (post_buf == NULL ? 0 : post_buf->Size), false, WTG_HTTP_PROXY_FOR_WEBAPP_MAX_HTTP_LINE_SIZE);

				// Receive a response from the destination server, and transfers to the client
				WtLogEx(wt, log_prefix, "Receinging HTTP response from the server...");
				r2 = RecvHttpHeader(s2, WTG_HTTP_PROXY_FOR_WEBAPP_MAX_HTTP_LINE_SIZE, WTG_HTTP_PROXY_FOR_WEBAPP_MAX_HTTP_LINE_SIZE);
				if (r2 == NULL)
				{
					WtLogEx(wt, log_prefix, "RecvHttpHeader() error.");
					err = true;
				}
				else
				{
					WtLogEx(wt, log_prefix, "HTTP Response: %s %s %s (headers: %u)", r2->Method, r2->Target, r2->Version, LIST_NUM(r2->ValueList));

					//DebugHttpHeader(r2);
					if (PostHttp(s, r2, NULL, 0) == false)
					{
						WtLogEx(wt, log_prefix, "PostHttp() to the client error.");
						err = true;
					}
					else
					{
						if (StrCmpi(h->Method, "HEAD") != 0)
						{
							bool is_chunked = false;
							UINT i;
							for (i = 0;i < LIST_NUM(r2->ValueList);i++)
							{
								HTTP_VALUE* v = LIST_DATA(r2->ValueList, i);
								if (StrCmpi(v->Name, "Transfer-Encoding") == 0)
								{
									if (InStr(v->Data, "chunked"))
									{
										is_chunked = true;
									}
								}
							}

							if (is_chunked == false)
							{
								// 非 Chunk
								UINT content_length = GetContentLength(r2);
								UINT buf_size = 65536;
								UCHAR* buf = Malloc(buf_size);
								UINT pos = 0;

								WtLogEx(wt, log_prefix, "Non-chunked response. content_length = %u", content_length);

								while (pos < content_length)
								{
									UINT r;
									UINT recv_size;

									recv_size = MIN(buf_size, (content_length - pos));

									r = Recv(s2, buf, recv_size, true);

									if (r == 0)
									{
										err = true;
										WtLogEx(wt, log_prefix, "Recv() from the server error.");
										break;
									}

									if (SendAll(s, buf, r, true) == false)
									{
										WtLogEx(wt, log_prefix, "SendAll() to the client error.");
										err = true;
										break;
									}

									pos += r;
								}

								Free(buf);
							}
							else
							{
								WtLogEx(wt, log_prefix, "Chunked response.");

								BUF* chunk_buf = NewBuf();
								UINT chunk_tmp_size = WTG_HTTP_PROXY_INTERNAL_CHUNK_BUFFER_SIZE;
								UCHAR *chunk_tmp = Malloc(chunk_tmp_size);

								UINT total_chunk_contents_size = 0;

								// Chunked
								while (err == false)
								{
									char* size_line = NULL;

									// まず、"16 進数の数字 + \r\n" の 1 行を受信する。
									size_line = RecvLineEx(s2, 64, 64);
									if (size_line == NULL)
									{
										err = true;
										WtLogEx(wt, log_prefix, "RecvLineEx() [size] from the server error.");
										break;
									}

									// 受信したサイズの数字を 16 進数で解釈する
									UINT size_int = HexToInt(size_line);
									Free(size_line);

									// サイズデータをクライアントにそのまま送信する
									char str[64] = CLEAN;
									Format(str, sizeof(str), "%x\r\n", size_int);
									if (SendAll(s, str, StrLen(str), true) == false)
									{
										err = true;
										WtLogEx(wt, log_prefix, "SendAll() [size] to the client error.");
										break;
									}

									if (size_int == 0)
									{
										// すべてのデータが受信完了
										break;
									}

									UINT total_recv_size = 0;

									// size_int の長さに達するまで chunk データを受信し、そのままクライアントに転送する
									while (size_int > total_recv_size)
									{
										UINT recv_size = MIN(chunk_tmp_size, size_int - total_recv_size);
										UINT sz = Recv(s2, chunk_tmp, recv_size, true);
										if (sz == 0)
										{
											// サーバーから切断された
											WtLogEx(wt, log_prefix, "Recv() [data] from the server error.");
											err = true;
											break;
										}

										// 受信したデータをそのままクライアントに送信する
										if (SendAll(s, chunk_tmp, sz, true) == false)
										{
											WtLogEx(wt, log_prefix, "SendAll() [data] to the client error.");
											err = true;
											break;
										}

										total_recv_size += sz;
									}

									if (err)
									{
										break;
									}

									total_chunk_contents_size += total_recv_size;

									// size_int の長さ全部をクライアントに送信完了した。
									// サーバーから 2 バイトを受信する。これは "\r\n" となっているはずである。
									if (RecvAll(s2, chunk_tmp, 2, true) == false)
									{
										err = true;
										break;
									}

									if (Cmp(chunk_tmp, "\r\n", 2) != 0)
									{
										err = true;
										break;
									}

									// この "\r\n" をそのままクライアントに送信する。
									if (SendAll(s, chunk_tmp, 2, true) == false)
									{
										err = true;
										break;
									}
								}

								if (err == false)
								{
									// すべてのチャンクの受信が完了したら、一番最後に単なる改行 "\r\n" が届くはずなので、
									// これをそのままクライアントに送付して完了する。
									if (RecvAll(s2, chunk_tmp, 2, true) == false)
									{
										WtLogEx(wt, log_prefix, "RecvAll() [last_crlf] from the server error.");
										err = true;
										break;
									}

									if (Cmp(chunk_tmp, "\r\n", 2) != 0)
									{
										err = true;
										break;
									}

									// この "\r\n" をそのままクライアントに送信する。
									if (SendAll(s, chunk_tmp, 2, true) == false)
									{
										WtLogEx(wt, log_prefix, "SendAll() [last_crlf] to the server error.");
										err = true;
										break;
									}

									// 完了ログ
									WtLogEx(wt, log_prefix, "Tranfer all chunked data to the client OK. total_chunk_contents_size = %u", total_chunk_contents_size);
								}

								Free(chunk_tmp);
								FreeBuf(chunk_buf);
							}
						}
					}

					FreeHttpHeader(r2);
				}
			}

			FreeHttpHeader(h2);

			if (err)
			{
				Disconnect(s);

				// Disconnected the communication with the destination server
				if (s2 != NULL)
				{
					Disconnect(s2);
					ReleaseSock(s2);
					s2 = NULL;
				}
			}

			FreeBuf(post_buf);
		}
		else
		{
			// Unsupported method
			HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
		}

		if (h != first_header)
		{
			FreeHttpHeader(h);
		}
	}

	if (s2 != NULL)
	{
		Disconnect(s2);
		ReleaseSock(s2);
	}

	WtLogEx(wt, log_prefix, "Finished the proxy function.");
}

// WebSocket Accept
bool WtgWebSocketAccept(WT* wt, SOCK* s, char* url_target, TSESSION* session, TUNNEL* tunnel)
{
	bool ret = false;
	if (wt == NULL || s == NULL || url_target == NULL || session == NULL || tunnel == NULL)
	{
		return false;
	}

	WHERE;
	WS* w = NewWs(s);
	if (w != NULL)
	{
		if (false)
		{
			//// テストさん
			while (true)
			{
				WHERE;
				if (WsSendSync(w, "Hello", 5) == false)
				{
					WHERE;
					break;
				}
				SleepThread(100);
			}
		}
		
		// バッファサイズ変更
		w->MaxBufferSize = WT_WEBSOCK_WINDOW_SIZE;
		w->Wsp->MaxRecvPayloadSizeOverride = WT_WEBSOCK_WINDOW_SIZE;

		// この session にまだこの tunnel が属しているかどうか確認する
		Lock(session->Lock);
		{
			WHERE;
			if (IsInList(session->TunnelList, tunnel))
			{
				// 属している。状態を検査する。
				if (tunnel->WebSocket == NULL)
				{
					// WebSocket への切替えが未完了である。したがって、切替えることが可能である。
					// そこで、切替えを実施する。
					tunnel->WebSocket = w;

					// これ以降 WebSocket は別スレッドで処理されるため、AddRef する。
					// このスレッドの最後にソケットは解放される。
					AddRef(w->Ref);
					WHERE;

					ret = true;
				}
			}
		}
		Unlock(session->Lock);

		ReleaseWs(w);
	}
	WHERE;

	if (ret)
	{
		SetSockEvent(session->SockEvent);
	}

	return ret;
}

// WebSocket URL を元にセッションとトンネルを検索する
bool WtgSearchSessionAndTunnelByWebSocketUrl(WT* wt, char* url_target, TSESSION** pp_session, TUNNEL** pp_tunnel)
{
	if (wt == NULL || url_target == NULL || pp_session == NULL || pp_tunnel == NULL)
	{
		return false;
	}

	*pp_session = NULL;
	*pp_tunnel = NULL;

	TSESSION* session = NULL;
	TUNNEL* tunnel = NULL;

	// URL をパース
	char* prefix = "/websocket/";
	if (StartWith(url_target, prefix) == false)
	{
		return false;
	}

	char token1[64] = CLEAN;
	char token2[64] = CLEAN;

	char* s = url_target + StrLen(prefix);

	// URL の途中で ? または / が登場した場合、そこまでの文字列のみを読み取り、それ以降は無視をする
	char tmp[MAX_PATH] = CLEAN;
	StrCpy(tmp, sizeof(tmp), s);
	UINT index = SearchStrEx(tmp, "?", 0, false);
	if (index != INFINITE)
	{
		tmp[index] = 0;
	}
	index = SearchStrEx(tmp, "/", 0, false);
	if (index != INFINITE)
	{
		tmp[index] = 0;
	}

	TOKEN_LIST* tokens = ParseToken(tmp, "-");
	if (tokens->NumTokens == 2)
	{
		StrCpy(token1, sizeof(token1), tokens->Token[0]);
		StrCpy(token2, sizeof(token2), tokens->Token[1]);
	}
	FreeToken(tokens);

	if (IsEmptyStr(token1) || IsEmptyStr(token2))
	{
		return false;
	}

	UINT i;
	LockList(wt->SessionList);
	{
		for (i = 0; i < LIST_NUM(wt->SessionList);i++)
		{
			TSESSION* s = LIST_DATA(wt->SessionList, i);

			if (StrCmpi(s->WebSocketToken1, token1) == 0)
			{
				session = s;
				AddRef(session->Ref);
				break;
			}
		}
	}
	UnlockList(wt->SessionList);

	if (session != NULL)
	{
		Lock(session->Lock);
		{
			for (i = 0;i < LIST_NUM(session->TunnelList);i++)
			{
				TUNNEL* t = LIST_DATA(session->TunnelList, i);

				if (StrCmpi(t->WebSocketToken2, token2) == 0)
				{
					if (t->Gate_ClientSession_SwitchToWebSocketAcked)
					{
						tunnel = t;
						break;
					}
				}
			}
		}
		Unlock(session->Lock);

		if (tunnel == NULL)
		{
			WtReleaseSession(session);
			session = NULL;
		}
	}

	*pp_session = session;
	*pp_tunnel = tunnel;

	return (session != NULL && tunnel != NULL);
}

// WebSocket GET Handler
bool WtgWebSocketGetHandler(WT* wt, SOCK* s, HTTP_HEADER* h, char* url_target)
{
	HTTP_VALUE* req_upgrade;
	HTTP_VALUE* req_version;
	HTTP_VALUE* req_key;
	char response_key[64];
	UINT client_ws_version = 0;
	char* bad_request_body = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\"http://www.w3.org/TR/html4/strict.dtd\">\r\n<HTML><HEAD><TITLE>Bad Request</TITLE>\r\n<META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=us-ascii\"></HEAD>\r\n<BODY><h2>Bad Request</h2>\r\n<hr><p>HTTP Error 400. The request is badly formed.</p>\r\n</BODY></HTML>";
	if (wt == NULL || s == NULL || h == NULL || url_target == NULL)
	{
		return false;
	}

	char log_prefix[MAX_PATH] = CLEAN;

	Format(log_prefix, sizeof(log_prefix), "AcceptNewSession(WebSocket)/ClientIP=%r/ClientPort=%u/ServerIP=%r/ServerPort=%u", &s->RemoteIP, s->RemotePort, &s->LocalIP, s->LocalPort);

	req_upgrade = GetHttpValue(h, "Upgrade");
	if (req_upgrade == NULL || StrCmpi(req_upgrade->Data, "websocket") != 0)
	{
		MvpnSendReply(s, 400, "Bad Request", bad_request_body, StrLen(bad_request_body),
			NULL, NULL, NULL, NULL, NULL, h, false);
		WtLogEx(wt, log_prefix, "WebSocket Bad Request: Invalid headers");
		return false;
	}

	req_version = GetHttpValue(h, "Sec-WebSocket-Version");
	if (req_version != NULL) client_ws_version = ToInt(req_version->Data);
	if (client_ws_version != 13)
	{
		MvpnSendReply(s, 400, "Bad Request", NULL, 0,
			NULL, "Sec-WebSocket-Version", "13", NULL, NULL, h, false);
		WtLogEx(wt, log_prefix, "WebSocket Bad Request: client_ws_version = %u, not 13", client_ws_version);
		return false;
	}

	Zero(response_key, sizeof(response_key));
	req_key = GetHttpValue(h, "Sec-WebSocket-Key");
	if (req_key != NULL)
	{
		char tmp[MAX_SIZE];
		UCHAR hash[SHA1_SIZE];
		StrCpy(tmp, sizeof(tmp), req_key->Data);
		StrCat(tmp, sizeof(tmp), "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		HashSha1(hash, tmp, StrLen(tmp));
		B64_Encode(response_key, hash, SHA1_SIZE);
	}
	else
	{
		MvpnSendReply(s, 400, "Bad Request", NULL, 0,
			NULL, "Sec-WebSocket-Version", "13", NULL, NULL, h, false);
		WtLogEx(wt, log_prefix, "WebSocket Bad Request: No Sec-WebSocket-Key");
		return false;
	}

	char protocol[128] = CLEAN;
	HTTP_VALUE* protocol_value = GetHttpValue(h, "Sec-WebSocket-Protocol");
	if (protocol_value != NULL)
	{
		StrCpy(protocol, sizeof(protocol), protocol_value->Data);
	}

	WtLogEx(wt, log_prefix, "WebSocket protocol header value: '%s'", protocol);

	TSESSION* session = NULL;
	TUNNEL* tunnel = NULL;

	// WebSocket URL を元にセッションとトンネルを検索する
	if (WtgSearchSessionAndTunnelByWebSocketUrl(wt, url_target, &session, &tunnel) == false)
	{
		MvpnSendReply(s, 400, "Bad Request - WebSocket Session Not Found", NULL, 0, NULL, NULL, NULL, NULL, NULL, h, false);
		Debug("WebSocket: Session not found for URL %s\n", url_target);
		WtLogEx(wt, log_prefix, "WebSocket: Session not found for URL %s", url_target);
		return false;
	}

	MvpnSendReply(s, 101, "Switching Protocols", NULL, 0, NULL,
		"Sec-WebSocket-Accept", response_key,
		"Sec-WebSocket-Protocol", IsFilledStr(protocol) ? protocol : NULL,
		h, true);

	Debug("WebSocket: Session reconnect OK for URL %s\n", url_target);
	WtLogEx(wt, log_prefix, "WebSocket: Session reconnect OK for URL %s", url_target);

	WtgWebSocketAccept(wt, s, url_target, session, tunnel);

	WtReleaseSession(session);

	return true;
}

// Standalone Mode 初期化
void WtgSamInit(WT* wt)
{
	FOLDER* root = CLEAN;
	if (wt == NULL || wt->IsStandaloneMode == false)
	{
		return;
	}

	wt->MachineDatabase = NewList(NULL);

	wt->CfgRwMachineDatabase = NewCfgRwEx2A(&root, WTG_SAM_DATABASE_FILENAME, false, NULL);

	if (root != NULL)
	{
		// データベースファイルが発見された。読み込みをする。
		WtgSamLoadDatabase(wt, root);

		CfgDeleteFolder(root);
	}
	else
	{
		// データベースファイルがない。
	}

	// フラッシュを いたします
	WtgSamFlushDatabase(wt);

	// 自動保存スレッド開始
	wt->CfgSaveThreadHaltEvent = NewEvent();
	wt->CfgSaveThread = NewThread(CfgSaveThreadProc, wt);
}

// Standalone Mode 終了
void WtgSamFree(WT* wt)
{
	UINT i;
	if (wt == NULL || wt->IsStandaloneMode == false)
	{
		return;
	}

	wt->CfgSaveThreadHaltFlag = true;

	Set(wt->CfgSaveThreadHaltEvent);

	WaitThread(wt->CfgSaveThread, INFINITE);

	ReleaseThread(wt->CfgSaveThread);

	ReleaseEvent(wt->CfgSaveThreadHaltEvent);

	FreeCfgRw(wt->CfgRwMachineDatabase);
	wt->CfgRwMachineDatabase = NULL;

	for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
	{
		WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);
		Free(m);
	}

	ReleaseList(wt->MachineDatabase);
	wt->MachineDatabase = NULL;
}

// データベース定期保存スレッド
void CfgSaveThreadProc(THREAD* thread, void* param)
{
	WT* wt = (WT*)param;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		if (wt->CfgSaveThreadHaltFlag)
		{
			break;
		}

		Wait(wt->CfgSaveThreadHaltEvent, WT_SAM_DATABASE_AUTO_SAVE_INTERVAL);

		if (wt->CfgSaveThreadHaltFlag == false)
		{
			WtgSamFlushDatabase(wt);
		}
	}
}

// マシンデータベースの読み込み
void WtgSamLoadDatabase(WT* wt, FOLDER* root)
{
	FOLDER* machine = NULL;
	if (wt == NULL || root == NULL)
	{
		return;
	}

	wt->MachineDatabaseRevision = CfgGetInt(root, "Revision");

	machine = CfgGetFolder(root, "Machines");

	LockList(wt->MachineDatabase);
	{
		TOKEN_LIST *name_list = CfgEnumFolderToTokenList(machine);
		if (name_list != NULL)
		{
			UINT i;
			for (i = 0;i < name_list->NumTokens;i++)
			{
				char* name = name_list->Token[i];
				FOLDER* mf = CfgGetFolder(machine, name);

				if (mf != NULL)
				{
					WG_MACHINE* m = ZeroMalloc(sizeof(WG_MACHINE));

					CfgGetStr(mf, "Msid", m->Msid, sizeof(m->Msid));
					CfgGetStr(mf, "CertHash", m->CertHash, sizeof(m->CertHash));
					CfgGetStr(mf, "HostSecret2", m->HostSecret2, sizeof(m->HostSecret2));
					CfgGetStr(mf, "Pcid", m->Pcid, sizeof(m->Pcid));
					m->ServerMask64 = CfgGetInt64(mf, "ServerMask64");
					m->CreateDate = CfgGetInt64(mf, "CreateDate");
					m->UpdateDate = CfgGetInt64(mf, "UpdateDate");
					m->LastServerDate = CfgGetInt64(mf, "LastServerDate");
					m->FirstClientDate = CfgGetInt64(mf, "FirstClientDate");
					m->LastClientDate = CfgGetInt64(mf, "LastClientDate");
					m->NumServer = CfgGetInt(mf, "NumServer");
					m->NumClient = CfgGetInt(mf, "NumClient");
					CfgGetStr(mf, "CreateIp", m->CreateIp, sizeof(m->CreateIp));
					CfgGetStr(mf, "CreateHost", m->CreateHost, sizeof(m->CreateHost));
					CfgGetStr(mf, "LastIp", m->LastIp, sizeof(m->LastIp));
					CfgGetStr(mf, "WolMacList", m->WolMacList, sizeof(m->WolMacList));

					if (IsFilledStr(m->Msid) &&
						IsFilledStr(m->CertHash) &&
						IsFilledStr(m->HostSecret2) &&
						IsFilledStr(m->Pcid))
					{
						Add(wt->MachineDatabase, m);
					}
					else
					{
						Free(m);
					}
				}
			}

			FreeToken(name_list);
		}
	}
	UnlockList(wt->MachineDatabase);
}

// マシンデータベースのフラッシュ
void WtgSamFlushDatabase(WT* wt)
{
	FOLDER* root = NULL;
	FOLDER* machine = NULL;

	if (wt == NULL)
	{
		return;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	CfgAddInt(root, "Revision", wt->MachineDatabaseRevision);

	machine = CfgCreateFolder(root, "Machines");

	LockList(wt->MachineDatabase);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
		{
			WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);
			FOLDER* mf = CfgCreateFolder(machine, m->Msid);

			CfgAddStr(mf, "Msid", m->Msid);
			CfgAddStr(mf, "CertHash", m->CertHash);
			CfgAddStr(mf, "HostSecret2", m->HostSecret2);
			CfgAddStr(mf, "Pcid", m->Pcid);
			CfgAddInt64(mf, "ServerMask64", m->ServerMask64);
			CfgAddInt64(mf, "CreateDate", m->CreateDate);
			CfgAddInt64(mf, "UpdateDate", m->UpdateDate);
			CfgAddInt64(mf, "LastServerDate", m->LastServerDate);
			CfgAddInt64(mf, "FirstClientDate", m->FirstClientDate);
			CfgAddInt64(mf, "LastClientDate", m->LastClientDate);
			CfgAddInt(mf, "NumServer", m->NumServer);
			CfgAddInt(mf, "NumClient", m->NumClient);
			CfgAddStr(mf, "CreateIp", m->CreateIp);
			CfgAddStr(mf, "CreateHost", m->CreateHost);
			CfgAddStr(mf, "LastIp", m->LastIp);
			CfgAddStr(mf, "WolMacList", m->WolMacList);
		}
	}
	UnlockList(wt->MachineDatabase);

	Lock(wt->CfgRwSaveLock);
	{
		SaveCfgRwEx(wt->CfgRwMachineDatabase, root, wt->MachineDatabaseRevision);
	}
	Unlock(wt->CfgRwSaveLock);

	CfgDeleteFolder(root);
}

// 現在このスタンドアロン GW に接続しているセッションの一覧を表示する
void WtgSamProcessStat(WT* wt, SOCK* s, char* target)
{
	FOLDER* root;
	BUF* buf;
	if (wt == NULL || s == NULL)
	{
		return;
	}

	if (IsLocalHostIP(&s->RemoteIP) == false)
	{
		// おいこら！！ localhost 以外からは アクセス できません！！
		HttpSendForbidden(s, target, NULL);
		return;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	LockList(wt->SessionList);
	{
		UINT i, num;

		num = LIST_NUM(wt->SessionList);
		for (i = 0;i < num;i++)
		{
			TSESSION* s = LIST_DATA(wt->SessionList, i);
			char session_id_str[MAX_PATH];
			char tmp[MAX_PATH];
			FOLDER* f;

			BinToStr(session_id_str, sizeof(session_id_str), s->SessionId, sizeof(s->SessionId));

			f = CfgCreateFolder(root, session_id_str);

			CfgAddStr(f, "SessionId", session_id_str);
			CfgAddStr(f, "Msid", s->Msid);
			CfgAddInt64(f, "EstablishedDateTime", TickToTime(s->EstablishedTick));
			CfgAddInt(f, "NumClients", LIST_NUM(s->TunnelList));

			IPToStr(tmp, sizeof(tmp), &s->ServerTcp->Ip);
			CfgAddStr(f, "IpAddress", tmp);
			CfgAddStr(f, "Hostname", s->ServerTcp->Hostname);

			CfgAddInt64(f, "ServerMask64", s->ServerMask64);
		}

		CfgAddInt(root, "NumSession", num);
	}
	UnlockList(wt->SessionList);

	buf = CfgFolderToBufEx(root, true, true);

	CfgDeleteFolder(root);

	HttpSendBody(s, buf->Buf, buf->Size, "text/plain");

	FreeBuf(buf);
}

// リクエスト文字列の処理
void WtgSamProcessRequestStr(WT* wt, SOCK* s, char* reqstr)
{
	WPC_PACKET packet = CLEAN;
	BUF* buf;
	bool ok = false;
	PACK* ret_pack = NULL;
	UINT prev_revision = 0;
	if (wt == NULL || s == NULL || reqstr == NULL)
	{
		return;
	}

	prev_revision = wt->MachineDatabaseRevision;

	buf = NewBuf();
	WriteBuf(buf, reqstr, StrLen(reqstr));

	ok = WpcParsePacket(&packet, buf);

	FreeBuf(buf);

	if (ok)
	{
		ret_pack = WtgSamDoProcess(wt, s, &packet);
	}
	else
	{
		ret_pack = NewPack();
		PackAddInt(ret_pack, "Error", ERR_INTERNAL_ERROR);
	}

	if (ret_pack != NULL)
	{
		BUF* ret_buf = WpcGeneratePacket(ret_pack, NULL, NULL);

		if (ret_buf != NULL)
		{
			HttpSendBody(s, ret_buf->Buf, ret_buf->Size, "text/plain");

			FreeBuf(ret_buf);
		}

		FreePack(ret_pack);
	}

	WpcFreePacket(&packet);

	if (prev_revision != wt->MachineDatabaseRevision)
	{
		// DB の内容が大きく変更されていた場合は DB を強制フラッシュする
		WtgSamFlushDatabase(wt);
	}
}

// リスエストの処理
PACK* WtgSamDoProcess(WT* wt, SOCK* s, WPC_PACKET* packet)
{
	PACK* ret = NewPack();
	UINT err = ERR_INTERNAL_ERROR;
	PACK* req;
	char function[64] = CLEAN;
	UINT tmperr = ERR_INTERNAL_ERROR;
	char hostkey_str[SHA1_SIZE * 2 + 8] = CLEAN;
	char hostsecret_str[SHA1_SIZE * 2 + 8] = CLEAN;
	char* wol_maclist = NULL;
	UINT i;
	WG_MACHINE* authed = NULL;
	bool no_unlock_database = false;
	if (wt == NULL || s == NULL || packet == NULL)
	{
		err = ERR_INTERNAL_ERROR;
		goto LABEL_CLEANUP;
	}

	char log_prefix[MAX_PATH] = CLEAN;

	Format(log_prefix, sizeof(log_prefix), "RPC Request Processor/Anonymouse/ClientIP=%r/ClientPort=%u/ServerIP=%r/ServerPort=%u", &s->RemoteIP, s->RemotePort, &s->LocalIP, s->LocalPort);

	req = packet->Pack;

	LockList(wt->MachineDatabase);

	if (IsZero(packet->HostKey, SHA1_SIZE) == false &&
		IsZero(packet->HostSecret, SHA1_SIZE) == false)
	{
		// サーバーからの認証データで認証を実施
		BinToStr(hostkey_str, sizeof(hostkey_str), packet->HostKey, SHA1_SIZE);
		BinToStr(hostsecret_str, sizeof(hostsecret_str), packet->HostSecret, SHA1_SIZE);

		// ログインを試行
		for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
		{
			WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);

			if (StrCmpi(m->CertHash, hostkey_str) == 0 &&
				StrCmpi(m->HostSecret2, hostsecret_str) == 0)
			{
				// ログインに成功
				authed = m;
				break;
			}
		}

		if (authed != NULL)
		{
			Format(log_prefix, sizeof(log_prefix), "RPC Request Processor/Authed_Server/PCID=%s/MSID=%s/ClientIP=%r/ClientPort=%u/ServerIP=%r/ServerPort=%u",
				authed->Pcid, authed->Msid,
				&s->RemoteIP, s->RemotePort, &s->LocalIP, s->LocalPort);
		}
	}

	PackGetStr(req, "Function", function, sizeof(function));

	WtLogEx(wt, log_prefix, "Calling RPC function name: '%s'", function);

	if (StrCmpi(function, "RegistMachine") == 0)
	{
		// 新しい Machine の登録
		char pcid[64] = CLEAN;
		WG_MACHINE* m = NULL;

		PackGetStr(req, "Pcid", pcid, sizeof(pcid));

		Trim(pcid);
		StrLower(pcid);

		tmperr = WtgCheckPcid(pcid);
		if (tmperr != ERR_NO_ERROR)
		{
			err = tmperr;
			goto LABEL_CLEANUP;
		}

		// 同一キーが存在しないかどうかチェック
		if (WtgSamIsMachineExistsByHostKey(wt, hostkey_str))
		{
			// 存在する
			err = ERR_SECURITY_ERROR;
			goto LABEL_CLEANUP;
		}

		// 同一シークレットが存在しないかどうかチェック
		if (WtgSamIsMachineExistsByHostSecret(wt, hostsecret_str))
		{
			// 存在する
			err = ERR_SECURITY_ERROR;
			goto LABEL_CLEANUP;
		}

		// PCID が存在しないかどうかチェック
		if (WtgSamIsMachineExistsByPCID(wt, pcid))
		{
			// 存在する
			err = ERR_PCID_ALREADY_EXISTS;
			goto LABEL_CLEANUP;
		}

		// 存在しない場合のみ登録
		m = ZeroMalloc(sizeof(WG_MACHINE));
		WtgSamGenerateMsid(m->Msid, sizeof(m->Msid), hostkey_str);
		StrCpy(m->CertHash, sizeof(m->CertHash), hostkey_str);
		StrCpy(m->HostSecret2, sizeof(m->HostSecret2), hostsecret_str);
		StrCpy(m->Pcid, sizeof(m->Pcid), pcid);
		m->CreateDate = m->UpdateDate = m->LastServerDate = SystemTime64();
		IPToStr(m->CreateIp, sizeof(m->CreateIp), &s->RemoteIP);
		IPToStr(m->LastIp, sizeof(m->LastIp), &s->RemoteIP);
		StrCpy(m->CreateHost, sizeof(m->CreateHost), s->RemoteHostname);
		Add(wt->MachineDatabase, m);

		wt->MachineDatabaseRevision++;

		err = ERR_NO_ERROR;
	}
	else if (StrCmpi(function, "GetPcidCandidate") == 0)
	{
		char machine_name[32] = CLEAN;
		char computer_name[32] = CLEAN;
		char username[32] = CLEAN;
		char key[64] = CLEAN;
		UINT n = 0;
		char candidate[64] = CLEAN;

		PackGetStr(req, "MachineName", machine_name, sizeof(machine_name));
		PackGetStr(req, "ComputerName", computer_name, sizeof(computer_name));
		PackGetStr(req, "UserName", username, sizeof(username));

		WtgConvertStrToSafeForPcid(username, sizeof(username), username);

		i = SearchStrEx(machine_name, ".", 0, false);
		if (i != INFINITE)
		{
			machine_name[i] = 0;
		}
		machine_name[8] = 0;
		WtgConvertStrToSafeForPcid(machine_name, sizeof(machine_name), machine_name);

		Trim(machine_name);
		Trim(username);

		if (IsEmptyStr(username) == false && StrCmpi(username, "administrator") != 0 && StrCmpi(username, "system") != 0)
		{
			StrCpy(key, sizeof(key), username);
		}
		else if (IsEmptyStr(machine_name) == false)
		{
			StrCpy(key, sizeof(key), machine_name);
		}
		else
		{
			UCHAR rand2[2];
			Rand(rand2, sizeof(rand2));
			BinToStr(key, sizeof(key), rand2, sizeof(rand2));
		}

		StrLower(key);

		while (true)
		{
			i = 1 + Rand32() % 9999;
			n++;
			if (n >= 100)
			{
				i = Rand32() % 9999999 + n;
			}

			Format(candidate, sizeof(candidate), "%s-%u", key, i);

			if (WtgSamIsMachineExistsByPCID(wt, candidate) == false)
			{
				break;
			}
		}

		PackAddStr(ret, "Ret", candidate);
		err = ERR_NO_ERROR;
	}
	else if (StrCmpi(function, "ServerConnect") == 0)
	{
		UINT64 server_mask_64;
		BUF* b;
		UINT64 expires = 0;
		UCHAR sign[SHA1_SIZE] = CLEAN;
		if (authed == NULL)
		{
			err = ERR_NO_INIT_CONFIG;
			goto LABEL_CLEANUP;
		}

		if (LIST_NUM(wt->SessionList) >= WT_SAM_MAX_SERVER_SESSIONS)
		{
			err = ERR_WG_TOO_MANY_SESSIONS;
			goto LABEL_CLEANUP;
		}

		wol_maclist = PackGetStrCopy(req, "wol_maclist");
		if (wol_maclist == NULL) wol_maclist = CopyStr("");

		server_mask_64 = PackGetInt64(req, "ServerMask64");

		// 回数インクリメント、HOST_SECRET2 更新、WOL_MACLIST 更新, SERVERMASK64 更新
		authed->NumServer++;
		authed->LastServerDate = SystemTime64();
		IPToStr(authed->LastIp, sizeof(authed->LastIp), &s->RemoteIP);
		if (StrCmpi(authed->WolMacList, wol_maclist) != 0)
		{
			StrCpy(authed->WolMacList, sizeof(authed->WolMacList), wol_maclist);
			wt->MachineDatabaseRevision++;
		}
		if (authed->ServerMask64 != server_mask_64)
		{
			authed->ServerMask64 = server_mask_64;
			wt->MachineDatabaseRevision++;
		}

		expires = SystemTime64() + (UINT64)(20 * 60 * 1000);

		b = NewBuf();
		WriteBuf(b, authed->Msid, StrLen(authed->Msid));
		WriteBufInt64(b, expires);
		WriteBuf(b, wt->GateId, SHA1_SIZE);

		PackAddStr(ret, "Msid", authed->Msid);
		PackAddData(ret, "GateId", wt->GateId, SHA1_SIZE);
		PackAddInt64(ret, "Expires", expires);

		HashSha1(sign, b->Buf, b->Size);

		PackAddData(ret, "Signature2", sign, SHA1_SIZE);
		PackAddStr(ret, "Hostname", WT_CONTROLLER_GATE_SAME_HOST);
		PackAddStr(ret, "HostnameForProxy", WT_CONTROLLER_GATE_SAME_HOST);
		PackAddStr(ret, "Pcid", authed->Pcid);
		PackAddInt(ret, "Port", 443);

		FreeBuf(b);

		err = ERR_NO_ERROR;
	}
	else if (StrCmpi(function, "ClientConnect") == 0)
	{
		char pcid[WT_PCID_SIZE] = CLEAN;
		UINT ver = PackGetInt(req, "Ver");
		UINT build = PackGetInt(req, "Build");
		UINT64 client_flags = PackGetInt64(req, "ClientFlags");
		UINT client_options = PackGetInt(req, "ClientOptions");
		WG_MACHINE* target = NULL;
		TSESSION* target_session = NULL;
		char* msid = NULL;

		PackGetStr(req, "Pcid", pcid, sizeof(pcid));

		target = WtgSamGetMachineByPCID(wt, pcid);
		if (target == NULL)
		{
			err = ERR_PCID_NOT_FOUND;
			goto LABEL_CLEANUP;
		}

		msid = target->Msid;

		// 接続先の Gate と Session を取得
		LockList(wt->SessionList);
		{
			UINT i;
			UINT64 sort_test = 0;

			for (i = 0;i < LIST_NUM(wt->SessionList);i++)
			{
				TSESSION* s = LIST_DATA(wt->SessionList, i);

				// MSID が一致するセッションのうち、最も接続日時が新しいものを 1 つ取得する
				if (StrCmpi(s->Msid, msid) == 0)
				{
					if (s->EstablishedTick >= sort_test)
					{
						sort_test = s->EstablishedTick;
						target_session = s;
					}
				}
			}

			if (target_session == NULL)
			{
				// MSID が一致するセッションが 1 つもありませんでした！！
				err = ERR_DEST_MACHINE_NOT_EXISTS;
			}
			else
			{
				// セッションを発見いたしました。
				err = ERR_NO_ERROR;

				if ((client_options & WT_CLIENT_OPTIONS_WOL) != 0)
				{
					// WoL クライアントである
					if ((target_session->ServerMask64 & DS_MASK_SUPPORT_WOL_TRIGGER) == 0)
					{
						// トリガー PC のバージョンが WoL トリガー機能がない古いバージョンである
						err = ERR_WOL_TRIGGER_NOT_SUPPORTED;
					}
				}

				if (err == ERR_NO_ERROR)
				{
					// 接続 OK。情報をクライアントに返す
					PackAddStr(ret, "Hostname", WT_CONTROLLER_GATE_SAME_HOST);
					PackAddStr(ret, "HostnameForProxy", WT_CONTROLLER_GATE_SAME_HOST);
					PackAddInt(ret, "Port", 443);
					PackAddData(ret, "SessionId", target_session->SessionId, SHA1_SIZE);
					PackAddInt64(ret, "ServerMask64", target_session->ServerMask64);
					PackAddStr(ret, "WebSocketWildCardDomainName", wt->Wide->WebSocketWildCardDomainName);
					PackAddBool(ret, "IsStandaloneMode", true);
				}
			}
		}
		UnlockList(wt->SessionList);
	}
	else if (StrCmpi(function, "RenameMachine") == 0)
	{
		char new_name[WT_PCID_SIZE] = CLEAN;

		if (authed == NULL)
		{
			err = ERR_NO_INIT_CONFIG;
			goto LABEL_CLEANUP;
		}

		PackGetStr(req, "NewName", new_name, sizeof(new_name));

		Trim(new_name);
		StrLower(new_name);

		tmperr = WtgCheckPcid(new_name);
		if (tmperr != ERR_NO_ERROR)
		{
			err = tmperr;
			goto LABEL_CLEANUP;
		}

		if (WtgSamIsMachineExistsByPCID(wt, new_name))
		{
			// 既に存在する名前を指定した
			err = ERR_PCID_ALREADY_EXISTS;
			goto LABEL_CLEANUP;
		}

		err = ERR_NO_ERROR;

		// 名前の変更
		StrCpy(authed->Pcid, sizeof(authed->Pcid), new_name);

		wt->MachineDatabaseRevision++;
	}
	else if (StrCmpi(function, "ClientGetWolMacList") == 0)
	{
		WG_MACHINE* target_machine = NULL;
		char pcid[WT_PCID_SIZE] = CLEAN;
		PackGetStr(req, "Pcid", pcid, sizeof(pcid));

		target_machine = WtgSamGetMachineByPCID(wt, pcid);

		if (target_machine == NULL)
		{
			// PCID が見つからない
			err = ERR_PCID_NOT_FOUND;
			goto LABEL_CLEANUP;
		}

		PackAddStr(ret, "wol_maclist", target_machine->WolMacList);

		err = ERR_NO_ERROR;
	}
	else if (StrCmpi(function, "SendOtpEmail") == 0)
	{
		char otp[128] = CLEAN;
		char email[128] = CLEAN;
		char ip[64] = CLEAN;
		char fqdn[128] = CLEAN;
		UINT body_size = 4096;
		char* body = NULL;
		bool smtp_ok = false;

		char* body_format =
			"From: %s\r\nTo: %s\r\nSubject: Thin Telework OTP - %s\r\n\r\n"
			"Your new One Time Password (OTP) code is:\r\n"
			"%s\r\n\r\n"
			"A client is attempting to connect to the server: %s.\r\n\r\n"
			"The source IP address of the client is: %s\r\n\r\n";

		if (authed == NULL)
		{
			err = ERR_NO_INIT_CONFIG;
			goto LABEL_CLEANUP;
		}

		PackGetStr(req, "Otp", otp, sizeof(otp));
		PackGetStr(req, "Email", email, sizeof(email));
		PackGetStr(req, "Ip", ip, sizeof(ip));
		PackGetStr(req, "Fqdn", fqdn, sizeof(fqdn));

		if (IsEmptyStr(wt->SmtpServerHostname) || wt->SmtpServerPort == 0 ||
			IsEmptyStr(wt->SmtpOtpFrom))
		{
			err = ERR_WG_NO_SMTP_SERVER_CONFIG;
			goto LABEL_CLEANUP;
		}

		body = ZeroMalloc(body_size);

		Format(body, body_size, body_format, wt->SmtpOtpFrom, email, otp, otp, authed->Pcid, ip);

		smtp_ok = SmtpSendMail(wt->SmtpServerHostname, wt->SmtpServerPort, wt->SmtpOtpFrom, email,
			body);

		if (smtp_ok)
		{
			err = ERR_NO_ERROR;
		}
		else
		{
			err = ERR_WG_SMTP_ERROR;
		}

		Free(body);
	}

LABEL_CLEANUP:
	if (no_unlock_database == false)
	{
		UnlockList(wt->MachineDatabase);
	}

	PackAddInt(ret, "Error", err);

	Free(wol_maclist);

	if (err == ERR_NO_ERROR)
	{
		WtLogEx(wt, log_prefix, "RPC function '%s' result OK.", function);
	}
	else
	{
		WtLogEx(wt, log_prefix, "RPC function '%s' result error. Error code: %u", function, err);
	}

	return ret;
}

// PCID から Machine を取得
WG_MACHINE* WtgSamGetMachineByPCID(WT* wt, char* pcid)
{
	UINT i;
	if (wt == NULL || pcid == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
	{
		WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);

		if (StrCmpi(m->Pcid, pcid) == 0)
		{
			return m;
		}
	}

	return NULL;
}

// MSID から Machine を取得
WG_MACHINE* WtgSamGetMachineByMSID(WT* wt, char* msid)
{
	UINT i;
	if (wt == NULL || msid == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
	{
		WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);

		if (StrCmpi(m->Msid, msid) == 0)
		{
			return m;
		}
	}

	return NULL;
}

// PCID に使用できる文字列にコンバート
void WtgConvertStrToSafeForPcid(char* dst, UINT dst_size, char* src)
{
	char tmp[64] = CLEAN;
	UINT i, len;

	len = StrLen(src);

	for (i = 0;i < len;i++)
	{
		char c = src[i];
		if (WtgIsSafeCharForPcid(c))
		{
			char s[2] = CLEAN;
			s[0] = c;
			StrCat(tmp, sizeof(tmp), s);
		}
	}

	tmp[20] = 0;

	StrCpy(dst, dst_size, tmp);
}

// MSID の作成
void WtgSamGenerateMsid(char* msid, UINT msid_size, char* hostkey_str)
{
	ClearStr(msid, msid_size);
	if (msid == NULL || hostkey_str == NULL)
	{
		return;
	}

	Format(msid, msid_size, "MSID-DESK-%s", hostkey_str);
}

// 指定した HostKey を持った Machine が存在するかどうかチェック
bool WtgSamIsMachineExistsByHostKey(WT* wt, char* hostkey_str)
{
	UINT i;
	if (wt == NULL || hostkey_str == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
	{
		WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);

		if (StrCmpi(m->CertHash, hostkey_str) == 0)
		{
			return true;
		}
	}

	return false;
}

// 指定した HostSecret を持った Machine が存在するかどうかチェック
bool WtgSamIsMachineExistsByHostSecret(WT* wt, char* hostsecret_str)
{
	UINT i;
	if (wt == NULL || hostsecret_str == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
	{
		WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);

		if (StrCmpi(m->HostSecret2, hostsecret_str) == 0)
		{
			return true;
		}
	}

	return false;
}

// 指定した PCID を持った Machine が存在するかどうかチェック
bool WtgSamIsMachineExistsByPCID(WT* wt, char* pcid)
{
	UINT i;
	if (wt == NULL || pcid == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(wt->MachineDatabase);i++)
	{
		WG_MACHINE* m = LIST_DATA(wt->MachineDatabase, i);

		if (StrCmpi(m->Pcid, pcid) == 0)
		{
			return true;
		}
	}

	return false;
}

// PCID のチェック
UINT WtgCheckPcid(char* pcid)
{
	UINT i, len;
	len = StrLen(pcid);
	if (len == 0)
	{
		return ERR_PCID_NOT_SPECIFIED;
	}
	if (len > (WT_PCID_SIZE - 1))
	{
		return ERR_PCID_TOO_LONG;
	}
	for (i = 0;i < len;i++)
	{
		if (WtgIsSafeCharForPcid(pcid[i]) == false)
		{
			return ERR_PCID_INVALID;
		}
	}

	return ERR_NO_ERROR;
}
bool WtgIsSafeCharForPcid(char c)
{
	if ('a' <= c && c <= 'z')
	{
		return true;
	}
	else if ('A' <= c && c <= 'Z')
	{
		return true;
	}
	else if (c == '_' || c == '-')
	{
		return true;
	}
	else if ('0' <= c && c <= '9')
	{
		return true;
	}
	return false;
}

// Gate のセッションメイン関数
void WtgSessionMain(TSESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	MsSetThreadPriorityRealtime();
#endif  // OS_WIN32

	WideGateReportSessionAdd(s->wt->Wide, s);

	Debug("WtgSessionMain Start.\n");

	SetSockEvent(s->SockEvent);

	UINT64 last_traffic_stat = 0;

	WtSessionLog(s, "WtgSessionMain() start.");

	while (true)
	{
		bool disconnected = false;

		UINT64 now = Tick64();

		if (last_traffic_stat == 0 || (now >= (last_traffic_stat + 1234ULL)))
		{
			last_traffic_stat = now;

			StatManReportInt64(s->wt->StatMan, "WtgTrafficClientToServer_Total", s->Stat_ClientToServerTraffic);
			StatManReportInt64(s->wt->StatMan, "WtgTrafficServerToClient_Total", s->Stat_ServerToClientTraffic);

			s->Stat_ClientToServerTraffic = 0;
			s->Stat_ServerToClientTraffic = 0;

			WideGateCheckNextRebootTime64(s->wt->Wide);
		}

		// ソケットイベントを待機
		WtgWaitForSock(s);

		Lock(s->Lock);
		{
			do
			{
				s->StateChangedFlag = false;

				// クライアントからのデータを受信して処理
				WtgRecvFromClient(s);

				// サーバーからのデータを受信して処理
				WtgRecvFromServer(s);

				// クライアントへデータを送信
				WtgSendToClient(s);

				// サーバーへデータを送信
				WtgSendToServer(s);

				// TCP コネクションの切断の検査
				disconnected = WtgCheckDisconnect(s);

				if (s->Halt)
				{
					disconnected = true;
				}

				if (disconnected)
				{
					WtSessionLog(s, "Server session is disconnected.");
					break;
				}
			}
			while (s->StateChangedFlag);
		}
		Unlock(s->Lock);

		if (disconnected)
		{
			// サーバーとの接続が切断されたのでセッションを終了する
			break;
		}
	}

	Debug("WtgSessionMain Cleanup...\n");

	StatManReportInt64(s->wt->StatMan, "WtgTrafficClientToServer_Total", s->Stat_ClientToServerTraffic);
	StatManReportInt64(s->wt->StatMan, "WtgTrafficServerToClient_Total", s->Stat_ServerToClientTraffic);

	WideGateReportSessionDel(s->wt->Wide, s->SessionId);

	// すべてのクライアントセッションの切断
	WtgDisconnectAllClientSession(s);

	Debug("WtgSessionMain End.\n");

	WtSessionLog(s, "WtgSessionMain() End.");
}

// すべてのクライアントセッションの切断
void WtgDisconnectAllClientSession(TSESSION *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *t = LIST_DATA(s->TunnelList, i);

		WtDisconnectTTcp(t->ClientTcp);
	}
}

// TCP コネクションの切断の検査
bool WtgCheckDisconnect(TSESSION *s)
{
	UINT i;
	bool ret = false;
	LIST *o = NULL;
	UINT64 now = s->Tick;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *t = LIST_DATA(s->TunnelList, i);

		if (t->ClientTcp->DisconnectSignalReceived)
		{
			// サーバー側から受け取った切断信号に対応するクライアントとの
			// コネクションは切断しなければならない
			t->ClientTcp->Disconnected = true;

			WtSessionLog(s, "Client session (Tunnel ID: %u, EndPoint: [%r]:%u) is disconnected "
				"because of server's termination request.",
				t->TunnelId, &t->ClientTcp->Sock->RemoteIP, t->ClientTcp->Sock->RemotePort);
		}

		bool disconnect_this_tunnel = false;

		if (WtIsTTcpDisconnected(s, t, t->ClientTcp))
		{
			if (t->WebSocket == NULL)
			{
				// WebSocket 切替え前のトンネルに対する判定処理
				if (t->Gate_ClientSession_SwitchToWebSocketAcked && now < t->Gate_ClientSession_SwitchToWebSocket_Expires &&
					t->ClientTcp->DisconnectSignalReceived == false)
				{
					// WebSocket 切替え中のトンネルにおいては、WebSocket 切替えが完了していないトンネル
					// であっても、有効期限が切れるまでは、トンネルが切断されたとみなさない。
					// ただし、サーバー側から切断信号を受け取っている場合は、必ず、切断されたとみなす。
				}
				else
				{
					// クライアントとの接続が切断された
					// (WebSocket 切替え中のトンネルにおいて、WebSocket 切替え期限までに
					//  WebSocket 接続がなされない場合もここが実行される)
					disconnect_this_tunnel = true;
				}
			}
		}

		if (t->GuaProto_HasError_AndIgnore)
		{
			disconnect_this_tunnel = true;
		}

		if (t->WebSocket != NULL)
		{
			// WebSocket 切替え後のトンネルにおいては、その WebSocket 接続が切断されていたら
			// トンネルが切断されたとみなすのである
			if (t->WebSocket->Disconnected)
			{
				disconnect_this_tunnel = true;
			}
			if (t->ClientTcp->DisconnectSignalReceived)
			{
				disconnect_this_tunnel = true;
			}

			// WebSocket 切替え後において、切替え前のクライアントとの間で一時的に維持されていた物理的
			// TCP トンネルを強制的に切断する
			if (t->ClientTcp->Sock->Disconnecting == false)
			{
				t->ClientTcp->Disconnected = true;
			}

			if (disconnect_this_tunnel)
			{
				WtSessionLog(s, "Client session (Tunnel ID: %u, EndPoint: [%r]:%u)'s Web Socket is disconnected.",
					t->TunnelId, &t->WebSocket->Sock->RemoteIP, t->WebSocket->Sock->RemotePort);
			}
		}

		if (disconnect_this_tunnel)
		{
			// トンネル切断リストへの投入
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, t);
		}
	}

	if (o != NULL)
	{
		// 切断されたクライアントとの間のトンネルの解放
		for (i = 0;i < LIST_NUM(o);i++)
		{
			UINT tunnel_id;
			TUNNEL *t = LIST_DATA(o, i);

			tunnel_id = t->TunnelId;

//			Debug("Disconnect Tunnel: %u, time: %I64u\n", tunnel_id, SystemTime64());

			WtSessionLog(s, "Client session (Tunnel ID: %u, EndPoint: [%r]:%u) is now disconnected.",
				t->TunnelId, &t->ClientTcp->Sock->RemoteIP, t->ClientTcp->Sock->RemotePort);

			Delete(s->TunnelList, t);

			// トンネルの解放
			WtFreeTunnel(t);

			// サーバーに対して切断された旨の通知を送信
			WtInsertNewBlockToQueue(s->BlockQueue, s->ServerTcp,
				tunnel_id, NULL, 0);

			// トンネル ID を使用済みリストに追加
			WtAddUsedTunnelId(s->UsedTunnelList, tunnel_id, WT_TUNNEL_USED_EXPIRES * 2);
		}

		ReleaseList(o);
	}

	if (WtIsTTcpDisconnected(s, NULL, s->ServerTcp))
	{
		// サーバーとの接続が切断された
		ret = true;
	}

	return ret;
}

// 指定された TCP コネクションが切断されているかどうかチェックする
// tunnel の値は、ThinGate で、かつ Client との接続の場合のみ値が入っている
bool WtIsTTcpDisconnected(TSESSION* s, TUNNEL* tunnel, TTCP* ttcp)
{
	// 引数チェック
	if (ttcp == NULL || s == NULL)
	{
		return true;
	}

	if (ttcp->Disconnected == false)
	{
		if ((ttcp->LastCommTime + (UINT64)ttcp->TunnelTimeout) < s->Tick)
		{
			WtSessionLog(s, "WtIsTTcpDisconnected: Receive timeout detected. ttcp->LastCommTime = %I64u, ttcp->TunnelTimeout = %u, s->Tick = %I64u",
				ttcp->LastCommTime, ttcp->TunnelTimeout, s->Tick);
			ttcp->Disconnected = true;
		}
	}

	if (ttcp->Disconnected)
	{
		if (ttcp->Sock != NULL && ttcp->Sock->Connected)
		{
			WtSessionLog(s, "ttcp->Disconnected == true");
		}
		Disconnect(ttcp->Sock);

		return true;
	}

	return false;
}

// サーバーへデータを送信
void WtgSendToServer(TSESSION *s)
{
	TTCP *ttcp;
	QUEUE *blockqueue;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	ttcp = s->ServerTcp;
	blockqueue = s->BlockQueue;

	// 送信データの生成
	WtMakeSendDataTTcp(s, ttcp, blockqueue, NULL, false);

	// 送信
	WtSendTTcp(s, ttcp);
}

// クライアントへデータを送信
void WtgSendToClient(TSESSION *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *t = LIST_DATA(s->TunnelList, i);
		TTCP *ttcp = t->ClientTcp;
		QUEUE *blockqueue = t->BlockQueue;

		bool only_keepalive = false;

		if (t->WebSocket != NULL)
		{
			// WebSocket 切替え後のトンネルについては、WebSocket の側にデータを送信するため、
			// WtMakeSendDataTTcp ではキューからデータを取り出さず KeepAlive 処理のみとする
			only_keepalive = true;
		}

		// --- 通常ソケット ---

		// ※ Web Socket が有効なときは、only_keepalive == true になっているので、
		//    通常ソケットではデータは送信されない。

		// 送信データの作成
		WtMakeSendDataTTcp(s, ttcp, blockqueue, t, only_keepalive);

		// 送信
		WtSendTTcp(s, ttcp);

		if (t->WebSocket != NULL)
		{
			// --- Web Socket ---
			DATABLOCK* block;
			while ((block = GetNext(blockqueue)) != NULL)
			{
				if (g_show_debug_protocol)
				{
					BUF* b = NewBuf();
					WriteBuf(b, block->Data, block->DataSize);
					WriteBufChar(b, 0);
					Print("<Send G2W> \"%s\"\n", b->Buf);
					FreeBuf(b);
				}

				// 1 個のフレームをクライアントに WebSocket で送信する。まず送信データを生成する。
				WspTrySendFrame(t->WebSocket->Wsp, WS_OPCODE_TEXT, block->Data, block->DataSize);

				WtFreeDataBlock(block, false);
			}

			// 蓄積されたフレーム一覧を物理的に送信する。
			UINT total_sent_size = 0;
			WsTrySendAsync(t->WebSocket, &total_sent_size);

			if (total_sent_size >= 1)
			{
				s->StateChangedFlag = true;
			}
		}
	}
}

// 送信データの生成
// tunnel は、Gate --> Client の場合のみ値が入っている
void WtMakeSendDataTTcp(TSESSION* s, TTCP* ttcp, QUEUE* blockqueue, TUNNEL* tunnel, bool only_keepalive)
{
	DATABLOCK *block;
	FIFO *fifo;
	UINT i;
	// 引数チェック
	if (s == NULL || ttcp == NULL || blockqueue == NULL)
	{
		return;
	}

	fifo = ttcp->SendFifo;

	if (only_keepalive == false)
	{
		while ((block = GetNext(blockqueue)) != NULL)
		{
			if (ttcp->MultiplexMode)
			{
				i = Endian32(block->TunnelId);
				WriteFifo(fifo, &i, sizeof(UINT));
			}

			i = Endian32(block->PhysicalSize);
			WriteFifo(fifo, &i, sizeof(UINT));
			WriteFifo(fifo, block->Data, block->PhysicalSize);

			if (block->DataSize == 0)
			{
				ttcp->DisconnectSignalReceived = true;
			}
			else
			{
				if (g_show_debug_protocol) // debugdebug
				{
					if (ttcp->CurrentBlockSize != 0)
					{
						if (tunnel != NULL)
						{
							BUF* b = NewBuf();
							WriteBuf(b, block->Data, block->PhysicalSize);
							WriteBufChar(b, 0);
							Print("<Send G2C> \"%s\"\n", b->Buf);
							FreeBuf(b);
						}
						else
						{
							BUF* b = NewBuf();
							WriteBuf(b, block->Data, block->PhysicalSize);
							WriteBufChar(b, 0);
							Print("<Send G2S> \"%s\"\n", b->Buf);
							FreeBuf(b);
						}
					}
				}
			}

			WtFreeDataBlock(block, false);

			ttcp->LastKeepAliveTime = s->Tick;
		}
	}

	if ((ttcp->LastKeepAliveTime + (UINT64)ttcp->TunnelKeepAlive) < s->Tick)
	{
		i = Endian32(0);

		WriteFifo(fifo, &i, sizeof(UINT));

		ttcp->LastKeepAliveTime = s->Tick;
	}

	if (only_keepalive == false)
	{
		if (tunnel != NULL)
		{
			if (tunnel->Gate_ClientSession_SwitchToWebSocketRequested && tunnel->Gate_ClientSession_SwitchToWebSocketAcked == false)
			{
				tunnel->Gate_ClientSession_SwitchToWebSocketAcked = true;

				// 切替え有効期限を開始
				tunnel->Gate_ClientSession_SwitchToWebSocket_Expires = Tick64() + (UINT64)WT_WEBSOCK_SWITCH_EXPIRES;

				// WebSocket への切替え処理のリクエストが来ていたので、切替え処理 OK である旨の応答を返す
				i = Endian32(WT_SPECIALOPCODE_S2C_SWITCHTOWEBSOCKET_ACK);

				WriteFifo(fifo, &i, sizeof(UINT));
			}
		}
	}
}

// サーバーからのデータを受信
void WtgRecvFromServer(TSESSION *s)
{
	TTCP *ttcp;
	QUEUE *q;
	DATABLOCK *block;
	UINT last_tid = INFINITE;
	UINT i;
	UINT max_fifo_size = 0;
	UINT remain_buf_size = WT_WINDOW_SIZE;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	ttcp = s->ServerTcp;

	UINT min_remain_buf_size = 0x7FFFFFFF;

	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *t = LIST_DATA(s->TunnelList, i);

		UINT fifo_size_of_this_tunnel = FifoSize(t->ClientTcp->SendFifo);
		UINT max_fifo_size_of_this_tunnel = WT_WINDOW_SIZE;

		if (t->WebSocket != NULL)
		{
			fifo_size_of_this_tunnel = FifoSize(t->WebSocket->Wsp->PhysicalSendFifo);
			max_fifo_size_of_this_tunnel = t->WebSocket->MaxBufferSize;
		}

		UINT remain_buf_size_of_this_tunnel = 0;
		
		if (max_fifo_size_of_this_tunnel > fifo_size_of_this_tunnel)
		{
			remain_buf_size_of_this_tunnel = max_fifo_size_of_this_tunnel - fifo_size_of_this_tunnel;
		}
		else
		{
			remain_buf_size_of_this_tunnel = 0;
		}

		min_remain_buf_size = MIN(min_remain_buf_size, remain_buf_size_of_this_tunnel);
	}

	if (min_remain_buf_size > WT_WINDOW_SIZE)
	{
		min_remain_buf_size = WT_WINDOW_SIZE;
	}

	// Debug("remain_buf_size: %u\n", remain_buf_size);

	// TTCP からデータを受信
	WtRecvTTcpEx(s, ttcp, min_remain_buf_size);

	// 受信データを解釈
	q = WtParseRecvTTcp(s, ttcp, NULL);

	// 受信データをクライアントに対して配布
	while ((block = GetNext(q)) != NULL)
	{
		UINT tunnel_id = block->TunnelId;
		TUNNEL *t = WtgSearchTunnelById(s->TunnelList, tunnel_id);
		QUEUE *dest_queue = NULL;
		DATABLOCK* send_block = NULL;
		bool use_compress = false;

		if (t != NULL)
		{
			if (t->WebSocket == NULL)
			{
				// 通常ソケットを利用しているトンネル
				// クライアントに対してデータを転送する
				dest_queue = t->BlockQueue;
				send_block = block;
				use_compress = t->ClientTcp->UseCompress;
			}
			else
			{
				if (t->CurrentWebSocketFrame == NULL)
				{
					// CurrentWebSocketFrame のメモリは、ここで初めて確保する。
					// (不要なトンネルの場合は確保せず、メモリを節約するため。)
					// WtFreeTunnel でこのメモリは解放される。
					t->CurrentWebSocketFrame = NewBuf();
				}

				// WebSocket 切替え後のトンネル。サーバーから受信したデータは Guacamole プロトコル
				// に基づきカンマ ';' 区切りとなっている。そして、クライアント HTML5 Web ブラウザは
				// カンマ ';' 区切りのデータ 1 つずつを WebSocket の 1 つずつのメッセージとしてしか受付けず
				// このルールに反したデータが届くとプロトコルエラーを発生させてしまう。
				// そこで、本コードは、サーバーから届いたブロックをストリームとして結合し、
				// そのストリームをカンマ区切りに直して、WebSocket の 1 つずつのメッセージとして
				// 再構成を行なうのである。
				if (block->DataSize == 0)
				{
					// サーバーからこのクライアントに対する切断信号が届いた。WebSocket の場合は
					// ここで処理をする。
					t->ClientTcp->DisconnectSignalReceived = true; // 切断指令フラグさん
				}
				else
				{
					UCHAR* data = block->Data;
					UINT size = block->DataSize;

					if (t->GuaProto_HasError_AndIgnore == false)
					{
						// Guacamole のメッセージは、
						// 4.xxxx,5.yyyyy,6.zzzzzz;
						// のような具合にやってくる。数字は最大 5 桁のみ受付けることとする。
						// 状態遷移マシンをここで動作させて、届いたデータからこのメッセージを 1 つずつ区切って
						// 取り出すのである。

						UINT i;
						for (i = 0;i < size;i++)
						{
							UCHAR c = data[i];

							switch (t->GuaProto_Mode)
							{
							case 0: // 0 桁 ～ 5 桁の数字 + '.' を待つモードである。
								if (c == '.')
								{
									// 数字が全部受信された。数字を解釈する。
									t->GuaProto_CurrentSizeStrData[t->GuaProto_CurrentSizeStrLen] = 0;
									t->GuaProto_CurrentDataSize = ToInt(t->GuaProto_CurrentSizeStrData);
									t->GuaProto_CurrentSizeStrLen = 0;

									if (t->GuaProto_CurrentDataSize == 0)
									{
										// データサイズとして 0 が指定されていたら、プロトコルエラーとする。
										Debug("WebSocket Gua protocol error! t->GuaProto_CurrentDataSize == 0n");
										t->GuaProto_HasError_AndIgnore = true;
										break;
									}

									t->GuaProto_CurrentDataPos = 0;

									// モードを 1 にする。
									t->GuaProto_Mode = 1;
								}
								else if (c >= '0' && c <= '9')
								{
									// 1 桁数字が届いた。追記する。
									t->GuaProto_CurrentSizeStrData[t->GuaProto_CurrentSizeStrLen] = c;
									t->GuaProto_CurrentSizeStrLen++;
									if (t->GuaProto_CurrentSizeStrLen >= 6)
									{
										// 数字が 6 桁以上届いた。これはプロトコル・エラーとみなす。
										Debug("WebSocket Gua protocol error! t->GuaProto_CurrentSizeStrLen >= 6\n");
										t->GuaProto_HasError_AndIgnore = true;
										break;
									}
								}
								else
								{
									// おかしな文字が届いた。これはプロトコル・エラーとみなす。
									Debug("WebSocket Gua protocol error! t->GuaProto_CurrentSizeStrLen >= 6\n");
									t->GuaProto_HasError_AndIgnore = true;
									break;
								}

								// この受信した文字をバッファに追記する
								WriteBufChar(t->CurrentWebSocketFrame, c);

								break;

							case 1: // 指定されたサイズ分のデータを何も考えずに受信するモードである。
								WriteBufChar(t->CurrentWebSocketFrame, c);
								t->GuaProto_CurrentDataPos++;

								if (t->GuaProto_CurrentDataPos >= t->GuaProto_CurrentDataSize)
								{
									// すべて受信終わった。モードを 2 にする。
									t->GuaProto_Mode = 2;
								}
								break;

							case 2: // ',' で継続、';' で終了するモードである。
								if (c == ',')
								{
									// 継続である。モードを 0 に戻す。
									t->GuaProto_Mode = 0;
									t->GuaProto_CurrentDataSize = 0;
									t->GuaProto_CurrentDataPos = 0;
								}
								else if (c == ';')
								{
									// 終了である。モードを 0 に戻す。
									t->GuaProto_Mode = 0;
									t->GuaProto_CurrentDataSize = 0;
									t->GuaProto_CurrentDataPos = 0;
								}
								else
								{
									// おかしな文字を受信した。プロトコル・エラーである。
									Debug("WebSocket Gua protocol error! c = 0x%X\n");
									t->GuaProto_HasError_AndIgnore = true;
									break;
								}

								WriteBufChar(t->CurrentWebSocketFrame, c);

								if (c == ';')
								{
									// パケットの終了。ここまでたまっているフレームにおいて受信完了とみなす。
									DATABLOCK* new_block = WtNewDataBlock(tunnel_id,
										Clone(t->CurrentWebSocketFrame->Buf, t->CurrentWebSocketFrame->Size),
										t->CurrentWebSocketFrame->Size, 0);

									s->Stat_ServerToClientTraffic += new_block->DataSize;

									InsertQueue(t->BlockQueue, new_block);

									ClearBufEx(t->CurrentWebSocketFrame, true);
								}
								break;
							}

							if (t->GuaProto_HasError_AndIgnore)
							{
								// プロトコルエラーが発生しておるので無視 (危険なので)
								break;
							}
						}
					}
				}

				WtFreeDataBlock(block, false);
			}
		}
		else
		{
			if (block->DataSize == 0)
			{
				// 存在しないクライアントに対して切断指令が送信されようとした
				// ので無視する
				WtFreeDataBlock(block, false);
				continue;
			}

			// 存在しないクライアントに対してデータが送信されようとした
			// のでサーバーに対して切断通知を送信する
			WtFreeDataBlock(block, false);

			if (tunnel_id != last_tid)
			{
				last_tid = tunnel_id;
				send_block = WtNewDataBlock(tunnel_id, NULL, 0, 0);
				dest_queue = s->BlockQueue;
				use_compress = s->ServerTcp->UseCompress;
			}
			else
			{
				send_block = NULL;
			}
		}

		if (send_block != NULL)
		{
			send_block = WtRebuildDataBlock(send_block, use_compress ? 1 : 0);

			if (send_block != NULL)
			{
				s->Stat_ServerToClientTraffic += send_block->DataSize;
			}

			InsertQueue(dest_queue, send_block);
		}
	}

	ReleaseQueue(q);
}

// 新しいブロックを送信キューに追加
void WtInsertNewBlockToQueue(QUEUE *dest_queue, TTCP *dest_ttcp, UINT src_tunnel_id, void *data, UINT size)
{
	DATABLOCK *block;
	// 引数チェック
	if (dest_queue == NULL || dest_ttcp == NULL)
	{
		return;
	}

	block = WtNewDataBlock(src_tunnel_id, data, size, dest_ttcp->UseCompress ? 1 : 0);
	InsertQueue(dest_queue, block);
}

// データブロックの再構築 (古いデータブロックは解放)
DATABLOCK *WtRebuildDataBlock(DATABLOCK *src_block, int compress_flag)
{
	DATABLOCK *ret;
	// 引数チェック
	if (src_block == NULL)
	{
		return NULL;
	}

	if (compress_flag == 0)
	{
		// 無圧縮
		ret = src_block;
	}
	else
	{
		// 圧縮
		ret = WtNewDataBlock(src_block->TunnelId, src_block->Data, src_block->DataSize, compress_flag);
		WtFreeDataBlock(src_block, true);
	}

	return ret;
}

// クライアントからのデータを受信
void WtgRecvFromClient(TSESSION *s)
{
	UINT i;
	DATABLOCK *block;
	// 引数チェック 
	if (s == NULL)
	{
		return;
	}

	// Debug("FifoSize(s->ServerTcp->SendFifo): %u\n", FifoSize(s->ServerTcp->SendFifo));

	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *p = LIST_DATA(s->TunnelList, i);
		TTCP* ttcp = p->ClientTcp;
		WS* ws = p->WebSocket;

		if (FifoSize(s->ServerTcp->SendFifo) > WT_WINDOW_SIZE)
		{
			// サーバー宛の FIFO にデータが溜まりすぎている場合は新たに
			// クライアントからのデータを受信しない

			// タイムアウト防止
			if (ttcp != NULL)
			{
				ttcp->LastCommTime = s->Tick;
			}

			if (ws != NULL)
			{
				ws->LastCommTime = s->Tick;
			}

			continue;
		}

		if (ttcp != NULL)
		{
			// 通常ソケット
			QUEUE* q;

			// TTCP からデータを受信
			WtRecvTTcp(s, ttcp);

			// 受信データを解釈
			q = WtParseRecvTTcp(s, ttcp, p);

			// 受信データをサーバーに転送
			while ((block = GetNext(q)) != NULL)
			{
				if (block->DataSize != 0)
				{
					if (p->Gate_ClientSession_SwitchToWebSocketAcked == false)
					{
						// 通常ケース: WebSocket への切替え前は普通に受信処理を実施
						UINT tunnel_id = p->TunnelId;
						QUEUE* dest_queue;
						DATABLOCK* send_block;
						bool use_compress;

						dest_queue = s->BlockQueue;
						use_compress = s->ServerTcp->UseCompress;
						send_block = WtRebuildDataBlock(block, use_compress ? 1 : 0);

						if (send_block != NULL)
						{
							s->Stat_ClientToServerTraffic += send_block->DataSize;
							send_block->TunnelId = p->TunnelId;

							InsertQueue(dest_queue, send_block);
						}
					}
					else
					{
						// WebSocket への切替え申請後は受信処理をせず、すべての受信データは直ちに破棄する
						// (本来、WebSocket への切り替え申請を行なったクライアントは、それ以降
						//  データを送信してこないはずであるが、誤って送付してきた場合はここで破棄される)
						WtFreeDataBlock(block, false);
					}
				}
				else
				{
					// Keep Alive
					WtFreeDataBlock(block, false);
				}
			}

			ReleaseQueue(q);
		}

		if (ws != NULL)
		{
			// Web Socket からクライアントからのデータを受信 (WT プロトコルにおける最大フレームサイズごとに区切って受信する)
			while (true)
			{
				UINT r = WsRecvAsync(ws, s->RecvBuf, MIN(RECV_BUF_SIZE, WT_MAX_BLOCK_SIZE), s->Tick);
				if (r == 0)
				{
					// 切断された
					WtSessionLog(s, "WtgRecvFromClient: EndPoint [%r]:%u WebSocket is disconnected.",
						&ws->Sock->RemoteIP, ws->Sock->RemotePort);
					break;
				}
				else if (r == INFINITE)
				{
					// これ以上受信データがない
					break;
				}
				else
				{
					// 受信したデータをサーバーに転送
					UINT tunnel_id = p->TunnelId;
					QUEUE* dest_queue = s->BlockQueue;
					DATABLOCK* send_block = WtNewDataBlock(tunnel_id, Clone(s->RecvBuf, r), r, 0);

					s->Stat_ClientToServerTraffic += r;
					send_block->TunnelId = p->TunnelId;

					if (g_show_debug_protocol)
					{
						BUF* b = NewBuf();
						WriteBuf(b, send_block->Data, send_block->DataSize);
						WriteBufChar(b, 0);
						Print("<Recv W2G> \"%s\"\n", b->Buf);
						FreeBuf(b);
					}

					s->Stat_ClientToServerTraffic += send_block->DataSize;

					InsertQueue(dest_queue, send_block);
				}
			}
		}
	}
}

// 受信データを解釈
// tunnel は、Gate --> Client の場合のみ値が入っている
QUEUE *WtParseRecvTTcp(TSESSION *s, TTCP *ttcp, TUNNEL *tunnel)
{
	QUEUE *q;
	FIFO *fifo;
	// 引数チェック
	if (s == NULL || ttcp == NULL)
	{
		return NULL;
	}

	q = NewQueueFast();

	if (ttcp->WantSize == 0)
	{
		ttcp->WantSize = sizeof(UINT);
	}

	fifo = ttcp->RecvFifo;

	while (fifo->size >= ttcp->WantSize)
	{
		UCHAR *buf;
		void *data;
		DATABLOCK *block;
		UINT i;

		buf = (UCHAR *)fifo->p + fifo->pos;

		switch (ttcp->Mode)
		{
		case 0:
			// コネクション番号
			if (ttcp->MultiplexMode == false)
			{
				// 多重化モードでない場合は直接データサイズ受信に飛ぶ
				goto READ_DATA_SIZE;
			}

			ttcp->WantSize = sizeof(UINT);
			Copy(&i, buf, sizeof(UINT));
			ttcp->CurrentBlockConnectionId = Endian32(i);
			ReadFifo(fifo, NULL, sizeof(UINT));

			if (ttcp->CurrentBlockConnectionId != 0)
			{
				ttcp->Mode = 1;
			}
			else
			{
//				Debug("keep alive\n");
			}
			break;

		case 1:
READ_DATA_SIZE:
			// データサイズ
			Copy(&i, buf, sizeof(UINT));
			i = Endian32(i);

			if (i > WT_MAX_BLOCK_SIZE)
			{
				if (i >= WT_SPECIALOPCODE_MIN && i < WT_SPECIALOPCODE_MAX)
				{
					// 特殊コード受信
					ttcp->WantSize = sizeof(UINT);
					ttcp->Mode = 0;
					ReadFifo(fifo, NULL, sizeof(UINT));

					switch (i)
					{
					case WT_SPECIALOPCODE_C2S_SWITCHTOWEBSOCKET_REQUEST_GUACD:
						// WebSocket への切替え要求を受信したので、切替え処理を いたします。
						if (tunnel != NULL)
						{
							if (tunnel->Gate_ClientSession_SwitchToWebSocketRequested == false)
							{
								Debug("Received: Switch to WebSocket\n");
								WtSessionLog(s, "WtParseRecvTTcp: EndPoint [%r]:%u Received the request: Switch to WebSocket", &ttcp->Sock->RemoteIP, ttcp->Sock->RemotePort);
								tunnel->Gate_ClientSession_SwitchToWebSocketRequested = true;
							}
						}
						break;
					}
				}
				else
				{
					// 不正なデータサイズを受信。通信エラーか
					WtSessionLog(s, "WtParseRecvTTcp: EndPoint [%r]:%u Invalid receive data. i > WT_MAX_BLOCK_SIZE. i = %u", &ttcp->Sock->RemoteIP, ttcp->Sock->RemotePort, i);
					ttcp->Disconnected = true;
					ttcp->WantSize = sizeof(UINT);
					ReadFifo(fifo, NULL, sizeof(UINT));
					ttcp->Mode = 0;
				}
			}
			else
			{
				ttcp->CurrentBlockSize = i;
				ReadFifo(fifo, NULL, sizeof(UINT));
				ttcp->WantSize = ttcp->CurrentBlockSize;
				ttcp->Mode = 2;
			}
			break;

		case 2:
			// データ本体
			data = Malloc(ttcp->CurrentBlockSize);
			Copy(data, buf, ttcp->CurrentBlockSize);
			ReadFifo(fifo, NULL, ttcp->CurrentBlockSize);

			if (g_show_debug_protocol) // debugdebug
			{
				if (ttcp->CurrentBlockSize != 0)
				{
					if (tunnel != NULL)
					{
						BUF* b = NewBuf();
						WriteBuf(b, data, ttcp->CurrentBlockSize);
						WriteBufChar(b, 0);
						Print("<Recv C2G> \"%s\"\n", b->Buf);
						FreeBuf(b);
					}
					else
					{
						BUF* b = NewBuf();
						WriteBuf(b, data, ttcp->CurrentBlockSize);
						WriteBufChar(b, 0);
						Print("<Recv S2G> \"%s\"\n", b->Buf);
						FreeBuf(b);
					}
				}
			}

			block = WtNewDataBlock(ttcp->CurrentBlockConnectionId, data, ttcp->CurrentBlockSize,
				ttcp->UseCompress ? -1 : 0);

			InsertQueue(q, block);

			ttcp->WantSize = sizeof(UINT);
			ttcp->Mode = 0;
			break;
		}
	}

	return q;
}

// データブロックの解放
void WtFreeDataBlock(DATABLOCK *block, bool no_free_data)
{
	// 引数チェック
	if (block == NULL)
	{
		return;
	}

	if (no_free_data == false)
	{
		Free(block->Data);
	}

	Free(block);
}

// 新しいデータブロックの作成
DATABLOCK *WtNewDataBlock(UINT tunnel_id, void *data, UINT size, int compress_flag)
{
	DATABLOCK *block;

	if (size == 0 && data == NULL)
	{
		data = Malloc(1);
	}

	block = ZeroMalloc(sizeof(DATABLOCK));

	if (compress_flag == 0)
	{
		// 無圧縮
		block->Compressed = false;
		block->Data = data;
		block->DataSize = block->PhysicalSize = size;
		block->TunnelId = tunnel_id;
	}
	else if (compress_flag > 0)
	{
		UINT max_size;

		// 圧縮
		block->Compressed = true;
		max_size = CalcCompress(size);
		block->Data = Malloc(max_size);
		block->PhysicalSize = Compress(block->Data, max_size, data, size);
		block->DataSize = size;

		Free(data);
	}
	else
	{
		UINT max_size = WT_MAX_BLOCK_SIZE;
		void *tmp;
		UINT sz;

		// 解凍
		tmp = Malloc(max_size);
		sz = Uncompress(tmp, max_size, data, size);
		Free(data);

		block->Data = Clone(tmp, sz);
		Free(tmp);
		block->PhysicalSize = block->DataSize = sz;
	}

	return block;
}

// TTCP にデータを送信
void WtSendTTcp(TSESSION *s, TTCP *ttcp)
{
	SOCK *sock;
	FIFO *fifo;
	// 引数チェック
	if (ttcp == NULL || s == NULL)
	{
		return;
	}
	if (ttcp->Disconnected)
	{
		return;
	}

	sock = ttcp->Sock;
	if (sock->AsyncMode == false)
	{
		return;
	}

	fifo = ttcp->SendFifo;

	while (fifo->size != 0)
	{
		UCHAR *buf;
		UINT want_send_size;
		UINT size;

		buf = (UCHAR *)fifo->p + fifo->pos;
		want_send_size = fifo->size;

		size = WtSendSock(ttcp, buf, want_send_size);
		if (size == 0)
		{
			// 切断された
			ttcp->Disconnected = true;
			WtSessionLog(s, "WtSendTTcp: EndPoint [%r:%u] WtSendSock(): Physical socket is disconnected.",
				&ttcp->Sock->RemoteIP, ttcp->Sock->RemotePort);
			ClearFifo(fifo);
			break;
		}
		else if (size == SOCK_LATER)
		{
			// 送信に時間がかかっている
			break;
		}
		else
		{
			// 送信完了
			ReadFifo(fifo, NULL, size);

			if (ttcp->TunnelUseAggressiveTimeout == false)
			{
				// アグレッシブ・タイムアウト有効時はデータ送信時には LastCommTime は更新しません
				ttcp->LastCommTime = s->Tick;
			}

			s->StateChangedFlag = true;
		}
	}
}

// TTCP からデータを受信
void WtRecvTTcp(TSESSION *s, TTCP *ttcp)
{
	WtRecvTTcpEx(s, ttcp, INFINITE);
}
void WtRecvTTcpEx(TSESSION *s, TTCP *ttcp, UINT remain_buf_size)
{
	SOCK *sock;
	UINT size;
	void *recvbuf = s->RecvBuf;
	// 引数チェック
	if (ttcp == NULL || s == NULL)
	{
		return;
	}
	if (ttcp->Disconnected)
	{
		return;
	}

	sock = ttcp->Sock;
	if (sock->Connected == false)
	{
		WtSessionLog(s, "WtRecvTTcpEx: sock->Connected == false");
		ttcp->Disconnected = true;
		return;
	}
	if (sock->AsyncMode == false)
	{
		return;
	}

	// 受信
RECV_START:
	if (remain_buf_size == 0)
	{
		ttcp->LastCommTime = s->Tick;
		return;
	}
	size = WtRecvSock(ttcp, recvbuf, MIN(RECV_BUF_SIZE, remain_buf_size));
	if (size == 0)
	{
TTCP_DISCONNECTED:
		// コネクションが切断された
		WtSessionLog(s, "WtRecvTTcpEx: WtRecvSock(): EndPoint [%r]:%u Physical socket is disconnected.",
			&ttcp->Sock->RemoteIP, ttcp->Sock->RemotePort);
		ttcp->Disconnected = true;
		return;
	}
	else if (size == SOCK_LATER)
	{
		// 受信待ち
		if ((s->Tick > ttcp->LastCommTime) && ((s->Tick - ttcp->LastCommTime) >= (UINT64)ttcp->TunnelTimeout))
		{
			WtSessionLog(s, "WtIsTTcpDisconnected: EndPoint [%r]:%u Receive timeout detected. ttcp->LastCommTime = %I64u, ttcp->TunnelTimeout = %u, s->Tick = %I64u",
				&ttcp->Sock->RemoteIP, ttcp->Sock->RemotePort, ttcp->LastCommTime, ttcp->TunnelTimeout, s->Tick);
			// タイムアウト発生
			goto TTCP_DISCONNECTED;
		}
	}
	else
	{
		// データを受信
		ttcp->LastCommTime = s->Tick;
		// s->StateChangedFlag = true;

		WriteFifo(ttcp->RecvFifo, recvbuf, size);
		remain_buf_size -= size;

		goto RECV_START;
	}
}

// データの受信
UINT WtRecvSock(TTCP *ttcp, void *buf, UINT size)
{
	// 引数チェック
	if (ttcp == NULL || ttcp->Sock == NULL)
	{
		return 0;
	}

	return Recv(ttcp->Sock, buf, size, ttcp->Sock->SecureMode);
}

// データの送信
UINT WtSendSock(TTCP *ttcp, void *buf, UINT size)
{
	// 引数チェック
	if (ttcp == NULL || ttcp->Sock == NULL)
	{
		return 0;
	}

	return Send(ttcp->Sock, buf, size, ttcp->Sock->SecureMode);
}

// ソケットイベントを待機
void WtgWaitForSock(TSESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	Lock(s->Lock);
	{
		UINT i;

		// サーバーとのソケット
		SOCK *sock = s->ServerTcp->Sock;
		JoinSockToSockEvent(sock, s->SockEvent);

		// クライアントとの複数トンネルの各ソケット
		for (i = 0;i < LIST_NUM(s->TunnelList);i++)
		{
			TUNNEL *p = LIST_DATA(s->TunnelList, i);

			// 通常のソケット
			SOCK *sock = p->ClientTcp->Sock;
			JoinSockToSockEvent(sock, s->SockEvent);

			// WebSocket
			WS* websock = p->WebSocket;
			if (websock != NULL)
			{
				JoinSockToSockEvent(websock->Sock, s->SockEvent);
			}
		}
	}
	Unlock(s->Lock);

	WaitSockEvent(s->SockEvent, SELECT_TIME);

	s->Tick = Tick64();
}

// SNI 名を見て WebSocket 用証明書を利用するかどうか判断するコールバック関数
bool WtgDetermineWebSocketSslCertUseCallback(char* sni_name, void* param)
{
	if (sni_name == NULL)
	{
		return false;
	}

	return StartWith(sni_name, WIDE_WEBSOCKET_SNI_NAME_STARTWITH1) ||
		StartWith(sni_name, WIDE_WEBSOCKET_SNI_NAME_STARTWITH2) ||
		InStr(sni_name, WIDE_WEBSOCKET_SNI_NAME_INSTR1) ||
		InStr(sni_name, WIDE_WEBSOCKET_SNI_NAME_INSTR2);
}

// SNI 名を見て WebApp 用証明書を利用するかどうか判断するコールバック関数
bool WtgDetermineWebAppSslCertUseCallback(char* sni_name, void* param)
{
	if (sni_name == NULL)
	{
		return false;
	}

	return StartWith(sni_name, WIDE_WEBAPP_SNI_NAME_STARTWITH1) ||
		StartWith(sni_name, WIDE_WEBAPP_SNI_NAME_STARTWITH2) ||
		StartWith(sni_name, WIDE_WEBAPP_SNI_NAME_STARTWITH3) ||
		StartWith(sni_name, WIDE_WEBAPP_SNI_NAME_STARTWITH4) ||
		InStr(sni_name, WIDE_WEBAPP_SNI_NAME_INSTR1) ||
		InStr(sni_name, WIDE_WEBAPP_SNI_NAME_INSTR2) ||
		InStr(sni_name, WIDE_WEBAPP_SNI_NAME_INSTR3) ||
		InStr(sni_name, WIDE_WEBAPP_SNI_NAME_INSTR4);
}

// Gate による接続受付
void WtgAccept(WT *wt, SOCK *s)
{
	PACK *p;
	UCHAR session_id[WT_SESSION_ID_SIZE];
	WT_GATE_CONNECT_PARAM param;
	UINT code;
	char method[128];
	bool use_compress = false;
	TSESSION *session = NULL;
	char ip_str[MAX_PATH];
	bool support_timeout_param = false;
	bool check_ssl_ok = false;

	UINT tunnel_timeout = WT_TUNNEL_TIMEOUT;
	UINT tunnel_keepalive = WT_TUNNEL_KEEPALIVE;
	bool tunnel_use_aggressive_timeout = false;

	bool continue_ok = false;

	// 引数チェック
	if (wt == NULL || s == NULL)
	{
		return;
	}

	char log_prefix[MAX_PATH] = CLEAN;

	Format(log_prefix, sizeof(log_prefix), "AcceptNewSession/ClientIP=%r/ClientPort=%u/ServerIP=%r/ServerPort=%u", &s->RemoteIP, s->RemotePort, &s->LocalIP, s->LocalPort);

	StatManReportInt64(wt->StatMan, "WtgConnectedTcp_Total", 1);

	if (IsEmptyStr(wt->EntranceUrlForProxy))
	{
		WideLoadEntryPoint(NULL, wt->EntranceUrlForProxy, sizeof(wt->EntranceUrlForProxy), NULL, NULL, 0, NULL, 0);
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	Debug("WtgAccept() from %s\n", ip_str);
	WtLogEx(wt, log_prefix, "WtgAccept() started.");

	SetTimeout(s, CONNECTING_TIMEOUT);

	//SetSocketSendRecvBufferSize((int)s, WT_SOCKET_WINDOW_SIZE);

	// セッション ID の生成
	Rand(session_id, sizeof(session_id));

	char session_id_str[64] = CLEAN;
	BinToStr(session_id_str, sizeof(session_id_str), session_id, sizeof(session_id));

	//SetWantToUseCipher(s, "RC4-MD5");

	// SSL 通信の開始
	// SSL バージョン無効化
	s->SslAcceptSettings.AcceptOnlyTls = Vars_ActivePatch_GetBool("WtGateDisableSsl3");
	s->SslAcceptSettings.Tls_Disable1_0 = Vars_ActivePatch_GetBool("WtGateDisableTls1_0");
	s->SslAcceptSettings.Tls_Disable1_1 = Vars_ActivePatch_GetBool("WtGateDisableTls1_1"); 
	s->SslAcceptSettings.Tls_Disable1_2 = Vars_ActivePatch_GetBool("WtGateDisableTls1_2");
	s->SslAcceptSettings.Tls_Disable1_3 = Vars_ActivePatch_GetBool("WtGateDisableTls1_3");


	// WebSocket 用, WebApp 用証明書の取得
	CERTS_AND_KEY* ssl_additional_certs_array[2] = CLEAN;
	UINT num_certs_array_items = 0;

	CERTS_AND_KEY* web_socket_certs = NULL;
	CERTS_AND_KEY* web_app_certs = NULL;
	
	if (wt->IsStandaloneMode)
	{
		// スタンドアロンモードの場合、WebApp 証明書を読み込む
		web_app_certs = WideGetWebAppCertsAndKey(wt->Wide);
	}
	else
	{
		// 通常モードの場合、WebSocket 証明書を読み込む
		web_socket_certs = WideGetWebSocketCertsAndKey(wt->Wide);
	}

	if (web_socket_certs != NULL)
	{
		web_socket_certs->DetermineUseCallback = WtgDetermineWebSocketSslCertUseCallback;
		ssl_additional_certs_array[num_certs_array_items] = web_socket_certs;
		num_certs_array_items++;
	}

	if (web_app_certs != NULL)
	{
		web_app_certs->DetermineUseCallback = WtgDetermineWebAppSslCertUseCallback;
		ssl_additional_certs_array[num_certs_array_items] = web_app_certs;
		num_certs_array_items++;
	}

	WtLogEx(wt, log_prefix, "Trying StartSSLEx2()...");

	if (StartSSLEx2(s, wt->GateCert, wt->GateKey, true, 0, NULL, ssl_additional_certs_array, num_certs_array_items, NULL) == false)
	{
		WtLogEx(wt, log_prefix, "StartSSLEx2() error. Connection will be disconnected.");
		Debug("StartSSL Failed.\n");

		AddNoSsl(wt->Cedar, &s->RemoteIP);

		FreeCertsAndKey(web_socket_certs);
		FreeCertsAndKey(web_app_certs);

		return;
	}

	WtLogEx(wt, log_prefix, "SSL connection is established. SNI hostname: '%s', Cipher: '%s'.",
		s->SniHostname, s->CipherName);

	if (s->LocalX != NULL)
	{
		wchar_t x_names[MAX_PATH] = CLEAN;
		GetAllNameFromName(x_names, sizeof(x_names), s->LocalX->subject_name);
		WtLogEx(wt, log_prefix, "Selected Server Certificate: %S\n", x_names);
	}

	FreeCertsAndKey(web_socket_certs);
	FreeCertsAndKey(web_app_certs);

	// シグネチャのダウンロード
	continue_ok = WtgDownloadSignature(wt, s, &check_ssl_ok, wt->Wide->GateKeyStr, wt->EntranceUrlForProxy, wt->ProxyTargetUrlList);

	if (check_ssl_ok)
	{
		DecrementNoSsl(wt->Cedar, &s->RemoteIP, 2);
	}

	if (continue_ok == false)
	{
		return;
	}

	WtLogEx(wt, log_prefix, "WtgDownloadSignature OK.");

	// Hello パケットのアップロード
	if (WtgUploadHello(wt, s, session_id) == false)
	{
		Debug("WtgUploadHello Failed.\n");
		WtLogEx(wt, log_prefix, "WtgUploadHello Error.");
		WtgSendError(s, ERR_PROTOCOL_ERROR);
		return;
	}
	WtLogEx(wt, log_prefix, "WtgUploadHello OK.");

	// 接続パラメータのダウンロード
	p = HttpServerRecv(s);
	if (p == NULL)
	{
		Debug("HttpServerRecv Failed.\n");
		WtLogEx(wt, log_prefix, "HttpServerRecv Error.");
		WtgSendError(s, ERR_PROTOCOL_ERROR);
		return;
	}
	WtLogEx(wt, log_prefix, "HttpServerRecv OK.");

	if (PackGetStr(p, "method", method, sizeof(method)) == false)
	{
		FreePack(p);
		WtgSendError(s, ERR_PROTOCOL_ERROR);
		return;
	}

	support_timeout_param = PackGetBool(p, "support_timeout_param");

	if (support_timeout_param)
	{
		WideGateLoadAggressiveTimeoutSettingsWithInterval(wt->Wide);

		tunnel_timeout = wt->Wide->GateTunnelTimeout;
		tunnel_keepalive = wt->Wide->GateTunnelKeepAlive;
		tunnel_use_aggressive_timeout = wt->Wide->GateTunnelUseAggressiveTimeout;
	}

	bool is_trusted = PackGetBool(p, "is_trusted");
	char trusted_real_client_ip[128] = CLEAN;
	char trusted_real_client_fqdn[MAX_PATH] = CLEAN;
	UINT trusted_real_client_port = PackGetInt(p, "trusted_real_client_port");
	PackGetStr(p, "trusted_real_client_ip", trusted_real_client_ip, sizeof(trusted_real_client_ip));
	PackGetStr(p, "trusted_real_client_fqdn", trusted_real_client_fqdn, sizeof(trusted_real_client_fqdn));

	// trusted 情報の認証
	if (is_trusted)
	{
		bool ok = false;
		char tmp[512] = CLEAN;
		char sha1[SHA1_SIZE] = CLEAN;
		char sha1_received[SHA1_SIZE] = CLEAN;
		Format(tmp, sizeof(tmp), "%s/%s/%u/%s", trusted_real_client_ip, trusted_real_client_fqdn, trusted_real_client_port, wt->Wide->ControllerGateSecretKey);
		HashSha1(sha1, tmp, StrLen(tmp));

		if (PackGetData2(p, "trusted_auth_sha1", sha1_received, SHA1_SIZE))
		{
			if (Cmp(sha1_received, sha1, SHA1_SIZE) == 0)
			{
				ok = true;
			}
		}

		if (ok == false)
		{
			// 認証失敗
			FreePack(p);
			WtgSendError(s, ERR_DESK_SECRET_KEY_INVALID);
			return;
		}
	}

	IP local_ip = CLEAN;
	PackGetIp(p, "local_ip", &local_ip);

	wchar_t local_hostname[128] = CLEAN;
	PackGetUniStr(p, "local_hostname", local_hostname, sizeof(local_hostname));

	char local_version[128] = CLEAN;
	PackGetStr(p, "local_version", local_version, sizeof(local_version));

	WtLogEx(wt, log_prefix, "Method=%s,support_timeout_param=%u,tunnel_timeout=%u,"
		"tunnel_keepalive=%u,tunnel_use_aggressive_timeout=%u,"
		"local_ip=%r,local_hostname=%S,local_version=%s",
		method, support_timeout_param, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout,
		&local_ip, local_hostname, local_version);

	Debug("method: %s\n", method);
	if (StrCmpi(method, "new_session") == 0)
	{
		WtLogEx(wt, log_prefix, "Accepting new server session.");

		bool request_initial_pack;
		UINT64 server_mask_64 = 0;
		// 新しいセッションの確立
		Zero(&param, sizeof(param));
		if (WtGateConnectParamFromPack(&param, p) == false)
		{
			Debug("WtGateConnectParamFromPack failed.\n");
			WtLogEx(wt, log_prefix, "WtGateConnectParamFromPack Error.");
			FreePack(p);
			return;
		}

		// パラメータの取得
		use_compress = PackGetBool(p, "use_compress");
		use_compress = false; // 圧縮は強制無効化

		request_initial_pack = PackGetBool(p, "request_initial_pack");
		server_mask_64 = PackGetInt64(p, "server_mask_64");

		FreePack(p);

		WtLogEx(wt, log_prefix, "WtGateConnectParamFromPack OK. server_mask_64=%u", server_mask_64);

		// 接続パラメータの電子署名のチェック
		if (WtGateConnectParamCheckSignature(wt->Wide, &param) == false)
		{
			WtgSendError(s, ERR_PROTOCOL_ERROR);
			Debug("WtGateConnectParamCheckSignature Failed.\n");
			WtLogEx(wt, log_prefix, "WtGateConnectParamCheckSignature Error.");
			return;
		}

		WtLogEx(wt, log_prefix, "WtGateConnectParamCheckSignature OK.");

		// GateID のチェック
		if (Cmp(wt->GateId, param.GateId, SHA1_SIZE) != 0)
		{
			WtgSendError(s, ERR_PROTOCOL_ERROR);
			Debug("Cmp GateID Failed.\n");
			WtLogEx(wt, log_prefix, "Cmp GateID Failed.");
			return;
		}
		WtLogEx(wt, log_prefix, "Cmp GateID OK.");

		// 有効期限のチェック
		if (param.Expires < SystemTime64())
		{
			WtgSendError(s, ERR_PROTOCOL_ERROR);
			Debug("Expires Failed.\n");
			WtLogEx(wt, log_prefix, "Expires Failed. %I64u < %I64u", param.Expires, SystemTime64());
			return;
		}

		code = ERR_NO_ERROR;

		LockList(wt->SessionList);
		{
			// 既に同一の MSID を持つセッションが存在しないかどうか確認
			UINT i;
			bool exists = false;

			if (false)
			{
				for (i = 0;i < LIST_NUM(wt->SessionList);i++)
				{
					TSESSION *s = LIST_DATA(wt->SessionList, i);

					if (StrCmpi(s->Msid, param.Msid) == 0)
					{
						// 同一の MSID を持ったセッションを発見
						//exists = true;
						// 同一の MSID を持ったセッションが存在しても構わず接続させる
						break;
					}
				}
			}

			if (exists == false)
			{
				// セッションの作成
				TSESSION *sess = WtgNewSession(wt, s, param.Msid, session_id, use_compress, request_initial_pack, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout,
					&local_ip, local_hostname, local_version);

				sess->ServerMask64 = server_mask_64;

				Insert(wt->SessionList, sess);

				session = sess;
			}
			else
			{
				// すでに接続されている
				code = ERR_MACHINE_ALREADY_CONNECTED;
				Debug("Error: ERR_MACHINE_ALREADY_CONNECTED.\n");
				WtLogEx(wt, log_prefix, "Error: ERR_MACHINE_ALREADY_CONNECTED.");
			}
		}
		UnlockList(wt->SessionList);

		if (code != ERR_NO_ERROR)
		{
			// セッションの確立に失敗
			WtgSendError(s, code);
			return;
		}

		// 接続成功。
		p = NewPack();
		PackAddInt(p, "code", ERR_NO_ERROR);
		PackAddInt(p, "tunnel_timeout", tunnel_timeout);
		PackAddInt(p, "tunnel_keepalive", tunnel_keepalive);
		PackAddInt(p, "tunnel_use_aggressive_timeout", tunnel_use_aggressive_timeout);
		HttpServerSend(s, p);
		FreePack(p);

		SetTimeout(s, TIMEOUT_INFINITE);

		StatManReportInt64(wt->StatMan, "WtgConnnectedServerSessions_Total", 1);

		WtLogEx(wt, log_prefix, "New Server Session Established. SessionID=%s,tunnel_timeout=%u,tunnel_keepalive=%u,tunnel_use_aggressive_timeout=%u",
			session_id_str, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout);

		// セッションメイン
		WtgSessionMain(session);

		WtLogEx(wt, log_prefix, "Server Session Disconnected. SessionID=%s", session_id_str);

		LockList(wt->SessionList);
		{
			// セッションの削除
			Delete(wt->SessionList, session);
		}
		UnlockList(wt->SessionList);

		WtReleaseSession(session);
	}
	else if (StrCmpi(method, "connect_session") == 0)
	{
		WtLogEx(wt, log_prefix, "Accepting new client session.");

		// 既存のセッションへの接続
		char session_id[WT_SESSION_ID_SIZE];
		UCHAR client_id[SHA1_SIZE];
		TSESSION *session = NULL;

		Zero(client_id, sizeof(client_id));

		// パラメータの取得
		use_compress = PackGetBool(p, "use_compress");
		use_compress = false; // 圧縮は強制無効化

		Zero(session_id, sizeof(session_id));
		PackGetData2(p, "session_id", session_id, sizeof(session_id));

		PackGetData2(p, "rand", rand, SHA1_SIZE);

		// Client ID
		PackGetData2(p, "client_id", client_id, sizeof(client_id));
		if (IsZero(client_id, sizeof(client_id)))
		{
			// Client ID を IP アドレスから生成
			WtGenerateClientIdFromIP(client_id, &s->RemoteIP);
		}

		FreePack(p);

		BinToStr(session_id_str, sizeof(session_id_str), session_id, sizeof(session_id));

		WtLogEx(wt, log_prefix, "Accepting new client session. Client Requested Session ID: %s", session_id_str);

		// セッションの検索
		LockList(wt->SessionList);
		{
			if (true)
			{
				// 正規動作: セッションの検索
				TSESSION t;

				Zero(&t, sizeof(t));
				Copy(t.SessionId, session_id, WT_SESSION_ID_SIZE);

				session = Search(wt->SessionList, &t);

				if (session != NULL)
				{
					AddRef(session->Ref);
				}
			}
			else
			{
				// デバッグ動作: 1 番目のセッションを選択
				if (LIST_NUM(wt->SessionList) >= 1)
				{
					session = LIST_DATA(wt->SessionList, 0);
					AddRef(session->Ref);
				}
			}
		}
		UnlockList(wt->SessionList);

		if (session == NULL)
		{
			// 指定されたセッション ID は存在しない
			WtgSendError(s, ERR_DEST_MACHINE_NOT_EXISTS);
			Debug("Error: ERR_DEST_MACHINE_NOT_EXISTS\n");
			WtLogEx(wt, log_prefix, "Error: No Session ID '%s' found on this gate.", session_id_str);
			return;
		}

		if (LIST_NUM(session->TunnelList) > WT_MAX_TUNNELS_PER_SESSION)
		{
			// セッションあたりトンネル数が多すぎる
			WtReleaseSession(session);
			WtgSendError(s, ERR_TOO_MANY_CONNECTION);
			Debug("Error: ERR_TOO_MANY_CONNECTION\n");
			WtLogEx(wt, log_prefix, "Error: ERR_TOO_MANY_CONNECTION. %u > %u",
				LIST_NUM(session->TunnelList), WT_MAX_TUNNELS_PER_SESSION);
			return;
		}

		// 接続成功。
		UCHAR rand[SHA1_SIZE] = CLEAN;
		Rand(rand, sizeof(rand));
		char websocket_token2[128] = CLEAN;
		BinToStr(websocket_token2, sizeof(websocket_token2), rand, sizeof(rand));

		char websocket_url[MAX_PATH] = CLEAN;
		Format(websocket_url, sizeof(websocket_url), "/websocket/%s-%s", session->WebSocketToken1, websocket_token2);

		p = NewPack();
		PackAddInt(p, "code", ERR_NO_ERROR);
		PackAddInt(p, "tunnel_timeout", tunnel_timeout);
		PackAddInt(p, "tunnel_keepalive", tunnel_keepalive);
		PackAddInt(p, "tunnel_use_aggressive_timeout", tunnel_use_aggressive_timeout);
		PackAddStr(p, "websocket_url", websocket_url);
		HttpServerSend(s, p);
		FreePack(p);

		WtLogEx(wt, log_prefix, "Client Session Connect OK."
			" tunnel_timeout=%u,tunnel_keepalive=%u,tunnel_use_aggressive_timeout=%u,websocket_url=%s",
			tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout, websocket_url);

		SetTimeout(s, TIMEOUT_INFINITE);

		StatManReportInt64(wt->StatMan, "WtgConnnectedClientSessions_Total", 1);

		Lock(session->Lock);
		{
			// 新しいトンネルの生成
			UINT tunnel_id = WtgGenerateNewTunnelId(session);
			TUNNEL *tunnel;
			TTCP *ttcp;

			Debug("New Tunnel: %u\n", tunnel_id);

			WtLogEx(wt, log_prefix, "New Tunnel ID %u is now joined to the Session ID %s.\n", tunnel_id, session_id_str);

			ttcp = WtNewTTcp(s, use_compress, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout);

			tunnel = WtNewTunnel(ttcp, tunnel_id, NULL, websocket_token2);
			Copy(tunnel->ClientId, client_id, sizeof(client_id));
			Insert(session->TunnelList, tunnel);

			// Initial Pack の作成
			if (session->RequestInitialPack)
			{
				PACK *p = NewPack();
				BUF *b;
				UCHAR *buffer;

				if (is_trusted == false)
				{
					PackAddIp(p, "ClientIP", &s->RemoteIP);
					PackAddInt(p, "ClientPort", s->RemotePort);
					PackAddStr(p, "ClientHost", s->RemoteHostname);
				}
				else
				{
					IP ip_tmp = CLEAN;
					StrToIP(&ip_tmp, trusted_real_client_ip);
					PackAddIp(p, "ClientIP", &ip_tmp);
					PackAddInt(p, "ClientPort", trusted_real_client_port);
					PackAddStr(p, "ClientHost", trusted_real_client_fqdn);
					PackAddBool(p, "is_trusted", true);

					PackAddIp(p, "TrustedIP", &s->RemoteIP);
					PackAddInt(p, "TrustedPort", s->RemotePort);
					PackAddStr(p, "TruestedHost", s->RemoteHostname);
				}

				PackAddIp(p, "GateIP", &s->LocalIP);
				PackAddInt(p, "GatePort", s->LocalPort);
				PackAddInt64(p, "ClientConnectedTime", SystemTime64());
				PackAddInt(p, "TunnelId", tunnel_id);
				PackAddData(p, "ClientID", tunnel->ClientId, sizeof(tunnel->ClientId));

				b = PackToBuf(p);
				FreePack(p);

				buffer = ZeroMalloc(WT_INITIAL_PACK_SIZE);
				Copy(buffer, b->Buf, MIN(b->Size, WT_INITIAL_PACK_SIZE));
				FreeBuf(b);

				if (true)
				{
					DATABLOCK *block = WtNewDataBlock(tunnel_id, buffer, WT_INITIAL_PACK_SIZE,
						session->ServerTcp->UseCompress ? 1 : 0);
					block->TunnelId = tunnel_id;

					InsertQueue(session->BlockQueue, block);
				}
			}
		}
		Unlock(session->Lock);

		SetSockEvent(session->SockEvent);

		WtReleaseSession(session);
	}
}

// クライアント ID を IP アドレスから生成する
void WtGenerateClientIdFromIP(UCHAR *client_id, IP *ip)
{
	char ipstr[MAX_PATH];
	// 引数チェック
	if (client_id == NULL || ip == NULL)
	{
		return;
	}

	IPToStr(ipstr, sizeof(ipstr), ip);

	HashSha1(client_id, ipstr, StrLen(ipstr));
}

// 新しいトンネル ID の決定
UINT WtgGenerateNewTunnelId(TSESSION *s)
{
	UINT id = Rand32();
	LIST *o;
	UINT i = 0;
	// 引数チェック
	if (s == NULL)
	{
		return 0;
	}

	o = s->TunnelList;

	while (true)
	{
		TUNNEL *t;

		while (true)
		{
			id = Rand32();
			if (id != 0 && id != INFINITE)
			{
				break;
			}
		}

		if (WtIsTunnelIdExistsInUsedTunnelIdList(s->UsedTunnelList, id) == false)
		{
			t = WtgSearchTunnelById(o, id);
			if (t == NULL)
			{
				break;
			}
		}
	}

	return id;
}

// 新しいトンネルの作成
TUNNEL* WtNewTunnel(TTCP* client_tcp, UINT tunnel_id, SOCKIO* sockio, char* websocket_token2)
{
	TUNNEL *p;

	p = ZeroMalloc(sizeof(TUNNEL));
	p->BlockQueue = NewQueue();
	p->ClientTcp = client_tcp;
	p->TunnelId = tunnel_id;

	if (sockio != NULL)
	{
		p->SockIo = sockio;
		AddRef(sockio->Ref);
	}

	StrCpy(p->WebSocketToken2, sizeof(p->WebSocketToken2), websocket_token2);

	return p;
}

// Gate 上のセッションの作成
TSESSION* WtgNewSession(WT* wt, SOCK* sock, char* msid, void* session_id, bool use_compress, bool request_initial_pack, UINT tunnel_timeout, UINT tunnel_keepalive, bool tunnel_use_aggressive_timeout,
	IP* local_ip, wchar_t* local_hostname, char* local_version)
{
	TSESSION *s;
	// 引数チェック
	if (msid == NULL || session_id == NULL || sock == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(TSESSION));
	s->Lock = NewLock();
	s->Ref = NewRef();
	s->SessionType = WT_SESSION_GATE;
	StrCpy(s->Msid, sizeof(s->Msid), msid);
	Copy(s->SessionId, session_id, WT_SESSION_ID_SIZE);
	s->EstablishedTick = Tick64();
	s->ServerTcp = WtNewTTcp(sock, use_compress, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout);
	s->ServerTcp->MultiplexMode = true;
	s->BlockQueue = NewQueue();
	s->SockEvent = NewSockEvent();
	s->TunnelList = NewList(WtgCompareTunnel);
	s->RecvBuf = Malloc(RECV_BUF_SIZE);
	s->UsedTunnelList = WtNewUsedTunnelIdList();
	s->RequestInitialPack = request_initial_pack;
	s->wt = wt;

	CopyIP(&s->LocalIp, local_ip);
	UniStrCpy(s->LocalHostname, sizeof(s->LocalHostname), local_hostname);
	StrCpy(s->LocalVersion, sizeof(s->LocalVersion), local_version);

	UCHAR rand[SHA1_SIZE] = CLEAN;
	Rand(rand, sizeof(rand));
	BinToStr(s->WebSocketToken1, sizeof(s->WebSocketToken1), rand, sizeof(rand));

	return s;
}

// セッションの解放
void WtReleaseSession(TSESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (Release(s->Ref) == 0)
	{
		WtCleanupSession(s);
	}
}

// セッションのクリーンアップ
void WtCleanupSession(TSESSION *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	WtFreeDataBlockQueue(s->BlockQueue);

	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *t = LIST_DATA(s->TunnelList, i);

		WtFreeTunnel(t);
	}

	ReleaseList(s->TunnelList);
	DeleteLock(s->Lock);
	ReleaseSockEvent(s->SockEvent);
	Free(s->RecvBuf);
	WtFreeTTcp(s->ServerTcp);

	Disconnect(s->Sock);
	ReleaseSock(s->Sock);
	ReleaseThread(s->ConnectThread);
	if (s->ConnectParam != NULL)
	{
		WtFreeConnect(s->ConnectParam);
		Free(s->ConnectParam);
	}

	ReleaseList(s->AcceptThreadList);

	WtFreeTTcp(s->GateTcp);

	WtFreeUsedTunnelIdList(s->UsedTunnelList);

	WtFreeTunnel(s->ClientTunnel);

	Free(s);
}

// データブロックの入ったキューを解放
void WtFreeDataBlockQueue(QUEUE *q)
{
	DATABLOCK *block;
	// 引数チェック
	if (q == NULL)
	{
		return;
	}

	while ((block = GetNext(q)) != NULL)
	{
		WtFreeDataBlock(block, false);
	}

	ReleaseQueue(q);
}

// トンネルの解放
void WtFreeTunnel(TUNNEL *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	if (t->WebSocket != NULL)
	{
		Disconnect(t->WebSocket->Sock);
		ReleaseWs(t->WebSocket);
	}

	WtFreeDataBlockQueue(t->BlockQueue);
	WtFreeTTcp(t->ClientTcp);
	SockIoDisconnect(t->SockIo);
	ReleaseSockIo(t->SockIo);
	FreeBuf(t->CurrentWebSocketFrame);

	Free(t);
}

// TTCP の解放
void WtFreeTTcp(TTCP *ttcp)
{
	// 引数チェック
	if (ttcp == NULL)
	{
		return;
	}

	Disconnect(ttcp->Sock);
	ReleaseSock(ttcp->Sock);
	ReleaseFifo(ttcp->SendFifo);
	ReleaseFifo(ttcp->RecvFifo);

	Free(ttcp);
}

// TTCP の作成
TTCP *WtNewTTcp(SOCK *s, bool use_compress, UINT tunnel_timeout, UINT tunnel_keepalive, bool tunnel_use_aggressive_timeout)
{
	TTCP *t;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TTCP));
	t->Sock = s;
	StrCpy(t->Hostname, sizeof(t->Hostname), s->RemoteHostname);
	Copy(&t->Ip, &s->RemoteIP, sizeof(IP));
	t->Port = s->RemotePort;
	t->LastCommTime = Tick64();
	t->RecvFifo = NewFifo();
	t->SendFifo = NewFifo();
	t->UseCompress = use_compress;
	t->TunnelTimeout = tunnel_timeout;
	t->TunnelKeepAlive = tunnel_keepalive;
	t->TunnelUseAggressiveTimeout = tunnel_use_aggressive_timeout;
	AddRef(s->ref);

	return t;
}

// トンネルリストからトンネルの取得
TUNNEL *WtgSearchTunnelById(LIST *o, UINT id)
{
	TUNNEL t, *ret;
	// 引数チェック
	if (o == NULL || id == 0)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.TunnelId = id;

	ret = Search(o, &t);

	return ret;
}

// トンネルリストの比較
int WtgCompareTunnel(void *p1, void *p2)
{
	TUNNEL *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(TUNNEL **)p1;
	t2 = *(TUNNEL **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	if (t1->TunnelId > t2->TunnelId)
	{
		return 1;
	}
	else if (t1->TunnelId < t2->TunnelId)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// セッションリストの比較
int WtgCompareSession(void *p1, void *p2)
{
	TSESSION *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(TSESSION **)p1;
	s2 = *(TSESSION **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	return Cmp(s1->SessionId, s2->SessionId, WT_SESSION_ID_SIZE);
}

// エラーの送信
bool WtgSendError(SOCK *s, UINT code)
{
	PACK *p;
	bool ret;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	p = NewPack();
	PackAddInt(p, "code", code);

	ret = HttpServerSend(s, p);
	FreePack(p);

	return ret;
}

// Hello パケットのアップロード
bool WtgUploadHello(WT *wt, SOCK *s, void *session_id)
{
	PACK *p;
	// 引数チェック
	if (wt == NULL || s == NULL || session_id == NULL)
	{
		return false;
	}

	p = NewPack();
	PackAddData(p, "session_id", session_id, WT_SESSION_ID_SIZE);
	PackAddInt(p, "hello", 1);

	if(HttpServerSend(s, p) == false)
	{
		FreePack(p);
		return false;
	}

	FreePack(p);

	return true;
}

// シグネチャのダウンロード
bool WtgDownloadSignature(WT* wt, SOCK* s, bool* check_ssl_ok, char* gate_secret_key, char* entrance_url_for_proxy, LIST* entrance_url_list_for_proxy)
{
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	UINT num = 0, max = 19;
	static bool dummy = false;
	if (check_ssl_ok == NULL)
	{
		check_ssl_ok = &dummy;
	}
	*check_ssl_ok = false;
	// 引数チェック
	if (s == NULL || wt == NULL)
	{
		return false;
	}

	char log_prefix[MAX_PATH] = CLEAN;

	Format(log_prefix, sizeof(log_prefix), "AcceptNewSession(HTTPSvr)/ClientIP=%r/ClientPort=%u/ServerIP=%r/ServerPort=%u", &s->RemoteIP, s->RemotePort, &s->LocalIP, s->LocalPort);

	while (true)
	{
		num++;
		if (num > max)
		{
			// 切断
			return false;
		}
		// ヘッダを受信する
		UINT max_line_size = 0;
		if (wt->IsStandaloneMode)
		{
			max_line_size = WTG_HTTP_PROXY_FOR_WEBAPP_MAX_HTTP_LINE_SIZE;
		}
		h = RecvHttpHeader(s, max_line_size, max_line_size);
		if (h == NULL)
		{
			return false;
		}

		WtLogEx(wt, log_prefix, "HTTP Target Path: '%s'", h->Target);

		// 解釈する
		if (StartWith(h->Target, "/widecontrol/") || StartWith(h->Target, "/thincontrol/"))
		{
			if (wt->IsStandaloneMode)
			{
				HttpSendNotFound(s, h->Target);
				FreeHttpHeader(h);
			}
			else
			{
				char url[MAX_PATH];

				Debug("widecontrol request proxy: '%s'\n", h->Target);

				StrCpy(url, sizeof(url), entrance_url_for_proxy);

				ReplaceStrEx(url, sizeof(url), url, "https://", "http://", false);

				WtgHttpProxy(url, s, s->SecureMode, h, gate_secret_key, entrance_url_list_for_proxy);

				*check_ssl_ok = true;

				FreeHttpHeader(h);

				return false;
			}
		}
		else if (StartWith(h->Target, "/websocket/"))
		{
			// WebSocket Mode
			bool ws_ok = WtgWebSocketGetHandler(wt, s, h, h->Target);

			FreeHttpHeader(h);

			if (ws_ok)
			{
				return false;
			}

			continue;
		}
		else if (StartWith(h->Target, "/thingate/") && wt->IsStandaloneMode)
		{
			// ThinGate Standalone Mode
			char* recv_str = NULL;

			if (StrCmpi(h->Method, "POST") == 0)
			{
				// POST なのでデータを受信する
				data_size = GetContentLength(h);
				if (data_size > WTG_SAM_MAX_RECVSTR_SIZE)
				{
					// データが大きすぎる
					HttpSendForbidden(s, h->Target, NULL);
					FreeHttpHeader(h);
					return false;
				}
				data = ZeroMalloc(data_size + 2);
				if (RecvAll(s, data, data_size, s->SecureMode) == false)
				{
					// データ受信失敗
					Free(data);
					FreeHttpHeader(h);
					return false;
				}

				recv_str = data;
			}
			else
			{
				recv_str = CopyStr("");
			}

			WtgSamProcessRequestStr(wt, s, recv_str);

			Free(recv_str);

			*check_ssl_ok = true;

			FreeHttpHeader(h);
			
			return false;
		}
		else if (StartWith(h->Target, "/thinstat/") && wt->IsStandaloneMode)
		{
			WtgSamProcessStat(wt, s, h->Target);

			*check_ssl_ok = true;

			FreeHttpHeader(h);

			return false;
		}
		else if (StrCmpi(h->Target, HTTP_WIDE_TARGET2) == 0 && StrCmpi(h->Method, "POST") == 0)
		{
			// POST なのでデータを受信する
			data_size = GetContentLength(h);
			if (data_size > MAX_WATERMARK_SIZE || data_size < SizeOfWaterMark())
			{
				// データが大きすぎる
				HttpSendForbidden(s, h->Target, NULL);
				FreeHttpHeader(h);
				return false;
			}
			// Watermark を受信する
			data = ZeroMalloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false)
			{
				// データ受信失敗
				Free(data);
				FreeHttpHeader(h);
				return false;
			}
			// Watermark を確認する
			if (Cmp(data, GetWaterMark(), SizeOfWaterMark()) != 0)
			{
				// Watermark 不正
				Free(data);
				FreeHttpHeader(h);
				return false;
			}

			Free(data);
			FreeHttpHeader(h);

			*check_ssl_ok = true;
			return true;
		}
		else
		{
			if (wt->IsStandaloneMode)
			{
				// Standalone Mode の場合、WebApp へのプロキシを動作させる
				*check_ssl_ok = true;

				WtgHttpProxyForWebApp(wt, s, h);

				FreeHttpHeader(h);

				return false;
			}
			else
			{
				// これ以上解釈しても VPN クライアントで無い可能性が高いが
				// 一応する
				if (StrCmpi(h->Method, "GET") != 0)
				{
					// サポートされていないメソッド呼び出し
					HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
				}
				else
				{
					// Not Found
					HttpSendNotFound(s, h->Target);
				}
				FreeHttpHeader(h);
			}
		}
	}
}

// WT_GATE_CONNECT_PARAM の電子署名をチェック
bool WtGateConnectParamCheckSignature(WIDE *wide, WT_GATE_CONNECT_PARAM *g)
{
	BUF *b;
	bool ret = false;
	UCHAR hash[SHA1_SIZE];
	BUF *b2;
	char secret_key[64];
	// 引数チェック
	if (wide == NULL || g == NULL)
	{
		return false;
	}

	b = WtGateConnectParamPayloadToBuf(g);
	if (b == NULL)
	{
		return false;
	}

	// 署名検証
	if (wide->wt->IsStandaloneMode == false)
	{
		// 通常モード
		if (WideGateGetControllerGateSecretKey(wide, secret_key, sizeof(secret_key)))
		{
			b2 = NewBuf();
			WriteBuf(b2, secret_key, StrLen(secret_key));
			WriteBuf(b2, b->Buf, b->Size);

			HashSha1(hash, b2->Buf, b2->Size);

			FreeBuf(b2);

			if (Cmp(hash, g->Signature2, SHA1_SIZE) == 0)
			{
				ret = true;
			}
		}
		else
		{
			// 何らかの原因で Controller からの secret_key の取得に失敗している場合
			// はチェックをしない (fail safe)
			WHERE;
			ret = true;
		}
	}
	else
	{
		// Standalone Mode
		b2 = NewBuf();
		WriteBuf(b2, b->Buf, b->Size);

		HashSha1(hash, b2->Buf, b2->Size);

		FreeBuf(b2);

		if (Cmp(hash, g->Signature2, SHA1_SIZE) == 0)
		{
			ret = true;
		}
	}

	FreeBuf(b);

	return ret;
}

// WT_GATE_CONNECT_PARAM を Pack から取得
bool WtGateConnectParamFromPack(WT_GATE_CONNECT_PARAM *g, PACK *p)
{
	// 引数チェック
	if (g == NULL || p == NULL)
	{
		return false;
	}

	Zero(g, sizeof(WT_GATE_CONNECT_PARAM));

	if (PackGetStr(p, "Msid", g->Msid, sizeof(g->Msid)) == false)
	{
		Debug("PackGetStr(p, Msid, g->Msid, sizeof(g->Msid)) == false\n");
		return false;
	}

	g->Expires = PackGetInt64(p, "Expires");

	if (PackGetData2(p, "GateId", g->GateId, sizeof(g->GateId)) == false)
	{
		Debug("if (PackGetData2(p, GateId, g->GateId, sizeof(g->GateId)) == false)\n");
		return false;
	}

	if (PackGetData2(p, "Signature2", g->Signature2, sizeof(g->Signature2)) == false)
	{
		Debug("if (PackGetData2(p, Signature2, g->Signature2, sizeof(g->Signature2)) == false)\n");
		return false;
	}

	return true;
}

// WT_GATE_CONNECT_PARAM を Pack に変換
void WtGateConnectParamToPack(PACK *p, WT_GATE_CONNECT_PARAM *g)
{
	// 引数チェック
	if (p == NULL || g == NULL)
	{
		return;
	}

	PackAddStr(p, "Msid", g->Msid);
	PackAddInt64(p, "Expires", g->Expires);
	PackAddData(p, "GateId", g->GateId, sizeof(g->GateId));
	PackAddData(p, "Signature2", g->Signature2, sizeof(g->Signature2));
}

// WT_GATE_CONNECT_PARAM の内容をバッファに変換
BUF *WtGateConnectParamPayloadToBuf(WT_GATE_CONNECT_PARAM *g)
{
	BUF *b;
	// 引数チェック
	if (g == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, g->Msid, StrLen(g->Msid));
	WriteBufInt64(b, g->Expires);
	WriteBuf(b, g->GateId, sizeof(g->GateId));

	return b;
}

// WT_GATE_CONNECT_PARAM のクローン
WT_GATE_CONNECT_PARAM *WtCloneGateConnectParam(WT_GATE_CONNECT_PARAM *p)
{
	WT_GATE_CONNECT_PARAM *ret;
	// 引数チェック
	if (p == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(WT_GATE_CONNECT_PARAM));
	Copy(ret, p, sizeof(WT_GATE_CONNECT_PARAM));

	return ret;
}

// WT_GATE_CONNECT_PARAM の解放
void WtFreeGateConnectParam(WT_GATE_CONNECT_PARAM *p)
{
	Free(p);
}

// Gate のリスナースレッド
void WtgAcceptThread(THREAD *thread, void *param)
{
	TCP_ACCEPTED_PARAM *accepted_param;
	LISTENER *r;
	SOCK *s;
	WT *wt;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	accepted_param = (TCP_ACCEPTED_PARAM *)param;
	r = accepted_param->r;
	s = accepted_param->s;
	AddRef(r->ref);
	AddRef(s->ref);
	wt = (WT *)r->ThreadParam;
	AddRef(wt->Ref);

	AddSockThread(wt->SockThreadList, s, thread);

	NoticeThreadInit(thread);
	AcceptInitEx2(s, wt->Wide->NoLookupDnsHostname, wt->Wide->AcceptProxyProtocol);

	WtgAccept(wt, s);

	DelSockThread(wt->SockThreadList, s);

	ReleaseSock(s);
	ReleaseListener(r);
	ReleaseWt(wt);
}

// Gate の開始
void WtgStart(WT* wt, X* cert, K* key, UINT port, bool standalone_mode)
{
	// 引数チェック
	if (wt == NULL || cert == NULL || key == NULL || port == 0)
	{
		return;
	}

	wt->IsStandaloneMode = standalone_mode;

	if (wt->IsStandaloneMode)
	{
		// スタンドアロンモードの初期化
		WtgSamInit(wt);
	}

	// Total 統計のゼロ値追加
	StatManReportInt64(wt->StatMan, "WtgConnectedTcp_Total", 0);
	StatManReportInt64(wt->StatMan, "WtgConnnectedServerSessions_Total", 0);
	StatManReportInt64(wt->StatMan, "WtgConnnectedClientSessions_Total", 0);
	StatManReportInt64(wt->StatMan, "WtgTrafficClientToServer_Total", 0);
	StatManReportInt64(wt->StatMan, "WtgTrafficServerToClient_Total", 0);

	// メモリサイズの節約
	SetFifoCurrentReallocMemSize(65536);

	wt->GateCert = CloneX(cert);
	wt->GateKey = CloneK(key);

	Rand(wt->GateId, sizeof(wt->GateId));

	wt->SessionList = NewList(WtgCompareSession);

	// ソケットとスレッドのリストの作成
	wt->SockThreadList = NewSockThreadList();

	// リスナーの開始
	wt->Port = port;
	wt->Listener = NewListenerEx(wt->Cedar, LISTENER_TCP, port, WtgAcceptThread, wt);
}

// TTCP の切断
void WtDisconnectTTcp(TTCP *ttcp)
{
	// 引数チェック
	if (ttcp == NULL)
	{
		return;
	}

	Disconnect(ttcp->Sock);
	ttcp->Disconnected = true;
}

// Gate の停止
void WtgStop(WT *wt)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	// リスナーの停止
	StopAllListener(wt->Cedar);
	StopListener(wt->Listener);
	ReleaseListener(wt->Listener);

	// 接続中のすべてのソケットと対応するスレッドの削除
	FreeSockThreadList(wt->SockThreadList);
	wt->SockThreadList = NULL;

	// スタンドアロンモードの終了
	WtgSamFree(wt);

	ReleaseList(wt->SessionList);

	// リソースの解放
	FreeX(wt->GateCert);
	FreeK(wt->GateKey);
}

// HTTP プロキシ機能
void WtgHttpProxy(char *url_str, SOCK *s, bool ssl, HTTP_HEADER *first_header, char *shared_secret, LIST* entrance_url_list_for_proxy)
{
	URL_DATA url;
	SOCK *s2 = NULL;
	UINT num = 0;
	// Validate arguments
	if (url_str == NULL || s == NULL)
	{
		return;
	}

	Zero(&url, sizeof(url));
	// url_str のパースの試行
	if (ParseUrl(&url, url_str, false, NULL) == false)
	{
		// entrance_url_list_for_proxy の 1 個目のパースの試行
		if (LIST_NUM(entrance_url_list_for_proxy) == 0 || ParseUrl(&url, LIST_DATA(entrance_url_list_for_proxy, 0), false, NULL) == false)
		{
			Zero(&url, sizeof(url));
		}
	}

#ifndef	VPN_SPEED
	Debug("HttpProxy: Connected from %r:%u\n", &s->RemoteIP, s->RemotePort);
#endif	// VPN_SPEED

	num = 0;

	while (true)
	{
		// Reception of the HTTP header
		HTTP_HEADER *h = NULL;

		if (num == 0)
		{
			if (first_header != NULL)
			{
				h = first_header;
			}
		}
		num++;

		if (h == NULL)
		{
			h = RecvHttpHeader(s, 0, 0);
		}

		if (h == NULL)
		{
			break;
		}

		if (StrCmpi(h->Method, "POST") == 0 || StrCmpi(h->Method, "GET") == 0 || StrCmpi(h->Method, "HEAD") == 0)
		{
			// Supported method
			HTTP_HEADER *h2;
			char *http_version = h->Version;
			UINT i;
			bool err = false;
			bool disconnect_s2 = false;
			BUF *post_buf = NULL;
			char original_host[64];

			Zero(original_host, sizeof(original_host));

			if (StrCmpi(h->Method, "POST") == 0)
			{
				// Receive POST data also in the case of POST
				UINT content_len = GetContentLength(h);
				UINT buf_size = 65536;
				UCHAR *buf = Malloc(buf_size);

				content_len = MIN(content_len, WG_PROXY_MAX_POST_SIZE);

				post_buf = NewBuf();

				while (true)
				{
					UINT recvsize = MIN(buf_size, content_len - post_buf->Size);
					UINT size;

					if (recvsize == 0)
					{
						break;
					}

					size = Recv(s, buf, buf_size, ssl);
					if (size == 0)
					{
						// Disconnected
						break;
					}

					WriteBuf(post_buf, buf, size);
				}

				Free(buf);
			}

			h2 = NewHttpHeaderEx(h->Method, h->Target, h->Version, true);

			// Copy the request header
			for (i = 0;i < LIST_NUM(h->ValueList);i++)
			{
				HTTP_VALUE *v = LIST_DATA(h->ValueList, i);
				char name[MAX_SIZE], value[MAX_SIZE];

				StrCpy(name, sizeof(name), v->Name);
				StrCpy(value, sizeof(value), v->Data);

				if (StrCmpi(name, "HOST") == 0)
				{
					StrCpy(original_host, sizeof(original_host), value);
					StrCpy(value, sizeof(value), url.HeaderHostName);
				}

				AddHttpValue(h2, NewHttpValue(name, value));
			}

			// Add a special header
			if (shared_secret != NULL)
			{
				char tmp[MAX_SIZE];
				char src_ip_str[128];
				char src_port[64];

				Format(tmp, sizeof(tmp), "%r:%u", &s->LocalIP, s->LocalPort);
				AddHttpValue(h2, NewHttpValue("X-WG-Proxy-Server", tmp));

				ToStr(tmp, CEDAR_BUILD);
				AddHttpValue(h2, NewHttpValue("X-WG-Proxy-Build", tmp));

				AddHttpValue(h2, NewHttpValue("X-WG-Proxy-Host", original_host));

				// 現在時刻
				ToStr64(tmp, SystemTime64());
				AddHttpValue(h2, NewHttpValue("X-WG-Proxy-Time", tmp));

				IPToStr(src_ip_str, sizeof(src_ip_str), &s->RemoteIP);
				ToStr(src_port, s->RemotePort);

				AddHttpValue(h2, NewHttpValue("X-WG-Proxy-SrcIP", src_ip_str));
				AddHttpValue(h2, NewHttpValue("X-WG-Proxy-SrcPort", src_port));
			}

			// Connect to the destination server
			if (s2 == NULL)
			{
				if (LIST_NUM(entrance_url_list_for_proxy) == 0)
				{
					// entrance_url_list_for_proxy が 1 つも指定されていない場合は
					// url_str の指定ホストに対する接続を試行する
					s2 = ConnectEx2(url.HostName, url.Port, 0, NULL);
				}
				else
				{
					// entrance_url_list_for_proxy が 1 つ以上指定されている場合は
					// ランダム順に接続成功するまで 1 つずつ試行する
					// (シャッフルに必要なシードは、接続元ホストの IP アドレス文字列とする)
					char client_ip_str[64] = CLEAN;
					IPToStr(client_ip_str, sizeof(client_ip_str), &s->RemoteIP);
					UINT* seq = GenerateShuffleListWithSeed(LIST_NUM(entrance_url_list_for_proxy), client_ip_str, StrLen(client_ip_str));
					UINT j;
					for (j = 0;j < LIST_NUM(entrance_url_list_for_proxy);j++)
					{
						char* url = LIST_DATA(entrance_url_list_for_proxy, seq[j]);
						URL_DATA url2 = CLEAN;
						ParseUrl(&url2, url, false, NULL);
						Debug("WtgHttpProxy: Trying for %s ...\n", url);
						s2 = ConnectEx2(url2.HostName, url2.Port, CONNECTING_TIMEOUT_PROXY, NULL);
						if (s2 != NULL)
						{
							Debug("WtgHttpProxy: %s OK.\n", url);
							break;
						}
						else
						{
							Debug("WtgHttpProxy: %s Failed.\n", url);
						}
					}
					Free(seq);
				}

				if (s2 != NULL)
				{
					SetTimeout(s2, WG_PROXY_TCP_TIMEOUT_SERVER);
				}
			}

			if (s2 == NULL)
			{
				// Failed to connect to the destination server
				HttpSendNotFound(s, h->Target);
			}
			else
			{
				HTTP_HEADER *r2;

				// Send a request to the destination server
				PostHttp(s2, h2, (post_buf == NULL ? NULL : post_buf->Buf),  (post_buf == NULL ? 0 : post_buf->Size));

				// Receive a response from the destination server, and transfers to the client
				r2 = RecvHttpHeader(s2, 0, 0);
				if (r2 == NULL)
				{
					err = true;
					disconnect_s2 = true;
				}
				else
				{
					if (PostHttp(s, r2, NULL, 0) == false)
					{
						err = true;
					}
					else
					{
						if (StrCmpi(h->Method, "HEAD") != 0)
						{
							UINT content_length = GetContentLength(r2);
							UINT buf_size = 65536;
							UCHAR *buf = Malloc(buf_size);
							UINT pos = 0;

							while (pos < content_length)
							{
								UINT r;
								UINT recv_size;

								recv_size = MIN(buf_size, (content_length - pos));

								r = Recv(s2, buf, recv_size, false);

								if (r == 0)
								{
									disconnect_s2 = true;
									err = true;
									WHERE;
									break;
								}

								if (SendAll(s, buf, r, ssl) == false)
								{
									err = true;
									break;
								}

								pos += r;
							}

							Free(buf);
						}
					}

					FreeHttpHeader(r2);
				}
			}

			FreeHttpHeader(h2);

			if (err)
			{
				// An error has occured
				HttpSendServerError(s, h->Target);
			}

			if (disconnect_s2)
			{
				// Disconnected the communication with the destination server
				if (s2 != NULL)
				{
					Disconnect(s2);
					ReleaseSock(s2);
					s2 = NULL;
				}
			}

			FreeBuf(post_buf);
		}
		else
		{
			// Unsupported method
			HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
		}

		if (h != first_header)
		{
			FreeHttpHeader(h);
		}
	}

	if (s2 != NULL)
	{
		Disconnect(s2);
		ReleaseSock(s2);
	}

#ifndef	VPN_SPEED
	Debug("HttpProxy: Disconnected from %r:%u\n", &s->RemoteIP, s->RemotePort);
#endif	// VPN_SPEED
}

