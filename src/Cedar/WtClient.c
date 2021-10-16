﻿// IPA-DN-Ultra Library Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) NTT-East Impossible Telecom Mission Group.
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
// AGAINST US (IPA, NTT-EAST, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
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
// COMPLETELY AT YOUR OWN RISK. IPA AND NTT-EAST HAS DEVELOPED AND
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


// WtClient.c
// WideTunnel Client

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

// セッションメイン
void WtcSessionMain(TSESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	MsSetThreadPriorityRealtime();
#endif  // OS_WIN32

	SetSockEvent(s->SockEvent);

	while (true)
	{
		bool disconnected = false;
		TUNNEL *t = s->ClientTunnel;

		// ソケットイベントを待機
		WtcWaitForSocket(s);

		Lock(s->Lock);
		{
			// フラグのリセット
			t->SetSockIoEventFlag = false;

			do
			{
				s->StateChangedFlag = false;

				// Gate からのデータを受信して処理
				WtcRecvFromGate(s);

				// SOCKIO からキューを生成
				WtcInsertSockIosToSendQueue(s);

				// Gate へデータを送信
				WtcSendToGate(s);

				// TCP コネクションの切断の検査
				disconnected = WtcCheckDisconnect(s);

				if (s->Halt)
				{
					disconnected = true;
				}

				if (disconnected)
				{
					break;
				}
			}
			while (s->StateChangedFlag);

			if (t->SetSockIoEventFlag)
			{
				SockIoSetIoEvent(t->SockIo);
			}
		}
		Unlock(s->Lock);

		if (disconnected)
		{
			// セッションを終了する
			break;
		}
	}

	SockIoDisconnect(s->ClientTunnel->SockIo);
}

// TCP コネクションの切断の検査
bool WtcCheckDisconnect(TSESSION *s)
{
	bool ret = false;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	if (WtIsTTcpDisconnected(s, NULL, s->GateTcp))
	{
		// Gate との接続が切断された
		ret = true;
//		Debug("Disconnect Tunnel time: %I64u\n", SystemTime64());
	}

	if (SockIoIsConnected(s->ClientTunnel->SockIo) == false)
	{
		// SOCKIO が切断された
		ret = true;
	}

	return ret;
}

// Gate へデータを送信
void WtcSendToGate(TSESSION *s)
{
	TTCP *ttcp;
	QUEUE *blockqueue;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	ttcp = s->GateTcp;
	blockqueue = s->BlockQueue;

	// 送信データの生成
	WtMakeSendDataTTcp(s, ttcp, blockqueue, NULL, false);

	// 送信
	WtSendTTcp(s, ttcp);
}

// SOCKIO からキューを生成
void WtcInsertSockIosToSendQueue(TSESSION *s)
{
	QUEUE *blockqueue;
	TUNNEL *t;
	SOCKIO *sockio;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (FifoSize(s->GateTcp->SendFifo) > WT_WINDOW_SIZE)
	{
		return;
	}

	blockqueue = s->BlockQueue;
	t = s->ClientTunnel;
	sockio = t->SockIo;

	if (WtInsertSockIoToSendQueueEx(s->GateTcp, blockqueue, t, WT_WINDOW_SIZE - FifoSize(s->GateTcp->SendFifo)))
	{
		// s->StateChangedFlag = true;
	}
}

// Gate からのデータを受信して処理
void WtcRecvFromGate(TSESSION *s)
{
	TTCP *ttcp;
	QUEUE *q;
	DATABLOCK *block;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	ttcp = s->GateTcp;

	// TTCP からデータを受信
	WtRecvTTcp(s, ttcp);

	// 受信データを解釈
	q = WtParseRecvTTcp(s, ttcp, NULL);

	// 受信データを SOCKIO に対して配信
	while ((block = GetNext(q)) != NULL)
	{
		SOCKIO *sockio;
		TUNNEL *t = s->ClientTunnel;
		FIFO *fifo;

		sockio = t->SockIo;

		if (block->DataSize != 0)
		{
			// データあり
			fifo = SockIoGetRecvFifo(sockio);

			WriteFifo(fifo, block->Data, block->DataSize);

			SockIoReleaseFifo(fifo);
		}

		WtFreeDataBlock(block, false);

		t->SetSockIoEventFlag = true;
	}

	ReleaseQueue(q);
}

// ソケットイベントを待機
void WtcWaitForSocket(TSESSION *s)
{
	SOCK *sock;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	sock = s->Sock;
	JoinSockToSockEvent(sock, s->SockEvent);

	WaitSockEvent(s->SockEvent, SELECT_TIME);

	s->Tick = Tick64();
}

// 新しいクライアントセッションの作成
TSESSION *WtcNewSession(WT *wt, SOCK *s)
{
	TSESSION *t;
	SOCKIO *sockio;
	// 引数チェック
	if (wt == NULL || s == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TSESSION));
	t->Lock = NewLock();
	t->Ref = NewRef();
	t->SessionType = WT_SESSION_CLIENT;
	t->wt = wt;

	t->SockEvent = NewSockEvent();
	t->RecvBuf = Malloc(RECV_BUF_SIZE);
	t->BlockQueue = NewQueue();

	sockio = NewSockIo(t->SockEvent, NULL);
	t->ClientTunnel = WtNewTunnel(NULL, 0, sockio, NULL);
	ReleaseSockIo(sockio);

	t->Sock = s;
	AddRef(s->ref);

	return t;
}

// 接続
UINT WtcConnect(WT *wt, WT_CONNECT *connect, SOCKIO **sockio)
{
	return WtcConnectEx(wt, connect, sockio, 0, 0);
}
UINT WtcConnectEx(WT *wt, WT_CONNECT *connect, SOCKIO **sockio, UINT ver, UINT build)
{
	TSESSION *session;
	SOCK *s;
	UINT code;
	PACK *p;
	THREAD *thread;
	UINT zero = 0;
	SYSTEMTIME tm;
	UINT tunnel_timeout = WT_TUNNEL_TIMEOUT;
	UINT tunnel_keepalive = WT_TUNNEL_KEEPALIVE;
	bool tunnel_use_aggressive_timeout = false;
	char *sni = NULL;
	bool is_proxy_alternative_fqdn = false;

	// 引数チェック
	if (wt == NULL || connect == NULL || sockio == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	sni = connect->HostName;

	// Gate に接続
	Debug("WtcConnectEx: Try 0\n");
	s = WtSockConnect(connect, &code, false);
	if (s == NULL)
	{
		// 失敗
		if (connect->ProxyType == PROXY_HTTP && code != ERR_PROXY_CONNECT_FAILED &&
			IsEmptyStr(connect->HostNameForProxy) == false && StrCmpi(connect->HostNameForProxy, connect->HostName) != 0)
		{
L_PROXY_RETRY_WITH_ALTERNATIVE_FQDN:
			// HTTP プロキシサーバーの場合で単純プロキシサーバー接続不具合以外
			// の場合は、接続先接続先を HostNameForProxy にして再試行する
			Debug("WtcConnectEx: Try 1\n");
			s = WtSockConnect(connect, &code, true);

			if (s == NULL)
			{
				Debug("WtcConnectEx: Try 1 error: %u\n", code);
				return code;
			}

			Debug("WtcConnectEx: Try 1 Connect OK\n");

			sni = connect->HostNameForProxy;

			is_proxy_alternative_fqdn = true;
		}
		else
		{
			return code;
		}
	}

	//SetSocketSendRecvBufferSize((int)s, WT_SOCKET_WINDOW_SIZE);

	SetTimeout(s, CONNECTING_TIMEOUT);

	// SSL 通信の開始
	if (StartSSLEx(s, NULL, NULL, true, 0, sni) == false)
	{
		// 失敗
		Debug("StartSSL Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		s = NULL;

		if (is_proxy_alternative_fqdn == false && connect->ProxyType == PROXY_HTTP && IsEmptyStr(connect->HostNameForProxy) == false && StrCmpi(connect->HostNameForProxy, connect->HostName) != 0)
		{
			Debug("WtcConnectEx: Try 0 StartSSLEx error\n");
			// HTTP プロキシサーバーの場合で単純プロキシサーバー接続不具合以外
			// の場合は、接続先接続先を HostNameForProxy にして再試行する
			goto L_PROXY_RETRY_WITH_ALTERNATIVE_FQDN;
		}
		return ERR_PROTOCOL_ERROR;
	}

	SystemTime(&tm);

	if (connect->DontCheckCert == false)
	{
		// 証明書のチェック
		if (WtIsTrustedCert(wt, s->RemoteX) == false)
		{
			// 失敗
			Debug("WtIsTrustedCert Failed.\n");
			Disconnect(s);
			ReleaseSock(s);
			s = NULL;

			if (is_proxy_alternative_fqdn == false && connect->ProxyType == PROXY_HTTP && IsEmptyStr(connect->HostNameForProxy) == false && StrCmpi(connect->HostNameForProxy, connect->HostName) != 0)
			{
				Debug("WtcConnectEx: Try 0 WtIsTrustedCert error\n");
				// HTTP プロキシサーバーの場合で単純プロキシサーバー接続不具合以外
				// の場合は、接続先接続先を HostNameForProxy にして再試行する
				goto L_PROXY_RETRY_WITH_ALTERNATIVE_FQDN;
			}
			return ERR_SSL_X509_UNTRUSTED;
		}
	}

	// シグネチャのアップロード
	if (WtgClientUploadSignature(s) == false)
	{
		// 失敗
		Debug("WtgClientUploadSignature Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}

	// Hello パケットのダウンロード
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}
	if (PackGetInt(p, "hello") == 0)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		FreePack(p);
		Disconnect(s);
		ReleaseSock(s);
		return ERR_PROTOCOL_ERROR;
	}
	FreePack(p);

	// 接続パラメータの送信
	p = NewPack();
	if (wt->Wide != NULL)
	{
		PackAddData(p, "client_id", wt->Wide->ClientId, sizeof(wt->Wide->ClientId));
	}
	PackAddStr(p, "method", "connect_session");
	PackAddBool(p, "use_compress", connect->UseCompress);
	PackAddData(p, "session_id", connect->SessionId, WT_SESSION_ID_SIZE);
	PackAddInt(p, "ver", ver);
	PackAddInt(p, "build", build);
	PackAddStr(p, "name_suite", DESK_PRODUCT_NAME_SUITE);
	PackAddBool(p, "support_timeout_param", true);
	char ver_str[128] = CLEAN;
	Format(ver_str, sizeof(ver_str), "Ver=%u,Build=%u,Release=%s,CommitId=%s,Suite=%s", CEDAR_VER, CEDAR_BUILD, ULTRA_VER_LABEL, ULTRA_COMMIT_ID, DESK_PRODUCT_NAME_SUITE);
	PackAddStr(p, "local_version", ver_str);
	PackAddIp(p, "local_ip", &s->LocalIP);
	wchar_t computer_name[128] = CLEAN;
#ifdef OS_WIN32
	MsGetComputerNameFullEx(computer_name, sizeof(computer_name), true);
#endif // OS_WIN32
	if (wt->Wide != NULL)
	{
		PackAddInt(p, "se_lang", wt->Wide->SeLang);
	}

	PackAddStr(p, "env_product_name_suite", DESK_PRODUCT_NAME_SUITE);
	PackAddInt(p, "env_build", CEDAR_BUILD);
	PackAddInt(p, "env_ver", CEDAR_VER);
	PackAddStr(p, "env_commit_id", ULTRA_COMMIT_ID);
	LANGLIST current_lang = CLEAN;
	GetCurrentLang(&current_lang);
	PackAddStr(p, "env_language", current_lang.Name);

	if (HttpClientSend(s, p) == false)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		FreePack(p);
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}
	FreePack(p);

	// 結果の受信
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}

	code = PackGetInt(p, "code");
	if (code != ERR_NO_ERROR)
	{
		Debug("Gate Error: %u\n", code);
		// エラー発生
		FreePack(p);
		Disconnect(s);
		ReleaseSock(s);
		return code;
	}

	{
		UINT tunnel_timeout2 = PackGetInt(p, "tunnel_timeout");
		UINT tunnel_keepalive2 = PackGetInt(p, "tunnel_keepalive");
		bool tunnel_use_aggressive_timeout2 = PackGetBool(p, "tunnel_use_aggressive_timeout");
		if (tunnel_timeout2 && tunnel_keepalive2)
		{
			tunnel_timeout = tunnel_timeout2;
			tunnel_keepalive = tunnel_keepalive2;
			tunnel_use_aggressive_timeout = tunnel_use_aggressive_timeout2;
		}
	}

	FreePack(p);

	SetTimeout(s, TIMEOUT_INFINITE);

	session = WtcNewSession(wt, s);
	*sockio = session->ClientTunnel->SockIo;
	AddRef((*sockio)->Ref);
	(*sockio)->ServerMask64 = connect->ServerMask64;

	CopyIP(&((*sockio)->ClientLocalIP), &s->LocalIP);

	session->GateTcp = WtNewTTcp(s, connect->UseCompress, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout);

	thread = NewThread(WtcSessionMainThread, session);
	WaitThreadInit(thread);
	ReleaseThread(thread);

	ReleaseSock(s);

	SockIoSendAll(*sockio, &zero, sizeof(UINT));

	return ERR_NO_ERROR;
}

// セッションのメイン処理を行うスレッド
void WtcSessionMainThread(THREAD *thread, void *param)
{
	TSESSION *session;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	session = (TSESSION *)param;

	AddSockThread(session->wt->SockThreadList, session->Sock, thread);
	NoticeThreadInit(thread);

	WtcSessionMain(session);

	WtReleaseSession(session);
}

// クライアントサービスの開始
void WtcStart(WT *wt)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	wt->SockThreadList = NewSockThreadList();
}

// クライアントサービスの停止
void WtcStop(WT *wt)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	FreeSockThreadList(wt->SockThreadList);
	wt->SockThreadList = NULL;
}


