// IPA-DN-Ultra Library Source Code
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


// Wt.c
// WideTunnel Main Source

// Build 8600

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

// Mikaka DDNS クライアントの開始
MIKAKA_DDNS *NewMikakaDDnsClient(WT *wt)
{
	MIKAKA_DDNS *d = ZeroMalloc(sizeof(MIKAKA_DDNS));

	d->Wt = wt;

	if (d->Wt != NULL)
	{
		AddRef(d->Wt->Ref);
	}

	wchar_t exe_dir[MAX_PATH] = CLEAN;

	GetExeDirW(exe_dir, sizeof(exe_dir));

	CombinePathW(d->ConfigFilePath, sizeof(d->ConfigFilePath), exe_dir, MIKAKA_DDNS_CONFIG_FILENAME);

	d->Event = NewEvent();

	d->Thread = NewThread(MikakaDDnsClientThread, d);

	return d;
}

// Mikaka DDNS クライアントの停止
void FreeMikakaDDnsClient(MIKAKA_DDNS *d)
{
	if (d == NULL)
	{
		return;
	}

	d->Halt = true;

	Set(d->Event);

	WaitThread(d->Thread, INFINITE);

	ReleaseThread(d->Thread);

	ReleaseWt(d->Wt);

	ReleaseEvent(d->Event);

	Free(d);
}

// Mikaka DDNS クライアントメインループ内での登録処理等
void MikakaDDnsClientMain(MIKAKA_DDNS *d, MIKAKA_DDNS_CONFIG *c)
{
	UINT64 now = Tick64();
	if (d == NULL || c == NULL)
	{
		return;
	}

	// GetMyIp IPv4
	if (now >= d->NextTick_GetMyIp_IPv4)
	{
		char myip[MAX_PATH] = CLEAN;

		UINT err = MikakaDDnsGetMyIp(d, c, myip, sizeof(myip));

		if (err == ERR_NO_ERROR)
		{
			if (StrCmpi(myip, d->LastMyIp_IPv4) != 0)
			{
				StrCpy(d->LastMyIp_IPv4, sizeof(d->LastMyIp_IPv4), myip);

				d->NextTick_Update_IPv4 = 0;

				WtLogEx(d->Wt, MIKAKA_DDNS_LOG_PREFIX, "GetMyIp: This host's Global IPv4 address change detected. New IPv4 address is '%s'.", myip);
			}

			d->NextTick_GetMyIp_IPv4 = now + (UINT64)GenRandInterval(MIKAKA_DDNS_GETMYIP_INTERVAL_OK_MIN, MIKAKA_DDNS_GETMYIP_INTERVAL_OK_MAX);
		}
		else
		{
			d->NextTick_GetMyIp_IPv4 = 0;
		}
	}

	// Update IPv4
	if (now >= d->NextTick_Update_IPv4)
	{
		BUF *error_buf = NewBuf();
		bool is_server_error = false;

		UINT err = MikakaDDnsUpdate(d, c, error_buf, &is_server_error);

		if (err != ERR_NO_ERROR)
		{
			if (is_server_error)
			{
				d->NextTick_Update_IPv4 = now + (UINT64)GenRandInterval(MIKAKA_DDNS_REGISTER_INTERVAL_SERVER_ERROR_MIN, MIKAKA_DDNS_REGISTER_INTERVAL_SERVER_ERROR_MAX);

				char *retstr = GetOneLineStrFromBuf(error_buf, " ");
				char dtstr[MAX_PATH] = CLEAN;

				GetDateTimeStr64(dtstr, sizeof(dtstr), SystemToLocal64(TickToTime(d->NextTick_Update_IPv4)));

				WtLogEx(d->Wt, MIKAKA_DDNS_LOG_PREFIX, "DDNS register server returned a server error: '%s'. Next retry time: %s. Error code: %u.", retstr, dtstr, err);

				Free(retstr);
			}
			else
			{
				d->NextTick_Update_IPv4 = now + (UINT64)GenRandInterval(MIKAKA_DDNS_REGISTER_INTERVAL_NETWORK_ERROR_MIN, MIKAKA_DDNS_REGISTER_INTERVAL_NETWORK_ERROR_MAX);

				char dtstr[MAX_PATH] = CLEAN;

				GetDateTimeStr64(dtstr, sizeof(dtstr), SystemToLocal64(TickToTime(d->NextTick_Update_IPv4)));

				WtLogEx(d->Wt, MIKAKA_DDNS_LOG_PREFIX, "Network error occured when connecting to the DDNS register server. Next retry time: %s. Error code: %u.", dtstr, err);
			}
		}
		else
		{
			d->NextTick_Update_IPv4 = now + (UINT64)GenRandInterval(MIKAKA_DDNS_REGISTER_INTERVAL_OK_MIN, MIKAKA_DDNS_REGISTER_INTERVAL_OK_MAX);

			char *retstr = GetOneLineStrFromBuf(error_buf, " ");
			char dtstr[MAX_PATH] = CLEAN;

			GetDateTimeStr64(dtstr, sizeof(dtstr), SystemToLocal64(TickToTime(d->NextTick_Update_IPv4)));

			WtLogEx(d->Wt, MIKAKA_DDNS_LOG_PREFIX, "DDNS register OK. DDNS register server returned results: '%s'. Next register time: %s.", retstr, dtstr);

			Free(retstr);
		}

		FreeBuf(error_buf);
	}
}

// 更新処理メイン
UINT MikakaDDnsUpdate(MIKAKA_DDNS *d, MIKAKA_DDNS_CONFIG *c, BUF *result_buf_if_error, bool *is_server_error)
{
	if (is_server_error != NULL) *is_server_error = false;
	if (d == NULL || c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	URL_DATA data = CLEAN;

	if (ParseUrl(&data, c->DDnsUpdateUrl, false, NULL) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	UINT ret = ERR_INTERNAL_ERROR;

	BUF *sha1_hash = StrToBin(c->DDnsSslDigestSha1);

	UCHAR *sha1_hash_ptr = NULL;
	UINT sha1_hash_num = 0;
	if (sha1_hash != NULL && sha1_hash->Size == SHA1_SIZE)
	{
		sha1_hash_ptr = sha1_hash->Buf;
		sha1_hash_num = 1;
	}

	BUF *recv = HttpRequestEx6(&data, NULL, DDNS_CONNECT_TIMEOUT, DDNS_COMM_TIMEOUT, &ret, false, NULL, NULL,
		NULL, sha1_hash_ptr,
		sha1_hash_num, NULL, 0, NULL, NULL, NULL, false, false, result_buf_if_error, is_server_error);

	FreeBuf(sha1_hash);

	if (recv == NULL)
	{
		return ret;
	}

	char *str = ZeroMalloc(recv->Size + 1);
	Copy(str, recv->Buf, recv->Size);

	ret = ERR_NO_ERROR;

	Free(str);
	FreeBuf(recv);

	return ERR_NO_ERROR;
}

// GetMyIp 処理メイン
UINT MikakaDDnsGetMyIp(MIKAKA_DDNS *d, MIKAKA_DDNS_CONFIG *c, char *dst, UINT dst_size)
{
	if (d == NULL || c == NULL || dst == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	URL_DATA data = CLEAN;

	if (ParseUrl(&data, c->DDnsGetMyIpUrl, false, NULL) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	UINT ret = ERR_INTERNAL_ERROR;

	BUF *recv = HttpRequestEx3(&data, NULL, DDNS_CONNECT_TIMEOUT, DDNS_COMM_TIMEOUT, &ret, false, NULL, NULL,
		NULL, NULL,
		0, NULL, 0, NULL, NULL);

	if (recv == NULL)
	{
		return ret;
	}

	char *str = ZeroMalloc(recv->Size + 1);
	Copy(str, recv->Buf, recv->Size);

	char *str2 = GetFirstFilledStrFromStr(str);
	Free(str);
	str = str2;

	if (StartWith(str, "IP=") == false)
	{
		ret = ERR_PROTOCOL_ERROR;
	}
	else
	{
		StrCpy(dst, dst_size, str + 3);
		ret = ERR_NO_ERROR;
	}

	Free(str);
	FreeBuf(recv);

	return ERR_NO_ERROR;
}

// Mikaka DDNS クライアントメインスレッド
void MikakaDDnsClientThread(THREAD *thread, void *param)
{
	if (thread == NULL || param == NULL)
	{
		return;
	}

	MIKAKA_DDNS *d = (MIKAKA_DDNS *)param;

	UINT64 last_config_hash = 0;
	UINT64 last_network_if_hash = 0;

	while (d->Halt == false)
	{
		UINT next_wait_interval = GenRandInterval(MIKAKA_DDNS_POLL_INTERVAL_MIN, MIKAKA_DDNS_POLL_INTERVAL_MAX);

		MIKAKA_DDNS_CONFIG c = CLEAN;

		bool config_or_network_changed = false;
		bool config_changed = false;

		if (LoadMikakaDDnsConfig(d->ConfigFilePath, &c))
		{
			UINT64 current_config_hash = c.ConfigFileHash;

			if (last_config_hash != current_config_hash)
			{
				last_config_hash = current_config_hash;
				config_or_network_changed = true;
				config_changed = true;
			}

			if (c.DDnsEnabled)
			{
				UINT64 current_network_if_hash = GetHostIPAddressHash32();

				if (last_network_if_hash != current_network_if_hash)
				{
					last_network_if_hash = current_network_if_hash;
					config_or_network_changed = true;
				}
			}
			else
			{
				last_network_if_hash = 0;
			}
		}

		if (config_or_network_changed)
		{
			d->NextTick_GetMyIp_IPv4 = 0;
		}

		if (config_changed)
		{
			d->NextTick_Update_IPv4 = 0;
		}

		if (c.DDnsEnabled)
		{
			MikakaDDnsClientMain(d, &c);
		}

		UINT64 now = Tick64();

		if (d->NextTick_GetMyIp_IPv4 != 0)
		{
			if (now >= d->NextTick_GetMyIp_IPv4)
			{
				next_wait_interval = 0;
			}
			else
			{
				next_wait_interval = MIN(next_wait_interval, (UINT)(d->NextTick_GetMyIp_IPv4 - now));
			}
		}

		if (d->NextTick_Update_IPv4 != 0)
		{
			if (now >= d->NextTick_Update_IPv4)
			{
				next_wait_interval = 0;
			}
			else
			{
				next_wait_interval = MIN(next_wait_interval, (UINT)(d->NextTick_Update_IPv4 - now));
			}
		}

		if (next_wait_interval != 0)
		{
			Wait(d->Event, MAX(next_wait_interval, 1000)); // 独法式インチキ待機
		}
		else
		{
			SleepThread(1000); // 独法式インチキ待機ナンバー２
		}
	}
}

// Mikaka DDNS クライアントの設定ファイルの読み込み
bool LoadMikakaDDnsConfig(wchar_t *filepath, MIKAKA_DDNS_CONFIG *c)
{
	UINT num_retry = 0;
	if (filepath == NULL || c == NULL)
	{
		return false;
	}

	if (IsEmptyStr(MIKAKA_DDNS_DEFAULT_DOMAIN) || IsEmptyStr(MIKAKA_DDNS_DEFAULT_SSL_SHA1))
	{
		return false;
	}

	L_RETRY:

	Zero(c, sizeof(MIKAKA_DDNS_CONFIG));

	bool ret = false;

	BUF *buf = ReadDumpW(filepath);

	if (buf != NULL)
	{
		LIST *ini = ReadIni(buf);

		if (ini != NULL)
		{
			char *ddns_update_url = IniStrValue(ini, "DDNS_UPDATE_URL");
			char *ddns_ssl_digest_sha1 = IniStrValue(ini, "DDNS_SSL_DIGEST_SHA1");
			char *ddns_getmyip_url = IniStrValue(ini, "DDNS_GETMYIP_URL");
			char *ddns_enabled = IniStrValue(ini, "DDNS_ENABLED");

			if (IsFilledStr(ddns_update_url) &&
				IsFilledStr(ddns_ssl_digest_sha1) &&
				IsFilledStr(ddns_getmyip_url))
			{
				Trim(ddns_update_url);
				Trim(ddns_ssl_digest_sha1);
				Trim(ddns_getmyip_url);

				StrCpy(c->DDnsUpdateUrl, sizeof(c->DDnsUpdateUrl), ddns_update_url);
				StrCpy(c->DDnsSslDigestSha1, sizeof(c->DDnsSslDigestSha1), ddns_ssl_digest_sha1);
				StrCpy(c->DDnsGetMyIpUrl, sizeof(c->DDnsGetMyIpUrl), ddns_getmyip_url);

				c->DDnsEnabled = ToBool(ddns_enabled);

				UCHAR hash[SHA1_SIZE] = CLEAN;

				HashSha1(hash, buf->Buf, buf->Size);

				c->ConfigFileHash = READ_UINT64(hash);

				ret = true;
			}

			FreeIni(ini);
		}

		FreeBuf(buf);
	}

	if (ret == false)
	{
		if (num_retry == 0)
		{
			num_retry++;

			// 設定ファイルが存在しないか内容が不正なので、新たに作成する
			BUF *template_buf = ReadDump("|mikaka_ddns_config_template.txt");

			if (template_buf != NULL)
			{
				SeekBufToEnd(template_buf);
				WriteBufChar(template_buf, 0);

				UINT tmp_size = template_buf->Size * 4 + 10000; // 独法式インチキ計算式
				char *tmp = ZeroMalloc(tmp_size);

				StrCpy(tmp, tmp_size, template_buf->Buf);

				UCHAR key_data[SHA1_SIZE] = CLEAN;
				Rand(key_data, sizeof(key_data));

				char key_str[MAX_PATH] = CLEAN;
				BinToStr(key_str, sizeof(key_str), key_data, sizeof(key_data));

				ReplaceStrEx(tmp, tmp_size, tmp, "<DDNS_DOMAIN>", MIKAKA_DDNS_DEFAULT_DOMAIN, false);
				ReplaceStrEx(tmp, tmp_size, tmp, "<DDNS_SHA1>", MIKAKA_DDNS_DEFAULT_SSL_SHA1, false);
				ReplaceStrEx(tmp, tmp_size, tmp, "<DDNS_SECRET_KEY>", key_str, false);

				BUF *write_buf = NewBuf();

				WriteBuf(write_buf, tmp, StrLen(tmp));

				DumpBufW(write_buf, filepath);

				FreeBuf(write_buf);

				Free(tmp);

				FreeBuf(template_buf);
			}

			goto L_RETRY;
		}
	}

	return ret;
}

// Pack の送信
bool SockIoSendPack(SOCKIO *io, PACK *p)
{
	BUF *b;
	UINT size;
	// 引数チェック
	if (io == NULL || p == NULL)
	{
		return false;
	}

	b = PackToBuf(p);
	size = Endian32(b->Size);

	SockIoSendAdd(io, &size, sizeof(UINT));
	SockIoSendAdd(io, b->Buf, b->Size);

	FreeBuf(b);

	return SockIoSendNow(io);
}

// Pack の受信
PACK *SockIoRecvPack(SOCKIO *io)
{
	PACK *p;
	BUF *b;
	void *data;
	UINT sz;
	// 引数チェック
	if (io == NULL)
	{
		return NULL;
	}

	if (SockIoRecvAll(io, &sz, sizeof(UINT)) == false)
	{
		return false;
	}
	sz = Endian32(sz);
	if (sz > MAX_PACK_SIZE)
	{
		return false;
	}
	data = Malloc(sz);
	if (SockIoRecvAll(io, data, sz) == false)
	{
		Free(data);
		return false;
	}

	b = NewBuf();
	WriteBuf(b, data, sz);
	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);
	Free(data);

	return p;
}

// トンネル ID がリストに存在するかどうかチェック
bool WtIsTunnelIdExistsInUsedTunnelIdList(LIST *o, UINT tunnel_id)
{
	bool ret = false;
	// 引数チェック
	if (o == NULL)
	{
		return false;
	}

	LockList(o);
	{
		UINT i;

		WtDeleteOldUsedTunnelId(o);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			USED_TUNNELID *u = LIST_DATA(o, i);

			if (u->TunnelId == tunnel_id)
			{
				ret = true;
				break;
			}
		}
	}
	UnlockList(o);

	return ret;
}

// 古いトンネル ID エントリを削除する
void WtDeleteOldUsedTunnelId(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		LIST *d = NULL;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			USED_TUNNELID *u = LIST_DATA(o, i);

			if (u->Expires <= Tick64())
			{
				if (d == NULL)
				{
					d = NewListFast(NULL);
				}

				Add(d, u);
			}
		}

		if (d != NULL)
		{
			for (i = 0;i < LIST_NUM(d);i++)
			{
				USED_TUNNELID *u = LIST_DATA(d, i);

				Delete(o, u);
				Free(u);
			}

			ReleaseList(d);
		}
	}
	UnlockList(o);
}

// 新しいトンネル ID をリストに追加
void WtAddUsedTunnelId(LIST *o, UINT tunnel_id, UINT64 expire_span)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		if (WtIsTunnelIdExistsInUsedTunnelIdList(o, tunnel_id) == false)
		{
			USED_TUNNELID *u = ZeroMalloc(sizeof(USED_TUNNELID));

			u->TunnelId = tunnel_id;
			u->Expires = Tick64() + expire_span;

			Insert(o, u);
		}
	}
	UnlockList(o);
}

// 使用済みトンネル ID リストの解放
void WtFreeUsedTunnelIdList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		USED_TUNNELID *u = LIST_DATA(o, i);

		Free(u);
	}

	ReleaseList(o);
}

// 使用済みトンネル ID リストの作成
LIST *WtNewUsedTunnelIdList()
{
	LIST *o = NewList(NULL);

	return o;
}

// SOCKIO イベントオブジェクトの置換
void SockIoReplaceIoEvent(SOCKIO *io, SOCK_EVENT *e)
{
	// 引数チェック
	if (io == NULL || e == NULL)
	{
		return;
	}

	Lock(io->Lock);
	{
		ReleaseSockEvent(io->SockIoEvent);

		io->SockIoEvent = e;
		AddRef(e->ref);
	}
	Unlock(io->Lock);

	SockIoSetIoEvent(io);
}

// SOCKIO イベントの発生
void SockIoSetIoEvent(SOCKIO *io)
{
	SOCK_EVENT *e;
	// 引数チェック
	if (io == NULL)
	{
		return;
	}

	e = SockIoGetSockIoEvent(io);
	SetSockEvent(e);
	ReleaseSockEvent(e);
}

// 送信通知イベントの発生
void SockIoSetSentNoticeEvent(SOCKIO *io)
{
	SOCK_EVENT *e;
	// 引数チェック
	if (io == NULL)
	{
		return;
	}

	e = SockIoGetSentNoticeEvent(io);
	SetSockEvent(e);
	ReleaseSockEvent(e);
}

// SOCKIO イベントの取得
SOCK_EVENT *SockIoGetSockIoEvent(SOCKIO *io)
{
	SOCK_EVENT *ret;
	// 引数チェック
	if (io == NULL)
	{
		return NULL;
	}

	Lock(io->Lock);
	{
		ret = io->SockIoEvent;

		AddRef(ret->ref);
	}
	Unlock(io->Lock);

	return ret;
}

// 送信通知イベントの取得
SOCK_EVENT *SockIoGetSentNoticeEvent(SOCKIO *io)
{
	SOCK_EVENT *ret;
	// 引数チェック
	if (io == NULL)
	{
		return NULL;
	}

	ret = io->SentNoticeEvent;
	AddRef(ret->ref);

	return ret;
}

// 現在接続されているかどうか取得
bool SockIoIsConnected(SOCKIO *io)
{
	// 引数チェック
	if (io == NULL)
	{
		return false;
	}

	return io->Disconnected ? false : true;
}

// 切断
bool SockIoDisconnect(SOCKIO* io)
{
	// 引数チェック
	if (io == NULL)
	{
		return false;
	}
	if (io->Disconnected)
	{
		return false;
	}

	io->Disconnected = true;

	SockIoSetIoEvent(io);
	SockIoSetSentNoticeEvent(io);

	return true;
}

// すべて受信
bool SockIoRecvAll(SOCKIO *io, void *data, UINT size)
{
	UINT recv_size, sz, ret;
	// 引数チェック
	if (io == NULL || data == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}

	recv_size = 0;

	while (true)
	{
		sz = size - recv_size;
		ret = SockIoRecv(io, (UCHAR *)data + recv_size, sz);
		if (ret == 0)
		{
			return false;
		}
		recv_size += ret;
		if (recv_size >= size)
		{
			return true;
		}
	}
}

// 同期受信
UINT SockIoRecv(SOCKIO *io, void *data, UINT size)
{
	UINT ret = 0;
	UINT64 endtime;
	// 引数チェック
	if (io == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	endtime = Tick64() + io->Timeout;

	while (true)
	{
		ret = SockIoRecvAsync(io, data, size);

		if (ret == 0 || ret != INFINITE)
		{
			break;
		}
		else
		{
			SOCK_EVENT *e = SockIoGetSockIoEvent(io);
			UINT64 now = Tick64();

			if (io->Timeout != INFINITE)
			{
				if ((now > endtime) || WaitSockEvent(e, (UINT)(endtime - now)) == false)
				{
DISCONNECTED:
					SockIoDisconnect(io);
				}
			}
			else
			{
				if (WaitSockEvent(e, INFINITE) == false)
				{
					goto DISCONNECTED;
				}
			}

			ReleaseSockEvent(e);
		}
	}

	return ret;
}

// 非同期受信
UINT SockIoRecvAsync(SOCKIO *io, void *data, UINT size)
{
	FIFO *fifo;
	UINT current_size;
	UINT ret;
	// 引数チェック
	if (io == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	if (SockIoIsConnected(io) == false)
	{
		return 0;
	}

	fifo = SockIoGetRecvFifo(io);

	current_size = FifoSize(fifo);

	if (current_size == 0)
	{
		// データが届いていない
		ret = INFINITE;
	}
	else
	{
		// データが届いている
		ret = MIN(current_size, size);

		ReadFifo(fifo, data, ret);
	}

	SockIoReleaseFifo(fifo);

	return ret;
}

// すべて送信
bool SockIoSendAll(SOCKIO *io, void *data, UINT size)
{
	UCHAR *buf;
	UINT sent_size;
	UINT ret;
	// 引数チェック
	if (io == NULL || data == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}

	buf = (UCHAR *)data;
	sent_size = 0;

	while (true)
	{
		ret = SockIoSend(io, buf, size - sent_size);
		if (ret == 0)
		{
			return false;
		}

		sent_size += ret;
		buf += ret;
		if (sent_size >= size)
		{
			return true;
		}
	}
}

// 送信バッファを送信
bool SockIoSendNow(SOCKIO *io)
{
	// 引数チェック
	if (io == NULL)
	{
		return false;
	}

	if (SockIoSendAll(io, io->SendBuf->Buf, io->SendBuf->Size) == false)
	{
		return false;
	}

	ClearBuf(io->SendBuf);

	return true;
}

// 送信バッファに追加
void SockIoSendAdd(SOCKIO *io, void *data, UINT size)
{
	// 引数チェック
	if (io == NULL || data == NULL)
	{
		return;
	}

	WriteBuf(io->SendBuf, data, size);
}

// 同期送信
UINT SockIoSend(SOCKIO *io, void *data, UINT size)
{
	UINT ret = 0;
	UINT64 endtime;
	// 引数チェック
	if (io == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	endtime = Tick64() + io->Timeout;

	while (true)
	{
		ret = SockIoSendAsync(io, data, size);

		if (ret == 0 || ret != INFINITE)
		{
			break;
		}
		else
		{
			SOCK_EVENT *e = SockIoGetSockIoEvent(io);
			UINT64 now = Tick64();

			if (io->Timeout != INFINITE)
			{
				if ((now > endtime) || WaitSockEvent(e, (UINT)(endtime - now)) == false)
				{
DISCONNECTED:
					SockIoDisconnect(io);
				}
			}
			else
			{
				if (WaitSockEvent(e, INFINITE) == false)
				{
					goto DISCONNECTED;
				}
			}

			ReleaseSockEvent(e);
		}
	}

	return ret;
}

// 非同期送信
UINT SockIoSendAsync(SOCKIO *io, void *data, UINT size)
{
	FIFO *fifo;
	UINT current_size;
	UINT write_size;
	bool set_event = false;
	// 引数チェック
	if (io == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	if (SockIoIsConnected(io) == false)
	{
		return 0;
	}

	fifo = SockIoGetSendFifo(io);

	current_size = FifoSize(fifo);

	if (current_size < io->MaxSendBufferSize)
	{
		// バッファに空きあり
		write_size = MIN(io->MaxSendBufferSize - current_size, size);
		WriteFifo(fifo, data, write_size);
		set_event = true;
	}
	else
	{
		// バッファに空き無し
		write_size = INFINITE;
	}

	SockIoReleaseFifo(fifo);

	if (set_event)
	{
		SockIoSetSentNoticeEvent(io);
	}

	return write_size;
}

// タイムアウト値の設定
void SockIoSetTimeout(SOCKIO *io, UINT timeout)
{
	// 引数チェック
	if (io == NULL)
	{
		return;
	}
	if (timeout == 0)
	{
		timeout = INFINITE;
	}

	io->Timeout = timeout;
}

// 最大送信バッファサイズの指定
void SockIoSetMaxSendBufferSize(SOCKIO *io, UINT size)
{
	// 引数チェック
	if (io == NULL)
	{
		return;
	}
	if (size == 0)
	{
		size = INFINITE;
	}

	io->MaxSendBufferSize = size;
}

// FIFO の解放
void SockIoReleaseFifo(FIFO *fifo)
{
	// 引数チェック
	if (fifo == NULL)
	{
		return;
	}

	UnlockFifo(fifo);
	ReleaseFifo(fifo);
}

// 送信 FIFO の取得
FIFO *SockIoGetSendFifo(SOCKIO *io)
{
	FIFO *f;
	// 引数チェック
	if (io == NULL)
	{
		return NULL;
	}

	f = io->SendFifo;
	AddRef(f->ref);
	LockFifo(f);

	return f;
}

// 受信 FIFO の取得
FIFO *SockIoGetRecvFifo(SOCKIO *io)
{
	FIFO *f;
	// 引数チェック
	if (io == NULL)
	{
		return NULL;
	}

	f = io->RecvFifo;
	AddRef(f->ref);
	LockFifo(f);

	return f;
}

// 新しい SOCKIO の作成
SOCKIO *NewSockIo(SOCK_EVENT *sent_notice_event, SOCK_EVENT *sockio_event)
{
	SOCKIO *io = ZeroMalloc(sizeof(SOCKIO));

	io->Lock = NewLock();
	io->Ref = NewRef();
	io->SendFifo = NewFifo();
	io->RecvFifo = NewFifo();
	io->SendBuf = NewBuf();

	io->SockIoEvent = NewSockEvent();

	if (sent_notice_event != NULL)
	{
		io->SentNoticeEvent = sent_notice_event;
		AddRef(sent_notice_event->ref);
	}
	else
	{
		io->SentNoticeEvent = NewSockEvent();
	}

	SockIoSetMaxSendBufferSize(io, INFINITE);
	SockIoSetTimeout(io, INFINITE);

	SockIoSetSentNoticeEvent(io);
	SockIoSetIoEvent(io);

	return io;
}

// SOCKIO の解放
void ReleaseSockIo(SOCKIO *io)
{
	// 引数チェック
	if (io == NULL)
	{
		return;
	}

	if (Release(io->Ref) == 0)
	{
		CleanupSockIo(io);
	}
}

// SOCKIO のクリーンアップ
void CleanupSockIo(SOCKIO *io)
{
	// 引数チェック
	if (io == NULL)
	{
		return;
	}

	ReleaseFifo(io->SendFifo);
	ReleaseFifo(io->RecvFifo);

	ReleaseSockEvent(io->SentNoticeEvent);
	ReleaseSockEvent(io->SockIoEvent);

	if (io->InitialPack != NULL)
	{
		FreePack(io->InitialPack);
	}

	FreeBuf(io->SendBuf);

	DeleteLock(io->Lock);

	Free(io);
}

// ソケットとスレッドのリストの作成
LIST *NewSockThreadList()
{
	return NewList(NULL);
}

// ソケットとスレッドのリストからすべてのソケットを切断してスレッドの終了を待機する
void FreeSockThreadList(LIST *o)
{
	UINT i, num;
	SOCKTHREAD **stlist;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		stlist = ToArray(o);
		num = LIST_NUM(o);

		DeleteAll(o);
	}
	UnlockList(o);

	for (i = 0;i < num;i++)
	{
		SOCKTHREAD *st = stlist[i];

		Disconnect(st->Sock);
		WaitThread(st->Thread, INFINITE);

		ReleaseSock(st->Sock);
		ReleaseThread(st->Thread);

		Free(st);
	}

	Free(stlist);

	ReleaseList(o);
}

// ソケットとスレッドのリストからの削除
void DelSockThread(LIST *o, SOCK *s)
{
	// 引数チェック
	if (o == NULL || s == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SOCKTHREAD *st = LIST_DATA(o, i);

			if (st->Sock == s)
			{
				ReleaseSock(st->Sock);
				ReleaseThread(st->Thread);

				Delete(o, st);
				Free(st);

				break;
			}
		}
	}
	UnlockList(o);
}

// ソケットとスレッドのリストへの追加
void AddSockThread(LIST *o, SOCK *s, THREAD *t)
{
	// 引数チェック
	if (o == NULL || s == NULL || t == NULL)
	{
		return;
	}

	LockList(o);
	{
		SOCKTHREAD *st = ZeroMalloc(sizeof(SOCKTHREAD));
		st->Sock = s;
		st->Thread = t;

		AddRef(s->ref);
		AddRef(t->ref);

		Add(o, st);
	}
	UnlockList(o);
}

// 指定された証明書が信頼されているかどうかチェックする
bool WtIsTrustedCert(WT *wt, X *cert)
{
	// 引数チェック
	if (wt == NULL || cert == NULL)
	{
		return false;
	}

	if (CompareX(wt->MasterCert, cert))
	{
		// マスター証明書
		return true;
	}

	if (CheckXDateNow(cert) == false)
	{
		// 有効期限切れ
		return false;
	}

	if (CheckX(cert, wt->MasterCert))
	{
		// マスター証明書に署名された証明書
		return true;
	}

	return false;
}

// WideTunnel の初期化
WT *NewWtFromHamcore()
{
	WT *wt;
	X *master_cert;
	char mode[MAX_PATH] = {0};
	char system[MAX_PATH] = CLEAN;

	WideLoadEntryPoint(&master_cert, NULL, 0, NULL, mode, sizeof(mode), system, sizeof(system));

	wt = NewWt(master_cert);

	StrCpy(wt->EntranceMode, sizeof(wt->EntranceMode), mode);
	StrCpy(wt->System, sizeof(wt->System), system);

	FreeX(master_cert);

	return wt;
}
WT *NewWt(X *master_cert)
{
	WT *wt;
	// 引数チェック
	if (master_cert == NULL)
	{
		return NULL;
	}

	// プロセス優先度を上げる
	OSSetHighPriority();

	wt = ZeroMalloc(sizeof(WT));

	wt->ErrorControllersList = NewStrList();
	wt->ErrorControllersListLock = NewLock();

	wt->BootTime = SystemTime64();
	wt->BootTick = Tick64();

	wt->CfgRwSaveLock = NewLock();

	wt->Lock = NewLock();
	wt->Ref = NewRef();

	wt->EntranceCacheLock = NewLock();

	wt->Cedar = NewCedar(NULL, NULL);
	wt->MasterCert = CloneX(master_cert);

	wt->InternetSetting = ZeroMalloc(sizeof(INTERNET_SETTING));
	Copy(wt->InternetSetting, GetNullInternetSetting(), sizeof(INTERNET_SETTING));

	wt->DefaultEntranceCacheExpireSpan = WT_WPC_DEFAULT_ENTRANCE_CACHE_SPAN;

	return wt;
}

// WideTunnel の解放
void ReleaseWt(WT *wt)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	if (Release(wt->Ref) == 0)
	{
		CleanupWt(wt);
	}
}

// WideTunnel のクリーンアップ
void CleanupWt(WT *wt)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	ReleaseCedar(wt->Cedar);
	FreeX(wt->MasterCert);

	DeleteLock(wt->Lock);
	DeleteLock(wt->EntranceCacheLock);
	DeleteLock(wt->CfgRwSaveLock);
	Free(wt->InternetSetting);

	FreeStrList(wt->ErrorControllersList);
	DeleteLock(wt->ErrorControllersListLock);

	Free(wt);
}


