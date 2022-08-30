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


// DS.c
// シン・テレワークシステム サーバー

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

#ifdef _WIN32
#include "..\PenCore\resource.h"
#endif // _WIN32

// Guacd の開始
DS_GUACD* DsStartGuacd(DS* ds, UINT dn_flags)
{
#ifndef OS_WIN32
	return NULL;
#else	// OS_WIN32
	if (DsIsGuacdSupported(ds) == false)
	{
		DsDebugLog(ds, "DsStartGuacd", "DsIsGuacdSupported = false.");
		return NULL;
	}

	wchar_t guacd_dir[MAX_PATH] = CLEAN;

	DsGetGuacdTempDirName(guacd_dir, sizeof(guacd_dir));
	DsDebugLog(ds, "DsStartGuacd", "DsGetGuacdTempDirName: %S", guacd_dir);

	if (DsExtractGuacdToTempDir(ds) == false)
	{
		DsDebugLog(ds, "DsStartGuacd", "DsExtractGuacdToTempDir failed.");
		return NULL;
	}

	wchar_t exe_path[MAX_PATH] = CLEAN;
	CombinePathW(exe_path, sizeof(exe_path), guacd_dir, L"ThinWebGateway.exe");

	UINT port = 0;
	UINT process_id = 0;
	void *handle = DsStartGuacdOnRandomPort(ds, exe_path, DS_GUACD_RAND_PORT_MIN, DS_GUACD_RAND_PORT_MAX, DS_GUACD_RAND_PORT_NUM_TRY, &port, &process_id, dn_flags);
	if (handle == NULL)
	{
		DsDebugLog(ds, "DsStartGuacd", "DsStartGuacdOnRandomPort failed.");
		return NULL;
	}

	DsDebugLog(ds, "DsStartGuacd", "DsStartGuacdOnRandomPort OK. Port number = %u", port);

	SOCK* s = Connect("127.0.0.1", port);
	if (s == NULL)
	{
		DsDebugLog(ds, "DsStartGuacd", "Connect to the 127.0.0.1 port %u error", port);

		MsKillProcessByHandle(handle);
		MsCloseHandle(handle);
		return NULL;
	}

	DS_GUACD* g = ZeroMalloc(sizeof(DS_GUACD));

	g->ProcessHandle = handle;
	g->ProcessId = process_id;
	g->SelectedPort = port;
	g->Sock = s;

	return g;

#endif // OS_WIN32
}

// Guacd のすべてのゾンビ・プロセスを強制終了する
void DsKillAllZombineGuacdProcesses(DS* ds)
{
#ifndef OS_WIN32
	return;
#else	// OS_WIN32
	wchar_t guacd_dir[MAX_PATH] = CLEAN;

	DsGetGuacdTempDirName(guacd_dir, sizeof(guacd_dir));

	wchar_t exe_path[MAX_PATH] = CLEAN;
	CombinePathW(exe_path, sizeof(exe_path), guacd_dir, L"ThinWebGateway.exe");

	MsKillProcessByExeName(exe_path);
#endif // OS_WIN32
}

// Guacd の終了
void DsStopGuacd(DS* ds, DS_GUACD* g)
{
#ifndef OS_WIN32
	return;
#else	// OS_WIN32
	if (g == NULL)
	{
		return;
	}

	MsKillProcessByHandle(g->ProcessHandle);

	MsCloseHandle(g->ProcessHandle);

	Disconnect(g->Sock);
	ReleaseSock(g->Sock);

	Free(g);
#endif // OS_WIN32
}

// Guacd をランダムポートで起動
void* DsStartGuacdOnRandomPort(DS* ds, wchar_t* exe_path, UINT port_min, UINT port_max, UINT num_try, UINT* ret_port, UINT* ret_process_id, UINT dn_flags)
{
#ifndef OS_WIN32
	return NULL;
#else	// OS_WIN32
	if (exe_path == NULL || num_try == 0 || ret_port == NULL || ret_process_id == NULL)
	{
		return NULL;
	}

	DsDebugLog(ds, "DsStartGuacdOnRandomPort", "Trying port_min = %u, port_max = %u, num_try = %u",
		port_min, port_max, num_try);

	UINT i;
	for (i = 0; i < num_try;i++)
	{
		// 利用可能な TCP ランダムポートを 1 つ取得する
		UINT port = GetFreeRandomTcpPort(port_min, port_max, DS_GUACD_RAND_PORT_NUM_TRY2, true);
		if (port == 0)
		{
			DsDebugLog(ds, "DsStartGuacdOnRandomPort", "GetFreeRandomTcpPort error.");
			return NULL;
		}

		// このポートで起動して Listen 状態になるかどうか試す
		void* handle = DsStartGuacdOnSpecifiedPort(ds, exe_path, port, ret_process_id, dn_flags);
		if (handle != NULL)
		{
			// 起動成功
			*ret_port = port;
			DsDebugLog(ds, "DsStartGuacdOnRandomPort", "DsStartGuacdOnSpecifiedPort (port = %u) OK. Process ID = %u", port, *ret_process_id);
			return handle;
		}

		DsDebugLog(ds, "DsStartGuacdOnRandomPort", "DsStartGuacdOnSpecifiedPort (port = %u) error.", port);
	}

	// 指定回数試行しても起動に失敗した
	return NULL;

#endif // OS_WIN32
}

// Guacd を指定したポートで起動
void* DsStartGuacdOnSpecifiedPort(DS* ds, wchar_t* exe_path, UINT port, UINT* ret_process_id, UINT dn_flags)
{
#ifndef OS_WIN32
	return NULL;
#else	// OS_WIN32
	if (exe_path == NULL || port == 0 || ret_process_id == NULL)
	{
		return NULL;
	}

	wchar_t dir[MAX_PATH] = CLEAN;
	GetDirNameFromFilePathW(dir, sizeof(dir), exe_path);

	wchar_t args[MAX_PATH] = CLEAN;
	UniFormat(args, sizeof(args), L"-f -b 127.0.0.1 -l %u -d %u", port, dn_flags);

	// 起動を してみます
	UINT process_id = 0;
	void* handle = Win32RunEx4W(exe_path, args, true, &process_id, false, dir);
	if (handle == NULL)
	{
		// 起動に失敗
		DsDebugLog(ds, "DsStartGuacdOnRandomPort", "Win32RunEx4W error. exe = %S, args = %S",
			exe_path, args);
		return NULL;
	}
	DsDebugLog(ds, "DsStartGuacdOnRandomPort", "Win32RunEx4W OK. exe = %S, args = %S, proc_id = %u",
		exe_path, args, process_id);

	UINT64 now = Tick64();
	UINT64 giveup = now + (UINT64)DS_GUACD_STARTUP_TIMEOUT;

	bool ok = false;

	while (true)
	{
		// 定期的に TCP テーブルを確認し、指定したポートが Listen 状態になるまで待ちます
		LIST* tcp_table = GetTcpTableList();
		bool tcp_ok = false;
		if (tcp_table != NULL)
		{
			UINT i;
			for (i = 0;i < LIST_NUM(tcp_table);i++)
			{
				TCPTABLE* t = LIST_DATA(tcp_table, i);

				if (t->ProcessId == process_id)
				{
					if (t->LocalPort == port)
					{
						// 一致
						tcp_ok = true;
						break;
					}
				}
			}

			FreeTcpTableList(tcp_table);
		}
		else
		{
			// GetTcpTableList に失敗した場合 (通常は想定されない) は常に成功とみなす
			DsDebugLog(ds, "DsStartGuacdOnRandomPort", "GetTcpTableList error. Ignored.");
			tcp_ok = true;
		}

		if (tcp_ok)
		{
			ok = true;
			break;
		}

		now = Tick64();
		if (now >= giveup)
		{
			// タイムアウトが発生してしまいました
			DsDebugLog(ds, "DsStartGuacdOnRandomPort", "Timed out.");
			break;
		}

		if (MsWaitProcessExitWithTimeoutEx(handle, 100, true))
		{
			DsDebugLog(ds, "DsStartGuacdOnRandomPort", "Child process exited abnormally.");
			// プロセスが終了してしまいました
			break;
		}
	}

	if (ok == false)
	{
		// 失敗した場合はプロセスを Kill してハンドルを閉じる
		MsKillProcessByHandle(handle);
		MsCloseHandle(handle);
		return NULL;
	}
	else
	{
		// 成功した場合はハンドルを返す
		*ret_process_id = process_id;
		return handle;
	}

#endif // OS_WIN32
}

// Guacd 用 Temp ディレクトリ名を取得
void DsGetGuacdTempDirName(wchar_t* name, UINT size)
{
#ifdef OS_WIN32
	if (name == NULL) return;

	wchar_t *win_tmp_dir = MsGetTempDirW();
	wchar_t build_number_str[MAX_PATH] = CLEAN;

	UniFormat(build_number_str, sizeof(build_number_str), L"Build_%u", CEDAR_BUILD);

	CombinePathW(name, size, win_tmp_dir, L"ThinTelework_" APP_ID_PREFIX_UNICODE L"_Guacd");
	CombinePathW(name, size, name, build_number_str);
#else	// OS_WIN32
	UniStrCpy(name, size, L"");
#endif // OS_WIN32
}

// Guacd を Temp ディレクトリに展開する
bool DsExtractGuacdToTempDir(DS* ds)
{
#ifndef OS_WIN32
	return false;
#else	// OS_WIN32
	if (DsIsGuacdSupported(ds) == false)
	{
		return false;
	}

	bool ret = false;

	if (ds != NULL) Lock(ds->GuacdFileLock);
	{
		wchar_t dst_dir[MAX_PATH] = CLEAN;
		DsGetGuacdTempDirName(dst_dir, sizeof(dst_dir));
		MakeDirExW(dst_dir);

		wchar_t* src_dir = L"|ThinWebGateway\\";

		wchar_t tmp[MAX_PATH] = CLEAN;

		// ThinWebGatewayFileList.txt ファイルを読み込む
		CombinePathW(tmp, sizeof(tmp), src_dir, L"ThinWebGatewayFileList.txt");
		BUF* file_list_buf = ReadDumpW(tmp);

		if (file_list_buf != NULL)
		{
			SeekBufToEnd(file_list_buf);
			WriteBufChar(file_list_buf, 0);

			LIST* lines = GetStrListFromLines((char*)file_list_buf->Buf);

			if (lines != NULL)
			{
				UINT i;

				ret = true;

				for (i = 0;i < LIST_NUM(lines);i++)
				{
					char* filename = LIST_DATA(lines, i);

					if (IsFilledStr(filename))
					{
						wchar_t filename_w[MAX_PATH] = CLEAN;

						StrToUni(filename_w, sizeof(filename_w), filename);

						wchar_t src_fn[MAX_PATH] = CLEAN;
						wchar_t dst_fn[MAX_PATH] = CLEAN;

						CombinePathW(src_fn, sizeof(src_fn), src_dir, filename_w);
						CombinePathW(dst_fn, sizeof(dst_fn), dst_dir, filename_w);

						// ファイルが存在するか?
						if (IsFileExistsW(dst_fn) == false)
						{
							// 存在しない場合のみコピー
							if (FileCopyW(src_fn, dst_fn) == false)
							{
								Debug("DsExtractGuacdToTempDir: Copy Error: %S\n", dst_fn);
								ret = false;
							}
						}
					}
				}

				FreeStrList(lines);
			}

			FreeBuf(file_list_buf);
		}
	}
	if (ds != NULL) Unlock(ds->GuacdFileLock);

	return ret;

#endif // OS_WIN32
}

// Guacd がサポートされているかどうか
bool DsIsGuacdSupported(DS* ds)
{
#ifndef OS_WIN32
	return false;
#else	// OS_WIN32
	return MsIsVista();

#endif // OS_WIN32
}

// Windows RDP Policy GET
void DsWin32GetRdpPolicy(DS_WIN32_RDP_POLICY* pol)
{
	if (pol == NULL)
	{
		return;
	}

	Zero(pol, sizeof(DS_WIN32_RDP_POLICY));

#ifdef OS_WIN32
	if (MsIsRemoteDesktopAvailable())
	{
		pol->fDisableCdm = Win32ReadLocalGroupPolicyValueInt32(true,
			"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			"fDisableCdm");

		pol->fDenyTSConnections = Win32ReadLocalGroupPolicyValueInt32(true,
			"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			"fDenyTSConnections");

		pol->fDisableClip = Win32ReadLocalGroupPolicyValueInt32(true,
			"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			"fDisableClip");

		pol->HasValidValue = true;
	}
#endif // OS_WIN32

}

// Windows RDP Policy SET
bool DsWin32SetRdpPolicy(DS_WIN32_RDP_POLICY* pol)
{
	bool ret = false;
	if (pol == NULL || pol->HasValidValue == false)
	{
		return false;
	}

#ifdef OS_WIN32
	if (MsIsRemoteDesktopAvailable() == false)
	{
		return false;
	}

	if (MsIsAdmin() == false)
	{
		return false;
	}

	if (Win32WriteLocalGroupPolicyValueInt32(true,
		"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
		"fDisableCdm",
		pol->fDisableCdm))
	{
		ret = true;
	}

	if (Win32WriteLocalGroupPolicyValueInt32(true,
		"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
		"fDenyTSConnections",
		pol->fDenyTSConnections))
	{
		ret = true;
	}

	if (Win32WriteLocalGroupPolicyValueInt32(true,
		"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
		"fDisableClip",
		pol->fDisableClip))
	{
		ret = true;
	}
#endif // OS_WIN32

	return ret;
}

// 適用されるポリシーメッセージの表示
void DsPreparePolicyMessage(wchar_t *str, UINT str_size, DS_POLICY_BODY *pol)
{
	wchar_t *msg = _UU("DS_POLICY_NONE");
	wchar_t *otp_str = _UU("DS_POLICY_NO");
	wchar_t *inspection_str = _UU("DS_POLICY_NO");
	wchar_t *disableshare_str = _UU("DS_POLICY_NO");
	wchar_t *maccheck_str = _UU("DS_POLICY_NO");
	wchar_t syslog_str[256];
	URL_DATA url = {0};

	UniStrCpy(syslog_str, sizeof(syslog_str), _UU("DS_POLICY_NONE"));

	UniStrCpy(str, str_size, L"");

	if (pol == NULL || str == NULL)
	{
		return;
	}

	if (IsZero(pol, sizeof(DS_POLICY_BODY)))
	{
		return;
	}
	
	if (UniIsEmptyStr(pol->ServerMessage) == false)
	{
		msg = pol->ServerMessage;
	}

	// 通常版
	if (pol->EnforceOtp)
	{
		otp_str = _UU("DS_POLICY_YES");
	}

	if (pol->EnforceInspection)
	{
		inspection_str = _UU("DS_POLICY_YES");
	}

	if (pol->EnforceMacCheck)
	{
		maccheck_str = _UU("DS_POLICY_YES");
	}

	if (pol->DisableShare)
	{
		disableshare_str = _UU("DS_POLICY_YES");
	}

	if (IsEmptyStr(pol->SyslogHostname) == false)
	{
		UniFormat(syslog_str, sizeof(syslog_str), _UU("DS_POLICY_SYSLOG"), pol->SyslogHostname, pol->SyslogPort);
	}

	ParseUrl(&url, pol->SrcUrl, false, NULL);

	UniFormat(str, str_size, _UU("DS_POLICY_MESSAGE"),
		otp_str, disableshare_str, inspection_str, maccheck_str,
		syslog_str, msg, url.HostName);
}

// ポリシーファイルのパース
bool DsParsePolicyFile(DS_POLICY_BODY *b, BUF *buf)
{
	LIST *o;
	char *s;
	char *s_hash;
	wchar_t *ws;
	if (b == NULL || buf == NULL)
	{
		return false;
	}

	SeekBufToBegin(buf);

	Zero(b, sizeof(DS_POLICY_BODY));

	o = ReadIni(buf);

	if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") == false)
	{
		// 通常版
		b->EnforceOtp = IniIntValue(o, "ENFORCE_OTP");
		b->DisableOtp = IniIntValue(o, "DISABLE_OTP") && (!b->EnforceOtp);

		b->EnforceInspection = IniIntValue(o, "ENFORCE_INSPECTION");
		b->DisableInspection = IniIntValue(o, "DISABLE_INSPECTION") && (!b->EnforceInspection);

		b->EnforceMacCheck = IniIntValue(o, "ENFORCE_MACCHECK");
		b->DisableMacCheck = IniIntValue(o, "DISABLE_MACCHECK") && (!b->EnforceMacCheck);

		b->EnforceWatermark = IniIntValue(o, "ENFORCE_WATERMARK");
		b->DisableWatermark = IniIntValue(o, "DISABLE_WATERMARK") && (!b->EnforceWatermark);

		b->DisableShare = IniIntValue(o, "DISABLE_SHARE");
	}
	else
	{
		// LGWAN 版
		b->DisableOtp = IniIntValue(o, "DISABLE_OTP");
		b->EnforceOtp = !b->DisableOtp;

		b->DisableInspection = IniIntValue(o, "DISABLE_INSPECTION");
		b->EnforceInspection = !b->DisableInspection;

		b->DisableMacCheck = IniIntValue(o, "DISABLE_MACCHECK");
		b->EnforceMacCheck = !b->DisableMacCheck;

		b->DisableWatermark = IniIntValue(o, "DISABLE_WATERMARK");
		b->EnforceWatermark = !b->DisableWatermark;

		b->DisableShare = true;
	}

	if (Vars_ActivePatch_GetBool("IsPublicVersion") == false)
	{
		b->RequireMinimumClientBuild = IniIntValue(o, "REQUIRE_MINIMUM_CLIENT_BUILD");
		b->RequireMinimumClientBuild = MIN(b->RequireMinimumClientBuild, CEDAR_BUILD);
	}

	b->AuthLockoutCount = IniIntValue(o, "AUTH_LOCKOUT_COUNT");
	b->AuthLockoutTimeout = IniIntValue(o, "AUTH_LOCKOUT_TIMEOUT");
	b->IdleTimeout = IniIntValue(o, "IDLE_TIMEOUT");
	b->EnableOcsp = IniIntValue(o, "ENABLE_OCSP");

	if (b->IdleTimeout != 0)
	{
		// IDLE_TIMEOUT の最小値を設定する
		b->IdleTimeout = MAX(b->IdleTimeout, DS_POLICY_IDLE_TIMEOUT_MIN_SECS);
	}

	b->DenyClientsApp = IniIntValue(o, "DENY_CLIENTS_APP");
	b->DenyClientsHtml5 = IniIntValue(o, "DENY_CLIENTS_HTML5");

	if (b->DenyClientsApp && b->DenyClientsHtml5)
	{
		b->DenyClientsApp = false;
		b->DenyClientsHtml5 = false;
	}

	if (Vars_ActivePatch_GetBool("IsPublicVersion") == false)
	{
		// パブリック版以外では ENFORCE_LIMITED_FIREWALL を設定可能
		b->IsLimitedFirewallMandated = IniIntValue(o, "ENFORCE_LIMITED_FIREWALL");

		if (b->IsLimitedFirewallMandated)
		{
			// ENFORCE_LIMITED_FIREWALL_COMPUTERNAME_STARTWITH
			ws = IniUniStrValue(o, "ENFORCE_LIMITED_FIREWALL_COMPUTERNAME_STARTWITH");
			if (UniIsEmptyStr(ws) == false)
			{
				UniStrCpy(b->LimitedFirewallMandateExcludeComputernameStartWith,
					sizeof(b->LimitedFirewallMandateExcludeComputernameStartWith),
					ws);
			}
		}
	}

	b->EnforceProcessWatcherAlways = IniIntValue(o, "ENFORCE_PROCESS_WATCHER_ALWAYS");
	b->EnforceProcessWatcher = b->EnforceProcessWatcherAlways || IniIntValue(o, "ENFORCE_PROCESS_WATCHER");

	s = IniStrValue(o, "SERVER_ALLOWED_MAC_LIST_URL");
	if (IsEmptyStr(s) == false)
	{
		StrCpy(b->ServerAllowedMacListUrl, sizeof(b->ServerAllowedMacListUrl), s);
	}

	s = IniStrValue(o, "CLIENT_ALLOWED_MAC_LIST_URL");
	if (IsEmptyStr(s) == false)
	{
		StrCpy(b->ClientAllowedMacListUrl, sizeof(b->ClientAllowedMacListUrl), s);

		if (b->EnforceMacCheck)
		{
			if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") ||
				Vars_ActivePatch_GetBool("IsPrivateVersion"))
			{
				// セキュリティ強化版またはプライベート版では、NO_LOCAL_MAC_ADDRESS_LIST のポリシー指定を読み込むことができる
				b->NoLocalMacAddressList = IniIntValue(o, "NO_LOCAL_MAC_ADDRESS_LIST");
			}
		}
	}

	s = IniStrValue(o, "SYSLOG_HOSTNAME");
	if (IsEmptyStr(s) == false)
	{
		StrCpy(b->SyslogHostname, sizeof(b->SyslogHostname), s);
		b->SyslogPort = IniIntValue(o, "SYSLOG_PORT");

		if (b->SyslogPort == 0 || b->SyslogPort >= 65536)
		{
			b->SyslogPort = SYSLOG_PORT;
		}
	}

	if (b->EnforceWatermark)
	{
		ws = IniUniStrValue(o, "WATERMARK_MESSAGE");
		if (UniIsEmptyStr(ws) == false)
		{
			UniStrCpy(b->WatermarkMessage, sizeof(b->WatermarkMessage), ws);
			b->WatermarkMessage[40] = 0;
		}
	}

	s = IniStrValue(o, "ENFORCE_OTP_ENDWITH");
	s_hash = IniStrValue(o, "ENFORCE_OTP_ENDWITH_SECURITY");
	if (IsEmptyStr(s) == false && IsEmptyStr(s_hash) == false)
	{
		char tmp[128];
		UCHAR hash[SHA256_SIZE];
		BUF *hash2;

		Format(tmp, sizeof(tmp), "I_take_an_oath_that_I_will_not_violate_the_rights_of_our_employees_%s", s);
		StrUpper(tmp);

		HashSha256(hash, tmp, StrLen(tmp));

		hash2 = StrToBin(s_hash);

		if (hash2 != NULL && hash2->Size == SHA256_SIZE &&
			Cmp(hash2->Buf, hash, SHA256_SIZE) == 0)
		{
			// ハッシュ一致
			StrCpy(b->EnforceOtpEndWith, sizeof(b->EnforceOtpEndWith), s);
		}

		FreeBuf(hash2);
	}

	ws = IniUniStrValue(o, "SERVER_MESSAGE");
	if (UniIsEmptyStr(ws) == false)
	{
		wchar_t tmp[1024] = {0};

		UniStrCpy(tmp, sizeof(tmp), ws);

		UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"<br>", L"\r\n", false);

		UniStrCpy(b->ServerMessage, sizeof(b->ServerMessage), tmp);
	}

	FreeIni(o);

	return true;
}

// 現在のポリシーの取得
bool DsPolicyClientGetPolicy(DS_POLICY_CLIENT *c, DS_POLICY_BODY *pol)
{
	Zero(pol, sizeof(DS_POLICY_BODY));
	if (c == NULL || pol == NULL)
	{
		return false;
	}

	if (c->PolicyExpires <= Tick64())
	{
		return false;
	}

	Copy(pol, &c->Policy, sizeof(DS_POLICY_BODY));

	if (IsZero(pol, sizeof(DS_POLICY_BODY)))
	{
		return false;
	}

	return true;
}

// ポリシー取得試行が完了しているかどうか
bool DsIsTryCompleted(DS *ds)
{
	if (ds == NULL)
	{
		return false;
	}

	if (ds->PolicyClient == NULL)
	{
		return false;
	}

	if (ds->PolicyClient->NumTryCompleted >= ds->PolicyClient->NumThreads)
	{
		return true;
	}

	return false;
}

// 現在のポリシーの取得 (DS から)
bool DsGetPolicy(DS *ds, DS_POLICY_BODY *pol)
{
	Zero(pol, sizeof(DS_POLICY_BODY));
	if (ds == NULL || pol == NULL)
	{
		return false;
	}

	return DsPolicyClientGetPolicy(ds->PolicyClient, pol);
}

// ポリシークライアントスレッド
void DsPolicyClientThread(THREAD *thread, void *param)
{
	DS_POLICY_CLIENT *c;
	DS_POLICY_THREAD_CTX *ctx = (DS_POLICY_THREAD_CTX *)param;
	UINT num_try = 0;
	char prefix[128] = CLEAN;

	if (thread == NULL || param == NULL)
	{
		return;
	}

	Format(prefix, sizeof(prefix), "PolicyServer AutoDetect Thread %u", ctx->ClientId);

	c = ctx->Client;

	DS *ds = c->Ds;

	DsDebugLog(ds, prefix, "Thread is started.");

	while (c->Halt == false)
	{
		UINT i;
		LIST *dns_suffix_list = NULL;

		num_try++;

		if (ctx->ReplaceSuffix)
		{
#ifdef OS_WIN32
			dns_suffix_list = Win32GetDnsSuffixList();
#else	// OS_WIN32
			dns_suffix_list = NewStrList();
#endif	// OS_WIN32
		}

		for (i = 0;i < (dns_suffix_list == NULL ? 1 : LIST_NUM(dns_suffix_list));i++)
		{
			URL_DATA data;
			char url[MAX_PATH];

			if (c->Halt)
			{
				break;
			}

			// URL の確定
			StrCpy(url, sizeof(url), ctx->Url);

			if (dns_suffix_list != NULL)
			{
				char *suffix = LIST_DATA(dns_suffix_list, i);

				ReplaceStrEx(url, sizeof(url), url, "__DOMAIN__", suffix, false);
			}

			//Debug("Policy trying from %s ...\n", url);

			// この URL からのファイルの受信試行
			if (ParseUrl(&data, url, false, NULL))
			{
				DsDebugLog(ds, prefix, "Trying to detect the policy server for candidate URL %u '%s' ...", i, url);

				UINT err = 0;
				BUF *http_error_buf = NewBuf();
				bool is_server_error = false;
				BUF *buf = HttpRequestEx6(&data, NULL, 0, 0, &err, false, NULL, NULL, NULL, NULL, 0, &c->Halt,
					DS_POLICY_CLIENT_MAX_FILESIZE, NULL, NULL, NULL, false, true, http_error_buf,
					&is_server_error, HTTP_REQUEST_FLAG_NONE);

				if (buf != NULL)
				{
					DS_POLICY_BODY pol = {0};

					DsDebugLog(ds, prefix, "Policy server URL %u '%s' returned %u bytes data to the client.",
						i, url, buf->Size);

					if (DsParsePolicyFile(&pol, buf))
					{
						DsDebugLog(ds, prefix, "Policy server URL %u '%s' data parse OK.",
							i, url);

						StrCpy(pol.SrcUrl, sizeof(pol.SrcUrl), url);

						if (Cmp(&c->Policy, &pol, sizeof(DS_POLICY_BODY)) != 0)
						{
							DsDebugLog(ds, prefix, "Policy data is applied from URL %u '%s'.",
								i, url);
							//Debug("Policy received and updated from '%s'.\n", url);
							Copy(&c->Policy, &pol, sizeof(DS_POLICY_BODY));
						}
						else
						{
							DsDebugLog(ds, prefix, "The policy data on the client memory is exactly same to the downloaded data from URL %u '%s'. Do nothing.",
								i, url);
						}

						c->PolicyExpires = Tick64() + (UINT64)DS_POLICY_EXPIRES;
					}
					else
					{
						DsDebugLog(ds, prefix, "Policy server URL %u '%s' data error OK.",
							i, url);
					}

					FreeBuf(buf);
				}
				else
				{
					char *err_str = GetOneLineStrFromBuf(http_error_buf, NULL);
					DsDebugLog(ds, prefix, "Policy server candidate URL %u '%s' access error. Error code: %u, Error details: %s",
						i, url, err, err_str);
					Free(err_str);
					//UniDebug(L"%s\n", _E(err));
				}

				FreeBuf(http_error_buf);
			}
		}

		if (num_try == 1)
		{
			c->NumTryCompleted++;
		}

		FreeStrList(dns_suffix_list);

		if (c->Halt)
		{
			break;
		}

		// 次の受信まで待機
		DsDebugLog(ds, prefix, "Waiting for %u seconds for next retry to detect the policy server.", DS_POLICY_CLIENT_UPDATE_INTERVAL / 1000);
		Wait(ctx->HaltEvent, DS_POLICY_CLIENT_UPDATE_INTERVAL);
	}

	DsDebugLog(ds, prefix, "Thread is stopped. Bye.");

	ReleaseEvent(ctx->HaltEvent);

	Free(ctx);
}

// ポリシークライアントの開始
DS_POLICY_CLIENT *DsNewPolicyClient(DS *ds, char* server_hash)
{
	char args[MAX_SIZE];
	wchar_t hostname[MAX_PATH] = {0};
	DS_POLICY_CLIENT *c = ZeroMalloc(sizeof(DS_POLICY_CLIENT));

	c->Ds = ds;

#ifdef	OS_WIN32
	MsGetComputerNameFull(hostname, sizeof(hostname));
#endif	// OS_WIN32

	c->HaltEventList = NewList(NULL);

	c->ThreadList = NewThreadList();

	StrCpy(c->ServerHash, sizeof(c->ServerHash), server_hash);

	Format(args, sizeof(args), "?server_build=%u&server_hostname=%S&appid=%s",
		CEDAR_BUILD, hostname, APP_ID_PREFIX);

	if (true)
	{
		DS_POLICY_THREAD_CTX *ctx = ZeroMalloc(sizeof(DS_POLICY_THREAD_CTX));
		THREAD *t;

		c->NumThreads++;

		ctx->Client = c;

		ctx->ClientId = 1;

		ctx->HaltEvent = NewEvent();
		AddRef(ctx->HaltEvent->ref);
		Add(c->HaltEventList, ctx->HaltEvent);

		StrCpy(ctx->Url, sizeof(ctx->Url), "https://" DS_POLICY_INDOMAIN_SERVER_NAME ".__DOMAIN__/get-telework-policy/");
		StrCat(ctx->Url, sizeof(ctx->Url), args);
		ctx->ReplaceSuffix = true;

		t = NewThread(DsPolicyClientThread, ctx);

		AddThreadToThreadList(c->ThreadList, t);

		ReleaseThread(t);
	}

	if (true)
	{
		DS_POLICY_THREAD_CTX *ctx = ZeroMalloc(sizeof(DS_POLICY_THREAD_CTX));
		THREAD *t;

		c->NumThreads++;

		ctx->Client = c;

		ctx->ClientId = 2;

		ctx->HaltEvent = NewEvent();
		AddRef(ctx->HaltEvent->ref);
		Add(c->HaltEventList, ctx->HaltEvent);

		StrCpy(ctx->Url, sizeof(ctx->Url), "https://" DS_POLICY_IP_SERVER_NAME "/get-telework-policy/");
		StrCat(ctx->Url, sizeof(ctx->Url), args);
		ctx->ReplaceSuffix = false;

		t = NewThread(DsPolicyClientThread, ctx);

		AddThreadToThreadList(c->ThreadList, t);

		ReleaseThread(t);
	}

	return c;
}

// ポリシークライアントの終了
void DsFreePolicyClient(DS_POLICY_CLIENT *c)
{
	UINT i;
	if (c == NULL)
	{
		return;
	}

	c->Halt = true;

	for (i = 0; i < LIST_NUM(c->HaltEventList);i++)
	{
		EVENT *e = LIST_DATA(c->HaltEventList, i);

		Set(e);
	}

	FreeThreadList(c->ThreadList);


	for (i = 0; i < LIST_NUM(c->HaltEventList);i++)
	{
		EVENT *e = LIST_DATA(c->HaltEventList, i);

		ReleaseEvent(e);
	}

	ReleaseList(c->HaltEventList);

	Free(c);
}


//// 指定された IP アドレスがプライベート IP アドレスかどうかチェックする
//bool IsIPPrivate(IP *ip)
//{
//	// 引数チェック
//	if (ip == NULL)
//	{
//		return false;
//	}
//
//	if (ip->addr[0] == 10)
//	{
//		return true;
//	}
//
//	if (ip->addr[0] == 172)
//	{
//		if (ip->addr[1] >= 16 && ip->addr[1] <= 31)
//		{
//			return true;
//		}
//	}
//
//	if (ip->addr[0] == 192 && ip->addr[1] == 168)
//	{
//		return true;
//	}
//
//	if (ip->addr[0] == 169 && ip->addr[1] == 254)
//	{
//		return true;
//	}
//
//	return false;
//}

// Bluetooth データ受信処理メイン
void DsBluetoothMain(DS *ds, SOCKIO *sock)
{
#ifdef	OS_WIN32
	UINT64 last_save_tick = 0;
	// 引数チェック
	if (ds == NULL || sock == NULL)
	{
		return;
	}

	DsLog(ds, "DSL_BT_ESTABLISHED");

	while (true)
	{
		wchar_t filename[MAX_PATH];
		UINT filesize;
		UCHAR *data;
		UINT zero = 0;
		wchar_t fullpath[MAX_PATH];

		// ファイル名の受信
		if (SockIoRecvAll(sock, filename, sizeof(filename)) == false)
		{
			break;
		}

		Debug("bluetooth: filename: %S\n", filename);

		filename[MAX_PATH - 1] = 0;

		// ファイルサイズの受信
		if (SockIoRecvAll(sock, &filesize, sizeof(UINT)) == false)
		{
			break;
		}

		filesize = Endian32(filesize);

		if (filesize > DC_BLUETOOTH_MAX_FILESIZE)
		{
			break;
		}

		Debug("bluetooth: filesize: %u\n", filesize);

		// データの受信
		data = Malloc(filesize);

		if (SockIoRecvAll(sock, data, filesize) == false)
		{
			Free(data);
			break;
		}

		Debug("bluetooth: file received ok.\n");

		DsLog(ds, "DSL_RECV_BT_FILE", filename, filesize);

		// データを指定されたディレクトリに保存する
		if (UniIsEmptyStr(ds->BluetoothDir) == false)
		{
			UINT64 now = Tick64();

			if (last_save_tick != 0 &&
				((last_save_tick + (UINT64)DS_BLUETOOTH_FILE_SAVE_INTERVAL) > now))
			{
				SleepThread((UINT)(last_save_tick + (UINT64)DS_BLUETOOTH_FILE_SAVE_INTERVAL - now));
			}

			last_save_tick = now;

			// 一応ディレクトリを作成する
			MsUniMakeDirEx(ds->BluetoothDir);

			// フルパスの生成
			CombinePathW(fullpath, sizeof(fullpath), ds->BluetoothDir, filename);

			// データ保存
			FileWriteAllW(fullpath, data, filesize);

			Debug("file %S saved.\n", fullpath);

			DsLog(ds, "DSL_SAVE_BT_FILE", fullpath, filesize);

			// 受信完了通知
			if (SockIoSendAll(sock, &zero, sizeof(zero)) == false)
			{
				Free(data);
				break;
			}
		}
		else
		{
			SockIoDisconnect(sock);
			break;
		}

		Free(data);
	}

	DsLog(ds, "DSL_BT_CLOSES");
#endif  // OS_WIN32
}

// タスクトレイのアイコンを更新する
void DsUpdateTaskIcon(DS *ds)
{
#ifdef	OS_WIN32
	HICON hIcon;
	LIST *o;
	UINT num = 0;
	wchar_t tmp[MAX_SIZE * 2];
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	if (MsIsTrayInited() == false)
	{
		return;
	}

	hIcon = LoadSmallIcon(ICO_TOWER);

	LockList(ds->ClientList);
	{
		UINT i;

		o = NewListFast(CompareStr);

		if (LIST_NUM(ds->ClientList) >= 1)
		{
			hIcon = LoadSmallIcon(ICO_USER_ADMIN);
		}

		for (i = 0;i < LIST_NUM(ds->ClientList);i++)
		{
			DS_CLIENT *c = LIST_DATA(ds->ClientList, i);

			if (IsInListStr(o, c->HostName) == false)
			{
				Insert(o, c->HostName);
			}
		}

		if (LIST_NUM(o) == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("DS_TRAY_TOOLTIP_0"));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("DS_TRAY_TOOLTIP_1"));

			for (i = 0;i < LIST_NUM(o);i++)
			{
				char *name = LIST_DATA(o, i);
				wchar_t name_w[MAX_PATH];
	
				StrToUni(name_w, sizeof(name_w), name);

				UniStrCat(tmp, sizeof(tmp), name_w);

				if (i != (LIST_NUM(o) - 1))
				{
					UniStrCat(tmp, sizeof(tmp), _UU("DS_TRAY_TOOLTIP_SPLIT"));
				}
			}

			num = LIST_NUM(o);
		}

		ReleaseList(o);
	}
	UnlockList(ds->ClientList);

	if (num != 0)
	{
		hIcon = LoadSmallIcon(ICO_USER_ADMIN);
	}

	MsChangeIconOnTrayEx2((void *)hIcon, tmp, NULL, NULL, 0);
#endif  // OS_WIN32
}

// ログの種類文字列を取得する
wchar_t *DsGetLogTypeStr(UINT ds_log_type)
{
	switch (ds_log_type)
	{
	case DS_LOG_WARNING:
		return _UU("DS_LOG_WARNING");

	case DS_LOG_ERROR:
		return _UU("DS_LOG_ERROR");

	default:
		return _UU("DS_LOG_INFO");
	}
}

// ログをとる
void DsLog(DS *ds, char *name, ...)
{
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);

	DsLogMain(ds, DS_LOG_INFO, NULL, name, args);

	va_end(args);
}

void DsLogEx(DS *ds, UINT ds_log_type, char *name, ...)
{
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);

	DsLogMain(ds, ds_log_type, NULL, name, args);

	va_end(args);
}

void DsDebugLog(DS* ds, char* prefix, char* format, ...)
{
	va_list args;
	char format2[MAX_SIZE * 2] = CLEAN;
	// 引数チェック
	if (format == NULL)
	{
		return;
	}
	if (ds == NULL || ds->EnableDebugLog == false)
	{
		return;
	}

	Format(format2, sizeof(format2), "[DEBUG] (%s) %s", prefix, format);

	va_start(args, format);

	DsLogMain(ds, DS_LOG_INFO, format2, NULL, args);

	va_end(args);
}

void DsLogMain(DS* ds, UINT ds_log_type, char* alt_format_string, char* name, va_list args)
{
#ifdef	OS_WIN32
	wchar_t buf[MAX_SIZE * 2 + 64] = CLEAN;
	char buf3[MAX_SIZE * 2 + 64] = CLEAN;
	wchar_t buf2[MAX_SIZE * 2] = CLEAN;
	wchar_t *typestr = DsGetLogTypeStr(ds_log_type);
	SYSLOG_SETTING ss;
	bool lineonly = false;
	DS_POLICY_BODY pol = {0};

	DsGetPolicy(ds, &pol);

	if (alt_format_string == NULL)
	{
		UniFormatArgs(buf, sizeof(buf), _UU(name), args);
	}
	else
	{
		FormatArgs(buf3, sizeof(buf3), alt_format_string, args);
		StrToUni(buf, sizeof(buf), buf3);
	}

	if (UniStartWith(buf, L"-------"))
	{
		lineonly = true;
	}

	UniFormat(buf2, sizeof(buf2), L"[%s] %s", typestr, buf);

	if (ds->SaveLogFile)
	{
		// ファイルへのログ保存
		InsertUnicodeRecord(ds->Log, buf2);
	}

	if (lineonly == false)
	{
		if (ds->SupportEventLog	&& ds->SaveEventLog && ds->EventLog != NULL)
		{
			// イベントログへのログ保存
			MsWriteEventLog(ds->EventLog, ds_log_type, buf);
		}

		SiGetSysLogSetting(ds->Server, &ss);

		if (IsEmptyStr(pol.SyslogHostname) == false && pol.SyslogPort != 0)
		{
			// 現在の設定と異なる？
			if (StrCmpi(ss.Hostname, pol.SyslogHostname) != 0 || ss.Port != pol.SyslogPort || ss.SaveType != 1)
			{
				// ポリシーで Syslog が指定されている場合はこれを強制適用する
				Zero(&ss, sizeof(ss));
				ss.SaveType = 1;
				StrCpy(ss.Hostname, sizeof(ss.Hostname), pol.SyslogHostname);
				ss.Port = pol.SyslogPort;
				SiSetSysLogSetting(ds->Server, &ss);
			}
		}

		SiGetSysLogSetting(ds->Server, &ss);

		if (ss.SaveType != 0)
		{
			// syslog へのログ保存
			DsSendSyslog(ds->Server, buf2);
		}
	}

	Debug("DS_LOG: %S\n", buf2);
#endif  // OS_WIN32
}

// syslog 送信
void DsSendSyslog(SERVER *s, wchar_t *message)
{
	wchar_t tmp[1024];
	char machinename[MAX_HOST_NAME_LEN + 1];
	char datetime[MAX_PATH];
	SYSTEMTIME st;
	// 引数チェック
	if (s == NULL || message == NULL)
	{
		return;
	}

	// ホスト名
	GetMachineName(machinename, sizeof(machinename));

	// 日時
	LocalTime(&st);
	GetDateTimeStrMilli(datetime, sizeof(datetime), &st);

	UniFormat(tmp, sizeof(tmp), L"[%S/" DESK_PUBLISHER_NAME_UNICODE L"] (%S) : %s",
		machinename, datetime, message);

	SendSysLog(s->Syslog, tmp);
}

// plain パスワードでの認証
bool DsAuthUserByPlainPassword(DS *ds, UCHAR *client_id, HUB *hub, char *username, char *password, bool ast)
{
	bool ret;
	// 引数チェック
	if (ds == NULL || client_id == NULL || hub == NULL || username == NULL || password == NULL)
	{
		return false;
	}

	ret = DsTryRadiusCache(ds, client_id, username, password);

	if (ret)
	{
		return true;
	}

	ret = SamAuthUserByPlainPassword(NULL, hub, username, password, ast, NULL, NULL);

	if (ret)
	{
		DsAddRadiusCache(ds, client_id, username, password);
	}

	return ret;
}

// Radius キャッシュリストの初期化
void DsInitRadiusCacheList(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	ds->RadiusCacheList = NewList(NULL);
}

// Radius キャッシュリストの解放
void DsFreeRadiusCacheList(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	DsCleanAllRadiusCache(ds);

	ReleaseList(ds->RadiusCacheList);

	ds->RadiusCacheList = NULL;
}

// すべての Radius キャッシュの消去
void DsCleanAllRadiusCache(DS *ds)
{
	UINT i;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(ds->RadiusCacheList);i++)
	{
		DS_RADIUS_CACHE *c = LIST_DATA(ds->RadiusCacheList, i);

		Free(c);
	}

	DeleteAll(ds->RadiusCacheList);
}

// Radius キャッシュリストのトライ
bool DsTryRadiusCache(DS *ds, UCHAR *client_id, char *username, char *password)
{
	bool ret = false;
	UINT i;
	// 引数チェック
	if (ds == NULL || client_id == NULL || username == NULL || password == NULL)
	{
		return false;
	}

	LockList(ds->RadiusCacheList);
	{
		for (i = 0;i < LIST_NUM(ds->RadiusCacheList);i++)
		{
			DS_RADIUS_CACHE *c = LIST_DATA(ds->RadiusCacheList, i);

			if (Cmp(c->ClientID, client_id, SHA1_SIZE) == 0)
			{
				if (StrCmpi(c->UserName, username) == 0)
				{
					if (StrCmp(c->Password, password) == 0)
					{
						ret = true;
						break;
					}
				}
			}
		}
	}
	UnlockList(ds->RadiusCacheList);

	return ret;
}

// Radius キャッシュリストに追加
void DsAddRadiusCache(DS *ds, UCHAR *client_id, char *username, char *password)
{
	UINT i;
	// 引数チェック
	if (ds == NULL || client_id == NULL || username == NULL || password == NULL)
	{
		return;
	}

	LockList(ds->RadiusCacheList);
	{
		DS_RADIUS_CACHE *c = NULL;

		for (i = 0;i < LIST_NUM(ds->RadiusCacheList);i++)
		{
			DS_RADIUS_CACHE *cc = LIST_DATA(ds->RadiusCacheList, i);

			if (Cmp(cc->ClientID, client_id, SHA1_SIZE) == 0)
			{
				c = cc;
				break;
			}
		}

		if (c == NULL)
		{
			c = ZeroMalloc(sizeof(DS_RADIUS_CACHE));

			Add(ds->RadiusCacheList, c);
		}

		Copy(c->ClientID, client_id, SHA1_SIZE);
		StrCpy(c->UserName, sizeof(c->UserName), username);
		StrCpy(c->Password, sizeof(c->Password), password);
	}
	UnlockList(ds->RadiusCacheList);
}

// サーバーとしてのメイン処理
void DsServerMain(DS *ds, SOCKIO *sock)
{
#ifdef	OS_WIN32
	IP client_ip;
	char client_ip_str[MAX_PATH];
	UINT client_port;
	char client_host[MAX_PATH];
	UINT tunnel_id;
	UCHAR client_id[SHA1_SIZE];
	char client_id_str[MAX_PATH];
	PACK *p;
	UINT client_ver;
	UINT client_build;
	UCHAR rand[SHA1_SIZE];
	UCHAR machine_key[SHA1_SIZE];
	UCHAR secure_password[SHA1_SIZE];
	bool ret;
	UINT svc_type;
	SOCK *s;
	bool check_port;
	char c;
	bool pingmode;
	bool wol_mode;
	bool downloadmode;
	UINT download_size;
	bool is_share_disabled;
	UCHAR bluetooth_mode_client_id[SHA1_SIZE];
	bool first_connection;
	bool last_connection = false;
	bool has_urdp2_client = false;
	bool support_otp = false;
	bool support_otp_enforcement = false;
	bool is_smartcard_auth = false;
	bool support_inspect = false;
	bool support_watermark = false;
	bool guacd_mode = false;
	int guacd_flags = 0;
	UINT ds_caps = 0;
	UINT urdp_version = 0;
	DS_POLICY_BODY pol = {0};
	bool run_inspect = false;
	wchar_t computer_name[MAX_PATH];
	wchar_t user_name[MAX_PATH];
	IP client_local_ip = {0};
	bool server_allowed_mac_list_check_ok = true;
	bool support_server_allowed_mac_list_err = false;
	UINT total_relay_size = 0;
	bool enforce_limited_fw_excluded = false;
	char logprefix[128] = CLEAN;
	// 引数チェック
	if (ds == NULL || sock == NULL)
	{
		return;
	}

	// Config 正規化
	DsNormalizeConfig(ds, false);

	if (DsGetPolicy(ds, &pol) == false)
	{
		if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
		{
			// 強いセキュリティパッチ適用モード
			pol.EnforceOtp = true; // OTP が強制されているとみなす
		}
	}

	if (IsEmptyStr(pol.ServerAllowedMacListUrl) == false)
	{
		// SERVER_ALLOWED_MAC_LIST_URL は行政情報システム適応モードまたは ThinTelework_EnforceStrongSecurity のみ対応
		if (InStr(ds->Wide->wt->EntranceMode, "limited") || Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
		{
			// SERVER_ALLOWED_MAC_LIST_URL が指定されているのでダウンロードを試みる
			URL_DATA data;
			if (ParseUrl(&data, pol.ServerAllowedMacListUrl, false, NULL))
			{
				UINT err = 0;
				BUF *buf = HttpRequestEx5(&data, NULL,
					DS_POLICY_SERVER_ALLOWED_MAC_LIST_URL_TIMEOUT,
					DS_POLICY_SERVER_ALLOWED_MAC_LIST_URL_TIMEOUT,
					&err, false, NULL, NULL, NULL, NULL, 0, NULL,
					DS_POLICY_SERVER_ALLOWED_MAC_LIST_URL_MAX_SIZE,
					NULL, NULL, NULL, false, true);

				if (buf != NULL)
				{
					char local_mac_list[1024] = {0};

					GetMacAddressListLocalComputer(local_mac_list, sizeof(local_mac_list), false);

					SeekBufToEnd(buf);
					WriteBufChar(buf, 0);

					if (CheckStrListIncludedInOtherStrMac(buf->Buf, local_mac_list) == false)
					{
						// リストに ないですな
						server_allowed_mac_list_check_ok = false;
					}

					FreeBuf(buf);
				}
			}
		}
	}

	if (pol.EnforceOtp && IsEmptyStr(pol.EnforceOtpEndWith) == false)
	{
		// OTP 強制かつ末尾強制の場合は、適応しないメールアドレスが設定
		// されている場合は削除する
		if (EndWith(ds->OtpEmail, pol.EnforceOtpEndWith) == false)
		{
			ds->EnableOtp = false;
			ClearStr(ds->OtpEmail, sizeof(ds->OtpEmail));
		}
	}

	// 接続元クライアントの情報を取得する
	Zero(client_host, sizeof(client_host));
	Zero(client_id, sizeof(client_id));
	bool is_trusted = PackGetBool(sock->InitialPack, "is_trusted");
	PackGetIp(sock->InitialPack, "ClientIP", &client_ip);
	client_port = PackGetInt(sock->InitialPack, "ClientPort");
	PackGetStr(sock->InitialPack, "ClientHost", client_host, sizeof(client_host));
	tunnel_id = PackGetInt(sock->InitialPack, "TunnelId");
	PackGetData2(sock->InitialPack, "ClientID", client_id, sizeof(client_id));
	BinToStr(client_id_str, sizeof(client_id_str), client_id, sizeof(client_id));
	IPToStr(client_ip_str, sizeof(client_ip_str), &client_ip);

	IP trusted_ip = CLEAN;
	PackGetIp(sock->InitialPack, "TrustedIP", &trusted_ip);

	char trusted_str[128] = CLEAN;
	if (is_trusted)
	{
		Format(trusted_str, sizeof(trusted_str), " <via %r>", &trusted_ip);
	}

	Format(logprefix, sizeof(logprefix), "%r:%u (%s) [%u/%s]%s", &client_ip, client_port, client_host, tunnel_id, client_id_str, trusted_str);

	DsDebugLog(ds, logprefix, "DsServerMain Start");

	is_share_disabled = DsIsShareDisabled(ds);

	Rand(rand, sizeof(rand));

	SockIoSetTimeout(sock, DS_PROTOCOL_CONNECTING_TIMEOUT);
	DeskGetMachineKey(machine_key);

	// Pack の受信
	p = SockIoRecvPack(sock);
	if (p == NULL)
	{
		DsDebugLog(ds, logprefix, "Error: %s:%u", __FILE__, __LINE__);
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		return;
	}

	// バージョンを取得
	client_ver = PackGetInt(p, "ClientVer");
	client_build = PackGetInt(p, "ClientBuild");
	check_port = PackGetBool(p, "CheckPort");
	pingmode = PackGetBool(p, "PingMode");
	wol_mode = PackGetBool(p, "WoLMode");
	downloadmode = PackGetBool(p, "downloadmode");
	download_size = PackGetInt(p, "download_size");
	first_connection = PackGetBool(p, "FirstConnection");
	has_urdp2_client = PackGetBool(p, "HasURDP2Client");
	support_otp = PackGetBool(p, "SupportOtp");
	support_otp_enforcement = PackGetBool(p, "SupportOtpEnforcement");
	support_inspect = PackGetBool(p, "SupportInspect");
	support_server_allowed_mac_list_err = PackGetBool(p, "SupportServerAllowedMacListErr");

	support_watermark = PackGetBool(p, "SupportWatermark");
	guacd_mode = PackGetBool(p, "GuacdMode");
	guacd_flags = PackGetInt(p, "GuacdFlags");
	if (guacd_mode)
	{
		check_port = true;
	}

	PackGetUniStr(p, "ComputerName", computer_name, sizeof(computer_name));
	PackGetUniStr(p, "UserName", user_name, sizeof(user_name));
	PackGetIp(p, "ClientLocalIP", &client_local_ip);

	// ENFORCE_LIMITED_FIREWALL_COMPUTERNAME_STARTWITH 検査
	if (UniIsFilledStr(pol.LimitedFirewallMandateExcludeComputernameStartWith))
	{
		UNI_TOKEN_LIST* t = UniParseToken(pol.LimitedFirewallMandateExcludeComputernameStartWith, L";, \t");

		if (t != NULL)
		{
			UINT i;

			for (i = 0;i < t->NumTokens;i++)
			{
				wchar_t* s = t->Token[i];

				if (UniIsFilledStr(s))
				{
					if (UniStartWith(computer_name, s))
					{
						enforce_limited_fw_excluded = true;
					}
				}
			}

			UniFreeToken(t);
		}
	}

	if (MsIsWinXPOrWinVista() == false)
	{
		has_urdp2_client = false;
	}

	if (client_build < 5599)
	{
		first_connection = true;
	}
	Zero(bluetooth_mode_client_id, sizeof(bluetooth_mode_client_id));
	PackGetData2(p, "bluetooth_mode_client_id", bluetooth_mode_client_id, sizeof(bluetooth_mode_client_id));

	DsDebugLog(ds, logprefix, "client_ver=%u, client_build=%u, check_port=%u, pingmode=%u,"
		"wol_mode=%u,first_connection=%u,has_urdp2_client=%u,support_otp=%u,"
		"support_otp_enforcement=%u,support_inspect=%u,support_server_allowed_mac_list_err=%u,"
		"support_watermark=%u,client_local_ip=%r,guacd_mode=%u",
		client_ver, client_build, check_port, pingmode,
		wol_mode, first_connection, has_urdp2_client, support_otp,
		support_otp_enforcement, support_inspect, support_server_allowed_mac_list_err, support_watermark,
		&client_local_ip, guacd_mode);

	if (guacd_mode)
	{
		if (DsIsGuacdSupported(ds) == false)
		{
			// Guacd がサポートされていない OS である
			DsDebugLog(ds, logprefix, "Error: %s:%u", __FILE__, __LINE__);
			DsSendError(sock, ERR_DESK_GUACD_NOT_SUPPORTED_OS);
			FreePack(p);
			return;
		}

		if (pol.DenyClientsHtml5)
		{
			// HTML5 クライアントによる接続を禁止している
			DsDebugLog(ds, logprefix, "Error: %s:%u", __FILE__, __LINE__);
			DsSendError(sock, ERR_DESK_GUACD_PROHIBITED);
			FreePack(p);
			return;
		}
	}
	else
	{
		if (pol.DenyClientsApp)
		{
			// 通常版クライアントによる接続を禁止している
			DsDebugLog(ds, logprefix, "Error: %s:%u", __FILE__, __LINE__);
			UINT err_code = ERR_ACCESS_DENIED;
			if (client_build >= 9885)
			{
				err_code = ERR_DESK_GUACD_CLIENT_REQUIRED;
			}
			DsSendError(sock, err_code);
			FreePack(p);
			return;
		}
	}

	if (server_allowed_mac_list_check_ok == false)
	{
		// サーバー側 MAC アドレスチェック失敗
		DsDebugLog(ds, logprefix, "Error: %s:%u", __FILE__, __LINE__);
		DsSendError(sock, support_server_allowed_mac_list_err ? ERR_DESK_SERVER_ALLOWED_MAC_LIST : ERR_DESK_UNKNOWN_AUTH_TYPE);
		FreePack(p);
		return;
	}

	if (client_build != 0 && pol.RequireMinimumClientBuild != 0 && client_build < pol.RequireMinimumClientBuild)
	{
		// ポリシーの REQUIRE_MINIMUM_CLIENT_BUILD で指定されているよりも新しいクライアントビルドが必要です
		DsDebugLog(ds, logprefix, "Error: %s:%u", __FILE__, __LINE__);
		DsDebugLog(ds, logprefix, "client_build %u < pol.RequireMinimumClientBuild %u", client_build, pol.RequireMinimumClientBuild);
		DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
		FreePack(p);
		return;
	}

	if (wol_mode)
	{
		UINT mac_str_size = 4096;
		char *mac_str = NULL;

		// WoL モード
		if (ds->EnableWoLTrigger == false)
		{
			// WoL Trigger 機能が無効である
			DsDebugLog(ds, logprefix, "Error: %s:%u", __FILE__, __LINE__);
			DsSendError(sock, ERR_WOL_TRIGGER_NOT_ENABLED);
			FreePack(p);
			return;
		}

		mac_str = ZeroMalloc(mac_str_size);

		PackGetStr(p, "mac_list", mac_str, mac_str_size);

		// WoL 送信の実行
		DsDebugLog(ds, logprefix, "WoL Magic Sent to %s", mac_str);
		WoLSendPacketToMacAddressListStr(mac_str);

		Free(mac_str);

		DsSendError(sock, ERR_NO_ERROR);
		FreePack(p);

		// ダミー通信待機 (これがないと切断されたとみなされてしまう)
		SockIoSetTimeout(sock, DS_SEND_ERROR_AND_WAIT_SPAN);
		FreePack(SockIoRecvPack(sock));
		return;
	}

	FreePack(p);

	if (pingmode)
	{
		// ping mode (テスト用)
		DsDebugLog(ds, logprefix, "Start ping mode");
		while (true)
		{
			UINT64 tick;
			if (SockIoRecvAll(sock, &tick, sizeof(tick)) == false)
			{
				break;
			}
			if (SockIoSendAll(sock, &tick, sizeof(tick)) == false)
			{
				break;
			}
		}
		DsDebugLog(ds, logprefix, "End ping mode");

		return;
	}

	if (is_share_disabled)
	{
		if (client_build < 5599)
		{
			// 共有機能が禁止されており、かつ古いバージョンのクライアントが
			// 接続してきた場合はエラーにする
			DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_UNKNOWN_AUTH_TYPE (%s:%u)", __FILE__, __LINE__);
			return;
		}
	}

	if (ds->EnableOtp && support_otp == false)
	{
		// OTP が有効なのにクライアントが OTP 非サポート
		DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
		DsDebugLog(ds, logprefix, "Error: ERR_DESK_UNKNOWN_AUTH_TYPE (%s:%u)", __FILE__, __LINE__);
		return;
	}

	if (ds->ShowWatermark && support_watermark == false)
	{
		// 透かしが有効なのにクライアントが透かし非サポート
		DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
		DsDebugLog(ds, logprefix, "Error: ERR_DESK_UNKNOWN_AUTH_TYPE (%s:%u)", __FILE__, __LINE__);
		return;
	}

	if (pol.EnforceOtp && ds->EnableOtp == false)
	{
		// ポリシーで OTP 強制なのに OTP が設定されていない
		if (support_otp_enforcement == false)
		{
			// クライアントが ERR_DESK_OTP_ENFORCED_BUT_NO エラーを表示不能
			DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_UNKNOWN_AUTH_TYPE (%s:%u)", __FILE__, __LINE__);
		}
		else
		{
			// クライアントが ERR_DESK_OTP_ENFORCED_BUT_NO エラーを表示可能
			DsSendError(sock, ERR_DESK_OTP_ENFORCED_BUT_NO);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_OTP_ENFORCED_BUT_NO (%s:%u)", __FILE__, __LINE__);
		}
		return;
	}

	if (ds->EnableInspection || ds->EnableMacCheck)
	{
		run_inspect = true;

		if (support_inspect == false)
		{
			// クライアント検疫が設定されているのに対応していないバージョンのクライアント
			DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_UNKNOWN_AUTH_TYPE (%s:%u)", __FILE__, __LINE__);
			return;
		}
	}

	if (ds->UseAdvancedSecurity)
	{
		if (client_build < 5599)
		{
			// 新型ユーザー認証を使用する必要があるが
			// 旧型クライアントが接続してきた場合はエラーにする
			DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_UNKNOWN_AUTH_TYPE (%s:%u)", __FILE__, __LINE__);
			return;
		}
	}

#if	0
	if (downloadmode)
	{
		// download mode (テスト用)
		if (download_size <= (100000000))
		{
			void *data = ZeroMalloc(download_size);

			if (SockIoSendAll(sock, data, download_size) == false)
			{
				Debug("Send Failed.\n");
			}
			else
			{
				Debug("Send Ok.\n");
			}
			FreePack(SockIoRecvPack(sock));

			Free(data);
		}
		return;
	}
#endif

	if (client_ver == 0 || client_build == 0)
	{
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		DsDebugLog(ds, logprefix, "Error: ERR_PROTOCOL_ERROR (%s:%u)", __FILE__, __LINE__);
		return;
	}

	if (ds->Active == false)
	{
		// 接続を受け付けていない
		DsSendError(sock, ERR_DESK_NOT_ACTIVE);
		DsDebugLog(ds, logprefix, "Error: ERR_DESK_NOT_ACTIVE (%s:%u)", __FILE__, __LINE__);
		return;
	}

	svc_type = ds->ServiceType;

	// 認証パラメータを送信
	p = NewPack();
	if (ds->UseAdvancedSecurity == false)
	{
		PackAddInt(p, "AuthType", ds->AuthType);
	}
	else
	{
		// ダミー
		PackAddInt(p, "AuthType", 99);
	}

	UINT service_port = ds->RdpPort;
	if (ds->ServiceType == DESK_SERVICE_VNC)
	{
		service_port = DS_URDP_PORT;
	}

	PackAddInt(p, "ServiceType", ds->ServiceType);
	PackAddInt(p, "ServicePort", service_port);
	PackAddData(p, "Rand", rand, sizeof(rand));
	PackAddData(p, "MachineKey", machine_key, sizeof(machine_key));

	if (ds->Wide != NULL && ds->Wide->SessionLifeTime != 0)
	{
		PackAddInt64(p, "Lifetime", ds->Wide->SessionLifeTime);
		PackAddUniStr(p, "LifeTimeMsg", ds->Wide->SessionLifeTimeMsg);
	}

	ds_caps = DsGetCaps(ds);

	// Guacd Supported ver
	ds_caps |= DS_CAPS_GUACD_SUPPORTED;

	// Mic sharing supported ver
	ds_caps |= DS_CAPS_AUDIN_SUPPORTED;

	if (has_urdp2_client)
	{
		ds_caps |= DS_CAPS_SUPPORT_URDP2;
		urdp_version = 2;

		if (DeskCheckUrdpIsInstalledOnProgramFiles(2) == false && MsIsVista())
		{
			// UAC による制限が厳しいことを示すフラグを立てる
			ds_caps |= DS_CAPS_RUDP_VERY_LIMITED;
		}
	}
	else
	{
		if (DeskCheckUrdpIsInstalledOnProgramFiles(1) == false && MsIsVista())
		{
			// UAC による制限が厳しいことを示すフラグを立てる
			ds_caps |= DS_CAPS_RUDP_VERY_LIMITED;
		}
	}

	// Windows RDP が有効かどうかのフラグ
	if (MsIsRemoteDesktopAvailable() && MsIsRemoteDesktopEnabled())
	{
		ds_caps |= DS_CAPS_WIN_RDP_ENABLED;
	}

	if (ds->ShowWatermark)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t dtstr[MAX_PATH];
		wchar_t this_machine_name[MAX_PATH];
		IP this_machine_ip;
		char hash[128];
		UCHAR hash2[SHA1_SIZE];
		char hash_str[128];

		WideServerGetHash(ds->Wide, hash, sizeof(hash));
		HashSha1(hash2, hash, StrLen(hash));

		BinToStr(hash_str, sizeof(hash_str), hash2, sizeof(hash2));

		CopyIP(&this_machine_ip, &sock->ServerLocalIP);

		MsGetComputerNameFullEx(this_machine_name, sizeof(this_machine_name), true);

		GetDateTimeStrEx64(dtstr, sizeof(dtstr), LocalTime64(), NULL);

		// 透かし文字列を生成
		PackAddUniStr(p, "WatermarkStr1", ds->WatermarkStr);

		UniFormat(tmp, sizeof(tmp), _UU("DU_FELONY_STR2"),
			dtstr, hash_str, this_machine_name, &this_machine_ip,
			computer_name, client_host,
			&client_ip, &client_local_ip,
			user_name, hash_str);

		PackAddUniStr(p, "WatermarkStr2", tmp);
	}

	PackAddInt(p, "DsCaps", ds_caps);

	PackAddBool(p, "IsShareDisabled", is_share_disabled);
	PackAddBool(p, "UseAdvancedSecurity", ds->UseAdvancedSecurity);
	PackAddBool(p, "IsOtpEnabled", ds->EnableOtp);
	PackAddBool(p, "RunInspect", run_inspect);
	Debug("enforce_limited_fw_excluded = %u\n", enforce_limited_fw_excluded);
	PackAddBool(p, "IsLimitedFirewallMandated", pol.IsLimitedFirewallMandated && (enforce_limited_fw_excluded == false));
	PackAddInt(p, "IdleTimeout", pol.IdleTimeout);

	DsDebugLog(ds, logprefix, "ds_caps=%u, is_share_disabled=%u, UseAdvancedSecurity=%u, IsOtpEnabled=%u, run_inspect=%u",
		ds_caps, is_share_disabled, ds->UseAdvancedSecurity, ds->EnableOtp, run_inspect);

	ret = SockIoSendPack(sock, p);
	FreePack(p);

	if (ret == false)
	{
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		DsDebugLog(ds, logprefix, "Error: ERR_PROTOCOL_ERROR (%s:%u)", __FILE__, __LINE__);
		return;
	}

	// OTP 有効の場合は、OTP パスワードを受信
	if (ds->EnableOtp)
	{
		UINT64 now = Tick64();
		char otp[MAX_PATH];
		bool ok = false;
		bool ok_ticket = false;
		UINT i;

		if (first_connection)
		{
			// まずこの機会に急いで OTP を発行する
			if (IsEmptyStr(ds->LastOtp) || (now >= ds->LastOtpExpires) || (ds->OtpNumTry >= DS_OTP_NUM_TRY))
			{
				DsGenerateNewOtp(ds->LastOtp, sizeof(ds->LastOtp), DS_OTP_LENGTH);
				ds->OtpNumTry = 0;
			}
			ds->LastOtpExpires = now + (UINT64)DS_OTP_EXPIRES;
			ds->OtpNumTry++;

			// OTP をメール送信する
			for (i = 0;i < 5;i++)
			{
				// 失敗した場合に備えて念のため 5 通くらい送信する
				DsDebugLog(ds, logprefix, "SendOtpEmail: OTP=%s, Email=%s, ClientIP=%s, ClientHost=%s",
					ds->LastOtp, ds->OtpEmail, client_ip_str, client_host);

				UINT otp_err = WideServerSendOtpEmail(ds->Wide, ds->LastOtp, ds->OtpEmail, client_ip_str, client_host);
				if (otp_err == ERR_NO_ERROR)
				{
					DsDebugLog(ds, logprefix, "SendOtpEmail OK.");
					break;
				}

				DsDebugLog(ds, logprefix, "SendOtpEmail error. Error code: %u", otp_err);
			}
		}

		// クライアントからの OTP を受信する
		p = SockIoRecvPack(sock);
		if (p == NULL)
		{
			DsDebugLog(ds, logprefix, "Error: ERR_PROTOCOL_ERROR (%s:%u)", __FILE__, __LINE__);
			DsSendError(sock, ERR_PROTOCOL_ERROR);
			return;
		}

		PackGetStr(p, "Otp", otp, sizeof(otp));

		FreePack(p);

		// OTP 一致 / 不一致を確認し、結果をクライアントに送付する
		if (first_connection)
		{
			ok = (StrCmp(otp, ds->LastOtp) == 0);
			if (ok == false)
			{
				// 緊急用 OTP
				if (StrLen(ds->EmergencyOtp) >= DS_EMERGENCY_OTP_LENGTH)
				{
					ok = (StrCmp(otp, ds->EmergencyOtp) == 0);
				}
			}
		}

		ok_ticket = (StrCmp(otp, ds->OtpTicket) == 0);

		if (ok == false && ok_ticket == false)
		{
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_OTP_INVALID (%s:%u)", __FILE__, __LINE__);
			DsSendError(sock, ERR_DESK_OTP_INVALID);
			return;
		}

		// OTP 一致

		if (ok)
		{
			// 覚えをクリア
			ClearStr(ds->LastOtp, sizeof(ds->LastOtp));
			ds->LastOtpExpires = 0;
		}

		p = PackError(ERR_NO_ERROR);

		PackAddStr(p, "OtpTicket", ds->OtpTicket);

		SockIoSendPack(sock, p);

		FreePack(p);
	}

	// クライアント検疫処理の実行
	if (run_inspect)
	{
		DC_INSPECT ins;
		// クライアントからの DC_INSPECT を受信する
		p = SockIoRecvPack(sock);
		if (p == NULL)
		{
			DsSendError(sock, ERR_PROTOCOL_ERROR);
			DsDebugLog(ds, logprefix, "Error: ERR_PROTOCOL_ERROR (%s:%u)", __FILE__, __LINE__);
			return;
		}

		Zero(&ins, sizeof(ins));

		ins.AntiVirusOk = PackGetBool(p, "AntiVirusOk");
		ins.WindowsUpdateOk = PackGetBool(p, "WindowsUpdateOk");
		PackGetStr(p, "MacAddressList", ins.MacAddressList, sizeof(ins.MacAddressList));
		PackGetStr(p, "Ticket", ins.Ticket, sizeof(ins.Ticket));

		FreePack(p);

		if (StrCmpi(ins.Ticket, ds->InspectionTicket) == 0)
		{
			// チケットで OK
			DsDebugLog(ds, logprefix, "InspectionTicket Ok");
		}
		else
		{
			DsDebugLog(ds, logprefix, "EnableInspection=%u, EnableMacCheck=%u",
				ds->EnableInspection, ds->EnableMacCheck);

			// 結果を吟味
			if (ds->EnableInspection)
			{
				if (ins.AntiVirusOk == false)
				{
					DsSendError(sock, ERR_DESK_INSPECTION_AVS_ERROR);
					DsDebugLog(ds, logprefix, "Error: ERR_DESK_INSPECTION_AVS_ERROR (%s:%u)", __FILE__, __LINE__);
					return;
				}
				if (ins.WindowsUpdateOk == false)
				{
					DsSendError(sock, ERR_DESK_INSPECTION_WU_ERROR);
					DsDebugLog(ds, logprefix, "Error: ERR_DESK_INSPECTION_WU_ERROR (%s:%u)", __FILE__, __LINE__);
					return;
				}
			}

			if (ds->EnableMacCheck)
			{
				bool check_ret = false;

				DsDebugLog(ds, logprefix, "Client's MAC addresses List: %s", ins.MacAddressList);

				if (pol.NoLocalMacAddressList == false) // NO_LOCAL_MAC_ADDRESS_LIST が設定されていない場合のみローカルを読み込む
				{
					Lock(ds->ConfigLock);
					{
						// サーバーに登録されている (ローカルの) MAC アドレス一覧に一致するものがあるかどうか検査
						check_ret = CheckStrListIncludedInOtherStrMac(ds->MacAddressList, ins.MacAddressList);
					}
					Unlock(ds->ConfigLock);
				}

				if (check_ret == false)
				{
					bool policy_server_based_mac_ok = false;

					if (IsEmptyStr(pol.ClientAllowedMacListUrl) == false)
					{
						// CLIENT_ALLOWED_MAC_LIST_URL が指定されているのでダウンロードを試みる
						URL_DATA data;
						if (ParseUrl(&data, pol.ClientAllowedMacListUrl, false, NULL))
						{
							UINT err = 0;
							BUF *buf = HttpRequestEx5(&data, NULL,
								DS_POLICY_CLIENT_ALLOWED_MAC_LIST_URL_TIMEOUT,
								DS_POLICY_CLIENT_ALLOWED_MAC_LIST_URL_TIMEOUT,
								&err, false, NULL, NULL, NULL, NULL, 0, NULL,
								DS_POLICY_SERVER_ALLOWED_MAC_LIST_URL_MAX_SIZE,
								NULL, NULL, NULL, false, true);

							if (buf != NULL)
							{
								SeekBufToEnd(buf);
								WriteBufChar(buf, 0);

								if (CheckStrListIncludedInOtherStrMac(buf->Buf, ins.MacAddressList))
								{
									// リストに ありますな
									policy_server_based_mac_ok = true;
								}

								FreeBuf(buf);
							}
						}
					}

					if (policy_server_based_mac_ok == false)
					{
						DsSendError(sock, ERR_DESK_INSPECTION_MAC_ERROR);
						DsDebugLog(ds, logprefix, "Error: ERR_DESK_INSPECTION_MAC_ERROR (%s:%u)", __FILE__, __LINE__);
						return;
					}
				}
			}
		}

		// OK
		p = PackError(ERR_NO_ERROR);

		PackAddStr(p, "InspectionTicket", ds->InspectionTicket);

		SockIoSendPack(sock, p);

		FreePack(p);
	}

	// 認証データを受信
	p = SockIoRecvPack(sock);
	if (p == NULL)
	{
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		DsDebugLog(ds, logprefix, "Error: ERR_PROTOCOL_ERROR (%s:%u)", __FILE__, __LINE__);
		return;
	}

	Zero(secure_password, sizeof(secure_password));
	PackGetData2(p, "SecurePassword", secure_password, sizeof(secure_password));

	if (first_connection)
	{
		DsLogEx(ds, DS_LOG_INFO, "DSL_TUNNEL_CONNECTED",
			tunnel_id, client_ip_str, client_host, client_port, client_id_str,
			computer_name, user_name, &client_local_ip);
	}

	ret = false;
	// ユーザー認証を実施
	if (ds->UseAdvancedSecurity == false)
	{
		// アカウントロックアウト検査
		if (pol.AuthLockoutTimeout != 0 && pol.AuthLockoutCount != 0)
		{
			if (GetLockout(ds->Lockout, "", pol.AuthLockoutTimeout * 1000) >= pol.AuthLockoutCount)
			{
				// ロックアウト発生
				DsLogEx(ds, DS_LOG_WARNING, "DSL_LOCKOUT", tunnel_id, "", pol.AuthLockoutCount, pol.AuthLockoutTimeout);
				DsSendError(sock, ((client_build < 9862) ? ERR_ACCESS_DENIED : ERR_DESK_AUTH_LOCKOUT));
				FreePack(p);
				DsDebugLog(ds, logprefix, "Error: ERR_DESK_AUTH_LOCKOUT (%s:%u)", __FILE__, __LINE__);

				// ロックアウト記録
				AddLockout(ds->Lockout, "", pol.AuthLockoutTimeout * 1000);
				return;
			}
		}

		HUB *hub = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		bool is_password_empty = false;

		// IP アドレスを確認する
		if (IsIpDeniedByAcList(&client_ip, hub->HubDb->AcList))
		{
			// IP アドレスによるアクセス拒否
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_WARNING, "DSL_IP_NG", tunnel_id, client_ip_str);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			ReleaseHub(hub);
			DsSendError(sock, ((client_build < 5599) ? ERR_ACCESS_DENIED : ERR_IP_ADDRESS_DENIED));
			FreePack(p);
			DsDebugLog(ds, logprefix, "Error: ERR_IP_ADDRESS_DENIED (%s:%u)", __FILE__, __LINE__);
			return;
		}

		ReleaseHub(hub);

		// 旧型ユーザー認証
		if (ds->AuthType == DESK_AUTH_NONE)
		{
			// 認証無し
			is_password_empty = true;
		}
		else if (ds->AuthType == DESK_AUTH_PASSWORD)
		{
			UCHAR hash_of_server_pw[SHA1_SIZE];

			// サーバー側で設定されているパスワードが、空文字でないかどうか確認する
			HashSha1(hash_of_server_pw, NULL, 0);
			if (Cmp(hash_of_server_pw, ds->AuthPassword, SHA1_SIZE) == 0)
			{
				// サーバー側で設定されているパスワードが空文字である
				is_password_empty = true;
			}
			else if (IsZero(ds->AuthPassword, SHA1_SIZE))
			{
				// なぜかサーバー側のパスワードハッシュがゼロである
				is_password_empty = true;
			}
			else
			{
				UCHAR secure_password_2[SHA1_SIZE];

				// パスワード認証
				SecurePassword(secure_password_2, ds->AuthPassword, rand);

				if (Cmp(secure_password, secure_password_2, SHA1_SIZE) == 0)
				{
					// パスワード一致
					ret = true;
				}
			}
		}

		if (is_password_empty)
		{
			// アクセス拒否 - パスワード未設定
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_ERROR, "DSL_AUTH_ANONYMOUS_NG", tunnel_id);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			DsSendError(sock, ERR_DESK_PASSWORD_NOT_SET);
			FreePack(p);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_PASSWORD_NOT_SET (%s:%u)", __FILE__, __LINE__);
			return;
		}

		if (ret == false)
		{
			// アクセス拒否
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_ERROR, "DSL_AUTH_OLD_NG", tunnel_id);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}

			// ロックアウト記録
			bool lockout_as_result = false;
			if (pol.AuthLockoutTimeout != 0 && pol.AuthLockoutCount != 0)
			{
				if (first_connection)
				{
					AddLockout(ds->Lockout, "", pol.AuthLockoutTimeout * 1000);
				}

				if (GetLockout(ds->Lockout, "", pol.AuthLockoutTimeout * 1000) >= pol.AuthLockoutCount)
				{
					// 結果としてロックアウトが発生した
					lockout_as_result = true;
				}
			}

			DsSendError(sock, lockout_as_result == false ? ERR_AUTH_FAILED : ((client_build < 9862) ? ERR_ACCESS_DENIED : ERR_DESK_AUTH_LOCKOUT));
			FreePack(p);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_BAD_PASSWORD (%s:%u)", __FILE__, __LINE__);

			return;
		}

		if (pol.AuthLockoutTimeout != 0 && pol.AuthLockoutCount != 0)
		{
			// 認証成功時はロックアウト解除
			ClearLockout(ds->Lockout, "");
		}

		if (first_connection)
		{
			DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_OLD_OK",
				tunnel_id);
		}
		DsDebugLog(ds, logprefix, "Auth OK (%s:%u)", __FILE__, __LINE__);
	}
	else
	{
		// 新型ユーザー認証
		UINT authtype = GetAuthTypeFromPack(p);
		bool auth_ret;
		char auth_username[MAX_SIZE];
		char auth_username_real[MAX_SIZE];
		char plain_password[MAX_SIZE];
		HUB *hub = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		UINT cert_size;
		UCHAR *cert_buf;
		USER *user = NULL;

		Zero(auth_username, sizeof(auth_username));
		PackGetStr(p, "username", auth_username, sizeof(auth_username));

		// アカウントロックアウト検査
		if (pol.AuthLockoutTimeout != 0 && pol.AuthLockoutCount != 0)
		{
			if (GetLockout(ds->Lockout, auth_username, pol.AuthLockoutTimeout * 1000) >= pol.AuthLockoutCount)
			{
				// ロックアウト発生
				DsLogEx(ds, DS_LOG_WARNING, "DSL_LOCKOUT", tunnel_id, auth_username, pol.AuthLockoutCount, pol.AuthLockoutTimeout);
				DsSendError(sock, ((client_build < 9862) ? ERR_ACCESS_DENIED : ERR_DESK_AUTH_LOCKOUT));
				FreePack(p);
				DsDebugLog(ds, logprefix, "Error: ERR_DESK_AUTH_LOCKOUT (%s:%u)", __FILE__, __LINE__);

				// ロックアウト記録
				AddLockout(ds->Lockout, auth_username, pol.AuthLockoutTimeout * 1000);

				return;
			}
		}

		// IP アドレスを確認する
		if (IsIpDeniedByAcList(&client_ip, hub->HubDb->AcList))
		{
			// IP アドレスによるアクセス拒否
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_WARNING, "DSL_IP_NG", tunnel_id, client_ip_str);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			ReleaseHub(hub);
			DsSendError(sock, ((client_build < 5599) ? ERR_ACCESS_DENIED : ERR_IP_ADDRESS_DENIED));
			FreePack(p);
			DsDebugLog(ds, logprefix, "Error: ERR_IP_ADDRESS_DENIED (%s:%u)", __FILE__, __LINE__);
			return;
		}

		Lock(hub->lock);

		is_smartcard_auth = PackGetBool(p, "IsSmartCardAuth");

		// まず匿名認証を試行する
		auth_ret = SamAuthUserByAnonymous(hub, auth_username);

		if (auth_ret)
		{
			// ユーザー認証成功
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_AN_OK", tunnel_id, auth_username);
			}
		}

		if (auth_ret == false)
		{
			// 匿名認証に失敗した場合は他の認証方法を試行する
			switch (authtype)
			{
			case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
				if (PackGetStr(p, "plain_password", plain_password, sizeof(plain_password)))
				{
					UCHAR secure_password[SHA1_SIZE];
					UCHAR hashed_password[SHA1_SIZE];

					HashPassword(hashed_password, auth_username, plain_password);
					SecurePassword(secure_password, hashed_password, rand);
					auth_ret = SamAuthUserByPassword(hub, auth_username, rand, secure_password, NULL, NULL, NULL);
					if (auth_ret == false)
					{
						// 外部サーバーを用いたパスワード認証
						auth_ret = DsAuthUserByPlainPassword(ds, client_id, hub, auth_username, plain_password, false);

						if (auth_ret)
						{
							if (first_connection)
							{
								DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_PW2_OK", tunnel_id, auth_username);
							}
						}
					}
					else
					{
						if (first_connection)
						{
							DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_PW_OK", tunnel_id, auth_username);
						}
					}
					if (auth_ret == false)
					{
						bool b = false;
						AcLock(hub);
						{
							b = AcIsUser(hub, "*");
						}
						AcUnlock(hub);

						// アスタリスクユーザーがいる場合はそのユーザーとしてログオンする
						if (b)
						{
							auth_ret = DsAuthUserByPlainPassword(ds, client_id, hub, auth_username, plain_password, true);

							if (auth_ret)
							{
								if (first_connection)
								{
									DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_PW3_OK", tunnel_id, auth_username);
								}
							}
						}
					}
				}
				break;

			case CLIENT_AUTHTYPE_CERT:
				// 証明書認証
				cert_size = PackGetDataSize(p, "cert");
				if (cert_size >= 1 && cert_size <= DC_MAX_SIZE_CERT)
				{
					cert_buf = ZeroMalloc(cert_size);
					if (PackGetData(p, "cert", cert_buf))
					{
						UCHAR sign[4096 / 8];
						UINT sign_size = PackGetDataSize(p, "sign");
						if (sign_size <= sizeof(sign) && sign_size >= 1)
						{
							if (PackGetData(p, "sign", sign))
							{
								BUF *b = NewBuf();
								X *x;
								WriteBuf(b, cert_buf, cert_size);
								x = BufToX(b, false);
								if (x != NULL && x->is_compatible_bit &&
									sign_size == (x->bits / 8))
								{
									K *k = GetKFromX(x);
									// クライアントから受信した署名を確認する
									if (RsaVerifyEx(rand, SHA1_SIZE, sign, k, x->bits))
									{
										// 署名が一致したのでクライアントが確かにこの
										// 証明書を持っていたことが確認できた。
										// 証明書が有効かどうかをチェックする。
										bool ocsp_verify_error = false;
										auth_ret = SamAuthUserByCert(hub, auth_username, x, pol.EnableOcsp, &ocsp_verify_error);

										if (auth_ret)
										{
											if (ocsp_verify_error == false)
											{
												// 成功
												if (first_connection)
												{
													wchar_t tmp[MAX_SIZE];
													GetAllNameFromX(tmp, sizeof(tmp), x);
													DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_CERT_OK",
														tunnel_id, auth_username, tmp);
												}
											}
											else
											{
												// OCSP 検証失敗
												auth_ret = false;
												wchar_t tmp[MAX_SIZE];
												GetAllNameFromX(tmp, sizeof(tmp), x);
												DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_CERT_OCSP_ERROR",
													tunnel_id, auth_username, tmp);
											}
										}
									}
									else
									{
										// 認証失敗
									}
									FreeK(k);
								}
								FreeX(x);
								FreeBuf(b);
							}
						}
					}
					Free(cert_buf);
				}
				break;

			case CLIENT_AUTHTYPE_SMART_CARD_TICKET:
				// 既にスマートカードで認証済みのクライアントによるチケット受信
				{
					UCHAR ticket[SHA1_SIZE];

					if (PackGetData2(p, "SmartCardTicket", ticket, SHA1_SIZE))
					{
						if (Cmp(ticket, ds->SmartCardTicket, SHA1_SIZE) == 0)
						{
							auth_ret = true;
						}
					}
				}
				break;
			}
		}

		if (auth_ret)
		{
			user = AcGetUser(hub, auth_username);
			if (user == NULL)
			{
				user = AcGetUser(hub, "*");
				if (user == NULL)
				{
					// 認証失敗
					auth_ret = false;
				}
			}
		}

		if (auth_ret)
		{
			UINT64 user_expires = 0;
			Lock(user->lock);
			{
				// 有効期限を取得
				user_expires = user->ExpireTime;

				StrCpy(auth_username_real, sizeof(auth_username_real), user->Name);
			}
			Unlock(user->lock);

			// 有効期限を検査
			if (user_expires != 0 && user_expires <= SystemTime64())
			{
				// 有効期限が切れています
				auth_ret = false;

				if (first_connection)
				{
					DsLogEx(ds, DS_LOG_WARNING, "DSL_USER_EXPIRED", tunnel_id, auth_username_real);
					DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
				}
			}
			else
			{
				// ユーザー情報の更新
				Lock(user->lock);
				{
					if (true)
					{
						if (first_connection)
						{
							user->NumLogin++;
							user->LastLoginTime = SystemTime64();
						}
					}
				}
				Unlock(user->lock);
			}

			ReleaseUser(user);
		}

		Unlock(hub->lock);

		ReleaseHub(hub);

		if (auth_ret == false)
		{
			// 認証失敗
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_WARNING, "DSL_AUTH_FAILED", tunnel_id);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}

			bool lockout_as_result = false;

			// ロックアウト記録
			if (pol.AuthLockoutTimeout != 0 && pol.AuthLockoutCount != 0)
			{
				AddLockout(ds->Lockout, auth_username, pol.AuthLockoutTimeout * 1000);

				if (GetLockout(ds->Lockout, auth_username, pol.AuthLockoutTimeout * 1000) >= pol.AuthLockoutCount)
				{
					// 結果としてロックアウトが発生した
					lockout_as_result = true;
				}
			}

			DsSendError(sock, lockout_as_result == false ? ERR_AUTH_FAILED : ((client_build < 9862) ? ERR_ACCESS_DENIED : ERR_DESK_AUTH_LOCKOUT));
			FreePack(p);
			return;
		}

		if (pol.AuthLockoutTimeout != 0 && pol.AuthLockoutCount != 0)
		{
			// 認証成功時はロックアウト解除
			ClearLockout(ds->Lockout, auth_username);
		}

		DsDebugLog(ds, logprefix, "Auth OK (%s:%u)", __FILE__, __LINE__);
	}

	FreePack(p);

	DsDebugLog(ds, logprefix, "svc_type = %u", svc_type);

	if (svc_type == DESK_SERVICE_VNC)
	{
		bool is_locked = false;

		// URDP Server を使用する場合のチェック
		if (MsIsCurrentDesktopAvailableForVnc() == false)
		{
			is_locked = true;
		}

		// 2016.9.24 Windows 10 用により厳密なチェック
		if (ds->IsLocked != NULL)
		{
			if (ds->IsLocked->IsLockedFlag)
			{
				is_locked = true;
			}
		}

		if (is_locked)
		{
			// デスクトップがロックされている
			DsSendError(sock, ERR_DESK_URDP_DESKTOP_LOCKED);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_URDP_DESKTOP_LOCKED (%s:%u)", __FILE__, __LINE__);
			return;
		}
	}
	else if (svc_type == DESK_SERVICE_RDP)
	{
		// RDP を使用する場合のチェック
		if (MsIsRemoteDesktopEnabled() == false)
		{
			DsDebugLog(ds, logprefix, "MsIsRemoteDesktopEnabled() == false (%s:%u)", __FILE__, __LINE__);
			// 無効な場合は有効にする
			if (MsEnableRemoteDesktop())
			{
				DsDebugLog(ds, logprefix, "MsEnableRemoteDesktop() (%s:%u)", __FILE__, __LINE__);
				SleepThread(1000);
			}

			if (MsIsRemoteDesktopEnabled() == false)
			{
				// リモートデスクトップが無効になっている
				if (MsIsWin2000())
				{
					DsSendError(sock, ERR_DESK_RDP_NOT_ENABLED_2000);
					DsDebugLog(ds, logprefix, "Error: ERR_DESK_RDP_NOT_ENABLED_2000 (%s:%u)", __FILE__, __LINE__);

				}
				else if (MsIsVista() == false)
				{
					DsSendError(sock, ERR_DESK_RDP_NOT_ENABLED_XP);
					DsDebugLog(ds, logprefix, "Error: ERR_DESK_RDP_NOT_ENABLED_XP (%s:%u)", __FILE__, __LINE__);
				}
				else
				{
					DsSendError(sock, ERR_DESK_RDP_NOT_ENABLED_VISTA);
					DsDebugLog(ds, logprefix, "Error: ERR_DESK_RDP_NOT_ENABLED_VISTA (%s:%u)", __FILE__, __LINE__);
				}
				return;
			}
		}
		else
		{
			// 有効な場合でも再度有効にする
			MsEnableRemoteDesktop();
			DsDebugLog(ds, logprefix, "MsEnableRemoteDesktop() (%s:%u)", __FILE__, __LINE__);
		}

		DsDebugLog(ds, logprefix, "RdpEnableOptimizer = %u", ds->RdpEnableOptimizer);

		if (ds->RdpEnableOptimizer)
		{
			if (MsIsRemoteDesktopAvailable())
			{
				if (MsIsVista())
				{
					MsSetRdpAllowLoginScreen(true);
					MsRegWriteInt(REG_LOCAL_MACHINE,
						"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
						"UserAuthentication", 0);
					MsRegWriteInt(REG_LOCAL_MACHINE,
						"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
						"UserAuthentication", 0);
				}

				if (MsIsWindows10())
				{
					// Windows 10 2004 以降で 「Windows Hello 認証の強制」 が ON になっている場合は、RDP 接続がうまくできなくなる
					// バグがあるので、OFF に戻す。
					if (MsRegIsValueEx2(REG_LOCAL_MACHINE,
						"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\PasswordLess\\Device",
						"DevicePasswordLessBuildVersion", false, true))
					{
						MsRegWriteIntEx2(REG_LOCAL_MACHINE,
							"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\PasswordLess\\Device",
							"DevicePasswordLessBuildVersion", 0, false, true);
						DsDebugLog(ds, logprefix, "MsRegWriteIntEx2(RDP_win10_optimization) (%s:%u)", __FILE__, __LINE__);
					}
				}
			}
		}

		DsDebugLog(ds, logprefix, "RdpEnableGroupKeeper = %u", ds->RdpEnableGroupKeeper);

		if (MsIsRemoteDesktopAvailable())
		{
			if (ds->RdpEnableGroupKeeper && MsIsAdmin() && UniIsEmptyStr(ds->RdpGroupKeepUserName) == false)
			{
				if (UniInStr(ds->RdpGroupKeepUserName, L"\"") == false)
				{
					wchar_t net_exe[MAX_PATH];
					wchar_t args[300];
					void *proc_handle = NULL;
					void *wow = NULL;

					wow = MsDisableWow64FileSystemRedirection();

					CombinePathW(net_exe, sizeof(net_exe), MsGetSystem32DirW(), L"net.exe");
					UniFormat(args, sizeof(args), L"localgroup \"Remote Desktop Users\" \"%s\" /add", ds->RdpGroupKeepUserName);

					if (IsFileExistsW(net_exe))
					{
						if (MsExecuteEx3W(net_exe, args, &proc_handle, false, true))
						{
							DsDebugLog(ds, logprefix, "MsExecuteEx3W Ok (%s:%u)", __FILE__, __LINE__);
							MsWaitProcessExitWithTimeout(proc_handle, 5 * 1000);
						}
						else
						{
							DsDebugLog(ds, logprefix, "MsExecuteEx3W Error (%s:%u)", __FILE__, __LINE__);
						}
					}

					MsRestoreWow64FileSystemRedirection(wow);
				}
			}

			if (MsIsAdmin() && IsEmptyStr(ds->RdpStopServicesList) == false)
			{
				wchar_t net_exe[MAX_PATH];
				void *wow = NULL;
				TOKEN_LIST *t = NULL;

				DsDebugLog(ds, logprefix, "RdpStopServicesList = %s", ds->RdpStopServicesList);

				wow = MsDisableWow64FileSystemRedirection();
				CombinePathW(net_exe, sizeof(net_exe), MsGetSystem32DirW(), L"net.exe");

				if (IsFileExistsW(net_exe))
				{
					t = ParseTokenWithoutNullStr(ds->RdpStopServicesList, " \t");
					if (t != NULL)
					{
						UINT i;
						for (i = 0; i < t->NumTokens;i++)
						{
							char *svc_name = t->Token[i];
							if (IsEmptyStr(svc_name) == false && InStr(svc_name, "\"") == false && InStr(svc_name, " ") == false)
							{
								wchar_t args[300];
								void *proc_handle = NULL;
								UniFormat(args, sizeof(args), L"stop %S", svc_name);
								if (MsExecuteEx3W(net_exe, args, &proc_handle, false, true))
								{
									DsDebugLog(ds, logprefix, "MsExecuteEx3W Ok (%s:%u)", __FILE__, __LINE__);
									MsWaitProcessExitWithTimeout(proc_handle, 5 * 1000);
								}
								else
								{
									DsDebugLog(ds, logprefix, "MsExecuteEx3W Error (%s:%u)", __FILE__, __LINE__);
								}
							}
						}
						FreeToken(t);
					}
				}

				MsRestoreWow64FileSystemRedirection(wow);
			}
		}
	}

	if (svc_type == DESK_SERVICE_VNC)
	{
		// URDP Server の開始
		DeskStartUrdpServer(ds->UrdpServer, urdp_version);
		if (DeskWaitReadyForUrdpServer() == false)
		{
			// 開始の失敗
			DeskStopUrdpServer(ds->UrdpServer);
			DsSendError(sock, ERR_DESK_URDP_START_FAILED);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_URDP_START_FAILED (%s:%u)", __FILE__, __LINE__);
			return;
		}
	}

	if (svc_type == DESK_SERVICE_RDP)
	{
		Lock(ds->RDPSessionIncDecLock);
		{
			if (Inc(ds->CurrentNumRDPSessions) == 1)
			{
				// ポリシー調整
				if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
				{
					if (MsIsAdmin())
					{
						Zero(&ds->Win32RdpPolicy, sizeof(DS_WIN32_RDP_POLICY));
						Debug("*** DsWin32GetRdpPolicy()\n");

						if (MsRegReadIntEx2(REG_LOCAL_MACHINE,
							"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
							"fDisableCdm",
							false, true)
							&&
							MsRegReadIntEx2(REG_LOCAL_MACHINE,
								"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
								"fDisableClip",
								false, true))
						{
							// すでに fDisableCdm と fDisableClip が設定されている。
							// これはインストーラの SwInstallMain() の中で設定されたものであると思われる。
							// この場合、グループポリシーを読み書きするとそれが刺激となって
							// Windows の動作がおかしくなり、RDP を無効化してしまうおそれがある
							// ので、DsWin32GetRdpPolicy / DsWin32SetRdpPolicy 関係の処理は
							// すべてスキップすることにする。
							DsDebugLog(ds, logprefix, "fDisableCdm && fDisableClip", __FILE__, __LINE__);
						}
						else
						{
							DsWin32GetRdpPolicy(&ds->Win32RdpPolicy);

							Debug("HasValidValue: %u\n", ds->Win32RdpPolicy.HasValidValue);
							if (ds->Win32RdpPolicy.HasValidValue)
							{
								DS_WIN32_RDP_POLICY new_policy = CLEAN;

								Debug("fDisableCdm: %u\n", ds->Win32RdpPolicy.fDisableCdm);
								Debug("fDisableClip: %u\n", ds->Win32RdpPolicy.fDisableClip);
								Debug("fDenyTSConnections: %u\n", ds->Win32RdpPolicy.fDenyTSConnections);

								new_policy.HasValidValue = true;
								new_policy.fDisableCdm = 1;
								new_policy.fDisableClip = 1;
								new_policy.fDenyTSConnections = 0;

								if (DsWin32SetRdpPolicy(&new_policy) == false)
								{
									Zero(&ds->Win32RdpPolicy, sizeof(DS_WIN32_RDP_POLICY));

									Debug("DsWin32SetRdpPolocy error\n");
									DsDebugLog(ds, logprefix, "DsWin32SetRdpPolocy error", __FILE__, __LINE__);
								}
								else
								{
									Debug("DsWin32SetRdpPolocy ok\n");
									DsDebugLog(ds, logprefix, "DsWin32SetRdpPolocy ok", __FILE__, __LINE__);
								}
							}
						}
					}
				}
			}
		}
		Unlock(ds->RDPSessionIncDecLock);
	}

	DS_GUACD* guacd = NULL;

	// 接続
	s = NULL;
	if (guacd_mode)
	{
		// Guacd に接続するモードの場合、Guacd プロセスを開始する
		guacd = DsStartGuacd(ds, guacd_flags);
		if (guacd == NULL)
		{
			// 開始失敗
			DsSendError(sock, ERR_DESK_GUACD_START_ERROR);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_GUACD_START_ERROR (%s:%u)", __FILE__, __LINE__);

			goto LABEL_END;
		}

		// ソケットはすでに接続されております
		// これの参照カウンタをインクリメントしてローカル変数に渡す
		s = guacd->Sock;
		AddRef(s->ref);
	}
	else if (check_port)
	{
		UINT num_retry = 5;
		UINT i;

		for (i = 0;i < num_retry;i++)
		{
			// この段階で localhost ポートに接続する
			DsDebugLog(ds, logprefix, "DsConnectToLocalHostService (%u, %u) (%s:%u)", svc_type, ds->RdpPort, __FILE__, __LINE__);
			s = DsConnectToLocalHostService(svc_type, ds->RdpPort);

			if (s != NULL)
			{
				break;
			}

			if (i != (num_retry - 1))
			{
				// リトライ
				SleepThread(100);

				if (svc_type == DESK_SERVICE_RDP && MsIsAdmin())
				{
					// RDP の場合は、失敗する度に RDP の有効化を試行する (グループポリシーがおかしな挙動をして RDP を無効化することがあるため)
					MsEnableRemoteDesktop();
				}
			}
		}

		if (s == NULL)
		{
			// 開始失敗
			DsSendError(sock, ERR_DESK_FAILED_TO_CONNECT_PORT);
			DsDebugLog(ds, logprefix, "Error: ERR_DESK_FAILED_TO_CONNECT_PORT (%s:%u)", __FILE__, __LINE__);

			goto LABEL_END;
		}
	}

	if (is_smartcard_auth == false)
	{
		// 開始成功
		DsSendError(sock, ERR_NO_ERROR);
	}
	else
	{
		// スマートカード認証の場合はチケットも渡す
		DsSendErrorEx(sock, ERR_NO_ERROR, "SmartCardTicket", ds->SmartCardTicket, SHA1_SIZE);
	}

	SockIoSetTimeout(sock, INFINITE);

	// 1 文字待つ
	c = 0;
	SockIoRecvAll(sock, &c, 1);

	if (c == 'A')
	{
		DS_CLIENT *dsc;
		wchar_t text[MAX_SIZE];
		wchar_t title[MAX_SIZE];
		wchar_t datetime[MAX_PATH];
		wchar_t datetime2[MAX_PATH];
		UINT64 connected_datetime;
		UINT64 disconnected_datetime;
		UINT current_channel_count = 0;

		Debug("*** CONNECTED\n");

		if (s == NULL)
		{
			UINT num_retry = 5;
			UINT i;
			for (i = 0;i < num_retry;i++)
			{
				// この段階で localhost ポートに接続する
				s = DsConnectToLocalHostService(svc_type, ds->RdpPort);
				if (s != NULL)
				{
					break;
				}

				if (i != (num_retry - 1))
				{
					// リトライ
					SleepThread(100);

					if (svc_type == DESK_SERVICE_RDP && MsIsAdmin())
					{
						// RDP の場合は、失敗する度に RDP の有効化を試行する (グループポリシーがおかしな挙動をして RDP を無効化することがあるため)
						MsEnableRemoteDesktop();
					}
				}
			}
		}

		if (s == NULL)
		{
			DsDebugLog(ds, logprefix, "Error: DsConnectToLocalHostService failed. (%s:%u)", __FILE__, __LINE__);
		}

		connected_datetime = SystemTime64();

		dsc = ZeroMalloc(sizeof(DS_CLIENT));

		dsc->ConnectedTick = Tick64();
		Copy(&dsc->Ip, &client_ip, sizeof(IP));
		StrCpy(dsc->HostName, sizeof(dsc->HostName), client_host);
		dsc->Port = client_port;
		Copy(dsc->ClientID, client_id, SHA1_SIZE);
		dsc->TunnelID = tunnel_id;

		LockList(ds->ClientList);
		{
			dsc->SeqNo = (++ds->LastClientSeqNo);
			Add(ds->ClientList, dsc);
			current_channel_count = LIST_NUM(ds->ClientList);
		}
		UnlockList(ds->ClientList);

		DsDebugLog(ds, logprefix, "current_channel_count = %u, SeqNo = %u", current_channel_count, dsc->SeqNo);

		// リレー動作を開始することを示すログを出力する
		DsLogEx(ds, DS_LOG_INFO, "DSL_TUNNEL_RELAY_START",
			client_ip_str, client_host, client_port, client_id_str, dsc->SeqNo, current_channel_count);

		// バルーンを表示する
		GetDateTimeStrEx64(datetime, sizeof(datetime),
			SystemToLocal64(connected_datetime), NULL);
		UniFormat(title, sizeof(title), _UU("DS_BALLON_CONNECTED_TITLE"),
			client_ip_str);
		UniFormat(text, sizeof(text), _UU("DS_BALLON_CONNECTED_TEXT"),
			client_ip_str, client_port, datetime);

		MsChangeIconOnTrayEx2(NULL, NULL, text, title, 1);

		DsUpdateTaskIcon(ds);

		// プロセスウォッチャーを活性化
		MsActivateProcessWatcher(ds->ProcessWatcher);

		// リレー動作を開始
		DsDebugLog(ds, logprefix, "DeskRelay() started. (%s:%u)", __FILE__, __LINE__);

		UINT total_send = 0, total_recv = 0;

		total_relay_size = DeskRelay(sock, s, 3000, &total_send, &total_recv);

		DsDebugLog(ds, logprefix, "DeskRelay() finished. total_relay_size = %u (total_send = %u, total_recv = %u) (%s:%u)", total_relay_size, total_send, total_recv, __FILE__, __LINE__);

		// プロセスウォッチャーを非活性化
		MsDeactivateProcessWatcher(ds->ProcessWatcher);

		disconnected_datetime = SystemTime64();

		// バルーンを消す
		GetDateTimeStrEx64(datetime2, sizeof(datetime2),
			SystemToLocal64(disconnected_datetime), NULL);
		UniFormat(title, sizeof(title), _UU("DS_BALLON_DISCONNECTED_TITLE"),
			client_host);
		UniFormat(text, sizeof(text), _UU("DS_BALLON_DISCONNECTED_TEXT"),
			datetime, client_ip_str, client_port, datetime2);

		MsChangeIconOnTrayEx2(NULL, NULL, text, title, 1);

		LockList(ds->ClientList);
		{
			Delete(ds->ClientList, dsc);

			if (LIST_NUM(ds->ClientList) == 0)
			{
				last_connection = true;
			}

			current_channel_count = LIST_NUM(ds->ClientList);
		}
		UnlockList(ds->ClientList);

		DsDebugLog(ds, logprefix, "current_channel_count = %u", current_channel_count);
		DsDebugLog(ds, logprefix, "last_connection = %u", last_connection);

		// リレー動作を終了することを示すログを出力する
		DsLogEx(ds, DS_LOG_INFO, "DSL_TUNNEL_RELAY_STOP",
			client_ip_str, client_host, client_port, client_id_str, dsc->SeqNo, total_relay_size, current_channel_count);

		Debug("*** DISCONNECTED  total_size = %u\n", total_relay_size);

		DsUpdateTaskIcon(ds);

		Free(dsc);
	}
	else
	{
		DsDebugLog(ds, logprefix, "Error: c != 'A' (c == 0x%X) (%s:%u)", c, __FILE__, __LINE__);
	}

	if (last_connection)
	{
		DsCleanAllRadiusCache(ds);
	}

	Disconnect(s);
	ReleaseSock(s);

	if (svc_type == DESK_SERVICE_RDP)
	{
		Lock(ds->RDPSessionIncDecLock);
		{
			if (Dec(ds->CurrentNumRDPSessions) == 0)
			{
				// ポリシー調整
				if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
				{
					if (MsIsAdmin())
					{
						if (ds->Win32RdpPolicy.HasValidValue)
						{
							Debug("*** DsWin32SetRdpPolicy() -- restore\n");

							ds->Win32RdpPolicy.fDenyTSConnections = 0;

							if (DsWin32SetRdpPolicy(&ds->Win32RdpPolicy) == false)
							{
								Debug("DsWin32SetRdpPolicy() restore error\n");
								DsDebugLog(ds, logprefix, "DsWin32SetRdpPolocy error", __FILE__, __LINE__);
							}
							else
							{
								Debug("DsWin32SetRdpPolicy() restore OK\n");
								DsDebugLog(ds, logprefix, "DsWin32SetRdpPolocy ok", __FILE__, __LINE__);
							}
						}

						Zero(&ds->Win32RdpPolicy, sizeof(DS_WIN32_RDP_POLICY));
					}
				}
			}
		}
		Unlock(ds->RDPSessionIncDecLock);
	}

LABEL_END:

	if (guacd != NULL)
	{
		// Guacd の停止
		DsStopGuacd(ds, guacd);
	}

	if (svc_type == DESK_SERVICE_VNC)
	{
		// URDP Server の停止
		DeskStopUrdpServer(ds->UrdpServer);
	}
#endif  // OS_WIN32
}

// OTP 文字列の発行
void DsGenerateNewOtp(char *dst, UINT size, UINT len)
{
	UINT i;
	char tmp[MAX_PATH];
	if (dst == NULL)
	{
		return;
	}

	len = MIN(len, sizeof(tmp) - 1);

	Zero(tmp, sizeof(tmp));

	for (i = 0;i < len;i++)
	{
		char c = '0' + Rand32() % 9;

		tmp[i] = c;
	}

	StrCpy(dst, size, tmp);
}

// 認証失敗報告
void DsReportAuthFailed(DS *ds, UINT tunnel_id, IP *ip, char *hostname)
{
	UINT num;
	char ip_str[MAX_PATH];
	// 引数チェック
	if (ds == NULL || ip == NULL || hostname == NULL)
	{
		return;
	}

	IPToStr(ip_str, sizeof(ip_str), ip);

	DsLockHistory(ds);
	{
		DsAddHistory(ds, ip);

		num = DsGetHistoryCount(ds, ip);

		if (num >= DS_HISTORY_THRESHOLD)
		{
			// 警告を発生させる
			DsLogEx(ds, DS_LOG_ERROR, "DSL_AUTH_ERROR", tunnel_id, ip_str, hostname, (UINT)((UINT64)DS_HISTORY_EXPIRES / 1000ULL), num);
		}
	}
	DsUnlockHistory(ds);
}

// localhost で動作しているサービスポートに接続
SOCK *DsConnectToLocalHostService(UINT svc_type, UINT rdp_port)
{
	SOCK *s = NULL;

	switch (svc_type)
	{
	case DESK_SERVICE_RDP:
		s = Connect("127.0.0.1", rdp_port);
		break;

	case DESK_SERVICE_VNC:
		s = Connect("127.0.0.1", DS_URDP_PORT);
		break;
	}

	return s;
}

// エラーの送信
void DsSendError(SOCKIO *sock, UINT error_code)
{
	DsSendErrorEx(sock, error_code, NULL, 0, 0);
}
void DsSendErrorEx(SOCKIO *sock, UINT error_code, char *add_value_name, UCHAR *add_value_data, UINT data_size)
{
	PACK *p;
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}

	p = PackError(error_code);

	if (IsEmptyStr(add_value_name) == false)
	{
		PackAddData(p, add_value_name, add_value_data, data_size);
	}

	SockIoSendPack(sock, p);

	FreePack(p);

	if (error_code != ERR_NO_ERROR)
	{
		SockIoSetTimeout(sock, DS_SEND_ERROR_AND_WAIT_SPAN);

		FreePack(SockIoRecvPack(sock));
	}
}

// RPC 関数関係マクロ
#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	in_rpc(&t, p);													\
	err = function(ds, &t);											\
	if (err == ERR_NO_ERROR)										\
		{																\
		out_rpc(ret, &t);											\
		}																\
		free_rpc(&t);													\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	in_rpc(&t, p);													\
	err = function(ds, &t);											\
	if (err == ERR_NO_ERROR)										\
		{																\
		out_rpc(ret, &t);											\
		}																\
		ok = true;														\
	}
#define	DECLARE_RPCHUB_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	DelElement(p, "HubName");										\
	PackAddStr(p, "HubName", CEDAR_DESKVPN_HUBNAME);				\
	in_rpc(&t, p);													\
	err = function(a, &t);											\
	if (err == ERR_NO_ERROR)										\
{																\
	out_rpc(ret, &t);											\
}																\
	free_rpc(&t);													\
	ok = true;														\
	if (StartWith(name, "set") || StartWith(name, "add") || StartWith(name, "create") || StartWith(name, "delete"))	\
{																	\
	DsSaveConfig(ds);												\
}																	\
}
#define	DECLARE_RPCHUB(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	DelElement(p, "HubName");										\
	PackAddStr(p, "HubName", CEDAR_DESKVPN_HUBNAME);				\
	in_rpc(&t, p);													\
	err = function(a, &t);											\
	if (err == ERR_NO_ERROR)										\
{																\
	out_rpc(ret, &t);											\
}																\
	ok = true;														\
	if (StartWith(name, "set") || StartWith(name, "add") || StartWith(name, "create") || StartWith(name, "delete"))	\
{																	\
	DsSaveConfig(ds);												\
}																	\
}
#define	DECLARE_SC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)	\
	UINT function(RPC *r, data_type *t)									\
	{																	\
	PACK *p, *ret;													\
	UINT err;														\
	if (r == NULL || t == NULL)										\
		{																\
		return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		free_rpc(t);													\
		Zero(t, sizeof(data_type));										\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
		in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	DECLARE_SC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	UINT function(RPC *r, data_type *t)									\
	{																	\
	PACK *p, *ret;													\
	UINT err;														\
	if (r == NULL || t == NULL)										\
		{																\
		return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
		in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}


// RPC サーバープロシージャ
PACK *DsRpcServer(RPC *r, char *name, PACK *p)
{
	DS *ds = (DS *)r->Param;
	ADMIN admin = CLEAN, *a;
	PACK *ret;
	UINT err;
	bool ok;
	// 引数チェック
	if (r == NULL || name == NULL || p == NULL || ds == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;
	ok = false;

	a = &admin;
	Zero(a, sizeof(ADMIN));
	a->Server = ds->Server;
	a->ServerAdmin = true;
	a->HubName = NULL;
	a->Rpc = r;
	a->LogFileList = NULL;

	// RPC 定義 (サーバー側)
	if (0) {}

	// 通常系 RPC
	DECLARE_RPC("GetInternetSetting", INTERNET_SETTING, DtGetInternetSetting, InInternetSetting, OutInternetSetting)
	DECLARE_RPC("SetInternetSetting", INTERNET_SETTING, DtSetInternetSetting, InInternetSetting, OutInternetSetting)
	DECLARE_RPC("GetStatus", RPC_DS_STATUS, DtGetStatus, InRpcDsStatus, OutRpcDsStatus)
	DECLARE_RPC("RegistMachine", RPC_PCID, DtRegistMachine, InRpcPcid, OutRpcPcid)
	DECLARE_RPC("ChangePcid", RPC_PCID, DtChangePcid, InRpcPcid, OutRpcPcid)
	DECLARE_RPC("SetConfig", RPC_DS_CONFIG, DtSetConfig, InRpcDsConfig, OutRpcDsConfig)
	DECLARE_RPC("GetConfig", RPC_DS_CONFIG, DtGetConfig, InRpcDsConfig, OutRpcDsConfig)
	DECLARE_RPC("GetPcidCandidate", RPC_PCID, DtGetPcidCandidate, InRpcPcid, OutRpcPcid)
	DECLARE_RPC("ResetCertOnNextBoot", RPC_TEST, DtResetCertOnNextBoot, InRpcTest, OutRpcTest)

	// 仮想 HUB 操作系 RPC
	DECLARE_RPCHUB("GetHubRadius", RPC_RADIUS, StGetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPCHUB("SetHubRadius", RPC_RADIUS, StSetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPCHUB_EX("AddCa", RPC_HUB_ADD_CA, StAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
	DECLARE_RPCHUB_EX("EnumCa", RPC_HUB_ENUM_CA, StEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
	DECLARE_RPCHUB_EX("GetCa", RPC_HUB_GET_CA, StGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
	DECLARE_RPCHUB("DeleteCa", RPC_HUB_DELETE_CA, StDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
	DECLARE_RPCHUB_EX("CreateUser", RPC_SET_USER, StCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPCHUB_EX("SetUser", RPC_SET_USER, StSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPCHUB_EX("GetUser", RPC_SET_USER, StGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPCHUB("DeleteUser", RPC_DELETE_USER, StDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPCHUB_EX("EnumUser", RPC_ENUM_USER, StEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
	DECLARE_RPCHUB_EX("EnumCrl", RPC_ENUM_CRL, StEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
	DECLARE_RPCHUB_EX("AddCrl", RPC_CRL, StAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("DelCrl", RPC_CRL, StDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("GetCrl", RPC_CRL, StGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("SetCrl", RPC_CRL, StSetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("SetAcList", RPC_AC_LIST, StSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPCHUB_EX("GetAcList", RPC_AC_LIST, StGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPCHUB("SetSysLog", SYSLOG_SETTING, StSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPCHUB("GetSysLog", SYSLOG_SETTING, StGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	PackAddInt(ret, "error", err);

	return ret;
}

// RPC 定義 (クライアント側)
DECLARE_SC("GetInternetSetting", INTERNET_SETTING, DtcGetInternetSetting, InInternetSetting, OutInternetSetting)
DECLARE_SC("SetInternetSetting", INTERNET_SETTING, DtcSetInternetSetting, InInternetSetting, OutInternetSetting)
DECLARE_SC("GetStatus", RPC_DS_STATUS, DtcGetStatus, InRpcDsStatus, OutRpcDsStatus)
DECLARE_SC("RegistMachine", RPC_PCID, DtcRegistMachine, InRpcPcid, OutRpcPcid)
DECLARE_SC("ChangePcid", RPC_PCID, DtcChangePcid, InRpcPcid, OutRpcPcid)
DECLARE_SC("SetConfig", RPC_DS_CONFIG, DtcSetConfig, InRpcDsConfig, OutRpcDsConfig)
DECLARE_SC("GetConfig", RPC_DS_CONFIG, DtcGetConfig, InRpcDsConfig, OutRpcDsConfig)
DECLARE_SC("GetPcidCandidate", RPC_PCID, DtcGetPcidCandidate, InRpcPcid, OutRpcPcid)
DECLARE_SC("ResetCertOnNextBoot", RPC_TEST, DtcResetCertOnNextBoot, InRpcTest, OutRpcTest)

// 次回起動時に証明書リセット
UINT DtResetCertOnNextBoot(DS *ds, RPC_TEST *t)
{
	Zero(t, sizeof(RPC_TEST));

	DsResetCertOnNextBoot();

	// RegistrationEmail と RegistrationPassword も初期化
	if (ds->Wide != NULL)
	{
		ClearStr(ds->Wide->RegistrationEmail, sizeof(ds->Wide->RegistrationEmail));
		ClearStr(ds->Wide->RegistrationPassword, sizeof(ds->Wide->RegistrationPassword));

		DsSaveConfig(ds);
	}

	return ERR_NO_ERROR;
}

// PCID 候補の取得
UINT DtGetPcidCandidate(DS *ds, RPC_PCID *t)
{
#ifdef	OS_WIN32
	Zero(t, sizeof(RPC_PCID));

	return WideServerGetPcidCandidate(ds->Wide, t->Pcid, sizeof(t->Pcid), MsGetUserName());
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// インターネット接続設定の取得
UINT DtGetInternetSetting(DS *ds, INTERNET_SETTING *t)
{
	Zero(t, sizeof(INTERNET_SETTING));

	WideGetInternetSetting(ds->Wide, t);

	return ERR_NO_ERROR;
}

// インターネット接続設定の設定
UINT DtSetInternetSetting(DS *ds, INTERNET_SETTING *t)
{
	if (t->ProxyType != PROXY_DIRECT && t->ProxyType != PROXY_NO_CONNECT)
	{
		if (IsEmptyStr(t->ProxyHostName) || t->ProxyPort == 0)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	WideSetInternetSetting(ds->Wide, t);
	ds->IsConfigured = true;

	DsSaveConfig(ds);

	return ERR_NO_ERROR;
}

// 状態の取得
UINT DtGetStatus(DS *ds, RPC_DS_STATUS *t)
{
#ifdef	OS_WIN32
	HUB *h;
	DS_POLICY_BODY pol;
	Zero(t, sizeof(RPC_DS_STATUS));

	t->Version = DESK_VERSION;
	t->Build = DESK_BUILD;
	StrCpy(t->ExePath, sizeof(t->ExePath), MsGetExeFileName());
	StrCpy(t->ExeDir, sizeof(t->ExeDir), MsGetExeDirName());
	UniStrCpy(t->ExePathW, sizeof(t->ExePathW), MsGetExeFileNameW());
	UniStrCpy(t->ExeDirW, sizeof(t->ExeDirW), MsGetExeDirNameW());
	t->LastError = WideServerGetErrorCode(ds->Wide);
	t->IsConnected = WideServerIsConnected(ds->Wide);
	WideServerGetPcid(ds->Wide, t->Pcid, sizeof(t->Pcid));
	WideServerGetHash(ds->Wide, t->Hash, sizeof(t->Hash));
	WideServerGetSystem(ds->Wide, t->System, sizeof(t->System));
	t->ServiceType = ds->ServiceType;
	t->IsUserMode = ds->IsUserMode;
	t->Active = ds->Active;
	t->IsConfigured = ds->IsConfigured;
	t->DsCaps = DsGetCaps(ds);
	t->UseAdvancedSecurity = ds->UseAdvancedSecurity;
	t->ForceDisableShare = ds->ForceDisableShare;
	t->SupportEventLog = ds->SupportEventLog;
	t->NumConfigures = ds->NumConfigures;
	t->IsAdminOrSystem = MsIsAdmin();

	if (ds->Wide != NULL && ds->Wide->wt != NULL)
	{
		StrCpy(t->GateIP, sizeof(t->GateIP), ds->Wide->wt->CurrentGateIp);

		t->MsgForServerArrived = ds->Wide->MsgForServerArrived;
		UniStrCpy(t->MsgForServer, sizeof(t->MsgForServer), ds->Wide->MsgForServer);
		t->MsgForServerOnce = ds->Wide->MsgForServerOnce;
	}

	if (DsGetPolicy(ds, &pol))
	{
		// 規制が設定されている
		DsPreparePolicyMessage(t->MsgForServer2, sizeof(t->MsgForServer2), &pol);

		if (pol.DisableShare)
		{
			t->ForceDisableShare = true;
		}

		if (pol.EnforceOtp)
		{
			StrCpy(t->OtpEndWith, sizeof(t->OtpEndWith), pol.EnforceOtpEndWith);
		}

		t->EnforceOtp = pol.EnforceOtp;
		t->EnforceInspection = pol.EnforceInspection;
		t->EnforceMacCheck = pol.EnforceMacCheck;

		t->EnforceWatermark = pol.EnforceWatermark;

		t->DisableInspection = pol.DisableInspection;
		t->DisableMacCheck = pol.DisableMacCheck;
		t->DisableWatermark = pol.DisableWatermark;
		t->NoLocalMacAddressList = pol.NoLocalMacAddressList;
		t->PolicyServerManagedMacAddressList = IsFilledStr(pol.ServerAllowedMacListUrl);
		t->EnforceProcessWatcher = pol.EnforceProcessWatcher;
		t->EnforceProcessWatcherAlways = pol.EnforceProcessWatcherAlways;
	}
	else
	{
		if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
		{
			// 強いセキュリティパッチ適用モード
			// 検疫、MAC、透かし が強制されているものとみなす
			t->EnforceInspection = true;
			t->EnforceMacCheck = true;
			t->EnforceWatermark = true;
			t->EnforceOtp = true;
		}

		if (DsIsTryCompleted(ds))
		{
			if (UniIsEmptyStr(t->MsgForServer))
			{
				// 2021.1.20 このメッセージにはあまり意味がないので無効化
#if 0
				// 特に規制が設定されていない
				// 利用禁止ブラックリストにも入っていない
				char list_msg[256] = {0};
				UINT i;
				LIST *dns_list = Win32GetDnsSuffixList();

				if (LIST_NUM(dns_list) == 0)
				{
					char dom2[128];
					StrCpy(dom2, sizeof(dom2), "- Local Area Network\r\n");
					StrCat(list_msg, sizeof(list_msg), dom2);
				}
				else
				{
					for (i = 0; i < LIST_NUM(dns_list);i++)
					{
						char *dom = LIST_DATA(dns_list, i);

						if (IsEmptyStr(dom) == false)
						{
							char dom2[128];
							Format(dom2, sizeof(dom2), "- %s\r\n", dom);
							StrCat(list_msg, sizeof(list_msg), dom2);
						}
					}
				}

				UniFormat(t->MsgForServer2, sizeof(t->MsgForServer2), _UU("DS_POLICY_DEFAULT_MSG"), list_msg);

				ReleaseStrList(dns_list);
#endif // 0
			}
		}
	}

	if (ds->Server != NULL && ds->Server->Cedar != NULL)
	{
		LockHubList(ds->Server->Cedar);
		{
			h = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		}
		UnlockHubList(ds->Server->Cedar);

		if (h != NULL)
		{
			AcLock(h);
			{
				if (h->HubDb != NULL)
				{
					t->NumAdvancedUsers = LIST_NUM(h->HubDb->UserList);
				}
			}
			AcUnlock(h);

			ReleaseHub(h);
		}
	}

	return ERR_NO_ERROR;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// PCID の登録
UINT DtRegistMachine(DS *ds, RPC_PCID *t)
{
	X *x;
	K *k;
	UINT ret;

	if (WideServerGetCertAndKey(ds->Wide, &x, &k) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = WideServerRegistMachine(ds->Wide, t->Pcid, x, k);

	if (ret == ERR_NO_ERROR)
	{
		Lock(ds->Wide->SettingLock);
		{
			StrCpy(ds->Wide->Pcid, sizeof(ds->Wide->Pcid), t->Pcid);
		}
		Unlock(ds->Wide->SettingLock);

		WideServerReconnect(ds->Wide);
	}

	FreeX(x);
	FreeK(k);

	return ret;
}

// PCID の変更
UINT DtChangePcid(DS *ds, RPC_PCID *t)
{
	return WideServerRenameMachine(ds->Wide, t->Pcid);
}

// 設定の設定
UINT DtSetConfig(DS *ds, RPC_DS_CONFIG *t)
{
	bool wol_target_old = ds->EnableWoLTarget;
	bool reg_password_changed = false;

	Lock(ds->ConfigLock);
	{
		ds->Active = t->Active;
		ds->PowerKeep = t->PowerKeep;
		Copy(ds->HashedPassword, t->HashedPassword, sizeof(ds->HashedPassword));
		ds->AuthType = t->AuthType;
		Copy(ds->AuthPassword, t->AuthPassword, sizeof(ds->AuthPassword));
		ds->ServiceType = t->ServiceType;
		WideSetDontCheckCert(ds->Wide, t->DontCheckCert);
		ds->IsConfigured = true;
		ds->SaveLogFile = t->SaveLogFile;
		UniStrCpy(ds->BluetoothDir, sizeof(ds->BluetoothDir), t->BluetoothDir);
		ds->UseAdvancedSecurity = t->UseAdvancedSecurity;
		ds->SaveEventLog = t->SaveEventLog;
		ds->DisableShare = t->DisableShare;
		UniStrCpy(ds->AdminUsername, sizeof(ds->AdminUsername), t->AdminUsername);

		ds->EnableOtp = t->EnableOtp;
		StrCpy(ds->OtpEmail, sizeof(ds->OtpEmail), t->OtpEmail);

		ds->EnableInspection = t->EnableInspection;
		ds->EnableMacCheck = t->EnableMacCheck;
		StrCpy(ds->MacAddressList, sizeof(ds->MacAddressList), t->MacAddressList);

		if (StrLen(t->EmergencyOtp) >= DS_EMERGENCY_OTP_LENGTH)
		{
			StrCpy(ds->EmergencyOtp, sizeof(ds->EmergencyOtp), t->EmergencyOtp);
		}

		if (StrCmp(ds->Wide->RegistrationPassword, t->RegistrationPassword) != 0 ||
			StrCmp(ds->Wide->RegistrationEmail, t->RegistrationEmail) != 0)
		{
			reg_password_changed = true;
		}

		StrCpy(ds->Wide->RegistrationPassword, sizeof(ds->Wide->RegistrationPassword), t->RegistrationPassword);
		StrCpy(ds->Wide->RegistrationEmail, sizeof(ds->Wide->RegistrationEmail), t->RegistrationEmail);

		ds->RdpEnableGroupKeeper = t->RdpEnableGroupKeeper;
		UniStrCpy(ds->RdpGroupKeepUserName, sizeof(ds->RdpGroupKeepUserName), t->RdpGroupKeepUserName);
		ds->RdpEnableOptimizer = t->RdpEnableOptimizer;
		StrCpy(ds->RdpStopServicesList, sizeof(ds->RdpStopServicesList), t->RdpStopServicesList);

		ds->EnableDebugLog = t->EnableDebugLog;

		ds->ShowWatermark = t->ShowWatermark;
		UniStrCpy(ds->WatermarkStr, sizeof(ds->WatermarkStr), t->WatermarkStr);

		ds->EnableWoLTarget = t->EnableWoLTarget;
		ds->EnableWoLTrigger = t->EnableWoLTrigger;

#ifdef	OS_WIN32
		MsSetProcessWatcherAlwaysFlag(ds->ProcessWatcher, t->ProcessWatcherAlways);
		MsSetProcessWatcherDisabledFlag(ds->ProcessWatcher, !t->ProcessWatcherEnabled);
#endif	// OS_WIN32
	}
	Unlock(ds->ConfigLock);

	DsNormalizeConfig(ds, true);
	DsSaveConfig(ds);
	DsUpdatePowerKeepSetting(ds);

	if (ds->EnableWoLTarget != wol_target_old)
	{
		ds->Wide->SendMacList = ds->EnableWoLTarget;

		// WoL ターゲットの設定が変更された場合は再接続をする
		if (WideServerTryAutoReconnect(ds->Wide))
		{
			WideServerReconnect(ds->Wide);
		}
	}

	if (reg_password_changed)
	{
		// 初期ユーザー登録パスワードが変更になった場合は再接続する
		if (WideServerTryAutoReconnect(ds->Wide))
		{
			WideServerReconnect(ds->Wide);
		}
	}

	return ERR_NO_ERROR;
}

// 設定の取得
UINT DtGetConfig(DS *ds, RPC_DS_CONFIG *t)
{
	Zero(t, sizeof(RPC_DS_CONFIG));

	DsNormalizeConfig(ds, false);

	t->Active = ds->Active;
	t->PowerKeep = ds->PowerKeep;
	Copy(t->HashedPassword, ds->HashedPassword, sizeof(t->HashedPassword));
	t->AuthType = ds->AuthType;
	Copy(t->AuthPassword, ds->AuthPassword, sizeof(t->AuthPassword));
	t->ServiceType = ds->ServiceType;
	t->DontCheckCert = WideGetDontCheckCert(ds->Wide);
	t->SaveLogFile = ds->SaveLogFile;
	UniStrCpy(t->BluetoothDir, sizeof(t->BluetoothDir), ds->BluetoothDir);
	t->UseAdvancedSecurity = ds->UseAdvancedSecurity;
	t->SaveEventLog = ds->SaveEventLog;
	t->DisableShare = ds->DisableShare;
	UniStrCpy(t->AdminUsername, sizeof(t->AdminUsername), ds->AdminUsername);

	t->EnableOtp = ds->EnableOtp;
	StrCpy(t->OtpEmail, sizeof(t->OtpEmail), ds->OtpEmail);

	t->EnableInspection = ds->EnableInspection;
	t->EnableMacCheck = ds->EnableMacCheck;

	StrCpy(t->MacAddressList, sizeof(t->MacAddressList), ds->MacAddressList);

	StrCpy(t->EmergencyOtp, sizeof(t->EmergencyOtp), ds->EmergencyOtp);

	t->RdpEnableGroupKeeper = ds->RdpEnableGroupKeeper;
	UniStrCpy(t->RdpGroupKeepUserName, sizeof(t->RdpGroupKeepUserName), ds->RdpGroupKeepUserName);
	t->RdpEnableOptimizer = ds->RdpEnableOptimizer;
	StrCpy(t->RdpStopServicesList, sizeof(t->RdpStopServicesList), ds->RdpStopServicesList);

	t->EnableDebugLog = ds->EnableDebugLog;

	t->ShowWatermark = ds->ShowWatermark;
	UniStrCpy(t->WatermarkStr, sizeof(t->WatermarkStr), ds->WatermarkStr);

	t->EnableWoLTarget = ds->EnableWoLTarget;
	t->EnableWoLTrigger = ds->EnableWoLTrigger;

#ifdef	OS_WIN32
	t->ProcessWatcherAlways = MsGetProcessWatcherAlwaysFlag(ds->ProcessWatcher);
	t->ProcessWatcherEnabled = !MsGetProcessWatcherDisabledFlag(ds->ProcessWatcher);
#endif	// OS_WIN32

	StrCpy(t->RegistrationPassword, sizeof(t->RegistrationPassword), ds->Wide->RegistrationPassword);
	StrCpy(t->RegistrationEmail, sizeof(t->RegistrationEmail), ds->Wide->RegistrationEmail);

	return ERR_NO_ERROR;
}

// Accept プロシージャ
void DsAcceptProc(THREAD* thread, SOCKIO* sock, void* param)
{
	DS* ds;
	UINT64 now;
	// 引数チェック
	if (thread == NULL || sock == NULL || param == NULL)
	{
		return;
	}

	ds = (DS*)param;

	DsDebugLog(ds, "DsAcceptProc", "CommitId = %s", ULTRA_COMMIT_ID);

	Debug("Tunnel Accepted.\n");

	Lock(ds->SessionIncDecLock);
	{
		bool beyond_threshold = false;
		UINT num_current_sessions = Inc(ds->CurrentNumSessions);
		if (num_current_sessions == 1)
		{
			// 前回の最後のセッションが切断されてからしばらく経過した最初のセッションかどうか判定
			now = Tick64();
			if (ds->LastSessionDisconnectedTick == 0)
			{
				beyond_threshold = true;
			}

			if (ds->LastSessionDisconnectedTick != 0 && now > ds->LastSessionDisconnectedTick)
			{
				if ((now - ds->LastSessionDisconnectedTick) >= DS_SESSION_INC_DEC_THRESHOLD)
				{
					beyond_threshold = true;
				}
			}
		}

		DsDebugLog(ds, "DsAcceptProc", "num_current_sessions = %u, beyond_threshold = %u", num_current_sessions, beyond_threshold);

		if (beyond_threshold)
		{
			// 初回の接続であるか、または、前回のすべてのセッションが切断されてから随分時間
			// が経過した後のセッションである場合は、ワンタイムチケットを消去する。

			Debug("beyond_threshold = 1\n");

			Rand(ds->SmartCardTicket, SHA1_SIZE);
			DsGenerateNewOtp(ds->OtpTicket, sizeof(ds->OtpTicket), 128);
			DsGenerateNewOtp(ds->InspectionTicket, sizeof(ds->InspectionTicket), 48);
		}
	}
	Unlock(ds->SessionIncDecLock);

	DsServerMain(ds, sock);

	Debug("Tunnel Disconnected.\n");

	Lock(ds->SessionIncDecLock);
	{
		ds->LastSessionDisconnectedTick = Tick64();
		UINT num_current_sessions = Dec(ds->CurrentNumSessions);
		DsDebugLog(ds, "DsAcceptProc", "num_current_sessions = %u", num_current_sessions);
	}
	Unlock(ds->SessionIncDecLock);
}

// RPC 接続
UINT DtcConnect(char *password, RPC **rpc)
{
#ifdef	OS_WIN32
	SOCK *s;
	PACK *p;
	UINT ret;
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (password == NULL)
	{
		password = "";
	}
	if (rpc == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	s = Connect("localhost", DS_RPC_PORT);
	if (s == NULL)
	{
		return ERR_DESK_RPC_CONNECT_FAILED;
	}

	SetTimeout(s, 5000);

	p = RecvPack(s);

	if (p == NULL)
	{
		ReleaseSock(s);
		return ERR_DESK_RPC_PROTOCOL_ERROR;
	}
	else
	{
		// バージョンチェック
		wchar_t adminname[MAX_PATH];
		UINT build = PackGetInt(p, "Build");
		UINT ver = PackGetInt(p, DS_RPC_VER_SIGNATURE_STR);

		Zero(adminname, sizeof(adminname));
		PackGetUniStr(p, "AdminUsername", adminname, sizeof(adminname));

		FreePack(p);
		if (build == 0 || ver == 0)
		{
			ReleaseSock(s);
			return ERR_DESK_RPC_PROTOCOL_ERROR;
		}

		if (build != DESK_BUILD || ver != DESK_VERSION)
		{
			ReleaseSock(s);
			return ERR_DESK_VERSION_DIFF;
		}

		if (UniIsEmptyStr(adminname) == false && UniStrCmpi(adminname, MsGetUserNameW()) != 0)
		{
			// 管理者ユーザー名が異なる
			ReleaseSock(s);
			return ERR_DESK_DIFF_ADMIN;
		}
	}

	SetTimeout(s, INFINITE);

	p = NewPack();
	if (StrLen(password) == 0)
	{
		Zero(hash, sizeof(hash));
	}
	else
	{
		HashSha1(hash, password, StrLen(password));
	}

	PackAddData(p, "HashedPassword", hash, SHA1_SIZE);
	SendPack(s, p);
	FreePack(p);

	p = RecvPack(s);
	if (p == NULL)
	{
		ReleaseSock(s);
		return ERR_DESK_RPC_PROTOCOL_ERROR;
	}

	ret = GetErrorFromPack(p);
	FreePack(p);

	if (ret != ERR_NO_ERROR)
	{
		ReleaseSock(s);
		return ret;
	}

	*rpc = StartRpcClient(s, NULL);

	ReleaseSock(s);

	return ERR_NO_ERROR;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// RPC 処理メインプロシージャ
void DsRpcMain(DS *ds, SOCK *s)
{
#ifdef	OS_WIN32
	PACK *p;
	bool ret;
	UCHAR hashed_password[SHA1_SIZE];
	RPC *rpc;
	// 引数チェック
	if (ds == NULL || s == NULL)
	{
		return;
	}

	// バージョン情報等を送信
	p = NewPack();
	PackAddInt(p, DS_RPC_VER_SIGNATURE_STR, DESK_VERSION);
	PackAddBool(p, "IsUserMode", ds->IsUserMode);
	PackAddStr(p, "ExePath", MsGetExeFileName());
	PackAddStr(p, "ExeDir", MsGetExeDirName());
	PackAddStr(p, "UserName", MsGetUserNameEx());
	PackAddUniStr(p, "ExePathW", MsGetExeFileNameW());
	PackAddUniStr(p, "ExeDirW", MsGetExeDirNameW());
	PackAddUniStr(p, "UserNameW", MsGetUserNameExW());
	PackAddUniStr(p, "AdminUsername", ds->AdminUsername);
	PackAddBool(p, "ForceDisableShare", ds->ForceDisableShare);
	PackAddInt(p, "Build", DESK_BUILD);
	ret = SendPack(s, p);
	FreePack(p);
	if (ret == false)
	{
		return;
	}

	// 設定パスワードを確認
	p = RecvPack(s);
	if (p == NULL)
	{
		return;
	}
	if (PackGetBool(p, "Exit") && ds->IsUserMode)
	{
		// ユーザーモードで停止命令を受けた
		FreePack(p);
		MsStopUserModeFromService();
		return;
	}
	Zero(hashed_password, sizeof(hashed_password));
	PackGetData2(p, "HashedPassword", hashed_password, sizeof(hashed_password));
	FreePack(p);

	if (IsZero(ds->HashedPassword, sizeof(ds->HashedPassword)) == false &&
		Cmp(ds->HashedPassword, hashed_password, SHA1_SIZE) != 0)
	{
		// パスワードが不正
		p = PackError(ERR_ACCESS_DENIED);
		SendPack(s, p);
		FreePack(p);
		return;
	}

	// 認証成功
	p = PackError(ERR_NO_ERROR);
	SendPack(s, p);
	FreePack(p);

	ds->NumConfigures++;

	DsSaveConfig(ds);

	// RPC の開始
	rpc = StartRpcServer(s, DsRpcServer, ds);
	RpcServer(rpc);
	RpcFree(rpc);

	DsSaveConfig(ds);
#endif  // OS_WIN32
}

// リスナースレッド
void DsRpcListenerThread(THREAD *thread, void *param)
{
	TCP_ACCEPTED_PARAM *accepted_param;
	LISTENER *r;
	SOCK *s;
	DS *ds;
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
	ds = (DS *)r->ThreadParam;
	AddSockThread(ds->SockThreadList, s, thread);
	NoticeThreadInit(thread);

	Debug("RPC Accepted.\n");

	DsRpcMain(ds, s);
	SleepThread(100);

	DelSockThread(ds->SockThreadList, s);
	ReleaseSock(s);
	ReleaseListener(r);
}

// RPC ポートが動作しているかどうか確認する
bool DsCheckServiceRpcPort()
{
	return DsCheckServiceRpcPortEx(NULL);
}
bool DsCheckServiceRpcPortEx(bool *bad_protocol)
{
	UINT ret;
	DS_INFO info;

	ret = DsGetServiceInfo(&info);

	if (ret == ERR_NO_ERROR)
	{
		return true;
	}
	else if (ret == ERR_PROTOCOL_ERROR)
	{
		if (bad_protocol != NULL)
		{
			*bad_protocol = true;
		}
	}
	else
	{
		if (bad_protocol != NULL)
		{
			*bad_protocol = false;
		}
	}

	return false;
}

// ユーザーモードサービスを停止する
void DsStopUsermodeService()
{
	SOCK *s;
	PACK *p;
	UINT ret = ERR_NO_ERROR;

	s = ConnectEx("localhost", DS_RPC_PORT, 500);
	if (s == NULL)
	{
		return;
	}

	SetTimeout(s, 5000);

	p = RecvPack(s);

	FreePack(p);

	p = NewPack();
	PackAddBool(p, "Exit", true);

	SendPack(s, p);

	FreePack(p);

	SleepThread(100);

	Disconnect(s);
	ReleaseSock(s);
}

// サービスの情報を取得する
UINT DsGetServiceInfo(DS_INFO *info)
{
	SOCK *s;
	PACK *p;
	UINT ret = ERR_NO_ERROR;
	// 引数チェック
	if (info == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Zero(info, sizeof(DS_INFO));

	s = ConnectEx("localhost", DS_RPC_PORT, 500);
	if (s == NULL)
	{
		return ERR_DESK_RPC_CONNECT_FAILED;
	}

	SetTimeout(s, 5000);

	p = RecvPack(s);

	if (p == NULL)
	{
		ret = ERR_DESK_RPC_PROTOCOL_ERROR;
	}
	else
	{
		PackGetStr(p, "ExeDir", info->ExeDir, sizeof(info->ExeDir));
		PackGetStr(p, "ExePath", info->ExePath, sizeof(info->ExePath));
		PackGetStr(p, "UserName", info->UserName, sizeof(info->UserName));
		PackGetUniStr(p, "ExeDirW", info->ExeDirW, sizeof(info->ExeDirW));
		PackGetUniStr(p, "ExePathW", info->ExePathW, sizeof(info->ExePathW));
		PackGetUniStr(p, "UserNameW", info->UserNameW, sizeof(info->UserNameW));
		if (UniIsEmptyStr(info->ExeDirW))
		{
			StrToUni(info->ExeDirW, sizeof(info->ExeDirW), info->ExeDir);
		}
		if (UniIsEmptyStr(info->ExePathW))
		{
			StrToUni(info->ExePathW, sizeof(info->ExePathW), info->ExePath);
		}
		if (UniIsEmptyStr(info->UserNameW))
		{
			StrToUni(info->UserNameW, sizeof(info->UserNameW), info->UserName);
		}
		info->Version = PackGetInt(p, DS_RPC_VER_SIGNATURE_STR);
		info->IsUserMode = PackGetBool(p, "IsUserMode");
		info->Build = PackGetInt(p, "Build");
		info->ForceDisableShare = PackGetBool(p, "ForceDisableShare");

		if (info->Version == 0)
		{
			ret = ERR_DESK_RPC_PROTOCOL_ERROR;
		}

		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// デフォルト設定に戻す
void DsInitDefaultConfig(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	// デフォルトで Debug Log を有効にする
	ds->EnableDebugLog = true;

	// ユーザー認証無し
	ds->AuthType = DESK_AUTH_NONE;

	// パスワード無し
	Zero(ds->HashedPassword, SHA1_SIZE);

	// 電源維持機能を有効
	ds->PowerKeep = true;

	// ログファイル保存を有効
	ds->SaveLogFile = true;

	// アクティブ
	ds->Active = true;

#ifdef OS_WIN32
	if (ds->IsUserMode)
	{
		// ユーザーモードの場合は URDP を使用する
		ds->ServiceType = DESK_SERVICE_VNC;

		if (false) // 2020/4/18 折角実装したが、いったんキャンセル。
			// 一般ユーザー権限しかないユーザーは Remote Desktop Users グループに
			// 入っていない可能性が高いので、RDP で接続しても意味
			// がない。
		{
			// 2020/4/17 ユーザーモードであっても、RDP ポートが開いていて利用可能
			// であれば DESK_SERVICE_RDP にする
			if (MsIsRemoteDesktopAvailable())
			{
				if (MsIsRemoteDesktopCanEnableByRegistory())
				{
					if (MsEnableRemoteDesktop())
					{
						if (MsIsRemoteDesktopEnabled())
						{
							// リモートデスクトップが有効になったようだぞ
							// ポートチェックして、有効なようならこれをデフォルトで
							// 使う
							if (MsCheckLocalhostRemoteDesktopPort())
							{
								ds->ServiceType = DESK_SERVICE_RDP;
							}
						}
					}
				}
			}
		}
	}
#endif // OS_WIN32

	ds->RdpEnableGroupKeeper = true;
	ds->RdpEnableOptimizer = true;

#ifdef OS_WIN32
	// プロセスウォッチャー
	MsSetProcessWatcherAlwaysFlag(ds->ProcessWatcher, false);
	MsSetProcessWatcherDisabledFlag(ds->ProcessWatcher, false);
#endif // OS_WIN32

	if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
	{
		// LGWAN 版では初期状態ではプロキシ設定をいじって未接続にしてしまう
		INTERNET_SETTING setting = CLEAN;
		setting.ProxyType = PROXY_NO_CONNECT;
		WideSetInternetSetting(ds->Wide, &setting);
	}

	UniStrCpy(ds->WatermarkStr, sizeof(ds->WatermarkStr), _UU("DU_FELONY_STR1"));

	WideSetDontCheckCert(ds->Wide, false);

	DsNormalizeConfig(ds, true);
}

// 設定の正規化
void DsNormalizeConfig(DS *ds, bool change_rdp_status)
{
#ifdef	OS_WIN32
	DS_POLICY_BODY pol;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	if (change_rdp_status)
	{
		if (MsIsRemoteDesktopAvailable() == false)
		{
			// OS がリモートデスクトップをサポートしていない場合は URDP を使用する
			ds->ServiceType = DESK_SERVICE_VNC;
		}

		if (ds->IsUserMode == false)
		{
			// ただしサービスモードの場合は必ず RDP を使用する
			// 例: Windows XP Home Edition などでもここに到達する可能性はある
			//     が、そもそもインストーラの時点で弾かれるべきである
			ds->ServiceType = DESK_SERVICE_RDP;
		}

		if (ds->ServiceType == DESK_SERVICE_RDP)
		{
			// リモートデスクトップを有効にしておく
			MsEnableRemoteDesktop();
		}
	}

	Lock(ds->ConfigLock);
	{
		if (IsEmptyStr(ds->OtpEmail))
		{
			// OTP メールアドレス未設定の場合は EnableOtp を false にする
			ds->EnableOtp = false;
		}

		NormalizeMacAddressListStr(ds->MacAddressList, sizeof(ds->MacAddressList), ds->MacAddressList);

		if (DsGetPolicy(ds, &pol))
		{
			// ポリシーサーバーから設定が配信されている
			if (pol.EnforceInspection)
			{
				ds->EnableInspection = true;
			}
			else if (pol.DisableInspection)
			{
				ds->EnableInspection = false;
			}

			if (pol.EnforceMacCheck)
			{
				ds->EnableMacCheck = true;
			}
			else if (pol.DisableMacCheck)
			{
				ds->EnableMacCheck = false;
			}

			if (pol.EnforceWatermark)
			{
				ds->ShowWatermark = true;

				if (UniIsEmptyStr(pol.WatermarkMessage) == false)
				{
					UniStrCpy(ds->WatermarkStr, sizeof(ds->WatermarkStr), pol.WatermarkMessage);
				}
			}
			else if (pol.DisableWatermark)
			{
				ds->ShowWatermark = false;
			}

			if (pol.DisableOtp)
			{
				ds->EnableOtp = false;
			}

			if (pol.EnforceProcessWatcher)
			{
				MsSetProcessWatcherDisabledFlag(ds->ProcessWatcher, false);
			}

			if (pol.EnforceProcessWatcherAlways)
			{
				MsSetProcessWatcherAlwaysFlag(ds->ProcessWatcher, true);
			}

			if (pol.EnforceOtp)
			{
				if (IsEmptyStr(ds->OtpEmail) == false)
				{
					ds->EnableOtp = true;
				}
			}
		}
		else
		{
			// ポリシーサーバーから設定が配信されていない
			if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
			{
				// 強いセキュリティパッチ適用モード
				ds->EnableInspection = true;
				ds->EnableMacCheck = true;
				ds->ShowWatermark = true;
			}
		}

		if (StrLen(ds->EmergencyOtp) < DS_EMERGENCY_OTP_LENGTH)
		{
			DsGenerateNewOtp(ds->EmergencyOtp, sizeof(ds->EmergencyOtp), DS_EMERGENCY_OTP_LENGTH);
		}

		if (UniIsEmptyStr(ds->WatermarkStr))
		{
			UniStrCpy(ds->WatermarkStr, sizeof(ds->WatermarkStr), _UU("DU_FELONY_STR1"));
		}
	}
	Unlock(ds->ConfigLock);

#endif  // OS_WIN32
}

// 設定の読み込み
bool DsLoadConfig(DS *ds)
{
	FOLDER *root;
	bool ret;
	// 引数チェック
	if (ds == NULL)
	{
		return false;
	}

	ds->CfgRw = NewCfgRwEx(&root, DS_CONFIG_FILENAME, true);

	if (root == NULL)
	{
		return false;
	}

	// 設定の読み込みメイン
	ret = DsLoadConfigMain(ds, root);

	CfgDeleteFolder(root);

	DsNormalizeConfig(ds, true);

	return ret;
}

// 設定の書き込み
void DsSaveConfig(DS *ds)
{
	FOLDER *root;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	root = DsSaveConfigMain(ds);
	SaveCfgRw(ds->CfgRw, root);
	CfgDeleteFolder(root);

	if (ds->Wide != NULL)
	{
		ds->Wide->ServerMask64 = DsCalcMask(ds);
	}
}

// 設定の読み込みメイン
bool DsLoadConfigMain(DS *ds, FOLDER *root)
{
	INTERNET_SETTING setting;
	FOLDER *f;
	FOLDER *syslog_f = NULL;
	bool process_watcher_enabled = false;
	bool process_watcher_always = false;
	// 引数チェック
	if (ds == NULL || root == NULL)
	{
		return false;
	}

	ds->PowerKeep = CfgGetBool(root, "PowerKeep");
	ds->SaveLogFile = CfgGetBool(root, "DontSaveLogFile") ? false : true;

	ds->RdpEnableGroupKeeper = CfgGetBoolEx(root, "RdpEnableGroupKeeper", true);
	CfgGetUniStr(root, "RdpGroupKeepUserName", ds->RdpGroupKeepUserName, sizeof(ds->RdpGroupKeepUserName));
	ds->RdpEnableOptimizer = CfgGetBoolEx(root, "RdpEnableOptimizer", true);
	CfgGetStr(root, "RdpStopServicesList", ds->RdpStopServicesList, sizeof(ds->RdpStopServicesList));

	ds->EnableDebugLog = CfgGetBoolEx(root, "EnableDebugLog", true);

	ds->ShowWatermark = CfgGetBool(root, "ShowWatermark");
	CfgGetUniStr(root, "WatermarkStr", ds->WatermarkStr, sizeof(ds->WatermarkStr));
	if (UniIsEmptyStr(ds->WatermarkStr))
	{
		UniStrCpy(ds->WatermarkStr, sizeof(ds->WatermarkStr), _UU("DU_FELONY_STR1"));
	}

	Zero(ds->HashedPassword, SHA1_SIZE);
	CfgGetByte(root, "HashedPassword", ds->HashedPassword, SHA1_SIZE);

	ds->AuthType = CfgGetInt(root, "AuthType");

	ds->EnableWoLTarget = CfgGetBool(root, "EnableWoLTarget");
	ds->EnableWoLTrigger = CfgGetBool(root, "EnableWoLTrigger");

#ifdef OS_WIN32
	process_watcher_enabled = CfgGetBoolEx(root, "ProcessWatcherEnabled", true);
	process_watcher_always = CfgGetBoolEx(root, "ProcessWatcherAlways", false);

	MsSetProcessWatcherAlwaysFlag(ds->ProcessWatcher, process_watcher_always);
	MsSetProcessWatcherDisabledFlag(ds->ProcessWatcher, !process_watcher_enabled);
#endif // OS_WIN32

	switch (ds->AuthType)
	{
	case DESK_AUTH_PASSWORD:
		Zero(ds->AuthPassword, SHA1_SIZE);
		CfgGetByte(root, "AuthPassword", ds->AuthPassword, SHA1_SIZE);
		break;
	}

	ds->ServiceType = CfgGetInt(root, "ServiceType");

	WideSetDontCheckCert(ds->Wide, CfgGetBool(root, "DontCheckCert"));

	ds->Active = CfgGetBool(root, "Active");

	CfgGetUniStr(root, "BluetoothDir", ds->BluetoothDir, sizeof(ds->BluetoothDir));

	ds->IsConfigured = CfgGetBool(root, "IsConfigured");

#ifndef	DESK_DISABLE_NEW_FEATURE
	ds->UseAdvancedSecurity = CfgGetBool(root, "UseAdvancedSecurity");

	ds->SaveEventLog = CfgGetBool(root, "SaveEventLog");
#endif	// DESK_DISABLE_NEW_FEATURE

	ds->DisableShare = CfgGetBool(root, "DisableShare");

	CfgGetUniStr(root, "AdminUsername", ds->AdminUsername, sizeof(ds->AdminUsername));

	ds->NumConfigures = CfgGetInt(root, "NumConfigures");

	ds->EnableOtp = CfgGetBool(root, "EnableOtp");
	CfgGetStr(root, "OtpEmail", ds->OtpEmail, sizeof(ds->OtpEmail));

	// 2020/10/3 保存不要!?
	//CfgGetStr(root, "RegistrationPassword", ds->Wide->RegistrationPassword, sizeof(ds->Wide->RegistrationPassword));
	CfgGetStr(root, "RegistrationEmail", ds->Wide->RegistrationEmail, sizeof(ds->Wide->RegistrationEmail));

	ds->EnableInspection = CfgGetBool(root, "EnableInspection");
	ds->EnableMacCheck = CfgGetBool(root, "EnableMacCheck");
	CfgGetStr(root, "MacAddressList", ds->MacAddressList, sizeof(ds->MacAddressList));

	CfgGetStr(root, "EmergencyOtp", ds->EmergencyOtp, sizeof(ds->EmergencyOtp));

	f = CfgGetFolder(root, "ProxySetting");

	if (f != NULL)
	{
		DsLoadInternetSetting(f, &setting);

		WideSetInternetSetting(ds->Wide, &setting);
	}

	f = CfgGetFolder(root, DS_CFG_SECURITY_SETTINGS);
	if (f != NULL)
	{
		HUB *h;
		bool b = false;

#ifdef	DESK_DISABLE_NEW_FEATURE
		b = true;
#endif	// DESK_DISABLE_NEW_FEATURE

		h = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		if (h != NULL)
		{
			DelHub(ds->Server->Cedar, h);
			ReleaseHub(h);
		}

		SiLoadHubCfg(ds->Server, f, CEDAR_DESKVPN_HUBNAME);
	}

#ifndef	DESK_DISABLE_NEW_FEATURE
	// syslog
	syslog_f = CfgGetFolder(f, "SyslogSettings");
	if (syslog_f != NULL)
	{
		SYSLOG_SETTING set;

		Zero(&set, sizeof(set));

		set.SaveType = CfgGetInt(syslog_f, "SaveType");
		CfgGetStr(syslog_f, "HostName", set.Hostname, sizeof(set.Hostname));
		set.Port = CfgGetInt(syslog_f, "Port");
		if (set.Port == 0)
		{
			set.Port = SYSLOG_PORT;
		}

		SiSetSysLogSetting(ds->Server, &set);
	}
	else
#endif	// DESK_DISABLE_NEW_FEATURE
	{
		SYSLOG_SETTING set;

		Zero(&set, sizeof(set));

		set.SaveType = 0;
		set.Port = SYSLOG_PORT;

		SiSetSysLogSetting(ds->Server, &set);
	}

	return true;
}

// 設定の書き込みメイン
FOLDER *DsSaveConfigMain(DS *ds)
{
	FOLDER *root;
	FOLDER *f = NULL;
	INTERNET_SETTING setting;
	HUB *h = NULL;
	FOLDER *syslog_f = NULL;
	// 引数チェック
	if (ds == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	Lock(ds->ConfigLock);
	{
		CfgAddBool(root, "PowerKeep", ds->PowerKeep);

		CfgAddBool(root, "DontSaveLogFile", ds->SaveLogFile ? false : true);

#ifndef	DESK_DISABLE_NEW_FEATURE
		CfgAddBool(root, "SaveEventLog", ds->SaveEventLog);
#endif	// DESK_DISABLE_NEW_FEATURE

		CfgAddBool(root, "DisableShare", ds->DisableShare);

		CfgAddBool(root, "EnableOtp", ds->EnableOtp);

		CfgAddStr(root, "OtpEmail", ds->OtpEmail);

#ifdef OS_WIN32
		CfgAddBool(root, "ProcessWatcherAlways", MsGetProcessWatcherAlwaysFlag(ds->ProcessWatcher));
		CfgAddBool(root, "ProcessWatcherEnabled", !MsGetProcessWatcherDisabledFlag(ds->ProcessWatcher));
#endif // OS_WIN32

		// 2020/10/3 保存不要!?
		//if (IsEmptyStr(ds->Wide->RegistrationPassword) == false)
		//{
		//	CfgAddStr(root, "RegistrationPassword", ds->Wide->RegistrationPassword);
		//}

		if (IsEmptyStr(ds->Wide->RegistrationEmail) == false)
		{
			CfgAddStr(root, "RegistrationEmail", ds->Wide->RegistrationEmail);
		}

		CfgAddStr(root, "EmergencyOtp", ds->EmergencyOtp);

		CfgAddBool(root, "EnableInspection", ds->EnableInspection);
		CfgAddBool(root, "EnableMacCheck", ds->EnableMacCheck);
		CfgAddStr(root, "MacAddressList", ds->MacAddressList);

		CfgAddBool(root, "IsConfigured", ds->IsConfigured);

		CfgAddBool(root, "Active", ds->Active);

		CfgAddBool(root, "RdpEnableGroupKeeper", ds->RdpEnableGroupKeeper);
		CfgAddUniStr(root, "RdpGroupKeepUserName", ds->RdpGroupKeepUserName);
		CfgAddBool(root, "RdpEnableOptimizer", ds->RdpEnableOptimizer);
		CfgAddStr(root, "RdpStopServicesList", ds->RdpStopServicesList);

		CfgAddBool(root, "EnableDebugLog", ds->EnableDebugLog);

		CfgAddBool(root, "ShowWatermark", ds->ShowWatermark);
		CfgAddUniStr(root, "WatermarkStr", ds->WatermarkStr);

		CfgAddUniStr(root, "AdminUsername", ds->AdminUsername);

		CfgAddBool(root, "EnableWoLTarget", ds->EnableWoLTarget);
		CfgAddBool(root, "EnableWoLTrigger", ds->EnableWoLTrigger);

		if (ds->SupportBluetooth)
		{
			CfgAddUniStr(root, "BluetoothDir", ds->BluetoothDir);
		}

#ifndef	DESK_DISABLE_NEW_FEATURE
		CfgAddBool(root, "UseAdvancedSecurity", ds->UseAdvancedSecurity);
#endif	// DESK_DISABLE_NEW_FEATURE

		if (IsZero(ds->HashedPassword, SHA1_SIZE) == false)
		{
			CfgAddByte(root, "HashedPassword", ds->HashedPassword, SHA1_SIZE);
		}

		CfgAddInt(root, "AuthType", ds->AuthType);

		CfgAddInt(root, "NumConfigures", ds->NumConfigures);

		switch (ds->AuthType)
		{
		case DESK_AUTH_PASSWORD:
			CfgAddByte(root, "AuthPassword", ds->AuthPassword, SHA1_SIZE);
			break;
		}

		CfgAddInt(root, "ServiceType", ds->ServiceType);

#if	0
		f = CfgCreateFolder(root, "CommSetting");
		DsSaveConfigCommSetting(f);
#endif

		WideGetInternetSetting(ds->Wide, &setting);

		CfgAddBool(root, "DontCheckCert", WideGetDontCheckCert(ds->Wide));

		f = CfgCreateFolder(root, "ProxySetting");

		DsSaveInternetSetting(f, &setting);

		f = CfgCreateFolder(root, DS_CFG_SECURITY_SETTINGS);

		h = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		if (h != NULL)
		{
			Lock(h->lock);
			{
				bool b = false;
#ifdef	DESK_DISABLE_NEW_FEATURE
				b = true;
#endif	// DESK_DISABLE_NEW_FEATURE
				SiWriteHubCfg(f, h);
			}
			Unlock(h->lock);

			ReleaseHub(h);
		}

		// syslog
#ifndef	DESK_DISABLE_NEW_FEATURE
		syslog_f = CfgCreateFolder(f, "SyslogSettings");
		if (syslog_f != NULL)
		{
			SYSLOG_SETTING set;

			SiGetSysLogSetting(ds->Server, &set);

			CfgAddInt(syslog_f, "SaveType", set.SaveType);
			CfgAddStr(syslog_f, "HostName", set.Hostname);
			CfgAddInt(syslog_f, "Port", set.Port);
		}
#endif	// DESK_DISABLE_NEW_FEATURE
	}
	Unlock(ds->ConfigLock);

	return root;
}

// INTERNET_SETTING の読み込み
void DsLoadInternetSetting(FOLDER *f, INTERNET_SETTING *setting)
{
	BUF *b;
	// 引数チェック
	if (f == NULL || setting == NULL)
	{
		return;
	}

	Zero(setting, sizeof(INTERNET_SETTING));

	setting->ProxyType = CfgGetInt(f, "ProxyType");

	CfgGetStr(f, "ProxyHostName", setting->ProxyHostName, sizeof(setting->ProxyHostName));
	setting->ProxyPort = CfgGetInt(f, "ProxyPort");
	CfgGetStr(f, "ProxyUsername", setting->ProxyUsername, sizeof(setting->ProxyUsername));
	b = CfgGetBuf(f, "ProxyPassword");

	if (b != NULL)
	{
		DsDecryptPassword(b, setting->ProxyPassword, sizeof(setting->ProxyPassword));
	}

	CfgGetStr(f, "ProxyUserAgent", setting->ProxyUserAgent, sizeof(setting->ProxyUserAgent));
	if (IsEmptyStr(setting->ProxyUserAgent))
	{
		StrCpy(setting->ProxyUserAgent, sizeof(setting->ProxyUserAgent), DEFAULT_PROXY_USER_AGENT);
	}

	FreeBuf(b);
}

// INTERNET_SETTING の保存
void DsSaveInternetSetting(FOLDER *f, INTERNET_SETTING *setting)
{
	BUF *b;
	// 引数チェック
	if (f == NULL || setting == NULL)
	{
		return;
	}

	CfgAddInt(f, "ProxyType", setting->ProxyType);

	CfgAddStr(f, "ProxyHostName", setting->ProxyHostName);
	CfgAddInt(f, "ProxyPort", setting->ProxyPort);
	CfgAddStr(f, "ProxyUsername", setting->ProxyUsername);
	b = DsEncryptPassword(setting->ProxyPassword);
	CfgAddBuf(f, "ProxyPassword", b);
	CfgAddStr(f, "ProxyUserAgent", setting->ProxyUserAgent);
	FreeBuf(b);
}

// パスワードの解読
void DsDecryptPassword(BUF *b, char *str, UINT str_size)
{
	UINT size;
	char *tmp;
	CRYPT *c;
	// 引数チェック
	if (b == NULL || str == NULL)
	{
		return;
	}

	size = b->Size;
	tmp = ZeroMalloc(size + 1);

	c = NewCrypt(DS_PASSWORD_ENCRYPT_KEY, StrLen(DS_PASSWORD_ENCRYPT_KEY));
	Encrypt(c, tmp, b->Buf, size);
	FreeCrypt(c);

	StrCpy(str, str_size, tmp);
	Free(tmp);
}

// パスワードの暗号化
BUF *DsEncryptPassword(char *password)
{
	CRYPT *c;
	BUF *b;
	// 引数チェック
	if (password == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, password, StrLen(password));

	c = NewCrypt(DS_PASSWORD_ENCRYPT_KEY, StrLen(DS_PASSWORD_ENCRYPT_KEY));
	Encrypt(c, b->Buf, b->Buf, b->Size);
	FreeCrypt(c);

	return b;
}

// CommSetting の保存
void DsSaveConfigCommSetting(FOLDER *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	CfgAddBool(f, "UDP_Hole_Punching", true);
	CfgAddBool(f, "UDP_DNS_Packet_Capsule", true);
	CfgAddBool(f, "TCP_NAT_Reverse", true);
	CfgAddBool(f, "Univ_Plug_and_Play", true);
	CfgAddBool(f, "Univ_Plug_and_Play_2", true);
	CfgAddBool(f, "TCP_NAT_Auto_PortMapping", true);
	CfgAddBool(f, "TCP_NAT_Full_Cone", true);
	CfgAddBool(f, "TCP_NAT_Restricted_Cone", true);
	CfgAddBool(f, "TCP_NAT_Port_Restricted_Cone", true);
	CfgAddBool(f, "TCP_NAT_Symmetric", true);
	CfgAddBool(f, "TCP_MS_Messenger_Capsule", true);
}

// 設定解放
void DsFreeConfig(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	// 設定保存
	DsSaveConfig(ds);

	// 解放
	FreeCfgRw(ds->CfgRw);
}

// レジストリから RDP のポート番号を取得する
UINT DsGetRdpPortFromRegistry()
{
#ifdef	OS_WIN32
	return MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "PortNumber");
#else   // OS_WIN32
	return 0;
#endif  // OS_WIN32
}

// 設定初期化
void DsInitConfig(DS *ds)
{
	UINT port;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	// 設定読み込み
	if (DsLoadConfig(ds) == false)
	{
		// デフォルト設定
		DsInitDefaultConfig(ds);
	}

	ds->RdpPort = DS_RDP_PORT;

	port = DsGetRdpPortFromRegistry();

	if (port != 0)
	{
		ds->RdpPort = port;
	}

	// 設定保存
	DsSaveConfig(ds);

	DsUpdatePowerKeepSetting(ds);
}

// 次回起動時に証明書をリセット
void DsResetCertOnNextBoot()
{
	PACK *p;

	p = NewPack();
	WideWriteSecurePack(DESK_SECURE_PACK_NAME, p);
	FreePack(p);
}

// 証明書のリセット用プロシージャ
void DsResetCertProc(WIDE *wide, void *param)
{
	X *cert = NULL;
	K *key = NULL;
	// 引数チェック
	if (wide == NULL)
	{
		return;
	}

	Debug("--------- Proxy Connect ---------\n");

	// 新規作成
	WideServerGenerateCertAndKey(&cert, &key);

	// ディスクに保存
	DsWriteSecureCertAndKey(cert, key);

	// WideServer に書き込んで再接続
	WideServerSetCertAndKeyEx(wide, cert, key, true);

	FreeX(cert);
	FreeK(key);
}

// マスク値の計算
UINT64 DsCalcMask(DS *ds)
{
#ifdef	OS_WIN32
	UINT64 ret = 0;
	DS_POLICY_BODY pol = {0};
	// 引数チェック
	if (ds == NULL)
	{
		return 0;
	}

	ret |= DS_MASK_SUPPORT_WOL_TRIGGER;

	if (ds->IsUserMode)
	{
		ret |= DS_MASK_USER_MODE;
	}
	else
	{
		ret |= DS_MASK_SERVICE_MODE;
	}

	if (ds->EnableOtp)
	{
		ret |= DS_MASK_OTP_ENABLED;
	}

	if (DsGetPolicy(ds, &pol))
	{
		ret |= DS_MASK_POLICY_ENFORCED;
	}

	if (ds->ServiceType == DESK_SERVICE_RDP)
	{
		// RDP モードの場合、Terminal Service (複数セッションログオン) が利用可能か
		// どうか取得する
		if (MsIsTerminalServiceMultiUserInstalled() == false)
		{
			ret |= DS_MASK_WIN_RDP_NORMAL;
		}
		else
		{
			ret |= DS_MASK_WIN_RDP_TS;
		}
	}
	else
	{
		ret |= DS_MASK_URDP_CLIENT;
	}

	return ret;
#else   // OS_WIN32
	return 0;
#endif  // OS_WIN32
}

// 共有機能が無効化されているかどうか調べる
bool DsIsShareDisabled(DS *ds)
{
	DS_POLICY_BODY pol;
	// 引数チェック
	if (ds == NULL)
	{
		return false;
	}

	if (ds->ForceDisableShare)
	{
		return true;
	}

	if (ds->DisableShare)
	{
		return true;
	}

	if (DsGetPolicy(ds, &pol))
	{
		if (pol.DisableShare)
		{
			return true;
		}
	}

	return false;
}

// Caps を取得
UINT DsGetCaps(DS *ds)
{
	UINT ret = 0;
	// 引数チェック
	if (ds == NULL)
	{
		return 0;
	}

	return ret;
}

// 指定された EXE ファイル名に共有を無効化するシグネチャが書いてあるかどうか検査する
bool DsCheckShareDisableSignature(wchar_t *exe)
{
#ifdef	OS_WIN32
	IO *io;
	UINT size;
	bool ret = false;
	if (exe == NULL)
	{
		exe = MsGetExeFileNameW();
	}

	io = FileOpenW(exe, false);
	if (io == NULL)
	{
		return false;
	}

	size = FileSize(io);
	if (size >= 10000)
	{
		UCHAR tmp[DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE];
		Zero(tmp, sizeof(tmp));

		FileSeek(io, FILE_BEGIN, size - DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE);

		FileRead(io, tmp, DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE);

		if (Cmp(tmp, DESK_EXE_DISABLE_SHARE_SIGNATURE, DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE) == 0)
		{
			ret = true;
		}
	}

	FileClose(io);

	return ret;
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}

#ifdef	OS_WIN32
// プロセスウォッチャーのコールバック
void DsWin32ProcessWatcherCallback(bool start, MS_PROCESS* process, void* param)
{
	DS* ds = NULL;
	if (param == NULL)
	{
		return;
	}

	ds = (DS*)param;

	DsLogEx(ds, DS_LOG_INFO, start ? "DSL_PROCESS_START" : "DSL_PROCESS_END",
		process->ProcessId,
		process->ExeFilenameW,
		process->Is64BitProcess ? _UU("DS_POLICY_YES") : _UU("DS_POLICY_NO"),
		process->CommandLineW);
}
#endif //OS_WIN32

// シン・テレワークシステム サーバーの初期化
DS *NewDs(bool is_user_mode, bool force_share_disable)
{
#ifdef	OS_WIN32
	DS *ds;
	X *cert;
	K *key;
	char server_hash[128] = {0};

	// ポリシーサーバーから設定が配信されていない
	if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
	{
		// 強いセキュリティパッチ適用モード
		force_share_disable = true;
	}

	InitWinUi(_UU("DS_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	ds = ZeroMalloc(sizeof(DS));

	ds->GuacdFileLock = NewLock();

	ds->Lockout = NewLockout();

	ds->ConfigLock = NewLock();

	ds->CurrentNumSessions = NewCounter();
	ds->CurrentNumRDPSessions = NewCounter();

	ds->SessionIncDecLock = NewLock();
	ds->RDPSessionIncDecLock = NewLock();

	Rand(ds->SmartCardTicket, SHA1_SIZE);

	DsGenerateNewOtp(ds->OtpTicket, sizeof(ds->OtpTicket), 128);

	DsGenerateNewOtp(ds->InspectionTicket, sizeof(ds->InspectionTicket), 48);

	ds->History = NewList(NULL);

	ds->ForceDisableShare = force_share_disable;

	ds->Server = SiNewServer(false);

	//ds->SupportBluetooth = IsFileExists(DC_BLUETOOTH_FLAG_FILENAME);

	if (MsIsNt() && MsIsAdmin())
	{
		// イベントログ機能は Windows NT でかつ Admin の場合のみサポート
		ds->SupportEventLog = true;
	}

	DsInitRadiusCacheList(ds);

	ds->Log = NewLog(DS_LOG_DIRNAME, "desk", LOG_SWITCH_DAY);
	ds->Log->Flush = true;

	if (ds->SupportEventLog)
	{
		ds->EventLog = MsInitEventLog(DS_EVENTLOG_SOURCE_NAME);
	}

	// プロセスウォッチャーの作成
	ds->ProcessWatcher = MsNewProcessWatcher(DsWin32ProcessWatcherCallback, ds);

	ds->ClientList = NewList(NULL);

	DsLog(ds, "DSL_LINE");

	ds->UrdpServer = DeskInitUrdpServer();
	ds->IsUserMode = is_user_mode;
	ds->PowerKeepLock = NewLock();
	ds->SockThreadList = NewSockThreadList();

	if (ds->IsUserMode)
	{
		if (Win32IsWindow10OrLater())
		{
			ds->IsLocked = MsNewIsLocked();
		}
	}

	ds->Cedar = NewCedar(NULL, NULL);
	DsUpdateTaskIcon(ds);

	ds->Wide = WideServerStartEx(DESK_SVC_NAME, DsAcceptProc, ds, _GETLANG(),
		DsResetCertProc, ds);

	WideServerSuppressAutoReconnect(ds->Wide, true);

	// 証明書の初期化
	if (DsReadSecureCertAndKey(&cert, &key) == false)
	{
		// 証明書の新規作成
		WideServerGenerateCertAndKey(&cert, &key);
		DsWriteSecureCertAndKey(cert, key);
	}

	// RPC の開始
	ds->RpcListener = NewListenerEx2(ds->Cedar, LISTENER_TCP,
		DS_RPC_PORT, DsRpcListenerThread, ds, true);

	// 設定初期化
	DsInitConfig(ds);

	// 生き残っている Guacd のゾンビ・プロセスを強制終了する
	DsKillAllZombineGuacdProcesses(ds);

	ds->Wide->SendMacList = ds->EnableWoLTarget;

	// WIDE 基礎モジュールに対して証明書が設定され、接続が開始される
	WideServerSetCertAndKey(ds->Wide, cert, key);

	WideServerSuppressAutoReconnect(ds->Wide, false);

	FreeX(cert);
	FreeK(key);

	WideServerGetHash(ds->Wide, server_hash, sizeof(server_hash));

	// ポリシー規制クライアント開始
	ds->PolicyClient = DsNewPolicyClient(ds, server_hash);

	DsLog(ds, "DSL_START1", DESK_VERSION / 100, DESK_VERSION % 100, DESK_BUILD);
	DsLog(ds, "DSL_START2", ds->Cedar->BuildInfo);
	DsLog(ds, "DSL_START3");

	DsLog(ds, "DSL_START4");

	return ds;
#else   // OS_WIN32
	return NULL;
#endif  // OS_WIN32
}

// PowerKeep の設定に変更があった
void DsUpdatePowerKeepSetting(DS *ds)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	Lock(ds->PowerKeepLock);
	{
		if (ds->PowerKeepHandle != NULL)
		{
			MsNoSleepEnd(ds->PowerKeepHandle);
			ds->PowerKeepHandle = NULL;
		}

		if (ds->PowerKeep)
		{
			ds->PowerKeepHandle = MsNoSleepStart(ds->ServiceType == DESK_SERVICE_VNC);
		}
	}
	Unlock(ds->PowerKeepLock);
#endif  // OS_WIN32
}

// 履歴のカウント
UINT DsGetHistoryCount(DS *ds, IP *ip)
{
	UINT i, ret;
	// 引数チェック
	if (ds == NULL || ip == NULL)
	{
		return 0;
	}

	ret = 0;

	DsFlushHistory(ds);

	for (i = 0;i < LIST_NUM(ds->History);i++)
	{
		DS_HISTORY *h = LIST_DATA(ds->History, i);

		if (Cmp(&h->Ip, ip, sizeof(IP)) == 0)
		{
			ret++;
		}
	}

	return ret;
}

// 古い履歴の削除
void DsFlushHistory(DS *ds)
{
	UINT i;
	UINT64 now = Tick64();
	LIST *o;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(ds->History);i++)
	{
		DS_HISTORY *h = LIST_DATA(ds->History, i);

		if (h->Expires <= now)
		{
			Add(o, h);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		DS_HISTORY *h = LIST_DATA(o, i);

		Delete(ds->History, h);

		Free(h);
	}

	ReleaseList(o);
}

// 履歴追加
void DsAddHistory(DS *ds, IP *ip)
{
	DS_HISTORY *h;
	// 引数チェック
	if (ds == NULL || ip == NULL)
	{
		return;
	}

	h = ZeroMalloc(sizeof(DS_HISTORY));

	h->Expires = Tick64() + (UINT64)DS_HISTORY_EXPIRES;
	Copy(&h->Ip, ip, sizeof(IP));

	Add(ds->History, h);

	DsFlushHistory(ds);
}

// 履歴ロック
void DsLockHistory(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	LockList(ds->History);
}

// 履歴ロック解除
void DsUnlockHistory(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	UnlockList(ds->History);
}

// シン・テレワークシステム サーバーの解放
void FreeDs(DS *ds)
{
#ifdef	OS_WIN32
	UINT i;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	DsLog(ds, "DSL_END1");

	// 生き残っている Guacd のゾンビ・プロセスを強制終了する
	DsKillAllZombineGuacdProcesses(ds);

	// RPC の停止
	StopAllListener(ds->Cedar);
	StopListener(ds->RpcListener);
	ReleaseListener(ds->RpcListener);

	FreeSockThreadList(ds->SockThreadList);

	// 設定解放
	DsFreeConfig(ds);

	WideServerStop(ds->Wide);

	ReleaseCedar(ds->Cedar);

	if (ds->PowerKeepHandle != NULL)
	{
		MsNoSleepEnd(ds->PowerKeepHandle);
		ds->PowerKeepHandle = NULL;
	}
	DeleteLock(ds->PowerKeepLock);

	DeskFreeUrdpServer(ds->UrdpServer);

	DsLog(ds, "DSL_END2");
	DsLog(ds, "DSL_LINE");

	ReleaseList(ds->ClientList);

	SiReleaseServer(ds->Server);
	ds->Server = NULL;

	MsFreeProcessWatcher(ds->ProcessWatcher);

	DsFreePolicyClient(ds->PolicyClient);

	MsFreeEventLog(ds->EventLog);

	FreeLog(ds->Log);

	for (i = 0;i < LIST_NUM(ds->History);i++)
	{
		DS_HISTORY *h = LIST_DATA(ds->History, i);

		Free(h);
	}

	ReleaseList(ds->History);

	DsFreeRadiusCacheList(ds);

	if (ds->IsLocked != NULL)
	{
		MsFreeIsLocked(ds->IsLocked);
	}

	DeleteCounter(ds->CurrentNumSessions);
	DeleteCounter(ds->CurrentNumRDPSessions);

	DeleteLock(ds->SessionIncDecLock);
	DeleteLock(ds->RDPSessionIncDecLock);

	DeleteLock(ds->ConfigLock);

	FreeLockout(ds->Lockout);

	DeleteLock(ds->GuacdFileLock);

	Free(ds);

	FreeWinUi();
#endif  // OS_WIN32
}

// 証明書の読み込み
bool DsReadSecureCertAndKey(X **cert, K **key)
{
	PACK *p;
	bool ret = false;
	// 引数チェック
	if (cert == NULL || key == NULL)
	{
		return false;
	}

	p = WideReadSecurePack(DESK_SECURE_PACK_NAME);
	if (p == NULL)
	{
		return false;
	}

	*cert = PackGetX(p, "Cert");
	*key = PackGetK(p, "Key");

	if (*cert != NULL && *key != NULL)
	{
		ret = true;
	}
	else
	{
		FreeX(*cert);
		FreeK(*key);
	}

	FreePack(p);

	return ret;
}

// 証明書の書き込み
void DsWriteSecureCertAndKey(X *cert, K *key)
{
	PACK *p;

	// 引数チェック
	if (cert == NULL || key == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddX(p, "Cert", cert);
	PackAddK(p, "Key", key);
	WideWriteSecurePack(DESK_SECURE_PACK_NAME, p);
	FreePack(p);
}


// 十分なメモリがあるかチェックする
wchar_t* DsCheckSufficientMemoryGetMsg()
{
	wchar_t* ret = NULL;

#ifdef OS_WIN32

	MEMINFO info = CLEAN;

	GetMemInfo(&info);

	if (info.TotalPhys != 0)
	{
		if (info.FreePhys <= 500000000ULL) // 空きメモリがおおむね 500MB 未満の場合
		{
			return _UU("DS_MEMORY_MSG_1");
		}
		else if (info.TotalPhys <= 5000000000ULL) // 合計メモリがおおむね 4GB 以下の場合
		{
			return _UU("DS_MEMORY_MSG_2");
		}
	}

#endif // OS_WIN32

	return ret;
}
