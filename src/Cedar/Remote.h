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


// Remote.h
// Header of Remote.c

#ifndef	REMOTE_H
#define	REMOTE_H

// RPC execution function
typedef PACK *(RPC_DISPATCHER)(RPC *r, char *function_name, PACK *p);

// RPC object
struct RPC
{
	SOCK *Sock;						// Socket
	bool ServerMode;				// Server mode
	RPC_DISPATCHER *Dispatch;		// Execution routine
	void *Param;					// Parameters
	bool ServerAdminMode;			// Server management mode
	char HubName[MAX_HUBNAME_LEN + 1];	// Managing HUB name
	char Name[MAX_SIZE];			// RPC session name
	LOCK *Lock;						// Lock
	bool IsVpnServer;				// Whether VPN Server management RPC
	CLIENT_OPTION VpnServerClientOption;
	char VpnServerHubName[MAX_HUBNAME_LEN + 1];
	UCHAR VpnServerHashedPassword[SHA1_SIZE];
	char VpnServerClientName[MAX_PATH];
};

#define STATMAN_DEFAULT_SEND_INTERVAL		(30 * 60 * 1000)
#define STATMAN_DEFAULT_SAVE_INTERVAL		(5 * 60 * 1000)

#define STATMAN_DEFAULT_FILENAME			L"@Statistics.db"

#define STATMAN_DEFAULT_SYSTEMNAME			"default_system"
#define STATMAN_DEFAULT_LOGNAME				"default_stat"

typedef void (STATMAN_POLL_CALLBACK)(STATMAN *stat, void *param, PACK *ret);

struct STATMAN_CONFIG
{
	UINT PostInterval;
	UINT SaveInterval;
	char PostUrl[MAX_PATH];
	wchar_t StatFilename[MAX_PATH];
	char SystemName[MAX_PATH];
	char LogName[MAX_PATH];
	void* Param;
	STATMAN_POLL_CALLBACK* Callback;
};

// Stat manager
struct STATMAN
{
	volatile bool Halt;

	STATMAN_CONFIG Config;

	EVENT* HaltEvent1;
	EVENT* HaltEvent2;

	THREAD* SaveThread;
	THREAD* PostThread;

	CFG_RW* CfgRw;
	FOLDER* Root;

	LOCK* Lock;

	IP CurrentLocalIp;
};

// Function prototype
RPC *StartRpcClient(SOCK *s, void *param);
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param);
PACK *RpcCallInternal(RPC *r, PACK *p);
PACK *RpcCall(RPC *r, char *function_name, PACK *p);
void RpcServer(RPC *r);
bool RpcRecvNextCall(RPC *r);
PACK *CallRpcDispatcher(RPC *r, PACK *p);
void RpcError(PACK *p, UINT err);
bool RpcIsOk(PACK *p);
UINT RpcGetError(PACK *p);
void EndRpc(RPC *rpc);
void RpcFree(RPC *rpc);
void RpcFreeEx(RPC *rpc, bool no_disconnect);

STATMAN* NewStatMan(STATMAN_CONFIG* config);
void FreeStatMan(STATMAN* m);
void StopStatMan(STATMAN* m);
void StatManPostThreadProc(THREAD* thread, void* param);
void StatManSaveThreadProc(THREAD* thread, void* param);
bool StatManPostMain(STATMAN* m);

void StatManNormalizeAndPoll(STATMAN* m);

void StatManAddReport(STATMAN* m, PACK* p);
void StatManReportInt64(STATMAN* m, char *name, UINT64 value);

UINT HttpPostData(char* url, UINT timeout, char* post_str, bool* cancel);


#endif	// REMOTE_H

