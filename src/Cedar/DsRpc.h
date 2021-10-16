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


// DsRpc.h
// DsRpc.c のヘッダ

struct RPC_DS_STATUS
{
	UINT Version;
	UINT Build;
	char ExePath[MAX_PATH];
	wchar_t ExePathW[MAX_PATH];
	char ExeDir[MAX_PATH];
	wchar_t ExeDirW[MAX_PATH];
	UINT LastError;
	bool IsConnected;
	char Pcid[MAX_PATH];
	char Hash[MAX_PATH];
	char System[MAX_PATH];
	UINT ServiceType;
	bool IsUserMode;
	bool Active;
	bool IsConfigured;
	UINT DsCaps;
	bool UseAdvancedSecurity;
	bool ForceDisableShare;
	bool SupportEventLog;
	UINT NumConfigures;
	UINT NumAdvancedUsers;
	char GateIP[256];
	bool MsgForServerArrived;			// 新しいメッセージが WideController から届いている
	wchar_t MsgForServer[MAX_SIZE];		// 届いているメッセージ
	wchar_t MsgForServer2[MAX_SIZE * 2];	// 届いているメッセージ (ポリシー関係)
	bool MsgForServerOnce;				// 次回から表示しない を許可
	char OtpEndWith[64];

	// ポリシー規制の状態
	bool EnforceOtp;
	bool EnforceInspection;
	bool EnforceMacCheck;
	bool EnforceWatermark;
	bool DisableInspection;
	bool DisableMacCheck;
	bool DisableWatermark;
	bool NoLocalMacAddressList;
	bool PolicyServerManagedMacAddressList;
	bool IsAdminOrSystem;
	bool EnforceProcessWatcher;
	bool EnforceProcessWatcherAlways;
};

struct RPC_PCID
{
	char Pcid[MAX_PATH];
};

struct RPC_DS_CONFIG
{
	bool Active;
	bool PowerKeep;
	bool DontCheckCert;
	UCHAR HashedPassword[SHA1_SIZE];
	bool UseAdvancedSecurity;
	UINT AuthType;
	UCHAR AuthPassword[SHA1_SIZE];
	UINT ServiceType;
	bool SaveLogFile;
	wchar_t BluetoothDir[MAX_PATH];
	bool SaveEventLog;
	bool DisableShare;
	wchar_t AdminUsername[MAX_PATH];
	bool EnableOtp;
	char OtpEmail[MAX_PATH];
	char EmergencyOtp[128];

	bool EnableInspection;
	bool EnableMacCheck;
	char MacAddressList[1024];

	bool RdpEnableGroupKeeper;
	wchar_t RdpGroupKeepUserName[MAX_PATH];
	bool RdpEnableOptimizer;
	char RdpStopServicesList[MAX_PATH];

	bool EnableDebugLog;

	bool ShowWatermark;
	wchar_t WatermarkStr[MAX_PATH];

	bool EnableWoLTarget;
	bool EnableWoLTrigger;

	bool ProcessWatcherEnabled;
	bool ProcessWatcherAlways;

	char RegistrationPassword[MAX_PATH];
	char RegistrationEmail[MAX_PATH];
};

void InInternetSetting(INTERNET_SETTING *t, PACK *p);
void OutInternetSetting(PACK *p, INTERNET_SETTING *t);
void InRpcDsStatus(RPC_DS_STATUS *t, PACK *p);
void OutRpcDsStatus(PACK *p, RPC_DS_STATUS *t);
void InRpcPcid(RPC_PCID *t, PACK *p);
void OutRpcPcid(PACK *p, RPC_PCID *t);
void InRpcDsConfig(RPC_DS_CONFIG *t, PACK *p);
void OutRpcDsConfig(PACK *p, RPC_DS_CONFIG *t);


