﻿// IPA-DN-Ultra Library Source Code
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


// DeskType.h
// PacketiX Desktop VPN 型一覧ヘッダ

#ifndef	DESKTYPE_H
#define DESKTYPE_H

// Desk.h
typedef struct URDP_SERVER URDP_SERVER;

// DS.h
typedef struct DS DS;
typedef struct DS_INFO DS_INFO;
typedef struct DS_CLIENT DS_CLIENT;
typedef struct DS_HISTORY DS_HISTORY;
typedef struct DS_RADIUS_CACHE DS_RADIUS_CACHE;
typedef struct DS_POLICY_CLIENT DS_POLICY_CLIENT;
typedef struct DS_POLICY_THREAD_CTX DS_POLICY_THREAD_CTX;
typedef struct DS_POLICY_BODY DS_POLICY_BODY;

// DC.h
typedef struct DC_INSPECT DC_INSPECT;
typedef struct DC_ADVAUTH DC_ADVAUTH;
typedef struct DC DC;
typedef struct DC_AUTH DC_AUTH;
typedef bool (DC_AUTH_CALLBACK)(DC *dc, DC_AUTH *dc_auth, void *param);
typedef struct DC_SESSION DC_SESSION;
typedef bool (DC_PASSWORD_CALLBACK)(DC_SESSION *s, char *password, UINT password_max_size);
typedef bool (DC_OTP_CALLBACK)(DC *dc, char *otp, UINT otp_max_size, DC_SESSION *param);
typedef bool (DC_INSPECT_CALLBACK)(DC *dc, DC_INSPECT *ins, DC_SESSION *param);
typedef bool (DC_ADVAUTH_CALLBACK)(DC_SESSION *s, DC_AUTH *auth);
typedef void (DC_EVENT_CALLBACK)(DC_SESSION *s, UINT event_type, void *event_param);
typedef struct DC_LISTENED_SOCK_THREAD_PARAM DC_LISTENED_SOCK_THREAD_PARAM;
typedef struct DC_BLUE DC_BLUE;

// DsRpc.h
typedef struct RPC_DS_STATUS RPC_DS_STATUS;
typedef struct RPC_PCID RPC_PCID;
typedef struct RPC_DS_CONFIG RPC_DS_CONFIG;


#endif	// DESKTYPE_H



