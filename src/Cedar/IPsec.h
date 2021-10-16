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


// IPsec.h
// Header of IPsec.c

#ifndef	IPSEC_H
#define	IPSEC_H

//// Constants

// UDP port number
#define	IPSEC_PORT_L2TP					1701		// L2TP
#define	IPSEC_PORT_IPSEC_ISAKMP			500			// ISAKMP
#define	IPSEC_PORT_IPSEC_ESP_UDP		4500		// IPsec ESP over UDP
#define	IPSEC_PORT_IPSEC_ESP_RAW		MAKE_SPECIAL_PORT(50)	// Raw mode ESP Protocol No: 50
#define	IPSEC_PORT_IPSEC_ESP_RAW_WPF	MAKE_SPECIAL_PORT(52)	// Raw mode ESP Protocol No: 52 (WPF)
#define	IPSEC_PORT_L2TPV3_VIRTUAL		1000001		// L2TPv3 virtual port

// IP protocol number
#define	IPSEC_IP_PROTO_ETHERIP			IP_PROTO_ETHERIP	// EtherIP
#define	IPSEC_IP_PROTO_L2TPV3			IP_PROTO_L2TPV3		// L2TPv3

// WFP tag
#define	WFP_ESP_PACKET_TAG_1		0x19841117
#define	WFP_ESP_PACKET_TAG_2		0x1accafe1

// Monitoring interval of OS service
#define	IPSEC_CHECK_OS_SERVICE_INTERVAL_INITIAL	1024
#define	IPSEC_CHECK_OS_SERVICE_INTERVAL_MAX		(5 * 60 * 1000)

// Default IPsec pre-shared key
#define	IPSEC_DEFAULT_SECRET			"vpn"


//// Type

// List of services provided by IPsec server
struct IPSEC_SERVICES
{
	bool L2TP_Raw;								// Raw L2TP
	bool L2TP_IPsec;							// L2TP over IPsec
	bool EtherIP_IPsec;							// EtherIP over IPsec

	char IPsec_Secret[MAX_SIZE];				// IPsec pre-shared key
	char L2TP_DefaultHub[MAX_SIZE];				// Default Virtual HUB name for L2TP connection
};

// EtherIP key list entry
struct ETHERIP_ID
{
	char Id[MAX_SIZE];							// ID
	char HubName[MAX_HUBNAME_LEN + 1];			// Virtual HUB name
	char UserName[MAX_USERNAME_LEN + 1];		// User name
	char Password[MAX_USERNAME_LEN + 1];		// Password
};

// IPsec server
struct IPSEC_SERVER
{
	CEDAR *Cedar;
	UDPLISTENER *UdpListener;
	bool Halt;
	bool NoMoreChangeSettings;
	LOCK *LockSettings;
	IPSEC_SERVICES Services;
	L2TP_SERVER *L2TP;							// L2TP server
	IKE_SERVER *Ike;							// IKE server
	LIST *EtherIPIdList;						// EtherIP setting list
	UINT EtherIPIdListSettingVerNo;				// EtherIP setting list version number
	THREAD *OsServiceCheckThread;				// OS Service monitoring thread
	EVENT *OsServiceCheckThreadEvent;			// Event for OS Service monitoring thread
	IPSEC_WIN7 *Win7;							// Helper module for Windows Vista / 7
	bool Check_LastEnabledStatus;
	bool HostIPAddressListChanged;
	bool OsServiceStoped;
};


//// Function prototype
IPSEC_SERVER *NewIPsecServer(CEDAR *cedar);
void FreeIPsecServer(IPSEC_SERVER *s);
void IPsecServerUdpPacketRecvProc(UDPLISTENER *u, LIST *packet_list);
void IPsecServerSetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl);
void IPsecNormalizeServiceSetting(IPSEC_SERVER *s);
void IPsecServerGetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl);
void IPsecProcPacket(IPSEC_SERVER *s, UDPPACKET *p);
int CmpEtherIPId(void *p1, void *p2);
bool SearchEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id, char *id_str);
void AddEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id);
bool DeleteEtherIPId(IPSEC_SERVER *s, char *id_str);
void IPsecOsServiceCheckThread(THREAD *t, void *p);
bool IPsecCheckOsService(IPSEC_SERVER *s);
void IPSecSetDisable(bool b);


#endif	// IPSEC_H

