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


// BridgeUnix.h
// Header of BridgeUnix.c

#ifndef	BRIDGEUNIX_H
#define	BRIDGEUNIX_H

// Macro
#ifndef SOL_PACKET
#define	SOL_PACKET	263
#endif
#ifndef ifr_newname
#define ifr_newname     ifr_ifru.ifru_slave
#endif

// Constants
#define	UNIX_ETH_TMP_BUFFER_SIZE		(2000)
#define	SOLARIS_MAXDLBUF				(32768)
#define BRIDGE_MAX_QUEUE_SIZE			(4096*1500)

// ETH structure
struct ETH
{
	char *Name;					// Adapter name
	char *Title;				// Adapter title
	CANCEL *Cancel;				// Cancel object
	int IfIndex;				// Index
	int Socket;					// Socket
	UINT InitialMtu;			// Initial MTU value
	UINT CurrentMtu;			// Current MTU value
	int SocketBsdIf;			// BSD interface operation socket
	UCHAR MacAddress[6];		// MAC address

#ifdef BRIDGE_PCAP
	void *Pcap;					// Pcap descriptor
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// Pcap relay thread
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
	UINT BufSize;				// Buffer size to read the BPF (error for other)
#ifdef BRIDGE_BPF_THREAD
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// BPF relay thread
#else // BRIDGE_BPF_THREAD
	UCHAR *Buffer;				// Buffer to read the BPF
	UCHAR *Next;
	int Rest;
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF

	VLAN *Tap;					// tap
	bool Linux_IsAuxDataSupported;	// Is PACKET_AUXDATA supported

	bool IsRawIpMode;			// RAW IP mode
	SOCK *RawTcp, *RawUdp, *RawIcmp;	// RAW sockets
	bool RawIp_HasError;
	UCHAR RawIpMyMacAddr[6];
	UCHAR RawIpYourMacAddr[6];
	IP MyIP;
	IP YourIP;
	QUEUE *RawIpSendQueue;
	IP MyPhysicalIP;
	IP MyPhysicalIPForce;
	UCHAR *RawIP_TmpBuffer;
	UINT RawIP_TmpBufferSize;
};

#if defined( BRIDGE_BPF ) || defined( BRIDGE_PCAP )
struct CAPTUREBLOCK{
	UINT Size;
	UCHAR *Buf;
};
#endif // BRIDGE_BPF


// Function prototype
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedLinux();
bool IsEthSupportedSolaris();
bool IsEthSupportedPcap();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip);
TOKEN_LIST *GetEthListLinux(bool enum_normal, bool enum_rawip);
TOKEN_LIST *GetEthListSolaris();
TOKEN_LIST *GetEthListPcap();
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthLinux(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthSolaris(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthPcap(char *name, bool local, bool tapmode, char *tapaddr);
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, UINT *dst_devid, char *src_name);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
UINT EthGetPacketLinux(ETH *e, void **data);
UINT EthGetPacketSolaris(ETH *e, void **data);
UINT EthGetPacketPcap(ETH *e, void **data);
UINT EthGetPacketBpf(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);
bool EthGetInterfaceDescriptionUnix(char *name, char *str, UINT size);
bool EthIsInterfaceDescriptionSupportedUnix();

ETH *OpenEthLinuxIpRaw();
void CloseEthLinuxIpRaw(ETH *e);
UINT EthGetPacketLinuxIpRaw(ETH *e, void **data);
UINT EthGetPacketLinuxIpRawForSock(ETH *e, void **data, SOCK *s, UINT proto);
void EthPutPacketLinuxIpRaw(ETH *e, void *data, UINT size);
bool EthProcessIpPacketInnerIpRaw(ETH *e, PKT *p);
void EthSendIpPacketInnerIpRaw(ETH *e, void *data, UINT size, USHORT protocol);

#ifdef	UNIX_SOLARIS
// Function prototype for Solaris
bool DlipAttatchRequest(int fd, UINT devid);
bool DlipReceiveAck(int fd);
bool DlipPromiscuous(int fd, UINT level);
bool DlipBindRequest(int fd);
#endif	// OS_SOLARIS

int UnixEthOpenRawSocket();

#endif	// BRIDGEUNIX_H


