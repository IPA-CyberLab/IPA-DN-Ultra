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


// Wpc.h
// Header of Wpc.c

#ifndef	WPC_H
#define	WPC_H

// Constant
#define WPC_HTTP_POST_NAME			"POST"		// POST
#define WPC_HTTP_GET_NAME			"GET"		// GET
#define WPC_USER_AGENT				DEFAULT_USER_AGENT	// User Agent
#define WPC_TIMEOUT					(15 * 1000)	// Time-out
#define WPC_RECV_BUF_SIZE			64000		// Receive buffer size
#define WPC_DATA_ENTRY_SIZE			4			// Data entry size
#define WPC_MAX_HTTP_DATASIZE		(134217728)	// Maximum HTTP data size

// Connection parameters
struct WPC_CONNECT
{
	char HostName[MAX_HOST_NAME_LEN + 1];		// Host name
	UINT Port;									// Port number
	UINT ProxyType;								// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// Proxy server host name
	UINT ProxyPort;								// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// Proxy server password
	char ProxyUserAgent[MAX_SIZE + 1];			// Proxy server user agent
	bool UseCompress;							// Use of compression
	bool DontCheckCert;							// Do not check the certificate
};

// Internet connection settings
struct INTERNET_SETTING
{
	UINT ProxyType;								// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// Proxy server host name
	UINT ProxyPort;								// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// Proxy server password
	char ProxyUserAgent[MAX_SIZE + 1];			// Proxy server user agent
};

// URL
struct URL_DATA
{
	bool Secure;							// Whether HTTPS
	char HostName[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
	char HeaderHostName[MAX_HOST_NAME_LEN + 16];	// Host name on the header
	char Method[32];						// Method
	char Target[MAX_SIZE * 3];				// Target
	char Referer[MAX_SIZE * 3];				// Referer
	char AdditionalHeaderName[128];			// Additional header name
	char AdditionalHeaderValue[MAX_SIZE];	// Additional header value
	char SniString[MAX_SIZE];				// SNI String
};

// WPC entry
struct WPC_ENTRY
{
	char EntryName[WPC_DATA_ENTRY_SIZE];		// Entry name
	void *Data;									// Data
	UINT Size;									// Data size
};

// WPC packet
struct WPC_PACKET
{
	PACK *Pack;								// Pack (data body)
	UCHAR Hash[SHA1_SIZE];					// Data hash
	//X *Cert;								// Certificate
	//UCHAR Sign[128];						// Digital signature
	UCHAR HostKey[SHA1_SIZE];
	UCHAR HostSecret[SHA1_SIZE];
};

struct CERT_SERVER_CLIENT_PARAM
{
	char CertListSrcUrl[MAX_PATH];
	char CertKeySrcUrl[MAX_PATH];
	char BasicAuthUsername[MAX_PATH];
	char BasicAuthPassword[MAX_PATH];
	char ManagerLogName[MAX_PATH];
	wchar_t DestDir[MAX_PATH];
};

struct CERT_SERVER_CLIENT
{
	CERT_SERVER_CLIENT_PARAM Param;
	THREAD* Thread;
	volatile bool Halt;
	EVENT* HaltEvent;
	WT* Wt;
};

#define MAX_CERT_SERVER_CLIENT_DOWNLOAD_SIZE	(256 * 1024)

#define CERT_SERVER_CLIENT_INTERVAL_NORMAL			(1 * 60 * 60 * 1000)
#define CERT_SERVER_CLIENT_INTERVAL_RETRY_INITIAL	(15 * 1000)
#define CERT_SERVER_CLIENT_INTERVAL_RETRY_MAX		(5 * 60 * 1000)



// Reception callback
typedef bool (WPC_RECV_CALLBACK)(void *param, UINT total_size, UINT current_size, BUF *recv_buf);

// Function prototype
void EncodeSafe64(char *dst, void *src, UINT src_size);
UINT DecodeSafe64(void *dst, char *src, UINT src_strlen);
void Base64ToSafe64(char *str);
void Safe64ToBase64(char *str);
bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer);
void CreateUrl(char *url, UINT url_size, URL_DATA *data);
void GetSystemInternetSetting(INTERNET_SETTING *setting);
bool GetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type);
BUF *HttpRequest(URL_DATA *data, INTERNET_SETTING *setting,
				 UINT timeout_connect, UINT timeout_comm,
				 UINT *error_code, bool check_ssl_trust, char *post_data,
				 WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash);
BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size);
BUF *HttpRequestEx2(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size, char *header_name, char *header_value);
BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value);
BUF *HttpRequestEx4(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value, WT *wt);
BUF *HttpRequestEx5(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value, WT *wt, bool global_ip_only, bool dest_private_ip_only);
BUF *HttpRequestEx6(URL_DATA *data, INTERNET_SETTING *setting,
	UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust, char *post_data,
	WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
	bool *cancel, UINT max_recv_size, char *header_name, char *header_value, WT *wt, bool global_ip_only, bool dest_private_ip_only,
	BUF *result_buf_if_error, bool *is_server_error);
SOCK *WpcSockConnect(WPC_CONNECT *param, UINT *error_code, UINT timeout);
SOCK *WpcSockConnectEx(WPC_CONNECT *param, UINT *error_code, UINT timeout, bool *cancel);
SOCK *WpcSockConnect2(char *hostname, UINT port, INTERNET_SETTING *t, UINT *error_code, UINT timeout);
INTERNET_SETTING *GetNullInternetSetting();
void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size);
void WpcAddDataEntryBin(BUF *b, char *name, void *data, UINT size);
void WpcFillEntryName(char *dst, char *name);
LIST *WpcParseDataEntry(BUF *b);
void WpcFreeDataEntryList(LIST *o);
WPC_ENTRY *WpcFindDataEntry(LIST *o, char *name);
WPC_ENTRY* WpcFindDataEntryEx(LIST* o, char* name, UINT index);
BUF *WpcDataEntryToBuf(WPC_ENTRY *e);
BUF *WpcGeneratePacket(PACK *pack, UCHAR *host_key, UCHAR *host_secret);
bool WpcParsePacket(WPC_PACKET *packet, BUF *buf);
void WpcFreePacket(WPC_PACKET *packet);
PACK *WpcCall(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
			  char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash);
PACK *WpcCallEx(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
			  char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, bool *cancel, UINT max_recv_size,
			  char *additional_header_name, char *additional_header_value);
PACK *WpcCallEx2(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
				char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, UINT num_hashes, bool *cancel, UINT max_recv_size,
				char *additional_header_name, char *additional_header_value, char *sni_string);
bool IsProxyPrivateIp(INTERNET_SETTING *s);
CERTS_AND_KEY* DownloadCertsAndKeyFromCertServer(CERT_SERVER_CLIENT_PARAM* param, bool* cancel);
BUF* HttpDownload(char* url, char *basic_auth_username, char *basic_auth_password,
	INTERNET_SETTING* setting, UINT timeout_connect, UINT timeout_comm,
	UINT* error_code, bool check_ssl_trust,
	void* sha1_cert_hash, UINT num_hashes,
	bool* cancel, UINT max_recv_size);
void GenerateHttpBasicAuthHeaderValue(char* dst, UINT dst_size, char* username, char* password);
CERTS_AND_KEY* DownloadCertsAndKeyFromCertServer(CERT_SERVER_CLIENT_PARAM* param, bool* cancel);
void FreeCertServerClient(CERT_SERVER_CLIENT* c);
CERT_SERVER_CLIENT* NewCertServerClient(WT *wt, CERT_SERVER_CLIENT_PARAM* param);
void CertServerClientThreadProc(THREAD* thread, void* param);



#endif	// WPC_H


