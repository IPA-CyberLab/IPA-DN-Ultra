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


// Cfg.h
// Header of Cfg.c

#ifndef	CFG_H
#define	CFG_H

// Macro
//#define	CHECK_CFG_NAME_EXISTS			// Check duplication of the existing name

#define	SAVE_BINARY_FILE_NAME_SWITCH	L"@save_binary"

// Constants
#define	TAG_DECLARE			"declare"
#define	TAG_STRING			"string"
#define	TAG_INT				"uint"
#define	TAG_INT64			"uint64"
#define	TAG_BOOL			"bool"
#define	TAG_BYTE			"byte"
#define	TAG_TRUE			"true"
#define	TAG_FALSE			"false"
#define	TAG_END				"end"
#define	TAG_ROOT			"root"

#define	TAG_CPYRIGHT		"\xef\xbb\xbf# Software Configuration File\r\n# ---------------------------\r\n# \r\n# You may edit this file when the server program is not running.\r\n# \r\n# In prior to edit this file manually by your text editor,\r\n# shutdown the server background service.\r\n# Otherwise, all changes will be lost.\r\n# \r\n"
#define	TAG_BINARY			"SEVPN_DB"

// Data type
#define	ITEM_TYPE_INT		1		// int
#define	ITEM_TYPE_INT64		2		// int64
#define	ITEM_TYPE_BYTE		3		// byte
#define	ITEM_TYPE_STRING	4		// string
#define	ITEM_TYPE_BOOL		5		// bool

// Folder
struct FOLDER
{
	char *Name;				// Folder name
	LIST *Items;			// List of items
	LIST *Folders;			// Subfolder
	struct FOLDER *Parent;	// Parent Folder
};

// Item
struct ITEM
{
	char *Name;				// Item Name
	UINT Type;				// Data type
	void *Buf;				// Data
	UINT size;				// Data size
	FOLDER *Parent;			// Parent Folder
};

// Configuration file reader and writer
struct CFG_RW
{
	LOCK *lock;				// Lock
	char *FileName;			// File name (ANSI)
	wchar_t *FileNameW;		// File name (Unicode)
	IO *Io;					// IO
	UCHAR LashHash[SHA1_SIZE];	// Hash value which is written last
	bool DontBackup;		// Do not use the backup
	wchar_t LastSavedDateStr[MAX_SIZE];	// Date and time string that last saved
};

typedef bool (*ENUM_FOLDER)(FOLDER *f, void *param);
typedef bool (*ENUM_ITEM)(ITEM *t, void *param);

// Parameters for the enumeration
struct CFG_ENUM_PARAM
{
	BUF *b;
	FOLDER *f;
	UINT depth;
};

int CmpItemName(void *p1, void *p2);
int CmpFolderName(void *p1, void *p2);
ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size);
void CfgDeleteFolder(FOLDER *f);
FOLDER *CfgCreateFolder(FOLDER *parent, char *name);
void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param);
TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f);
TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f);
void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param);
FOLDER *CfgFindFolder(FOLDER *parent, char *name);
ITEM *CfgFindItem(FOLDER *parent, char *name);
ITEM *CfgAddInt(FOLDER *f, char *name, UINT i);
ITEM *CfgAddBool(FOLDER *f, char *name, bool b);
ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i);
ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size);
ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b);
ITEM *CfgAddStr(FOLDER *f, char *name, char *str);
ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str);
FOLDER *CfgGetFolder(FOLDER *parent, char *name);
UINT CfgGetInt(FOLDER *f, char *name);
bool CfgGetBool(FOLDER *f, char *name);
bool CfgGetBoolEx(FOLDER *f, char *name, bool default_value);
UINT64 CfgGetInt64(FOLDER *f, char *name);
UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size);
BUF *CfgGetBuf(FOLDER *f, char *name);
bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size);
bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size);
bool CfgIsItem(FOLDER *f, char *name);
bool CfgIsFolder(FOLDER *f, char *name);
void CfgTest();
void CfgTest2(FOLDER *f, UINT n);
char *CfgEscape(char *name);
bool CfgCheckCharForName(char c);
char *CfgUnescape(char *str);
BUF *CfgFolderToBuf(FOLDER *f, bool textmode);
BUF *CfgFolderToBufEx(FOLDER *f, bool textmode, bool no_banner);
BUF *CfgFolderToBufText(FOLDER *f);
BUF *CfgFolderToBufTextEx(FOLDER *f, bool no_banner);
BUF *CfgFolderToBufBin(FOLDER *f);
void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth);
void CfgOutputFolderBin(BUF *b, FOLDER *f);
void CfgAddLine(BUF *b, char *str, UINT depth);
void CfgAddDeclare(BUF *b, char *name, UINT depth);
void CfgAddEnd(BUF *b, UINT depth);
void CfgAddData(BUF *b, UINT type, char *name, char *data, char *sub, UINT depth);
UINT CfgStrToType(char *str);
char *CfgTypeToStr(UINT type);
void CfgAddItemText(BUF *b, ITEM *t, UINT depth);
bool CfgEnumFolderProc(FOLDER *f, void *param);
bool CfgEnumItemProc(ITEM *t, void *param);
FOLDER *CfgBufTextToFolder(BUF *b);
FOLDER *CfgBufBinToFolder(BUF *b);
void CfgReadNextFolderBin(BUF *b, FOLDER *parent);
char *CfgReadNextLine(BUF *b);
bool CfgReadNextTextBUF(BUF *b, FOLDER *current);
void CfgSave(FOLDER *f, char *name);
void CfgSaveW(FOLDER *f, wchar_t *name);
bool CfgSaveEx(CFG_RW *rw, FOLDER *f, char *name);
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name);
bool CfgSaveExW2(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size);
bool CfgSaveExW3(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size, bool write_binary);
FOLDER *CfgRead(char *name);
FOLDER *CfgReadW(wchar_t *name);
FOLDER *CfgCreateRoot();
void CfgTest();
void CfgTest2(FOLDER *f, UINT n);
CFG_RW *NewCfgRw(FOLDER **root, char *cfg_name);
CFG_RW *NewCfgRwW(FOLDER **root, wchar_t *cfg_name);
CFG_RW *NewCfgRwEx(FOLDER **root, char *cfg_name, bool dont_backup);
CFG_RW *NewCfgRwExW(FOLDER **root, wchar_t *cfg_name, bool dont_backup);
CFG_RW *NewCfgRwEx2W(FOLDER **root, wchar_t *cfg_name, bool dont_backup, wchar_t *template_name);
CFG_RW *NewCfgRwEx2A(FOLDER **root, char *cfg_name_a, bool dont_backup, char *template_name_a);
UINT SaveCfgRw(CFG_RW *rw, FOLDER *f);
UINT SaveCfgRwEx(CFG_RW *rw, FOLDER *f, UINT revision_number);
UINT SaveCfgRwEx2(CFG_RW* rw, FOLDER* f, UINT revision_number, bool write_binary);
void FreeCfgRw(CFG_RW *rw);
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip);
UINT CfgGetIp32(FOLDER *f, char *name);
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
bool FileCopy(char *src, char *dst);
bool FileCopyW(wchar_t *src, wchar_t *dst);
bool FileCopyExW(wchar_t *src, wchar_t *dst, bool read_lock);
void BackupCfgWEx(CFG_RW *rw, FOLDER *f, wchar_t *original, UINT revision_number);
void CfgDeleteItem(ITEM* t);

#if	(!defined(CFG_C)) || (!defined(OS_UNIX))
bool CfgGetIp(FOLDER *f, char *name, struct IP *ip);
ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip);
#endif

#endif	// CFG_H



