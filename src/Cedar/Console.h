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


// Console.h
// Header of Console.c

#ifndef	CONSOLE_H
#define	CONSOLE_H

// Constant
#define	MAX_PROMPT_STRSIZE			65536
#define	WIN32_DEFAULT_CONSOLE_WIDTH	100

// Types of console
#define	CONSOLE_LOCAL				0	// Local console
#define	CONSOLE_CSV					1	// CSV output mode

// Parameters completion prompt function
typedef wchar_t *(PROMPT_PROC)(CONSOLE *c, void *param);

// Parameter validation prompt function
typedef bool (EVAL_PROC)(CONSOLE *c, wchar_t *str, void *param);

// Definition of the parameter item
struct PARAM
{
	char *Name;					// Parameter name
	PROMPT_PROC *PromptProc;	// Prompt function that automatically invoked if the parameter is not specified
								//  (This is not called in the case of NULL)
	void *PromptProcParam;		// Any pointers to pass to the prompt function
	EVAL_PROC *EvalProc;		// Parameter string validation function
	void *EvalProcParam;		// Any pointers to be passed to the validation function
	char *Tmp;					// Temporary variable
};

// Parameter value of the internal data
struct PARAM_VALUE
{
	char *Name;					// Name
	char *StrValue;				// String value
	wchar_t *UniStrValue;		// Unicode string value
	UINT IntValue;				// Integer value
};

// Console service structure
struct CONSOLE
{
	UINT ConsoleType;										// Type of console
	UINT RetCode;											// The last exit code
	void *Param;											// Data of any
	void (*Free)(CONSOLE *c);								// Release function
	wchar_t *(*ReadLine)(CONSOLE *c, wchar_t *prompt, bool nofile);		// Function to read one line
	char *(*ReadPassword)(CONSOLE *c, wchar_t *prompt);		// Function to read the password
	bool (*Write)(CONSOLE *c, wchar_t *str);				// Function to write a string
	UINT (*GetWidth)(CONSOLE *c);							// Get the width of the screen
	bool ProgrammingMode;									// Programming Mode
	LOCK *OutputLock;										// Output Lock
};

// Local console parameters
struct LOCAL_CONSOLE_PARAM
{
	IO *InFile;		// Input file
	BUF *InBuf;		// Input buffer
	IO *OutFile;	// Output file
	UINT Win32_OldConsoleWidth;	// Previous console size
};

// Command procedure
typedef UINT (COMMAND_PROC)(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);

// Definition of command
struct CMD
{
	char *Name;				// Command name
	COMMAND_PROC *Proc;		// Procedure function
};

// Evaluate the minimum / maximum value of the parameter
struct CMD_EVAL_MIN_MAX
{
	char *StrName;
	UINT MinValue, MaxValue;
};


// Function prototype
wchar_t *Prompt(wchar_t *prompt_str);
char *PromptA(wchar_t *prompt_str);
bool PasswordPrompt(char *password, UINT size);
void *SetConsoleRaw();
void RestoreConsole(void *p);
wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list);
wchar_t *ParseCommand(wchar_t *str, wchar_t *name);
TOKEN_LIST *GetCommandNameList(wchar_t *str);
char *ParseCommandA(wchar_t *str, char *name);
LIST *NewParamValueList();
int CmpParamValue(void *p1, void *p2);
void FreeParamValueList(LIST *o);
PARAM_VALUE *FindParamValue(LIST *o, char *name);
char *GetParamStr(LIST *o, char *name);
wchar_t *GetParamUniStr(LIST *o, char *name);
UINT GetParamInt(LIST *o, char *name);
bool GetParamYes(LIST *o, char *name);
LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param);
bool IsNameInRealName(char *input_name, char *real_name);
void GetOmissionName(char *dst, UINT size, char *src);
bool IsOmissionName(char *input_name, char *real_name);
TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list);
bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param);
UINT GetConsoleWidth(CONSOLE *c);
bool DispatchNextCmd(CONSOLE *c, char *prompt, CMD cmd[], UINT num_cmd, void *param);
bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param);
void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space);
UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width);
UINT GetNextWordWidth(wchar_t *str);
bool IsWordChar(wchar_t c);
void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help);
void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description);
bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param);
wchar_t *CmdPrompt(CONSOLE *c, void *param);
bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalInt1(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param);
void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list);
int CompareCandidateStr(void *p1, void *p2);
bool IsHelpStr(char *str);

CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile);
void ConsoleLocalFree(CONSOLE *c);
wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile);
char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt);
bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str);
void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf);
wchar_t *ConsoleReadNextFromInFile(CONSOLE *c);
UINT ConsoleLocalGetWidth(CONSOLE *c);


#endif	// CONSOLE_H



