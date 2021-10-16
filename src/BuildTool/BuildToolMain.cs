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


using System;
using System.Threading;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Drawing2D;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using CoreUtil;

namespace BuildTool
{
	public class BuildToolMain
	{
		public static bool pause = false;

		// Main function
		public static int Main(string[] args)
		{
			string errMsg = "";

			int ret = 0;

			ret = ConsoleService.EntryPoint("BuildTool " + Env.CommandLine, "BuildTool", typeof(BuildToolMain), out errMsg);

			if (ret != 0)
			{
				Con.WriteLine("{0}: fatal error C0001: {1}", Path.GetFileNameWithoutExtension(Env.ExeFileName), errMsg);

				if (pause)
				{
					Console.Write("Press any key to exit...");
					Console.ReadKey();
				}

				Environment.Exit(1);
			}

			return ret;
		}

		// Command execution
		[ConsoleCommandMethod(
			"VPN Build Utility",
			"[/IN:infile] [/OUT:outfile] [/CSV] [/PAUSEIFERROR:yes|no] [/CMD command_line...]",
			"VPN Build Utility",
			"IN:This will specify the text file 'infile' that contains the list of commands that are automatically executed after the connection is completed. If the /IN parameter is specified, the vpncmd program will terminate automatically after the execution of all commands in the file are finished. If the file contains multiple-byte characters, the encoding must be Unicode (UTF-8). This cannot be specified together with /CMD (if /CMD is specified, /IN will be ignored).",
			"OUT:You can specify the text file 'outfile' to write all strings such as onscreen prompts, message, error and execution results. Note that if the specified file already exists, the contents of the existing file will be overwritten. Output strings will be recorded using Unicode (UTF-8) encoding.",
			"CMD:If the optional command 'command_line...' is included after /CMD, that command will be executed after the connection is complete and the vpncmd program will terminate after that. This cannot be specified together with /IN (if specified together with /IN, /IN will be ignored). Specify the /CMD parameter after all other vpncmd parameters.",
			"CSV:Enable CSV Mode.",
			"PAUSEIFERROR:Specify yes if you'd like to pause before exiting the process if there are any errors."
			)]
		public static int BuildTool(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("IN", null, null, null, null),
				new ConsoleParam("OUT", null, null, null, null),
				new ConsoleParam("CMD", null, null, null, null),
				new ConsoleParam("CSV", null, null, null, null),
				new ConsoleParam("PAUSEIFERROR", null, null, null, null),
				new ConsoleParam("DT", null, null, null, null),
			};

			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			pause = vl["PAUSEIFERROR"].BoolValue;

			string cmdline = vl["CMD"].StrValue;

			if (vl["DT"].IsEmpty == false)
			{
				//BuildSoftwareList.ListCreatedDateTime = Str.StrToDateTime(vl["DT"].StrValue);
			}

			ConsoleService cs = c;
			
			while (cs.DispatchCommand(cmdline, "BuildTool>", typeof(BuildToolCommands), null))
			{
				if (Str.IsEmptyStr(cmdline) == false)
				{
					break;
				}
			}

			return cs.RetCode;
		}
	}
}


