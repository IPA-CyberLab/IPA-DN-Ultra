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
	public static class PEUtil
	{
		public const int NumRetries = 5;
		public const int RetryIntervals = 200;
		public const string MutexName = "peutil_setmanifest_mutex";

		// Set the version of the PE header to 4 (to work in Windows 98, etc.)
		public static void SetPEVersionTo4(byte[] srcData)
		{
			int offset = 0x140 + (int)((uint)srcData[0x3c] + ((uint)srcData[0x3d] * 256)) - 0xf8;

			if (!((srcData[offset] == 0x04 || srcData[offset] == 0x05) && srcData[offset + 1] == 0x00))
			{
				throw new ApplicationException("The specified file is not PE file.");
			}

			srcData[offset] = 0x04;
		}
		public static void SetPEVersionTo4(string fileName)
		{
			FileInfo fi = new FileInfo(fileName);

			byte[] data = File.ReadAllBytes(fileName);
			SetPEVersionTo4(data);

			int i;
			for (i = 0; ; i++)
			{
				try
				{
					File.WriteAllBytes(fileName, data);
					break;
				}
				catch (Exception ex)
				{
					if (i >= (NumRetries - 1))
					{
						throw ex;
					}

					Kernel.SleepThread(RetryIntervals);
				}
			}

			File.SetCreationTime(fileName, fi.CreationTime);
			File.SetLastAccessTime(fileName, fi.LastAccessTime);
			File.SetLastWriteTime(fileName, fi.LastWriteTime);
		}

		public static void SetManifest(string exe, string manifestName)
		{
			Mutex x = new Mutex(false, MutexName);

			x.WaitOne();

			try
			{
				// Manifest file name
				string filename = Path.Combine(Paths.ManifestsDir, manifestName);
				if (File.Exists(filename) == false)
				{
					throw new FileNotFoundException(filename);
				}

				FileInfo fi = new FileInfo(exe);

				// Copy exe file to a temporary directory
				string exeTmp = IO.CreateTempFileNameByExt(".exe");
				IO.FileCopy(exe, exeTmp);

				string mtFileName = Path.Combine(Paths.MicrosoftSDKBinDir, "mt.exe");
				string mtArgs = string.Format("-nologo -manifest \"{0}\" -outputresource:\"{1}\";1", filename, exeTmp);

				Exception ex = null;

				int i;
				// Repeated 20 times in order to avoid locking the file by the anti-virus software
				for (i = 0; i < 20; i++)
				{
					try
					{
						// Execute
						Win32BuildTool.ExecCommand(mtFileName, mtArgs, false, true);
						ex = null;

						break;
					}
					catch (Exception ex2)
					{
						ex = ex2;
					}

					ThreadObj.Sleep(Secure.Rand31i() % 50);
				}

				if (ex != null)
				{
					throw new ApplicationException("mt.exe Manifest Processing for '" + exe + "' Failed.");
				}

				ex = null;

				// Revert to the original file
				for (i = 0; i < 20; i++)
				{
					try
					{
						IO.FileCopy(exeTmp, exe);
						ex = null;

						break;
					}
					catch (Exception ex2)
					{
						ex = ex2;
					}

					ThreadObj.Sleep(Secure.Rand31i() % 50);
				}

				// Restore the date and time
				File.SetCreationTime(exe, fi.CreationTime);
				File.SetLastAccessTime(exe, fi.LastAccessTime);
				File.SetLastWriteTime(exe, fi.LastWriteTime);
			}
			finally
			{
				x.ReleaseMutex();
			}
		}
	}
}
