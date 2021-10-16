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
using System.Data;
using System.Data.Sql;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
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
using System.Web.Mail;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Xml.Serialization;
using System.DirectoryServices;
using CoreUtil;
using CoreUtil.Internal;

namespace CoreUtil
{
	public static class Win32
	{
		static Win32()
		{
		}

		public static void CreateUser(string machineName, string userName, string password, string description)
		{
			Str.NormalizeString(ref userName);
			Str.NormalizeString(ref password);
			Str.NormalizeString(ref description);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry newUser = sam.Children.Add(userName, "user"))
				{
					newUser.Invoke("SetPassword", new object[] { password });
					newUser.Invoke("Put", new object[] { "Description", description });
					newUser.CommitChanges();
					Console.WriteLine(newUser.Path);
				}
			}

			try
			{
				AddUserToGroup(machineName, userName, "Users");
			}
			catch
			{
			}
		}

		public static void ChangeUserPassword(string machineName, string userName, string oldPassword, string newPassword)
		{
			Str.NormalizeString(ref userName);
			Str.NormalizeString(ref oldPassword);
			Str.NormalizeString(ref newPassword);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry user = sam.Children.Find(userName, "user"))
				{
					user.Invoke("ChangePassword", oldPassword, newPassword);
				}
			}
		}

		public static void SetUserPassword(string machineName, string userName, string password)
		{
			Str.NormalizeString(ref userName);
			Str.NormalizeString(ref password);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry user = sam.Children.Find(userName, "user"))
				{
					user.Invoke("SetPassword", password);
				}
			}
		}

		public static string[] GetMembersOfGroup(string machineName, string groupName)
		{
			List<string> ret = new List<string>();

			Str.NormalizeString(ref groupName);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry g = sam.Children.Find(groupName, "group"))
				{
					object members = g.Invoke("Members", null);

					foreach (object member in (IEnumerable)members)
					{
						using (DirectoryEntry e = new DirectoryEntry(member))
						{
							ret.Add(e.Name);
						}
					}

					return ret.ToArray();
				}
			}
		}

		public static bool IsUserMemberOfGroup(string machineName, string userName, string groupName)
		{
			Str.NormalizeString(ref userName);
			Str.NormalizeString(ref groupName);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry g = sam.Children.Find(groupName, "group"))
				{
					using (DirectoryEntry u = sam.Children.Find(userName, "user"))
					{
						return (bool)g.Invoke("IsMember", u.Path);
					}
				}
			}
		}

		public static void DeleteUserFromGroup(string machineName, string userName, string groupName)
		{
			Str.NormalizeString(ref userName);
			Str.NormalizeString(ref groupName);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry g = sam.Children.Find(groupName, "group"))
				{
					using (DirectoryEntry u = sam.Children.Find(userName, "user"))
					{
						g.Invoke("Remove", u.Path);
					}
				}
			}
		}

		public static void AddUserToGroup(string machineName, string userName, string groupName)
		{
			Str.NormalizeString(ref userName);
			Str.NormalizeString(ref groupName);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry g = sam.Children.Find(groupName, "group"))
				{
					using (DirectoryEntry u = sam.Children.Find(userName, "user"))
					{
						g.Invoke("Add", u.Path);
					}
				}
			}
		}

		public static void DeleteUser(string machineName, string userName)
		{
			Str.NormalizeString(ref userName);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				using (DirectoryEntry u = sam.Children.Find(userName, "user"))
				{
					sam.Children.Remove(u);
				}
			}
		}

		public static bool IsUserExists(string machineName, string userName)
		{
			Str.NormalizeString(ref userName);

			using (DirectoryEntry sam = OpenSam(machineName))
			{
				try
				{
					using (DirectoryEntry user = sam.Children.Find(userName, "user"))
					{
						if (user == null)
						{
							return false;
						}

						return true;
					}
				}
				catch (COMException ce)
				{
					if ((uint)ce.ErrorCode == 0x800708AD)
					{
						return false;
					}
					else
					{
						throw;
					}
				}
			}
		}

		public static DirectoryEntry OpenSam()
		{
			return OpenSam(null);
		}
		public static DirectoryEntry OpenSam(string machineName)
		{
			if (Str.IsEmptyStr(machineName))
			{
				machineName = Env.MachineName;
			}

			return new DirectoryEntry(string.Format("WinNT://{0},computer",
				machineName));
		}
	}
}
