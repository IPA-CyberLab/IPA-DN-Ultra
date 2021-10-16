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
using System.Diagnostics;
using System.Web.Mail;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace CoreUtil
{
	public class AppReg
	{
		string appSubKey;
		public string AppSubKey
		{
			get { return appSubKey; }
		}
		RegRoot rootKey;
		public RegRoot RootKey
		{
			get { return rootKey; }
		}

		public AppReg(RegRoot root, string subkey)
		{
			subkey = subkey.TrimEnd('\\');
			this.rootKey = root;
			this.appSubKey = subkey;
		}

		public AppReg GetSubReg(string subKeyName)
		{
			return new AppReg(rootKey, appSubKey + "\\" + subKeyName);
		}

		public bool WriteStr(string name, string value)
		{
			return Reg.WriteStr(rootKey, appSubKey, name, value);
		}

		public bool WriteInt(string name, int value)
		{
			return Reg.WriteInt(rootKey, appSubKey, name, value);
		}

		public bool WriteStrList(string name, string[] values)
		{
			return Reg.WriteStrList(rootKey, appSubKey, name, values);
		}

		public bool WriteByte(string name, byte[] data)
		{
			return Reg.WriteByte(rootKey, appSubKey, name, data);
		}

		public bool DeleteValue(string name)
		{
			return Reg.DeleteValue(rootKey, appSubKey, name);
		}

		public string ReadStr(string name)
		{
			return Reg.ReadStr(rootKey, appSubKey, name);
		}

		public int ReadInt(string name)
		{
			return Reg.ReadInt(rootKey, appSubKey, name);
		}

		public string[] ReadStrList(string name)
		{
			return Reg.ReadStrList(rootKey, appSubKey, name);
		}

		public byte[] ReadByte(string name)
		{
			return Reg.ReadByte(rootKey, appSubKey, name);
		}
	}

	public enum RegRoot
	{
		LocalMachine = 0,
		CurrentUser = 1,
		Users = 2,
	}

	public static class Reg
	{
		static RegistryKey rootKey(RegRoot r)
		{
			switch (r)
			{
				case RegRoot.LocalMachine:
					return Registry.LocalMachine;

				case RegRoot.CurrentUser:
					return Registry.CurrentUser;

				case RegRoot.Users:
					return Registry.Users;
			}

			throw new ArgumentException();
		}

		public static string[] EnumValue(RegRoot root, string keyname)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				if (key == null)
				{
					return new string[0];
				}

				try
				{
					return key.GetValueNames();
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return new string[0];
			}
		}

		public static string[] EnumKey(RegRoot root, string keyname)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				if (key == null)
				{
					return new string[0];
				}

				try
				{
					return key.GetSubKeyNames();
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return new string[0];
			}
		}

		public static bool WriteByte(RegRoot root, string keyname, string valuename, byte[] data)
		{
			return WriteValue(root, keyname, valuename, data);
		}

		public static byte[] ReadByte(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return new byte[0];
			}

			try
			{
				return (byte[])o;
			}
			catch
			{
				return new byte[0];
			}
		}

		public static bool WriteInt(RegRoot root, string keyname, string valuename, int value)
		{
			return WriteValue(root, keyname, valuename, value);
		}

		public static int ReadInt(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return 0;
			}

			try
			{
				return (int)o;
			}
			catch
			{
				return 0;
			}
		}

		public static bool WriteStrList(RegRoot root, string keyname, string valuename, string[] value)
		{
			return WriteValue(root, keyname, valuename, value);
		}

		public static string[] ReadStrList(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return new string[0];
			}

			try
			{
				return (string[])o;
			}
			catch
			{
				return new string[0];
			}
		}

		public static bool WriteStr(RegRoot root, string keyname, string valuename, string value)
		{
			return WriteValue(root, keyname, valuename, value);
		}

		public static string ReadStr(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return "";
			}

			try
			{
				return (string)o;
			}
			catch
			{
				return "";
			}
		}

		public static bool WriteValue(RegRoot root, string keyname, string valuename, object o)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname, true);

				if (key == null)
				{
					key = rootKey(root).CreateSubKey(keyname);

					if (key == null)
					{
						return false;
					}
				}

				try
				{
					key.SetValue(valuename, o);

					return true;
				}
				catch
				{
					return false;
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return false;
			}
		}

		public static object ReadValue(RegRoot root, string keyname, string valuename)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				if (key == null)
				{
					return null;
				}

				try
				{
					return key.GetValue(valuename);
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return null;
			}
		}

		public static bool IsValue(RegRoot root, string keyname, string valuename)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				try
				{
					object o = key.GetValue(valuename);

					if (o == null)
					{
						return false;
					}
				}
				finally
				{
					key.Close();
				}

				return true;
			}
			catch
			{
				return false;
			}
		}

		public static bool DeleteValue(RegRoot root, string keyname, string valuename)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname, true);

				if (key == null)
				{
					return false;
				}

				try
				{
					key.DeleteValue(valuename);

					return true;
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return false;
			}
		}

		public static bool DeleteKey(RegRoot root, string keyname)
		{
			return DeleteKey(root, keyname, false);
		}
		public static bool DeleteKey(RegRoot root, string keyname, bool deleteAll)
		{
			try
			{
				if (deleteAll == false)
				{
					rootKey(root).DeleteSubKey(keyname);
				}
				else
				{
					rootKey(root).DeleteSubKeyTree(keyname);
				}

				return true;
			}
			catch
			{
				return false;
			}
		}

		public static bool NewKey(RegRoot root, string keyname)
		{
			if (IsKey(root, keyname))
			{
				return true;
			}

			try
			{
				RegistryKey key = rootKey(root).CreateSubKey(keyname);

				if (key == null)
				{
					return false;
				}

				key.Close();

				return true;
			}
			catch
			{
				return false;
			}
		}

		public static bool IsKey(RegRoot root, string name)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(name);

				if (key == null)
				{
					return false;
				}

				key.Close();

				return true;
			}
			catch
			{
				return false;
			}
		}
	}
}
