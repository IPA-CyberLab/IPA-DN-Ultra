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

namespace CoreUtil
{
	public enum CacheType
	{
		UpdateExpiresWhenAccess = 0,
		DoNotUpdateExpiresWhenAccess = 1,
	}

	public class Cache<TKey, TValue>
	{
		class Entry
		{
			DateTime createdDateTime;
			public DateTime CreatedDateTime
			{
				get { return createdDateTime; }
			}
			DateTime updatedDateTime;
			public DateTime UpdatedDateTime
			{
				get { return updatedDateTime; }
			}
			DateTime lastAccessedDateTime;
			public DateTime LastAccessedDateTime
			{
				get { return lastAccessedDateTime; }
			}

			TKey key;
			public TKey Key
			{
				get
				{
					return key;
				}
			}

			TValue value;
			public TValue Value
			{
				get
				{
					lastAccessedDateTime = Time.NowDateTime;
					return this.value;
				}
				set
				{
					this.value = value;
					updatedDateTime = Time.NowDateTime;
					lastAccessedDateTime = Time.NowDateTime;
				}
			}

			public Entry(TKey key, TValue value)
			{
				this.key = key;
				this.value = value;
				lastAccessedDateTime = updatedDateTime = createdDateTime = Time.NowDateTime;
			}

			public override int GetHashCode()
			{
				return key.GetHashCode();
			}

			public override string ToString()
			{
				return key.ToString() + "," + value.ToString();
			}
		}

		public static readonly TimeSpan DefaultExpireSpan = new TimeSpan(0, 5, 0);
		public const CacheType DefaultCacheType = CacheType.UpdateExpiresWhenAccess;

		TimeSpan expireSpan;
		public TimeSpan ExpireSpan
		{
			get { return expireSpan; }
		}
		CacheType type;
		public CacheType Type
		{
			get { return type; }
		}
		Dictionary<TKey, Entry> list;
		object lockObj;

		public Cache()
		{
			init(DefaultExpireSpan, DefaultCacheType);
		}
		public Cache(CacheType type)
		{
			init(DefaultExpireSpan, type);
		}
		public Cache(TimeSpan expireSpan)
		{
			init(expireSpan, DefaultCacheType);
		}
		public Cache(TimeSpan expireSpan, CacheType type)
		{
			init(expireSpan, type);
		}
		void init(TimeSpan expireSpan, CacheType type)
		{
			this.expireSpan = expireSpan;
			this.type = type;

			list = new Dictionary<TKey, Entry>();
			lockObj = new object();
		}

		public void Add(TKey key, TValue value)
		{
			lock (lockObj)
			{
				Entry e;

				deleteExpired();

				if (list.ContainsKey(key) == false)
				{
					e = new Entry(key, value);

					list.Add(e.Key, e);

					deleteExpired();
				}
				else
				{
					e = list[key];
					e.Value = value;
				}
			}
		}

		public void Delete(TKey key)
		{
			lock (lockObj)
			{
				if (list.ContainsKey(key))
				{
					list.Remove(key);
				}
			}
		}

		public TValue this[TKey key]
		{
			get
			{
				lock (lockObj)
				{
					deleteExpired();

					if (list.ContainsKey(key) == false)
					{
						return default(TValue);
					}

					return list[key].Value;
				}
			}
		}

		static long last_deleted = 0;

		void deleteExpired()
		{
			bool do_delete = false;
			long now = Tick64.Value;
			long delete_inveral = expireSpan.Milliseconds / 10;

			lock (lockObj)
			{
				if (last_deleted == 0 || now > (last_deleted + delete_inveral))
				{
					last_deleted = now;
					do_delete = true;
				}
			}

			if (do_delete == false)
			{
				return;
			}

			lock (lockObj)
			{
				List<Entry> o = new List<Entry>();
				DateTime expire = Time.NowDateTime - this.expireSpan;

				foreach (Entry e in list.Values)
				{
					if (this.type == CacheType.UpdateExpiresWhenAccess)
					{
						if (e.LastAccessedDateTime < expire)
						{
							o.Add(e);
						}
					}
					else
					{
						if (e.UpdatedDateTime < expire)
						{
							o.Add(e);
						}
					}
				}

				foreach (Entry e in o)
				{
					list.Remove(e.Key);
				}
			}
		}
	}
}

