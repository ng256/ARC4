using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Resources;
using System.Runtime.InteropServices;

namespace System.ComponentModel
{
	internal class AssemblyMessageFormatter
	{
		private static readonly int[] _installedLangs;
		private static readonly AssemblyMessageFormatter _defaultFormatter;
		private static readonly Assembly _mscorlib;
		private readonly int _lcid = CultureInfo.CurrentUICulture.LCID;
		private readonly Assembly _assembly = _mscorlib;
		private readonly CultureInfo _culture = CultureInfo.CurrentUICulture;

		public int LCID => _lcid;
		public static AssemblyMessageFormatter DefaultFormatter => _defaultFormatter;

		static AssemblyMessageFormatter()
		{
			_defaultFormatter = new AssemblyMessageFormatter();
			_mscorlib = Assembly.GetAssembly(typeof(object));
			CultureInfo[] installedCultures = CultureInfo.GetCultures(CultureTypes.InstalledWin32Cultures);
			CultureInfo[] specificCultures = CultureInfo.GetCultures(CultureTypes.SpecificCultures);
			List<int> installedLangs = new List<int>(installedCultures.Length);
			CultureInfo[] array = specificCultures;
			foreach (CultureInfo culture in array)
			{
				if (installedCultures.Contains(culture))
				{
					installedLangs.Add(culture.LCID);
				}
			}
			_installedLangs = installedLangs.ToArray();
		}

		public AssemblyMessageFormatter(Assembly assembly = null)
		{
			if (assembly != null)
			{
				_assembly = assembly;
			}
		}

		public AssemblyMessageFormatter(int lcid, Assembly assembly = null)
			: this(assembly)
		{
			if (_installedLangs.Contains(lcid))
			{
				_culture = new CultureInfo(lcid);
				_lcid = lcid;
			}
		}

		public AssemblyMessageFormatter(CultureInfo culture, Assembly assembly = null)
			: this(assembly)
		{
			if (culture != null && _installedLangs.Contains(culture.LCID))
			{
				_culture = culture;
				_lcid = culture.LCID;
			}
		}

		public AssemblyMessageFormatter(TextInfo info, Assembly assembly = null)
			: this(assembly)
		{
			if (info != null && _installedLangs.Contains(info.LCID))
			{
				_culture = new CultureInfo(info.LCID);
				_lcid = info.LCID;
			}
		}

		public AssemblyMessageFormatter(string name, Assembly assembly = null)
			: this(assembly)
		{
			try
			{
				CultureInfo culture = CultureInfo.GetCultureInfo(name);
				if (_installedLangs.Contains(culture.LCID))
				{
					_lcid = culture.LCID;
				}
			}
			catch
			{
				_lcid = CultureInfo.CurrentUICulture.LCID;
			}
		}

		private static string GetDescription(Enum enumElement)
		{
			Type type = enumElement.GetType();
			MemberInfo[] memInfo = type.GetMember(enumElement.ToString());
			if (memInfo != null && memInfo.Length != 0)
			{
				object[] attrs = memInfo[0].GetCustomAttributes(typeof(DescriptionAttribute), inherit: false);
				if (attrs != null && attrs.Length != 0)
				{
					return ((DescriptionAttribute)attrs[0]).Description;
				}
			}
			return enumElement.ToString();
		}

		public static string GetMessage(string messageId, CultureInfo targetUICulture = null, Assembly assembly = null)
		{
			try
			{
				if (targetUICulture == null)
				{
					targetUICulture = CultureInfo.CurrentUICulture;
				}
				if (assembly == null)
				{
					assembly = _mscorlib;
				}
				ResourceManager resourceManager = new ResourceManager(assembly.GetName().Name, assembly);
				return resourceManager.GetResourceSet(targetUICulture, createIfNotExists: true, tryParents: true)?.GetString(messageId);
			}
			catch
			{
				return null;
			}
		}

		public string GetMessage(string messageId)
		{
			return GetMessage(messageId, new CultureInfo(_lcid), _assembly);
		}

		public string FormatMessage(string messageId, params object[] arguments)
		{
			return string.Format(_culture, GetMessage(messageId), arguments);
		}

		public Exception CreateException(Exception innerException, string messageId, params object[] arguments)
		{
			string message = FormatMessage(messageId, arguments);
			return new Exception(message, innerException);
		}

		public Exception CreateException(string messageId, params object[] arguments)
		{
			string message = FormatMessage(messageId, arguments);
			return new Exception(message);
		}

		public override string ToString()
		{
			string name = CultureInfo.GetCultureInfo(_lcid).DisplayName;
			return string.IsNullOrEmpty(name) ? _lcid.ToString() : name;
		}
	}
}
