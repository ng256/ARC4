using System.Globalization;
using System.Reflection;
using System.Resources;

namespace System.Security.Cryptography
{
    internal static class InternalTools
    {
        private static RNGCryptoServiceProvider _rng;

        internal static RNGCryptoServiceProvider InternalRng
        {
            get
            {
                if (_rng == null)
                {
                    _rng = new RNGCryptoServiceProvider();
                }
                return _rng;
            }
        }

        // Mscorlib resources.
        internal static ResourceSet _mscorlib = null;

        // Gets mscorlib internal error message.
        internal static string GetResourceString(string name)
        {
            if (_mscorlib == null)
            {
                var assembly = Assembly.GetAssembly(typeof(object));
                var assemblyName = assembly.GetName().Name;
                var manager = new ResourceManager(assemblyName, assembly);
                _mscorlib = manager.GetResourceSet(CultureInfo.CurrentUICulture, true, true);
            }
            return _mscorlib.GetString(name);
        }

        // Gets parametrized mscorlib internal error message.
        internal static string GetResourceString(string name, params object[] args)
        {
            return string.Format(GetResourceString(name) ?? throw new ArgumentNullException(nameof(name)), args);
        }

        internal static unsafe void EraseArray(ref byte[] array)
        {
            if (array != null && array.Length != 0)
            {
                int length = array.Length;
                fixed (byte* ptr = array)
                {
                    for (int i = 0; i < length; i++)
                    {
                        *(ptr + i) = 0;
                    }
                }
            }
            array = null;
        }

        internal static Exception BufferNullException(string name)
        {
            return new ArgumentNullException(name,
                InternalTools.GetResourceString("ArgumentNull_Buffer"));
        }

        internal static Exception BufferIndexCountException(string name)
        {
            return new ArgumentOutOfRangeException(name,
                InternalTools.GetResourceString("ArgumentOutOfRange_IndexCountBuffer"));
        }
    }
}
