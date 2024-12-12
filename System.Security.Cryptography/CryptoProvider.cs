using System.Globalization;
using System.Reflection;
using System.Resources;

namespace System.Security.Cryptography
{
    internal static class CryptoProvider
    {
        private static RNGCryptoServiceProvider _rng;

        public static RNGCryptoServiceProvider InternalRng
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
        private static ResourceSet _mscorlib = null;

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

        public static unsafe void EraseArray(ref byte[] array)
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

        //public abstract void Cipher(byte[] buffer, int offset, int count);
    }
}
