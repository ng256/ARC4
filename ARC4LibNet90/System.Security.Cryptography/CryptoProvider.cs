namespace System.Security.Cryptography
{
	internal abstract class CryptoProvider
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

		public abstract void Cipher(byte[] buffer, int offset, int count);
	}
}
