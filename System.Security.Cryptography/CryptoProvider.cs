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

		public static void EraseArray(byte[] array)
		{
			if (array != null && array.Length != 0)
			{
				Array.Clear(array, 0, array.Length);
				InternalRng.GetBytes(array);
			}
		}

		public abstract void Cipher(byte[] buffer, int offset, int count);
	}
}
