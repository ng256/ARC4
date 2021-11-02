namespace System.Security.Cryptography
{
	public abstract class ARC4 : SymmetricAlgorithm
	{
		private static bool _registered;

		public static void Register()
		{
			if (!_registered)
			{
				CryptoConfig.AddAlgorithm(typeof(ARC4Managed), "ARC4", "ARC4Managed");
				CryptoConfig.AddAlgorithm(typeof(ARC4Managed), "ARC4Managed", "ARC4Managed");
				CryptoConfig.AddAlgorithm(typeof(ARC4Managed), "System.Security.Cryptography.ARC4", "ARC4Managed");
				CryptoConfig.AddAlgorithm(typeof(ARC4Managed), "System.Security.Cryptography.ARC4Managed", "ARC4Managed");
			}
			_registered = true;
		}

		static ARC4()
		{
			_registered = false;
			Register();
		}

		public new static ARC4 Create()
		{
			return Create("System.Security.Cryptography.ARC4Managed");
		}

		public new static ARC4 Create(string algName)
		{
			return (ARC4)CryptoConfig.CreateFromName(algName);
		}

		public static ARC4 Create(byte[] key, byte[] iv)
		{
			return new ARC4Managed(key, iv);
		}

		public static ARC4 Create(byte[] key, ARC4SBlock[] iv)
		{
			return new ARC4Managed(key, iv);
		}
	}
}
