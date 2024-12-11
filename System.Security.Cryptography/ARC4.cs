namespace System.Security.Cryptography
{
	/// <summary>
	/// Represents the base class from which all implementations are built <see cref = "ARC4" />
	/// symmetric encryption algorithm.
	/// </summary> 
	public abstract class ARC4 : SymmetricAlgorithm
	{
		private static bool _registered = false;
		
		/// <summary>
		/// Adds matching names with algorithm <see cref = "ARC4" /> for the current application domain.
		/// </summary> 
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

		/// <summary>
		/// Creates a cryptographic object for executing the <see cref = "ARC4" /> algorithm using random parameters.
		/// </summary> 
		public new static ARC4 Create()
		{
			return new ARC4Managed();
		}

		/// <summary>
		/// Creates a cryptographic object for executing the specified implementation <see cref = "ARC4" /> of the algorithm.
		/// </summary>
		/// <param name = "algName">
		/// The name of the concrete implementation <see cref = "ARC4" /> to create.
		/// </param>
		/// <returns> Cryptographic object. </returns> 
	 	public new static ARC4 Create(string algName)
		{
			return (ARC4)CryptoConfig.CreateFromName(algName);
		}
		
		/// <summary>
		/// Creates a cryptographic object for executing the <see cref = "ARC4" /> algorithm using the specified parameters.
		/// </summary> 
		/// <param name = "key"> The secret key to be used for the symmetric algorithm. </param>
		/// <param name = "iv"> Initialization vector. </param> 
		public static ARC4 Create(byte[] key, byte[] iv)
		{
			return new ARC4Managed(key, iv);
		}

		/// <summary>
		/// Creates a cryptographic object for executing the <see cref = "ARC4" /> algorithm using the specified parameters.
		/// </summary> 
		/// <param name = "key"> The secret key to be used for the symmetric algorithm. </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param>
		public static ARC4 Create(byte[] key, ARC4SBlock[] sblock)
		{
			return new ARC4Managed(key, sblock);
		}
		
		/// <summary>
		/// Creates a cryptographic object for executing the <see cref = "ARC4" /> algorithm using the specified parameters.
		/// </summary> 
		/// <param name = "key"> The secret key to be used for the symmetric algorithm. </param>
		public static ARC4 Create(byte[] key)
		{
			return new ARC4Managed(key, ARC4SBlock.DefaultSBlock);
		}
	}
}
