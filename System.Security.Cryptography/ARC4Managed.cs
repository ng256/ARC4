using System.Linq;

namespace System.Security.Cryptography
{
	/// <summary>
	/// Provides managed version <see cref = "ARC4CryptoProvider" />.
	/// This class could not be inherited.
	/// </summary> 
	public sealed class ARC4Managed : ARC4
	{
		private const int KeySizeDefaultValue = 256;
		private const int IVSizeValue = 256;
		private bool _disposed = false;

		/// <summary>
		/// Initializes a new object <see cref = "ARC4Managed" /> using random parameters.
		/// </summary> 
		public ARC4Managed()
		{
			GenerateKey();
			GenerateIV();
			KeySizeValue = KeyValue.Length * 8;
			BlockSizeValue = 8;
			FeedbackSizeValue = 8;
			LegalBlockSizesValue = new KeySizes[1]
			{
				new KeySizes(8, int.MaxValue, 8)
			};
			LegalKeySizesValue = new KeySizes[1]
			{
				new KeySizes(8, int.MaxValue, 8)
			};
			ModeValue = CipherMode.CTS;
			PaddingValue = PaddingMode.None;
		}

		/// <summary>
		/// Initializes a new object <see cref = "ARC4Managed" /> using the specified parameters.
		/// </summary>
		/// <param name = "key"> Encryption key. </param>
		/// <param name = "iv"> Initialization vector. </param> 
		public ARC4Managed(byte[] key, byte[] iv)
		{
			if (key == null)
			{
				throw new ArgumentNullException("key");
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, "key");
			}
			if (iv == null)
			{
				throw new ArgumentNullException("iv");
			}
			if (!ARC4SBlock.ValidBytes(iv))
			{
				throw new ArgumentException(null, "iv");
			}
			int keyLength = key.Length;
			KeyValue = new byte[keyLength];
			KeySizeValue = key.Length * 8;
			Array.Copy(key, KeyValue, keyLength);
			IVValue = new byte[IVSizeValue];
			Array.Copy(iv, IVValue, IVSizeValue);
			BlockSizeValue = 8;
			FeedbackSizeValue = 8;
			LegalBlockSizesValue = new KeySizes[1]
			{
				new KeySizes(8, int.MaxValue, 8)
			};
			LegalKeySizesValue = new KeySizes[1]
			{
				new KeySizes(8, int.MaxValue, 8)
			};
			ModeValue = CipherMode.CTS;
			PaddingValue = PaddingMode.None;
		}

		/// <summary>
		/// Initializes a new object <see cref = "ARC4Managed" /> using the specified parameters.
		/// </summary>
		/// <param name = "key"> Encryption key. </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param> 
		public ARC4Managed(byte[] key, ARC4SBlock[] sblock)
		{
			if (key == null)
			{
				throw new ArgumentNullException("key");
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, "key");
			}
			if (sblock == null)
			{
				throw new ArgumentNullException("sblock");
			}
			int keyLength = key.Length;
			KeyValue = new byte[keyLength];
			KeySizeValue = key.Length * 8;
			Array.Copy(key, KeyValue, keyLength);
			IVValue = new byte[IVSizeValue];
			Array.Copy(sblock, IVValue, IVSizeValue);
			BlockSizeValue = 8;
			FeedbackSizeValue = 8;
			LegalBlockSizesValue = new KeySizes[1]
			{
				new KeySizes(8, int.MaxValue, 8)
			};
			LegalKeySizesValue = new KeySizes[1]
			{
				new KeySizes(8, int.MaxValue, 8)
			};
			ModeValue = CipherMode.CTS;
			PaddingValue = PaddingMode.None;
		}
		
		/// <summary>
		/// Initializes a new object <see cref = "ARC4Managed" /> using the specified encryption key.
		/// </summary>
		/// <param name = "key"> Encryption key. </param> 
		public ARC4Managed(byte[] key) : this(key, ARC4SBlock.DefaultSBlock)
		{

		}

		/// <inheritdoc cref="SymmetricAlgorithm.CreateEncryptor(byte[], byte[])"/>
		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
		{
			return new ARC4CryptoTransform(rgbKey, rgbIV);
		}

		/// <inheritdoc cref="SymmetricAlgorithm.CreateDecryptor(byte[], byte[])"/>
		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
		{
		        return new ARC4CryptoTransform(rgbKey, rgbIV);
		}

		/// <inheritdoc cref="SymmetricAlgorithm.GenerateKey"/>
		public override void GenerateKey()
		{
			KeyValue = new byte[KeySizeDefaultValue];
			KeySizeValue = KeySizeDefaultValue;
			CryptoProvider.InternalRng.GetBytes(KeyValue);
		}

		/// <inheritdoc cref="SymmetricAlgorithm.GenerateIV"/>
		public override void GenerateIV()
		{
		        using (ARC4SBlock sblock = ARC4SBlock.GenerateRandom()) IVValue = sblock;
		}

	        /// <inheritdoc cref="SymmetricAlgorithm.Dispose(bool)"/>
		protected override void Dispose(bool disposing)
		{
			if (disposing && !_disposed)
			{
				try
				{
					CryptoProvider.EraseArray(KeyValue);
					CryptoProvider.EraseArray(IVValue);
				}
				finally
				{
					_disposed = true;
				}
			}
			KeyValue = null;
			IVValue = null;
			base.Dispose(disposing);
		}
	}
}
