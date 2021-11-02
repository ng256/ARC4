using System.Linq;

namespace System.Security.Cryptography
{
	public sealed class ARC4Managed : ARC4
	{
		private const int KeySizeDefaultValue = 256;

		private const int IVSizeValue = 256;

		private bool _disposed = false;

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
			if (iv.Distinct().Count() != 256)
			{
				throw new ArgumentException(null, "iv");
			}
			KeyValue = new byte[key.Length];
			KeySizeValue = key.Length * 8;
			Array.Copy(key, KeyValue, key.Length);
			IVValue = new byte[iv.Length];
			Array.Copy(iv, IVValue, iv.Length);
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

		public ARC4Managed(byte[] key, ARC4SBlock[] iv)
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
			if (iv.Length != 256)
			{
				throw new ArgumentException(null, "iv");
			}
			KeyValue = new byte[key.Length];
			KeySizeValue = key.Length * 8;
			Array.Copy(key, KeyValue, key.Length);
			IVValue = new byte[iv.Length];
			Array.Copy(iv, IVValue, iv.Length);
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

		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
		{
			return new ARC4CryptoTransform(rgbKey, rgbIV);
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
		{
			return new ARC4CryptoTransform(rgbKey, rgbIV);
		}

		public override void GenerateKey()
		{
			KeyValue = new byte[256];
			KeySizeValue = 256;
			CryptoProvider.InternalRng.GetBytes(KeyValue);
		}

		public override void GenerateIV()
		{
			using (ARC4SBlock sblock = ARC4SBlock.GenerateRandom())
			{
				IVValue = sblock;
			}
		}

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
