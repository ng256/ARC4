using static System.ComponentModel.AssemblyMessageFormatter;

namespace System.Security.Cryptography
{
	// Provides methods and properties for implementing ARC4 data encryption.
	internal sealed class ARC4CryptoProvider : CryptoProvider, IDisposable
	{
		private byte[] _sblock = new byte[256]; // S
        private int x = 0;
        private int y = 0;
        private bool _disposed = false;

		public ARC4SBlock State => new ARC4SBlock(_sblock);

		private static void Swap(byte[] array, int index1, int index2)
		{
			byte b = array[index1];
			array[index1] = array[index2];
			array[index2] = b;
		}

        /* Pseudo-random number generator
		    To generate the keystream, the cipher uses a hidden internal state, which consists of two parts:
		    - A permutation containing all possible bytes from 0x00 to 0xFF (array _sblock).
		    - Variables-counters x and y.
		*/
        public byte NextByte() // PRGA
		{
			x = (x + 1) % 256;
			y = (y + _sblock[x]) % 256;
			Swap(_sblock, x, y);
			return _sblock[(_sblock[x] + _sblock[y]) % 256];
		}

		public ARC4CryptoProvider(byte[] key) // KSA
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}
			int keyLength = key.Length;
			if (keyLength == 0)
			{
				throw new ArgumentException(DefaultFormatter.FormatMessage
                    ("Cryptography_CSP_AlgKeySizeNotAvailable", keyLength), nameof(key));
			}
			try
			{
				_sblock = ARC4SBlock.DefaultSBlock;
				int j = 0;
				for (int i = 0; i < 256; i++)
				{
					j = (j + _sblock[i] + key[i % keyLength]) % 256;
					Swap(_sblock, i, j);
				}
			}
			catch (Exception e)
			{
				throw new CryptographicException(
                    string.Format("{0} {1}",
                        DefaultFormatter.GetMessage("Arg_CryptographyException"), e.Message), e);
			}
		}

		public ARC4CryptoProvider(byte[] key, byte[] iv)
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}
			int keyLength = key.Length;
			if (keyLength == 0)
			{
				throw new ArgumentException(DefaultFormatter.FormatMessage
                    ("Cryptography_CSP_AlgKeySizeNotAvailable", keyLength), nameof(key));
			}
			if (iv == null)
			{
				throw new ArgumentNullException(nameof(iv));
			}
			if (!ARC4SBlock.ValidBytes(iv))
			{
				throw new ArgumentException(DefaultFormatter.GetMessage
                    ("Cryptography_InvalidIVSize"), nameof(iv));
			}
			try
			{
				Array.Copy(iv, _sblock, 256);
				int j = 0;
				for (int i = 0; i < 256; i++)
				{
					j = (j + _sblock[i] + key[i % keyLength]) % 256;
					Swap(_sblock, i, j);
				}
			}
			catch (Exception e)
			{
				throw new CryptographicException(
                    string.Format("{0} {1}",
                        DefaultFormatter.GetMessage("Arg_CryptographyException"), e.Message), e);
			}
		}

		public ARC4CryptoProvider(byte[] key, ARC4SBlock sblock)
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}
			int keyLength = key.Length;
			if (keyLength == 0)
			{
				throw new ArgumentException(DefaultFormatter.FormatMessage
                    ("Cryptography_CSP_AlgKeySizeNotAvailable", keyLength), nameof(key));
			}
			if (sblock == null)
			{
				throw new ArgumentNullException(nameof(sblock));
			}
			try
			{
				_sblock = sblock;
				int j = 0;
				for (int i = 0; i < 256; i++)
				{
					j = (j + _sblock[i] + key[i % keyLength]) % 256;
					Swap(_sblock, i, j);
				}
			}
			catch (Exception e)
			{
				throw new CryptographicException(string.Format("{0} {1}",
                    DefaultFormatter.GetMessage("Arg_CryptographyException"), e.Message));
			}
		}

		public ARC4CryptoProvider CreateRandom(byte[] key, out byte[] iv)
		{
			using (ARC4SBlock sblock = ARC4SBlock.GenerateRandom())
			{
				iv = sblock;
			}
			return new ARC4CryptoProvider(key, iv);
		}

                // Performs symmetric encryption using the ARC4 algorithm. 
		public override void Cipher(byte[] buffer, int offset, int count)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException(nameof(buffer));
			}
			int bufferLength = buffer.Length;
			if (bufferLength == 0)
			{
				throw new ArgumentException(DefaultFormatter.
                    GetMessage("Cryptography_InsufficientBuffer"), nameof(buffer));
			}
			if (count < 0 || count > bufferLength)
			{
				throw new ArgumentException(DefaultFormatter.
                    FormatMessage("ArgumentOutOfRange_ArrayLength", 0, bufferLength), nameof(count));
			}
			int length = bufferLength - count;
			if (offset < 0 || offset > length)
			{
				throw new ArgumentException(DefaultFormatter.
                    GetMessage("ArgumentOutOfRange_IndexOutOfRange"), nameof(offset));
			}
			if (count == 0)
			{
				return;
			}
			try
			{
				for (int i = offset; i < count; i++)
				{
					buffer[i] = (byte)(buffer[i] ^ NextByte());
				}
			}
			catch (Exception e)
			{
				throw new CryptographicException(
                    string.Format("{0} {1}",
                        DefaultFormatter.GetMessage("Arg_CryptographyException"), e.Message), e);
			}
		}

        internal unsafe void EraseState()
        {
            if (_disposed) return;
            try
            {
                fixed (int* ptr = &x) *ptr = -1;
                fixed (int* ptr = &y) *ptr = -1;
                EraseArray(ref _sblock);
            }
            finally
            {
                _disposed = true;
            }
        }

        public void Dispose()
        {
            EraseState();
            GC.SuppressFinalize(this);
		}

        /// <summary>
        /// <inheritdoc cref="object.Finalize"/>.
        /// </summary>
		~ARC4CryptoProvider()
		{
            EraseState();
		}
	}
}
