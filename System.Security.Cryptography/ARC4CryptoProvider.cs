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
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));

            int keyLength = key.Length;

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
                throw new CryptographicException("Arg_CryptographyException", e);
            }
        }

        public ARC4CryptoProvider(byte[] key, byte[] iv)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));
            ArgumentNullException.ThrowIfNull(iv, nameof(iv));
            ArgumentOutOfRangeException.ThrowIfNotEqual(ARC4SBlock.ValidBytes(iv), true, nameof(ARC4SBlock));
            int keyLength = key.Length;

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
                throw new CryptographicException("Arg_CryptographyException", e);
            }
        }

        public ARC4CryptoProvider(byte[] key, ARC4SBlock sblock)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));
            ArgumentNullException.ThrowIfNull(sblock, nameof(sblock));

            int keyLength = key.Length;

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
                throw new CryptographicException("Arg_CryptographyException");
            }
        }

        public ARC4CryptoProvider CreateRandom(byte[] key, out byte[] iv)
        {
            using (var sblock = ARC4SBlock.GenerateRandom())
            {
                iv = sblock;
            }
            return new ARC4CryptoProvider(key, iv);
        }

        // Performs symmetric encryption using the ARC4 algorithm. 
        public override void Cipher(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer, nameof(buffer));
            ArgumentOutOfRangeException.ThrowIfZero(buffer.Length, nameof(buffer));

            ArgumentOutOfRangeException.ThrowIfLessThan(count, 0, nameof(buffer));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(count, buffer.Length, nameof(buffer));

            ArgumentOutOfRangeException.ThrowIfLessThan(offset, 0, nameof(offset));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, buffer.Length - count, nameof(offset));


            if (count == 0)
                return;

            try
            {
                for (int i = offset; i < count; i++)
                {
                    buffer[i] = (byte)(buffer[i] ^ NextByte());
                }
            }
            catch (Exception e)
            {
                throw new CryptographicException("Arg_CryptographyException", e);
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
