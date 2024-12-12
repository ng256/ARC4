using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static System.ComponentModel.AssemblyMessageFormatter;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Represents the initial state of the cryptographic algorithm <see cref = "ARC4" />.
    ///     This class could not be inherited.
    /// </summary> 
    [Serializable]
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 256)]
    [DebuggerDisplay("{ToString()}")]
    public sealed class ARC4SBlock : IDisposable, ICloneable
    {
        [NonSerialized]
        public static readonly ARC4SBlock DefaultSBlock = new ARC4SBlock();

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        private byte[] _bytes = new byte[256];

        /// <summary>
        ///     Initializes an instance <see cref = "ARC4SBlock" />,
        ///     filled with pseudo-random values,
        ///     using the linear congruential random.
        /// </summary>
        /// <returns>
        ///     Instance <see cref = "ARC4SBlock" />.
        /// </returns> 
        public static ARC4SBlock GenerateRandom()
        {
            byte[] random = new byte[4];
            CryptoProvider.InternalRng.GetBytes(random);
            int r = random[0];
            int x = random[1];
            int a = ((random[2] & 0x3F) << 2) | 1;
            int c = ((random[3] & 0x7F) << 1) | 1;
            int s = (byte)((((random[2] >> 6) & 0b11) << 1) | ((random[3] >> 7) & 1));

            return new ARC4SBlock(x, a, c, r, s);
        }

        /// <summary>
        ///     Initializes an instance <see cref = "ARC4SBlock" />,
        ///     using the specified values.
        /// </summary>
        /// <param name = "bytes">
        ///     The initialization vector <see cref = "ARC4SBlock" />,
        ///     must be filled with 256 non-duplicate values.
        /// </param>
        /// <returns>
        ///     Instance <see cref = "ARC4SBlock" />.
        /// </returns> 
        public static ARC4SBlock FromBytes(params byte[] bytes)
        {
            if (!ValidBytes(bytes))
            {
                throw new DuplicateWaitObjectException("bytes");
            }

            return new ARC4SBlock(bytes);
        }

        /// <summary>
        ///     Initializes an instance <see cref = "ARC4SBlock" />,
        ///     using the specified salt.
        /// </summary>
        /// <param name = "salt">
        ///     Salt for the LCR algorithm. It must contain at least 4 bytes.
        /// </param>
        /// <returns>
        ///     Instance <see cref = "ARC4SBlock" />.
        /// </returns> 
        public static ARC4SBlock FromSalt(params byte[] salt)
        {
            if (salt.Length < 4)
            {
                throw new DuplicateWaitObjectException("bytes");
            }

            int r = salt[0];
            int x = salt[1];
            int a = ((salt[2] & 0x3F) << 2) | 1;
            int c = ((salt[3] & 0x7F) << 1) | 1;
            int s = (byte)((((salt[2] >> 6) & 0b11) << 1) | ((salt[3] >> 7) & 1));

            return new ARC4SBlock(x, a, c, r, s);
        }

        /// <summary>
        ///     Converts <see cref="ARC4SBlock"/> to <see cref="byte"/> array.
        /// </summary>
        /// <param name="sblock">
        ///     Instance <see cref="ARC4SBlock"/> for converting.
        /// </param>
        public static implicit operator byte[] (ARC4SBlock sblock)
        {
            if (sblock == null)
                throw new ArgumentNullException(nameof(sblock));
            if (sblock._bytes == null)
                throw  new ObjectDisposedException(nameof(sblock),
                    DefaultFormatter.GetMessage("ObjectDisposed_Generic"));

            byte[] bytes = new byte[256];
            Array.Copy(sblock._bytes ?? DefaultSBlock._bytes, bytes, 256);
            return bytes;
        }

        /// <summary>
        ///     Converts <see cref="byte"/> array to <see cref="ARC4SBlock"/>.
        /// </summary>
        /// <param name="bytes">
        ///     Array for converting.
        /// </param>
        public static explicit operator ARC4SBlock(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (!ValidBytes(bytes))
                throw new DuplicateWaitObjectException(nameof(bytes));

            return new ARC4SBlock(bytes);
        }

        // Checks that all 256 values should not be duplicated.
        internal static unsafe bool ValidBytes(byte[] bytes)
        {
            if (bytes == null || bytes.Length != 256)
                return false;

            fixed (byte* bytesPtr = bytes)
            {
                const int seenSize = (1 << 8) / 32;
                uint* seenPtr = stackalloc uint[seenSize];

                for (int i = 0; i < seenSize; i++)
                    seenPtr[i] = 0;

                for (int i = 0; i < 256; i++)
                {
                    byte b = bytesPtr[i];
                    uint flag = 1u << (b & 0x1F);
                    int offset = b >> 5;

                    if ((seenPtr[offset] & flag) != 0)
                        return false;

                    seenPtr[offset] |= flag;
                }
            }

            return true;
        }

        // Default S-Block.
        private ARC4SBlock()
        {
            for (int i = 0; i < 256; i++)
            {
                _bytes[i] = (byte) i;
            }
        }

        // Specified S-Block.
        internal ARC4SBlock(byte[] bytes)
        {
            Array.Copy(bytes, _bytes, 256);
        }

        // Random S-Block.
        internal ARC4SBlock(int x, int a, int c, int r, int s)
        {
            const int m = 256;
            for (int i = 0; i < m; i++)
            {
                int b = (x = (a * x + c) & (m - 1)) ^ r;
                _bytes[i] = (byte)(((b << s) | (b >> (8 - s))) & 0xFF);
            }

            if (!ValidBytes(_bytes))
                throw new InvalidOperationException();
        }

        /// <inheritdoc cref="IDisposable.Dispose"/>
        public void Dispose()
        {
            if (_bytes == null) return;
            CryptoProvider.EraseArray(ref _bytes);
            _bytes = null;
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc cref="ICloneable.Clone"/>
        public object Clone()
        {
            byte[] result = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                result[i] = _bytes[i];
            }
            return result;
        }

        /// <inheritdoc cref="object.ToString"/>
        public override string ToString()
        {
            StringBuilder stringBuilder = new StringBuilder(784);
            for (int i = 0; i < _bytes.Length; i++)
            {
                stringBuilder.Append($"{_bytes[i]:x2}");
                stringBuilder.Append(i % 16 == 15 ? "\r\n" : " ");
            }
            return stringBuilder.ToString();
        }
    }
}
