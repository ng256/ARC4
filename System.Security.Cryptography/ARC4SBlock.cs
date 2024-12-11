using System.Diagnostics;
using static System.ComponentModel.AssemblyMessageFormatter;
using System.Runtime.InteropServices;
using System.Text;

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
        private static readonly byte[] _A =
        {
            0x01, 0x05, 0x09, 0x0D, 0x11, 0x15, 0x19, 0x1D,
            0x21, 0x25, 0x29, 0x2D, 0x31, 0x35, 0x39, 0x3D,
            0x41, 0x45, 0x49, 0x4D, 0x51, 0x55, 0x59, 0x5D,
            0x61, 0x65, 0x69, 0x6D, 0x71, 0x75, 0x79, 0x7D,
            0x81, 0x85, 0x89, 0x8D, 0x91, 0x95, 0x99, 0x9D,
            0xA1, 0xA5, 0xA9, 0xAD, 0xB1, 0xB5, 0xB9, 0xBD,
            0xC1, 0xC5, 0xC9, 0xCD, 0xD1, 0xD5, 0xD9, 0xDD,
            0xE1, 0xE5, 0xE9, 0xED, 0xF1, 0xF5, 0xF9, 0xFD
        };

        [NonSerialized]
        private static readonly byte[] _C =
        {
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
            0x11, 0x13, 0x15, 0x17, 0x19, 0x1B, 0x1D, 0x1F,
            0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F,
            0x31, 0x33, 0x35, 0x37, 0x39, 0x3B, 0x3D, 0x3F,
            0x41, 0x43, 0x45, 0x47, 0x49, 0x4B, 0x4D, 0x4F,
            0x51, 0x53, 0x55, 0x57, 0x59, 0x5B, 0x5D, 0x5F,
            0x61, 0x63, 0x65, 0x67, 0x69, 0x6B, 0x6D, 0x6F,
            0x71, 0x73, 0x75, 0x77, 0x79, 0x7B, 0x7D, 0x7F,
            0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0x8F,
            0x91, 0x93, 0x95, 0x97, 0x99, 0x9B, 0x9D, 0x9F,
            0xA1, 0xA3, 0xA5, 0xA7, 0xA9, 0xAB, 0xAD, 0xAF,
            0xB1, 0xB3, 0xB5, 0xB7, 0xB9, 0xBB, 0xBD, 0xBF,
            0xC1, 0xC3, 0xC5, 0xC7, 0xC9, 0xCB, 0xCD, 0xCF,
            0xD1, 0xD3, 0xD5, 0xD7, 0xD9, 0xDB, 0xDD, 0xDF,
            0xE1, 0xE3, 0xE5, 0xE7, 0xE9, 0xEB, 0xED, 0xEF,
            0xF1, 0xF3, 0xF5, 0xF7, 0xF9, 0xFB, 0xFD, 0xFF
        };

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
            int a = _A[random[2] & 0x3F];
            int c = _C[random[3] & 0x7F];
            int s = (byte)(((random[2] >> 6) & 0b11) | ((random[3] >> 7) & 1));
        
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
            int a = _A[salt[2] & 0x3F];
            int c = _C[salt[3] & 0x7F];
            int s = (byte)(((salt[2] >> 6) & 0b11) | ((salt[3] >> 7) & 1));

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
