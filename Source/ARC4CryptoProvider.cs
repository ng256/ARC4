using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using static System.Security.Cryptography.InternalTools;

namespace System.Security.Cryptography
{
    [Serializable]
    [SecurityCritical]
    [StructLayout(LayoutKind.Auto, Pack = 4, Size = 256 + sizeof(int) * 2)]
#if DEBUG
    [DebuggerDisplay("{ToString()}")]
#endif
    internal unsafe class ARC4CryptoProvider : CryptoProvider, IDisposable, ICloneable
    {
        /// Internal state array (256 bytes).
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        private byte* _sblock = (byte*)Marshal.AllocHGlobal(256);

        // Indices used in the state array manipulation.
        [MarshalAs(UnmanagedType.I4)]
        private int _x = 0;

        [MarshalAs(UnmanagedType.I4)]
        private int _y = 0;

        #region Constructor

        // Initializes the state array with default values.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public ARC4CryptoProvider()
        {
            Initialize(_sblock);
        }

        // Initializes the state using an initialization vector (IV) and an optional index.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public ARC4CryptoProvider(byte[] iv, int index = 0)
        {
            if (iv == null)
                throw new ArgumentNullException(nameof(iv), GetResourceString("ArgumentNull_WithParamName", nameof(iv)));
            if (index < 0 || index >= iv.Length)
                throw new ArgumentOutOfRangeException(nameof(index),
                    GetResourceString("Arg_IndexOutOfRangeException"));

            switch (iv.Length - index)
            {
                case 4:
                    Initialize(_sblock, iv, index);
                    break;
                case 256:
                    fixed (byte* ivPtr = iv)
                    {
                        byte* ivStartPtr = ivPtr + index;
                        Copy(ivStartPtr, _sblock);
                    }
                    break;
                default:
                    throw new ArgumentException(GetResourceString("Cryptography_InvalidIVSize"));
            }

            // Verify that the generated state array has a full period.
            if (!IsValid(_sblock))
                throw new InvalidOperationException(GetResourceString("Cryptography_InvalidOperation"));
        }

        public ARC4CryptoProvider(int seed) : this(BitConverter.GetBytes(seed))
        {
        }

        public ARC4CryptoProvider(uint seed) : this(BitConverter.GetBytes(seed))
        {
        }

        #endregion

        #region Cryptography

        // Initializes the state array using the Key Scheduling Algorithm (KSA).
        private void Initialize(byte[] key)
        {
            const int m = 256;
            int keyLength = key.Length;
            for (int i = 0, j = 0; i < m; i++)
            {
                j = (j + _sblock[i] + key[i % keyLength]) & (m - 1);
                Swap(_sblock, i, j);
            }
        }

        // Generates the next byte in the PRGA sequence.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public override byte NextByte()
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            return GeneratePRGA();
        }

        // Generates the next byte in the PRGA sequence.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public override byte GetByte(byte value)
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            return _sblock[value];
        }



        // Updates the state array using a key (KSA algorithm).
        [MethodImpl(MethodImplOptions.Synchronized)]
        public override void Update(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key), 
                    GetResourceString("ArgumentNull_WithParamName", nameof(key)));
            if (key.Length == 0)
                return;
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            Initialize(key);
        }

        // Advances the PRGA sequence by skipping n bytes.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public override void DropDown(int n)
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            for (int i = 0; i < n; i++)
            {
                GeneratePRGA();
            }
        }

        // Returns a byte array containing the stream key.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public override byte[] GetBytes(int n)
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            byte[] keyStream = new byte[n];
            for (int i = 0; i < n; i++)
            {
                keyStream[i] = GeneratePRGA();
            }

            return keyStream;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public override byte[] Cipher(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            return base.Cipher(inputBuffer, inputOffset, inputCount);
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public override int Cipher(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            return base.Cipher(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        // Generates the next byte using the Pseudo-Random Generation Algorithm (PRGA).
        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte GeneratePRGA()
        {
            const int f = 0xFF;
            _x = (_x + 1) & f;
            _y = (_y + _sblock[_x]) & f;
            Swap(_sblock, _x, _y);
            return _sblock[(_sblock[_x] + _sblock[_y]) & f];
        }

        // Generates a stream key of specified length on the stack.
        protected internal override byte* KeyStream(int n)
        {
            if (n <= 0 || n > 256)
                throw new ArgumentOutOfRangeException(nameof(n),
                    GetResourceString("ArgumentOutOfRange_Bounds_Lower_Upper", 1, 256));

            byte* keyStream = stackalloc byte[n];
            for (int i = 0; i < n; i++)
            {
                keyStream[i] = GeneratePRGA();
            }

            return keyStream;
        }

        #endregion

        #region Tools

        // Creates a shallow copy of the current object.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public override object Clone()
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            ARC4CryptoProvider clone = (ARC4CryptoProvider)this.MemberwiseClone();
            clone._sblock = (byte*)Marshal.AllocHGlobal(256);
            Copy(this._sblock, clone._sblock);
            return clone;
        }

        // Returns a string representation of this object.
        [MethodImpl(MethodImplOptions.Synchronized)]
        public override string ToString()
        {
            if (_sblock == null)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            StringBuilder stringBuilder = new StringBuilder(784);

            for (int i = 0; i < 256; i++)
            {
                stringBuilder.Append($"{_sblock[i]:x2}");
                stringBuilder.Append(i % 16 == 15 ? "\r\n" : " ");
            }

            stringBuilder.Append($"x={_x:x2}, y={_y:x2}");
            
            return stringBuilder.ToString();
        }

        // Destructor to release allocated resources.
        ~ARC4CryptoProvider()
        {
            Dispose(false);
        }

        // Releases resources used by the object.
        public override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Releases resources used by the object, with optional managed resource disposal.
        [MethodImpl(MethodImplOptions.Synchronized)]
        protected virtual void Dispose(bool disposing)
        {
            if (_sblock == null)
                return;

            if (disposing)
            {
                Initialize(_sblock);
                _x = 0;
                _y = 0;
            }

            Marshal.FreeHGlobal((IntPtr)_sblock);
            _sblock = null;
        }

        #endregion
    }
}