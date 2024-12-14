using System.Text;
using System.Threading;
using static System.Security.Cryptography.InternalTools;

namespace System.Security.Cryptography
{
    // RC4A algorithm implementation based on the 2004 design by Souradyuti Paul and Bart Preneel.
    [Serializable]
    [SecurityCritical]
    internal class ARC4DualCryptoProvider : CryptoProvider
    {
        private readonly CryptoProvider _state1;
        private readonly CryptoProvider _state2;
        private bool _disposed = false;

        private int _k;

        public ARC4DualCryptoProvider(bool plus = false)
        {
            const uint seed = 4294967295 / 2;

            _state1 = plus 
                ? (CryptoProvider) new ARC4CryptoProvider() 
                : new ARC4PlusCryptoProvider();
            _state2 = plus 
                ? (CryptoProvider)new ARC4CryptoProvider(seed) 
                : new ARC4PlusCryptoProvider(seed);
        }

        public ARC4DualCryptoProvider(CryptoProvider state1, CryptoProvider state2)
        {
            _state1 = state1 ?? throw new ArgumentNullException(nameof(state1), 
                GetResourceString("ArgumentNull_WithParamName", nameof(state1)));
            _state2 = state2 ?? throw new ArgumentNullException(nameof(state2),
                GetResourceString("ArgumentNull_WithParamName", nameof(state2)));
        }

        public ARC4DualCryptoProvider(byte[] iv, bool plus = false)
        {
            _state1 = plus
                ? (CryptoProvider)new ARC4CryptoProvider(iv)
                : new ARC4PlusCryptoProvider(iv);
            _state2 = plus
                ? (CryptoProvider)new ARC4CryptoProvider(iv, 4)
                : new ARC4PlusCryptoProvider(iv, 4);
        }

        public ARC4DualCryptoProvider(long seed, bool plus = false) 
            : this(BitConverter.GetBytes(seed), plus)
        {
        }

        public ARC4DualCryptoProvider(ulong seed, bool plus = false) 
            : this(BitConverter.GetBytes(seed), plus)
        {
        }

        public override byte NextByte()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            return GeneratePRGA();
        }

        public override byte GetByte(byte value)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            return (value & 1) != 0
                ? _state1.GetByte(value) 
                : _state2.GetByte(value);
        }

        public override void Update(byte[] key)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            _state1.Update(key);
            _state2.Update(key);
        }

        public override void DropDown(int n)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            _state1.DropDown(n);
            _state2.DropDown(n);
        }

        public override byte[] GetBytes(int n)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));

            byte[] keyStream = new byte[n];
            for (int i = 0; i < n; i++)
            {
                keyStream[i] = GeneratePRGA();
            }

            return keyStream;
        }

        protected internal override unsafe byte* KeyStream(int n)
        {
            if (n <= 0 || n > 256)
                throw new ArgumentOutOfRangeException(nameof(n),
                    GetResourceString("ArgumentOutOfRange_Bounds_Lower_Upper", 1, 256));

            byte* keyStream1 = _state1.KeyStream(n);
            byte* keyStream2 = _state2.KeyStream(n);

            byte* keyStream = stackalloc byte[n];
            for (int i = 0; i < n; i++)
            {
                keyStream[i] = (i & 1) > 0 ? keyStream1[i] : keyStream2[2];
            }

            return keyStream;
        }

        // Generates the next byte using the Pseudo-Random Generation Algorithm (PRGA+).
        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected internal byte GeneratePRGA()
        {
            byte[] output = new byte[2];

            byte k1 = _state1.NextByte();
            byte k2 = _state2.NextByte();
            byte k = (_k = ~_k & 1) == 0 ? _state1.GetByte(k2) : output[1] = _state2.GetByte(k1);

            return k;
        }

        public override string ToString()
        {
            string s2 = _state2.ToString();
            string s1 = _state1.ToString();

            const StringSplitOptions options = StringSplitOptions.None;
            string[] separator = new string[] { "\r\n", "\n" };
            string[] lines1 = s1.Split(separator, options);
            string[] lines2 = s2.Split(separator, options);
            int maxLines = Math.Max(lines1.Length, lines2.Length);

            string[] result = new string[maxLines];
            for (int i = 0; i < maxLines; i++)
            {
                string line1 = i < lines1.Length ? lines1[i] : string.Empty;
                string line2 = i < lines2.Length ? lines2[i] : string.Empty;

                result[i] = $"{line1} | {line2}".Trim();
            }

            return string.Join("\r\n", result);
        }

        public override void Dispose()
        {
            Dispose(true);
        }

        public override object Clone()
        {
            return new ARC4DualCryptoProvider(
                (CryptoProvider)_state1.Clone(), 
                (CryptoProvider)_state2.Clone());
        }

        protected void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _state1?.Dispose();
                _state2?.Dispose();
                _k = 0;
            }

            _disposed = true;
        }
    }
}
