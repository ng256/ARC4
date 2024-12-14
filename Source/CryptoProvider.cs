using static System.Security.Cryptography.InternalTools;

namespace System.Security.Cryptography
{
    internal abstract unsafe class CryptoProvider : IDisposable, ICloneable
    {
        public static CryptoProvider Create(byte[] key, byte[] iv, int skip = 0, bool plus = false)
        {
            CryptoProvider provider;

            if (iv == null)
                provider = plus
                    ? (CryptoProvider)new ARC4CryptoProvider()
                    : new ARC4PlusCryptoProvider();
            else switch (iv.Length)
            {
                case 4:
                case 256:
                    provider = plus
                        ? (CryptoProvider)new ARC4CryptoProvider(iv)
                        : new ARC4PlusCryptoProvider(iv);
                    break;
                case 8:
                        provider = new ARC4DualCryptoProvider(iv, plus);
                    break;
                default:
                    throw new CryptographicException(GetResourceString("Cryptography_InvalidIVSize"));
            }

            if (key != null && key.Length > 0) 
                provider.Update(key);

            if (skip > 0)
                provider.DropDown(skip);

            return provider;
        }

        public static CryptoProvider Create(byte[] key, int seed, int skip = 0, bool plus = false)
        {
            return Create(key, BitConverter.GetBytes(seed), skip, plus);
        }

        public static CryptoProvider Create(byte[] key, uint seed, int skip = 0, bool plus = false)
        {
            return Create(key, BitConverter.GetBytes(seed), skip, plus);
        }

        public static CryptoProvider Create(byte[] key, long seed, int skip = 0, bool plus = false)
        {
            return Create(key, BitConverter.GetBytes(seed), skip, plus);
        }

        public static CryptoProvider Create(byte[] key, ulong seed, int skip = 0, bool plus = false)
        {
            return Create(key, BitConverter.GetBytes(seed), skip, plus);
        }

        // Generates a next byte.
        public abstract byte NextByte();

        // Cipher a value without changing state.
        public abstract byte GetByte(byte value);

        // Update the current state using encryption key.
        public abstract void Update(byte[] key);

        // Skip first n bytes.
        public abstract void DropDown(int n);

        // Generates the key stream.
        public abstract byte[] GetBytes(int n);

        // Release unmanaged resources.
        public abstract void Dispose();

        // Return a copy of the current object.
        public abstract object Clone();

        protected internal abstract byte* KeyStream(int n);

        // Initializes the state array with values from 0 to 255.
        internal void Initialize(byte* sblock)
        {
            for (int i = 0; i < 256; i++)
            {
                sblock[i] = (byte)i;
            }
        }

        // Initializes the state using a linear congruential generator.
        internal void Initialize(byte* sblock, byte[] iv, int index = 0)
        {
            int r = iv[0 + index];
            int x = iv[1 + index];
            int a = ((iv[2 + index] & 0x3F) << 2) | 1;
            int c = ((iv[3 + index] & 0x7F) << 1) | 1;
            int s = (byte)(((iv[2 + index] & 0xC0) >> 5) | ((iv[3 + index] & 0x80) >> 7));

            const int m = 256;
            for (int i = 0; i < m; i++)
            {
                int b = (x = (a * x + c) & (m - 1)) ^ r;
                sblock[i] = (byte)(((b << s) | (b >> (8 - s))) & (m - 1));
            }
        }

        // Swaps two elements in the byte array.
        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Swap(byte* bytes, int i, int j)
        {
            if (i != j)
            {
                bytes[i] ^= bytes[j];
                bytes[j] ^= bytes[i];
                bytes[i] ^= bytes[j];
            }
        }

        // Verifies that the byte array contains all possible values in a single period.
        internal static bool IsValid(byte* bytes)
        {
            if (bytes == null)
                return false;

            const int seenSize = (1 << 8) / sizeof(int);
            int* seenPtr = stackalloc int[seenSize];

            for (int i = 0; i < seenSize; i++)
                seenPtr[i] = 0;

            for (int i = 0; i < 256; i++)
            {
                byte b = bytes[i];
                int flag = 1 << (b & 0x1F);
                int offset = b >> 5;

                if ((seenPtr[offset] & flag) != 0)
                    return false;

                seenPtr[offset] |= flag;
            }

            return true;
        }

        // Copies the contents of one array into another.
        internal static void Copy(byte* input, byte* output)
        {
            long* longInput = (long*)input;
            long* longOutput = (long*)output;

            const int count = 256 / sizeof(long);
            for (int i = 0; i < count; i++)
            {
                *longOutput++ = *longInput++;
            }
        }

        protected static void CheckBuffer(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException(nameof(inputBuffer),
                    GetResourceString("ArgumentNull_Buffer"));
            if (inputOffset < 0 || inputOffset >= inputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputOffset),
                    GetResourceString("ArgumentOutOfRange_IndexCountBuffer"));
            if (inputCount < 0 || inputCount > inputBuffer.Length - inputOffset)
                throw new ArgumentOutOfRangeException(nameof(inputCount),
                    GetResourceString("ArgumentOutOfRange_IndexCountBuffer"));
        }

        protected static void CheckBuffer(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException(nameof(inputBuffer),
                    GetResourceString("ArgumentNull_Buffer"));
            if (outputBuffer == null)
                throw new ArgumentNullException(nameof(outputBuffer),
                    GetResourceString("ArgumentNull_Buffer"));
            if (inputOffset < 0 || inputOffset >= inputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputOffset),
                    GetResourceString("ArgumentOutOfRange_IndexCountBuffer"));
            if (outputOffset < 0 || outputOffset >= outputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(outputOffset),
                    GetResourceString("ArgumentOutOfRange_IndexCountBuffer"));
            if (inputCount < 0 || inputCount > inputBuffer.Length - inputOffset)
                throw new ArgumentOutOfRangeException(nameof(inputCount),
                    GetResourceString("ArgumentOutOfRange_IndexCountBuffer"));
            if (inputCount > outputBuffer.Length - outputOffset)
                throw new ArgumentException(GetResourceString("Arg_BufferTooSmall"), nameof(outputBuffer));
        }

        // Encrypts or decrypts a block of data using the current state array.
        public virtual byte[] Cipher(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            CheckBuffer(inputBuffer, inputOffset, inputCount);

            byte[] result = new byte[inputCount];
            int remainingBytes = inputCount;
            int currentIndex = inputOffset;
            int resultIndex = 0;

            const int blockSize = 256;
            while (remainingBytes > 0)
            {
                int currentBlockSize = remainingBytes > blockSize
                    ? blockSize
                    : remainingBytes;

                // Generate key stream for the current block.
                byte* keyStream = KeyStream(currentBlockSize);

                // Process the current block.
                for (int offset = 0; offset < currentBlockSize; offset++)
                {
                    result[resultIndex + offset]
                        = (byte)(inputBuffer[currentIndex + offset] ^ keyStream[offset]);
                }

                // Update indices and remaining bytes.
                currentIndex += currentBlockSize;
                resultIndex += currentBlockSize;
                remainingBytes -= currentBlockSize;
            }

            return result;
        }


        // Encrypts or decrypts a block of data and stores the result in the output block.
        public virtual int Cipher(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            CheckBuffer(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);

            int remainingBytes = inputCount;
            int currentInputIndex = inputOffset;
            int currentOutputIndex = outputOffset;

            const int blockSize = 256;
            while (remainingBytes > 0)
            {
                int currentBlockSize = remainingBytes > blockSize
                    ? blockSize
                    : remainingBytes;

                // Generate key stream for the current block.
                byte* keyStream = KeyStream(currentBlockSize);

                // Process the current block.
                for (int offset = 0; offset < currentBlockSize; offset++)
                {
                    outputBuffer[currentOutputIndex + offset]
                        = (byte)(inputBuffer[currentInputIndex + offset] ^ keyStream[offset]);
                }

                // Update indices and remaining bytes.
                currentInputIndex += currentBlockSize;
                currentOutputIndex += currentBlockSize;
                remainingBytes -= currentBlockSize;
            }

            return inputCount - remainingBytes;
        }
    }
}
