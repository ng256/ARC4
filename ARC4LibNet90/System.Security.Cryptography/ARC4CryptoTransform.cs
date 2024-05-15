namespace System.Security.Cryptography
{
    /// <summary>
    ///     Performs cryptographic transformation of data using the <see cref = "ARC4CryptoProvider" /> algorithm.
    ///     This class could not be inherited.
    /// </summary> 
    public sealed class ARC4CryptoTransform : ICryptoTransform
    {
        private bool _disposed = false;
        private ARC4CryptoProvider _arc4;

        /// <summary>
        ///     Current internal state of the algorithm <see cref = "ARC4" />.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public ARC4SBlock State =>
            _disposed
                ? throw new ObjectDisposedException(nameof(ARC4CryptoTransform), "ObjectDisposed_Generic")
                : _arc4.State;

        /// <inheritdoc cref="ICryptoTransform.InputBlockSize"/>
        public int InputBlockSize => 1;

        /// <inheritdoc cref="ICryptoTransform.OutputBlockSize"/>
        public int OutputBlockSize => 1;

        /// <inheritdoc cref="ICryptoTransform.CanTransformMultipleBlocks"/>
        public bool CanTransformMultipleBlocks => true;

        /// <inheritdoc cref="ICryptoTransform.CanReuseTransform"/>
        public bool CanReuseTransform => true;

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4CryptoTransform" />, using the specified parameters.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        public ARC4CryptoTransform(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));

            _arc4 = new ARC4CryptoProvider(key);
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "iv">
        ///     Initialization vector.
        /// </param> 
        public ARC4CryptoTransform(byte[] key, byte[] iv)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));

            ArgumentNullException.ThrowIfNull(iv, nameof(iv));
            ArgumentOutOfRangeException.ThrowIfZero(iv.Length, nameof(iv));

            ArgumentOutOfRangeException.ThrowIfNotEqual(ARC4SBlock.ValidBytes(iv), true, nameof(ARC4SBlock));

            _arc4 = new ARC4CryptoProvider(key, iv);
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="sblock"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "sblock">
        ///     An instance of <see cref = "ARC4SBlock" />
        ///     used as the initial state of the ARC4 algorithm.
        /// </param> 
        public ARC4CryptoTransform(byte[] key, ARC4SBlock sblock)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));

            ArgumentNullException.ThrowIfNull(sblock, nameof(sblock));

            _arc4 = new ARC4CryptoProvider(key, sblock);
        }

        /// <inheritdoc cref="ICryptoTransform.TransformBlock"/>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            ObjectDisposedException.ThrowIf(_disposed, typeof(ARC4CryptoTransform));
            ArgumentNullException.ThrowIfNull(inputBuffer, nameof(inputBuffer));
            ArgumentNullException.ThrowIfNull(outputBuffer, nameof(outputBuffer));
            ArgumentOutOfRangeException.ThrowIfLessThan(inputOffset, 0, nameof(inputOffset));
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(inputCount, 0, nameof(inputCount));
            ArgumentOutOfRangeException.ThrowIfNotEqual(inputCount % InputBlockSize, 0, nameof(inputCount));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(inputCount, inputBuffer.Length, nameof(inputCount));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(inputBuffer.Length - inputCount, inputOffset, nameof(inputCount));

            Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
            _arc4.Cipher(outputBuffer, outputOffset, inputCount);
            return inputCount;
        }

        /// <inheritdoc cref="ICryptoTransform.TransformFinalBlock"/>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            ObjectDisposedException.ThrowIf(_disposed, typeof(ARC4CryptoTransform));
            ArgumentNullException.ThrowIfNull(inputBuffer, nameof(inputBuffer));
            ArgumentOutOfRangeException.ThrowIfLessThan(inputOffset, 0, nameof(inputOffset));
            ArgumentOutOfRangeException.ThrowIfLessThan(inputCount, 0, nameof(inputCount));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(inputCount, inputBuffer.Length, nameof(inputCount));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(inputBuffer.Length - inputCount, inputOffset, nameof(inputCount));

            byte[] outputBuffer = new byte[inputCount];
            Array.Copy(inputBuffer, inputOffset, outputBuffer, 0, inputCount);
            _arc4.Cipher(outputBuffer, 0, inputCount);
            return outputBuffer;
        }

        /// <summary>
        ///     Reset the instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="sblock"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "sblock">
        ///     An instance of <see cref = "ARC4SBlock" />
        ///     used as the initial state of the ARC4 algorithm.
        /// </param> 
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public void Reset(byte[] key, ARC4SBlock sblock)
        {
            ObjectDisposedException.ThrowIf(_disposed, typeof(ARC4CryptoTransform));

            _arc4 = new ARC4CryptoProvider(key, sblock);
        }

        private void EraseState()
        {
            if (_disposed) return;
            _arc4?.EraseState();
            _disposed = true;
        }

        /// <inheritdoc cref="IDisposable.Dispose"/>
        public void Dispose()
        {
            EraseState();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// <inheritdoc cref="object.Finalize"/>.
        /// </summary>
        ~ARC4CryptoTransform()
        {
            EraseState();
        }
    }
}
