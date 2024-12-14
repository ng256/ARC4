namespace System.Security.Cryptography
{
    /// <summary>
    ///     Performs cryptographic transformation of data using the <see cref = "ARC4CryptoProvider" /> algorithm.
    ///     This class could not be inherited.
    /// </summary> 
    public sealed class ARC4CryptoTransform : ICryptoTransform
    {
        private bool _disposed = false;
        private CryptoProvider _initialState;
        private CryptoProvider _currentState;

        /// <summary>
        ///     Current internal state of the algorithm <see cref = "ARC4" />.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        internal string State =>
            _disposed
                ? throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    InternalTools.GetResourceString("ObjectDisposed_Generic"))
                : _currentState.ToString();

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
        public ARC4CryptoTransform(byte[] key, int skip = 0, bool plus = false)
        {
            _initialState = CryptoProvider.Create(key, null, skip, plus);
            _initialState.Update(key);
            _currentState = (ARC4CryptoProvider) _initialState.Clone();
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
        public ARC4CryptoTransform(byte[] key, byte[] iv, int skip = 0, bool plus = false)
        {
            _initialState = CryptoProvider.Create(key, iv, skip, plus);
            _initialState.Update(key);
            _currentState = (ARC4CryptoProvider)_initialState.Clone();
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "seed">
        ///     A signed 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param> 
        public ARC4CryptoTransform(byte[] key, int seed, int skip = 0, bool plus = false) 
            : this(key, BitConverter.GetBytes(seed))
        {
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param> 
        public ARC4CryptoTransform(byte[] key, uint seed, int skip = 0, bool plus = false) 
            : this(key, BitConverter.GetBytes(seed))
        {
        }

        /// <inheritdoc cref="ICryptoTransform.TransformBlock"/>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, 
            byte[] outputBuffer, int outputOffset)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    InternalTools.GetResourceString("ObjectDisposed_Generic"));

            int count = _currentState.Cipher(inputBuffer, inputOffset, inputCount, 
                outputBuffer, outputOffset);

            return count;
        }

        /// <inheritdoc cref="ICryptoTransform.TransformFinalBlock"/>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    InternalTools.GetResourceString("ObjectDisposed_Generic"));

            byte[] outputBuffer = _currentState.Cipher(inputBuffer, inputOffset, inputCount);
            Reset();

            //throw new CryptographicException()

            return outputBuffer;
        }

        /// <summary>
        ///     Reset the <see cref = "ARC4CryptoTransform" /> instance state.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public void Reset()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    InternalTools.GetResourceString("ObjectDisposed_Generic"));

            _currentState.Dispose();
            _currentState = (ARC4CryptoProvider)_initialState.Clone();
        }

        /// <summary>
        ///     Reset the <see cref = "ARC4CryptoTransform" /> instance state
        ///     using the specified <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name = "iv">
        ///     An initialization vector
        ///     used as the initial state of the ARC4 algorithm.
        /// </param> 
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public void Reset(byte[] key, byte[] iv)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    InternalTools.GetResourceString("ObjectDisposed_Generic"));

            _currentState.Dispose();
            _currentState = new ARC4CryptoProvider(iv);
            _currentState.Update(key);
        }

        /// <summary>
        ///     Reset the instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="seed"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name = "seed">
        ///     A signed 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param> 
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public void Reset(byte[] key, int seed)
        {
            Reset(key, BitConverter.GetBytes(seed));
        }

        /// <summary>
        ///     Reset the instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="seed"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param> 
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public void Reset(byte[] key, uint seed)
        {
            Reset(key, BitConverter.GetBytes(seed));
        }

        /// <summary>
        /// <inheritdoc cref="object.Finalize"/>.
        /// </summary>
        ~ARC4CryptoTransform()
        {
            Dispose(false);
        }

        // Dispose current instance.
        private void Dispose(bool disposing)
        {
            if (_disposed) 
                return;
            if (disposing)

            {
                _initialState?.Dispose();
                _currentState?.Dispose();
            }

            _initialState = null;
            _currentState = null;
            _disposed = true;
        }

        /// <inheritdoc cref="IDisposable.Dispose"/>
        public void Dispose()
        {
            if (_disposed) return;

            Dispose(true);
            GC.SuppressFinalize(this);
        }

    }
}