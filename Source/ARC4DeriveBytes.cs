using System.Text;
using static System.Security.Cryptography.InternalTools;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Implements the function of generating a key based on a password and salt
    ///     using a pseudo-random number generator <see cref = "ARC4" />.
    ///     This class could not be inherited.
    /// </summary> 
    public sealed class ARC4DeriveBytes : DeriveBytes
    {
        private CryptoProvider _initialState;
        private CryptoProvider _currentState;
        private byte[] _key;
        private byte[] _salt;
        private bool _disposed = false;

        /// <summary>
        ///     Current internal state of the algorithm <see cref="ARC4"/>.
        /// </summary> 
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4DeriveBytes"/> is disposed.
        /// </exception> 
        internal string State
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                        GetResourceString("ObjectDisposed_Generic"));

                return _currentState.ToString();
            }
        }

        /// <summary>
        ///     Gets or sets the key salt.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4DeriveBytes"/> is disposed.
        /// </exception> 
        public byte[] Salt
        {
            get
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                        GetResourceString("ObjectDisposed_Generic"));
                }

                return _salt;
            }
            set
            {
                if (value.Length < 4)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), value.Length,
                        GetResourceString("Argument_InvalidArrayLength", 4));
                }
                _salt = value;
                Reset();
            }
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4DeriveBytes" />
        ///     using the specified <paramref name="key"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown if the <paramref name="key"/> parameter is <see langword="null"/>.
        /// </exception> 
        public ARC4DeriveBytes(byte[] key)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _salt = new byte[4];
            InternalRng.GetBytes(_salt);
            Reset();
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4DeriveBytes" />
        ///     using the specified <paramref name="key"/> and <paramref name="salt"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name = "salt">
        ///     Key salt. It must contain at least 4 bytes.
        /// </param> 
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown if less than 4 bytes of salt is passed.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///     Thrown if one of the required arguments is <see langword="null"/>.
        /// </exception> 
        public ARC4DeriveBytes(byte[] key, params byte[] salt)
        {
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (salt.Length < 4) throw new ArgumentOutOfRangeException(nameof(salt), salt.Length,
                GetResourceString("Argument_InvalidArrayLength", 4));

            _key = key ?? throw new ArgumentNullException(nameof(key));
            _salt = salt;
            Reset();
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4DeriveBytes" />
        ///     using the specified <paramref name="password"/> and <paramref name="salt"/>.
        /// </summary>
        /// <param name = "password">
        ///     A string containing the secret password used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name = "encoding">
        ///     Character encoding for password to bytes conversion.
        /// </param>
        /// <param name = "salt">
        ///     Key salt. It must contain at least 4 bytes.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown if less than 4 bytes of salt is passed.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///     Thrown if one of the required arguments is <see langword="null"/>.
        /// </exception> 
        public ARC4DeriveBytes(string password, Encoding encoding, params byte[] salt)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (salt.Length < 4) throw new ArgumentOutOfRangeException(nameof(salt), salt.Length,
                GetResourceString("Argument_InvalidArrayLength", 4));

            _key = encoding.GetBytes(password);
            _salt = salt;
            Reset();
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4DeriveBytes" />
        ///     using the specified <paramref name="password"/>.
        /// </summary>
        /// <param name = "password">
        ///     A string containing the secret password used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name = "encoding">
        ///     Character encoding for password to bytes conversion.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown if one of the required arguments is <see langword="null"/>.
        /// </exception> 
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown if less than 4 bytes of salt is passed.
        /// </exception>
        public ARC4DeriveBytes(string password, Encoding encoding)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));

            _key = encoding.GetBytes(password);
            _salt = new byte[4];
            InternalRng.GetBytes(_salt);
            Reset();
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4DeriveBytes" />
        ///     using the specified <paramref name="password"/> and <paramref name="salt"/>.
        /// </summary>
        /// <param name = "password">
        ///     A string containing the secret password used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name = "salt">
        ///     Key salt. It must contain at least 4 bytes.
        /// </param> 
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown if less than 4 bytes of salt is passed.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///     Thrown if one of the required arguments is <see langword="null"/>.
        /// </exception> 
        public ARC4DeriveBytes(string password, params byte[] salt) : this(password, Encoding.UTF8, salt)
        {
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4DeriveBytes" />
        ///     using the specified <paramref name="password"/>.
        /// </summary>
        /// <param name = "password">
        ///     A string containing the secret password used for the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown if the <paramref name="password"/> parameter is <see langword="null"/>.
        /// </exception> 

        public ARC4DeriveBytes(string password) : this(password, Encoding.UTF8)
        {
        }

        /// <inheritdoc cref="DeriveBytes.GetBytes"/>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4DeriveBytes"/> is disposed.
        /// </exception> 
        public override unsafe byte[] GetBytes(int cb)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));
            }

            byte[] result = _currentState.GetBytes(cb);

            return result;
        }

        /// <inheritdoc cref="DeriveBytes.Reset"/>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4DeriveBytes"/> is disposed.
        /// </exception> 
        public override void Reset()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ARC4DeriveBytes),
                    GetResourceString("ObjectDisposed_Generic"));
            }

            _currentState = CryptoProvider.Create(_key, _salt);
            //_currentState.Update(_key);
        }

        /// <inheritdoc cref="DeriveBytes.Dispose(bool)"/>
        protected override void Dispose(bool disposing)
        {
            if (_disposed) return;
            _initialState?.Dispose();
            _currentState?.Dispose();
            _disposed = true;
            if (!disposing) return;
            EraseArray(ref _key);
            EraseArray(ref _salt);
            _initialState = null;
            _currentState = null;
        }

        /// <summary>
        /// <inheritdoc cref="object.Finalize"/>.
        /// </summary>
        ~ARC4DeriveBytes()
        {
            Dispose(false);
        }
    }
}
