using System.Text;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Implements the function of generating a key based on a password and salt
    ///     using a pseudo-random number generator <see cref = "ARC4" />.
    ///     This class could not be inherited.
    /// </summary> 
    public sealed class ARC4DeriveBytes : DeriveBytes
    {
        private ARC4CryptoProvider _arc4;
        private byte[] _key;
        private byte[] _salt;
        private bool _disposed = false;

        /// <summary>
        ///     Current internal state of the algorithm <see cref = "ARC4" />.
        /// </summary> 
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4DeriveBytes"/> is disposed.
        /// </exception> 
        public ARC4SBlock State
        {
            get
            {
                ObjectDisposedException.ThrowIf(_disposed, typeof(ARC4DeriveBytes));
                return _arc4.State;
            }
        }

        /// <summary>
        ///     Gets or sets the key salt.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4DeriveBytes"/> is disposed.
        /// </exception> 
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown if current size of <see langword="value"/> less than 4.
        /// </exception> 
        public byte[] Salt
        {
            get
            {
                ObjectDisposedException.ThrowIf(_disposed, typeof(ARC4DeriveBytes));
                return _salt;
            }
            set
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(value.Length, 4, nameof(value));
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
            ArgumentNullException.ThrowIfNull(key, nameof(key));

            _key = key;
            _salt = new byte[4];
            CryptoProvider.InternalRng.GetBytes(_salt);
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
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentNullException.ThrowIfNull(salt, nameof(salt));
            ArgumentOutOfRangeException.ThrowIfLessThan(salt.Length, 4, nameof(salt));

            _key = key;
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
        /// <exception cref="ArgumentException">
        ///     Thrown if password is <see langword="null"/> or empty.
        /// </exception> 
        public ARC4DeriveBytes(string password, Encoding encoding, params byte[] salt)
        {
            ArgumentException.ThrowIfNullOrEmpty(password, nameof(password));
            ArgumentNullException.ThrowIfNull(encoding, nameof(encoding));
            ArgumentNullException.ThrowIfNull(salt, nameof(salt));
            ArgumentOutOfRangeException.ThrowIfLessThan(salt.Length, 4, nameof(salt));

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
            ArgumentException.ThrowIfNullOrEmpty(password, nameof(password));
            ArgumentNullException.ThrowIfNull(encoding, nameof(encoding));

            _key = encoding.GetBytes(password);
            _salt = new byte[4];
            CryptoProvider.InternalRng.GetBytes(_salt);
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
            ObjectDisposedException.ThrowIf(_disposed, typeof(ARC4DeriveBytes));

            byte[] result = new byte[cb];
            int length = result.Length;
            fixed (byte* ptr = result)
            {
                for (var i = 0; i < length; i++)
                {
                    *(ptr + i) = _arc4.NextByte();
                }
            }

            return result;
        }

        /// <inheritdoc cref="DeriveBytes.Reset"/>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4DeriveBytes"/> is disposed.
        /// </exception> 
        public override void Reset()
        {
            ObjectDisposedException.ThrowIf(_disposed, typeof(ARC4DeriveBytes));

            _arc4 = new ARC4CryptoProvider(_key, ARC4SBlock.FromSalt(_salt));
        }

        /// <inheritdoc cref="DeriveBytes.Dispose(bool)"/>
        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            _arc4?.EraseState();
            _disposed = true;

            if (!disposing)
                return;

            CryptoProvider.EraseArray(ref _key);
            CryptoProvider.EraseArray(ref _salt);

            _arc4 = null;
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
