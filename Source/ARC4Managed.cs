using static System.Security.Cryptography.InternalTools;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Provides managed version <see cref = "ARC4CryptoProvider" />.
    ///     This class could not be inherited.
    /// </summary> 
    public sealed class ARC4Managed : ARC4
    {
        private const int KeySizeDefaultValue = 128;
        private const int IVSizeValue = 4;
        private int _skip = 0;
        private bool _plus = false;
        private bool _disposed = false;

        /// <summary>Gets or sets the block size, in bits, of the cryptographic operation.</summary>
        /// <returns>The block size, in bits.</returns>
        /// <exception cref="CryptographicException">The block size is invalid.</exception>
        public override int BlockSize
        {
            get
            {
                return BlockSizeValue;
            }
            set
            {
                BlockSizeValue = (value & 7) == 0
                    ? value
                    : throw new CryptographicException(GetResourceString("Cryptography_InvalidBlockSize"));
            }
        }

        private void Initialize(int skip = 0, bool arc4plus = false)
        {
            _skip = skip;
            _plus = arc4plus;
            BlockSizeValue = 8;
            FeedbackSizeValue = 8;
            LegalBlockSizesValue = new KeySizes[]
            {
                new KeySizes(8, int.MaxValue, 8)
            };
            LegalKeySizesValue = new KeySizes[]
            {
                new KeySizes(8, int.MaxValue, 8)
            };
            ModeValue = CipherMode.CTS;
            PaddingValue = PaddingMode.None;
        }

        /// <summary>
        ///     Initializes a new object <see cref = "ARC4Managed" /> using random parameters.
        /// </summary> 
        public ARC4Managed(int skip = 0, bool arc4plus = false)
        {
            GenerateKey();
            GenerateIV();
            KeySizeValue = KeyValue.Length * 8;
            Initialize(skip, arc4plus);
        }

        /// <summary>
        ///     Initializes a new object <see cref = "ARC4Managed" />
        ///     using the specified key and initialization vector.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "iv">
        ///     Initialization vector.
        /// </param> 
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        public ARC4Managed(byte[] key, byte[] iv, int skip = 0, bool arc4plus = false)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key),GetResourceString("ArgumentNull_WithParamName", nameof(key)));
            if (key.Length == 0)
                throw new CryptographicException(GetResourceString("Cryptography_InvalidKeySize"));
            if (iv == null)
                throw new ArgumentNullException(nameof(key), GetResourceString("ArgumentNull_WithParamName", nameof(iv)));
            if (iv.Length != IVSizeValue)
                throw new CryptographicException(GetResourceString("Cryptography_InvalidIVSize"));

            int keyLength = key.Length;
            KeyValue = new byte[keyLength];
            KeySizeValue = key.Length * 8;
            Array.Copy(key, KeyValue, keyLength);
            IVValue = new byte[IVSizeValue];
            Array.Copy(iv, IVValue, IVSizeValue);
            Initialize(skip, arc4plus);
        }

        /// <summary>
        ///     Initializes a new object <see cref = "ARC4Managed" />
        ///     using the specified key.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        public ARC4Managed(byte[] key, int skip = 0, bool arc4plus = false)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key),GetResourceString("ArgumentNull_WithParamName", nameof(key)));
            if (key.Length == 0)
                throw new CryptographicException(GetResourceString("Cryptography_InvalidKeySize"));

            int keyLength = key.Length;
            KeyValue = new byte[keyLength];
            KeySizeValue = key.Length * 8;
            Array.Copy(key, KeyValue, keyLength);
            IVValue = BitConverter.GetBytes(0);
            Initialize(skip, arc4plus);
        }

        /// <summary>
        ///     Creates a symmetric encryptor object
        ///     using current property <see cref = "SymmetricAlgorithm.Key" />
        ///     and default initialization vector (<see cref = "SymmetricAlgorithm.IV "/>).
        /// </summary>
        /// <param name = "rgbKey">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <returns>
        ///     Symmetric encoder object.
        /// </returns>
        public ICryptoTransform CreateEncryptor(byte[] rgbKey)
        {
            return CreateEncryptor(rgbKey);
        }

        /// <summary>
        ///     Creates a symmetric decryptor object
        ///     using current property <see cref = "SymmetricAlgorithm.Key" />
        ///     and default initialization vector (<see cref = "SymmetricAlgorithm.IV "/>).
        /// </summary>
        /// <param name = "rgbKey">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <returns>
        ///     Symmetric decoder object.
        /// </returns>

        public ICryptoTransform CreateDecryptor(byte[] rgbKey)
        {
            return new ARC4CryptoTransform(rgbKey, _skip, _plus);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.CreateEncryptor(byte[], byte[])"/>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new ARC4CryptoTransform(rgbKey, rgbIV, _skip, _plus);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.CreateDecryptor(byte[], byte[])"/>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new ARC4CryptoTransform(rgbKey, rgbIV, _skip, _plus);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.GenerateKey"/>
        public override void GenerateKey()
        {
            KeyValue = new byte[KeySizeDefaultValue];
            KeySizeValue = KeySizeDefaultValue;
            InternalRng.GetBytes(KeyValue);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.GenerateIV"/>
        public override void GenerateIV()
        {
            byte[] iv = new byte[IVSizeValue];

            InternalRng.GetBytes(iv);
            IVValue = iv;
        }

        /// <inheritdoc cref="SymmetricAlgorithm.Dispose(bool)"/>
        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                EraseArray(ref KeyValue);
                EraseArray(ref IVValue);
            }

            base.Dispose(disposing);

            _disposed = true;
        }
    }
}
