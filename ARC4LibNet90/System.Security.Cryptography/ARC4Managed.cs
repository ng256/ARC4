namespace System.Security.Cryptography
{
    /// <summary>
    ///     Provides managed version <see cref = "ARC4CryptoProvider" />.
    ///     This class could not be inherited.
    /// </summary> 
    public sealed class ARC4Managed : ARC4
    {
        private const int KeySizeDefaultValue = 256;
        private const int IVSizeValue = 256;
        private readonly bool _disposed = false;

        /// <summary>
        ///     Initializes a new object <see cref = "ARC4Managed" /> using random parameters.
        /// </summary> 
        public ARC4Managed()
        {
            GenerateKey();
            GenerateIV();
            KeySizeValue = KeyValue.Length * 8;
            BlockSizeValue = 8;
            FeedbackSizeValue = 8;
            LegalBlockSizesValue = [new KeySizes(8, int.MaxValue, 8)];
            LegalKeySizesValue = [new KeySizes(8, int.MaxValue, 8)];
            ModeValue = CipherMode.CTS;
            PaddingValue = PaddingMode.None;
        }

        /// <summary>
        ///     Initializes a new object <see cref = "ARC4Managed" />
        ///     using the specified <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "iv">
        ///     Initialization vector.
        /// </param> 
        public ARC4Managed(byte[] key, byte[] iv)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));

            ArgumentNullException.ThrowIfNull(iv, nameof(iv));
            ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSizeValue, nameof(iv));

            ArgumentOutOfRangeException.ThrowIfNotEqual(ARC4SBlock.ValidBytes(iv), true, nameof(ARC4SBlock));

            int keyLength = key.Length;
            KeyValue = new byte[keyLength];
            KeySizeValue = key.Length * 8;
            Array.Copy(key, KeyValue, keyLength);
            IVValue = new byte[IVSizeValue];
            Array.Copy(iv, IVValue, IVSizeValue);
            BlockSizeValue = 8;
            FeedbackSizeValue = 8;
            LegalBlockSizesValue = [new KeySizes(8, int.MaxValue, 8)];
            LegalKeySizesValue = [new KeySizes(8, int.MaxValue, 8)];
            ModeValue = CipherMode.CTS;
            PaddingValue = PaddingMode.None;
        }

        /// <summary>
        ///     Initializes a new object <see cref = "ARC4Managed" />
        ///     using the specified <paramref name="key"/> and <paramref name="sblock"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "sblock">
        ///     An instance of <see cref = "ARC4SBlock" />
        ///     used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param> 
        public ARC4Managed(byte[] key, ARC4SBlock[] sblock)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentOutOfRangeException.ThrowIfZero(key.Length, nameof(key));
            ArgumentNullException.ThrowIfNull(sblock, nameof(sblock));
            ArgumentOutOfRangeException.ThrowIfZero(sblock.Length, nameof(sblock));

            int keyLength = key.Length;
            KeyValue = new byte[keyLength];
            KeySizeValue = key.Length * 8;
            Array.Copy(key, KeyValue, keyLength);
            IVValue = new byte[IVSizeValue];
            Array.Copy(sblock, IVValue, IVSizeValue);
            BlockSizeValue = 8;
            FeedbackSizeValue = 8;
            LegalBlockSizesValue = [new KeySizes(8, int.MaxValue, 8)];
            LegalKeySizesValue = [new KeySizes(8, int.MaxValue, 8)];
            ModeValue = CipherMode.CTS;
            PaddingValue = PaddingMode.None;
        }

        /// <summary>
        ///     Initializes a new object <see cref = "ARC4Managed" /> using the specified encryption key.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param> 
        public ARC4Managed(byte[] key) : this(key, ARC4SBlock.DefaultSBlock)
        {

        }

        /// <summary>
        ///     Creates a symmetric encryptor object
        ///     with the given property <see cref = "SymmetricAlgorithm.Key" />
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
            return CreateEncryptor(rgbKey, ARC4SBlock.DefaultSBlock);
        }

        /// <summary>
        ///     Creates a symmetric decryptor object
        ///     with the given property <see cref = "SymmetricAlgorithm.Key" />
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
            return new ARC4CryptoTransform(rgbKey, ARC4SBlock.DefaultSBlock);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.CreateEncryptor(byte[], byte[])"/>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new ARC4CryptoTransform(rgbKey, rgbIV);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.CreateDecryptor(byte[], byte[])"/>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new ARC4CryptoTransform(rgbKey, rgbIV);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.GenerateKey"/>
        public override void GenerateKey()
        {
            KeyValue = new byte[KeySizeDefaultValue];
            KeySizeValue = KeySizeDefaultValue;
            CryptoProvider.InternalRng.GetBytes(KeyValue);
        }

        /// <inheritdoc cref="SymmetricAlgorithm.GenerateIV"/>
        public override void GenerateIV()
        {
            using (ARC4SBlock sblock = ARC4SBlock.GenerateRandom())
            {
                IVValue = sblock;
            }
        }
    }
}
