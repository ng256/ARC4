using System.IO;
using System.Text;
using static System.Security.Cryptography.InternalTools;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Implements object <see Cref = "Stream" /> using a cryptographic algorithm <see Cref = "ARC4" /> for data encryption.
    ///     This class could not be inherited.
    /// </summary>
    public sealed class ARC4Stream : Stream
    {
        private Stream _stream;
        private CryptoProvider _arc4;
        private readonly bool _leaveOpen = false;
        private bool _disposed = false;

        /// <inheritdoc cref="Stream.CanRead"/>
        public override bool CanRead => _stream.CanRead;

        /// <inheritdoc cref="Stream.CanSeek"/>
        public override bool CanSeek => _stream.CanSeek;

        /// <inheritdoc cref="Stream.CanWrite"/>
        public override bool CanWrite => _stream.CanWrite;

        /// <inheritdoc cref="Stream.Length"/>
        public override long Length => _stream.Length;

        /// <inheritdoc cref="Stream.Position"/>
        public override long Position
        {
            get => _stream.Position;
            set => _stream.Position = value;
        }
        
        /// <summary>
        ///     Current internal state of the algorithm <see cref = "ARC4" />.
        /// </summary> 
        internal string State => _arc4.ToString();

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream and encryption password.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the secret password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "encoding">
        ///     The character encoding used to convert the password.
        ///     If the value <see langword = "null" /> is passed, then the encoding will be used
        ///     <see cref = "Encoding.UTF8" />
        /// </param>
        /// <param name = "iv">
        ///     The initialization vector used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param>
        public ARC4Stream(Stream stream, string password, Encoding encoding, byte[] iv, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));
            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));
            encoding = encoding ?? Encoding.UTF8;
            byte[] key = encoding.GetBytes(password);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);
            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the secret password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "encoding">
        ///     The character encoding used to convert the password.
        ///     If the value <see langword = "null" /> is passed, then the encoding will be used
        /// <see cref = "Encoding.UTF8" />
        /// </param>
        /// <param name = "seed">
        ///     A signed 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, Encoding encoding, int seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            encoding = encoding ?? Encoding.UTF8;
            byte[] key = encoding.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);
            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the secret password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "encoding">
        ///     The character encoding used to convert the password.
        ///     If the value <see langword = "null" /> is passed, then the encoding will be used
        /// <see cref = "Encoding.UTF8" />
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, Encoding encoding, uint seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            encoding = encoding ?? Encoding.UTF8;
            byte[] key = encoding.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the secret password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "encoding">
        ///     The character encoding used to convert the password.
        ///     If the value <see langword = "null" /> is passed, then the encoding will be used
        /// <see cref = "Encoding.UTF8" />
        /// </param>
        /// <param name = "seed">
        ///     A signed 64-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, Encoding encoding, long seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            encoding = encoding ?? Encoding.UTF8;
            byte[] key = encoding.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the secret password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "encoding">
        ///     The character encoding used to convert the password.
        ///     If the value <see langword = "null" /> is passed, then the encoding will be used
        /// <see cref = "Encoding.UTF8" />
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 64-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, Encoding encoding, ulong seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            encoding = encoding ?? Encoding.UTF8;
            byte[] key = encoding.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and initialization vector.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "iv">
        ///     The initialization vector used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, byte[] iv, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));
            _arc4 = iv.Length == 4
                ? (CryptoProvider) new ARC4CryptoProvider(iv)
                : new ARC4DualCryptoProvider(iv);

            byte[] key = Encoding.UTF8.GetBytes(password);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);
            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     A signed 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, int seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] key = Encoding.UTF8.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, uint seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] key = Encoding.UTF8.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     A signed 64-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, long seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] key = Encoding.UTF8.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption password and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 64-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, ulong seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] key = Encoding.UTF8.GetBytes(password);
            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream and encryption password.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the password used to cryptographically transform the stream.
        /// </param>
        /// <param name = "encoding">
        ///     The character encoding used to convert the password.
        ///     If the value <see langword = "null" /> is passed, then the encoding will be used
        ///     <see cref = "Encoding.UTF8" />
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, Encoding encoding, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            encoding = encoding ?? Encoding.UTF8;
            byte[] key = encoding.GetBytes(password);
            _arc4 = CryptoProvider.Create(key, null, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream and encryption password.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "password">
        ///     A string containing the password used to cryptographically transform the stream.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, string password, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(GetResourceString("Arg_EmptyOrNullString"), nameof(password));

            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] key = Encoding.UTF8.GetBytes(password);
            _arc4 = CryptoProvider.Create(key, null, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption key and initialization vector.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "key">
        ///     The secret key to be used to cryptographically transform the stream.
        /// </param>
        /// <param name = "iv">
        ///     The initialization vector used as the initial state of the ARC4 algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, byte[] key, byte[] iv, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption key and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "key">
        ///     The secret key to be used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     A signed 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, byte[] key, int seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption key and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "key">
        ///     The secret key to be used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 32-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, byte[] key, uint seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption key and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "key">
        ///     The secret key to be used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     A signed 64-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, byte[] key, long seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);


            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption key and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "key">
        ///     The secret key to be used to cryptographically transform the stream.
        /// </param>
        /// <param name = "seed">
        ///     An unsigned 64-bit integer value used as the initial state of the <see cref="ARC4"/> algorithm.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, byte[] key, ulong seed, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            byte[] iv = BitConverter.GetBytes(seed);
            _arc4 = CryptoProvider.Create(key, iv, skip, arc4plus);


            _leaveOpen = leaveOpen;
        }

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4Stream" />,
        ///     using the target data stream, encryption key and seed value.
        /// </summary>
        /// <param name = "stream">
        ///     Stream for performing cryptographic transformation.
        /// </param>
        /// <param name = "key">
        ///     The secret key to be used to cryptographically transform the stream.
        /// </param>
        /// <param name="skip">
        ///     The number of initial bytes to drop from the keystream. This can be used to enhance security
        ///     by discarding the first few bytes of the keystream, which are sometimes predictable.
        /// </param>
        /// <param name="arc4plus">
        ///     A value of <see langword="true"/> to use the RC4+ algorithm instead of the standard RC4 algorithm;
        ///     otherwise, the value <see langword="false"/>.
        /// </param>
        /// <param name = "leaveOpen">
        ///     A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
        ///     <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
        /// </param> 
        public ARC4Stream(Stream stream, byte[] key, int skip = 0, bool arc4plus = false, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream),
                GetResourceString("ArgumentNull_Stream"));

            _arc4 = CryptoProvider.Create(key, null, skip, arc4plus);

            _leaveOpen = leaveOpen;
        }

        /// <inheritdoc cref="Stream.Flush()"/>
        public override void Flush()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4Stream),
                    GetResourceString("ObjectDisposed_Generic"));

            _stream.Flush();
        }

        /// <inheritdoc cref="Stream.Seek(long, SeekOrigin)"/>
        public override long Seek(long offset, SeekOrigin origin)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4Stream),
                    GetResourceString("ObjectDisposed_Generic"));

            return _stream.Seek(offset, origin);
        }

        /// <inheritdoc cref="Stream.SetLength(long)"/>
        public override void SetLength(long value)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ARC4Stream),
                    GetResourceString("ObjectDisposed_Generic"));
            }

            _stream.SetLength(value);
        }

        /// <inheritdoc cref="Stream.Read(byte[], int, int)"/>
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4Stream),
                    GetResourceString("ObjectDisposed_Generic"));
            if (!CanRead)
                throw new NotSupportedException(
                    GetResourceString("Argument_StreamNotReadable"));

            int length = _stream.Read(buffer, offset, count);
            _arc4.Cipher(buffer, offset, length, buffer, offset);
            return length;
        }

        /// <inheritdoc cref="Stream.Write(byte[], int, int)"/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ARC4Stream),
                    GetResourceString("ObjectDisposed_Generic"));
            if (!CanWrite)
                throw new NotSupportedException(
                    GetResourceString("Argument_StreamNotWritable"));

            buffer = _arc4.Cipher(buffer, offset, count);
            _stream.Write(buffer, offset, count);
        }

        /// <inheritdoc cref="Stream.Dispose(bool)"/>
        protected override void Dispose(bool disposing)
        {
            if (_disposed) return;
            _arc4?.Dispose();
            _disposed = true;
            if (!disposing) return;
            if (!_leaveOpen) _stream?.Dispose();
            _stream = null;
            _arc4 = null;
        }

        /// <summary>
        /// <inheritdoc cref="object.Finalize"/>.
        /// </summary>
        ~ARC4Stream()
        {
            Dispose(disposing: false);
        }
    }
}