using System.Security.Cryptography;
using System.Text;

namespace System.IO
{
	/// <summary>
	/// Implements object <see Cref = "Stream" /> using a cryptographic algorithm <see Cref = "ARC4" /> for data encryption.
	/// This class could not be inherited. 
	public sealed class ARC4Stream : Stream
	{
		private Stream _stream;
		private ARC4CryptoProvider _arc4;
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
		/// Current internal state of the algorithm <see cref = "ARC4" />.
		/// </summary> 
		public ARC4SBlock State => _arc4.State;

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream and encryption password.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "password">
		/// A string containing the password used to cryptographically transform the stream.
		/// </param>
		/// <param name = "encoding">
		/// The character encoding used to convert the password.
		/// If the value <see langword = "null" /> is passed, then the encoding will be used
		/// <see cref = "Encoding.UTF8" />
		/// </param>
		/// <param name = "iv">
		/// The initialization vector used as the initial state of the ARC4 algorithm.
		/// The length of the initialization vector must be 256 bytes, all values must be unique.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, string password, Encoding encoding, byte[] iv, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider((encoding ?? Encoding.UTF8).GetBytes(password), iv);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream and encryption password.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "password">
		/// A string containing the password used to cryptographically transform the stream.
		/// </param>
		/// <param name = "encoding">
		/// The character encoding used to convert the password.
		/// If the value <see langword = "null" /> is passed, then the encoding will be used
		/// <see cref = "Encoding.UTF8" />
		/// </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, string password, Encoding encoding, ARC4SBlock sblock, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider((encoding ?? Encoding.UTF8).GetBytes(password), sblock);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream and encryption password.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "password">
		/// A string containing the password used to cryptographically transform the stream.
		/// </param>
		/// <param name = "iv">
		/// The initialization vector used as the initial state of the ARC4 algorithm.
		/// The length of the initialization vector must be 256 bytes, all values must be unique.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, string password, byte[] iv, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(Encoding.UTF8.GetBytes(password), iv);
		}
		
		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream and encryption password.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "password">
		/// A string containing the password used to cryptographically transform the stream.
		/// </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, string password, ARC4SBlock sblock, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(Encoding.UTF8.GetBytes(password), sblock);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream and encryption password.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "password">
		/// A string containing the password used to cryptographically transform the stream.
		/// </param>
		/// <param name = "encoding">
		/// The character encoding used to convert the password.
		/// If the value <see langword = "null" /> is passed, then the encoding will be used
		/// <see cref = "Encoding.UTF8" />
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, string password, Encoding encoding, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider((encoding ?? Encoding.UTF8).GetBytes(password));
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream and encryption password.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "key">
		/// A string containing the password used to cryptographically transform the stream.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, string password, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(Encoding.UTF8.GetBytes(password));
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream, encryption key and initialization vector.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "key">
		/// Key used to cryptographically transform the stream.
		/// </param>
		/// <param name = "iv">
		/// The initialization vector used as the initial state of the ARC4 algorithm.
		/// The length of the initialization vector must be 256 bytes, all values ​​must be unique.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, byte[] key, byte[] iv, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(key, iv);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream, encryption key and initialization vector.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "key">
		/// Key used to cryptographically transform the stream.
		/// </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, byte[] key, ARC4SBlock sblock, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(key, sblock);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4Stream" />, using the target data stream, encryption key and initialization vector.
		/// </summary>
		/// <param name = "stream">
		/// Stream for performing cryptographic transformation.
		/// </param>
		/// <param name = "key">
		/// The key used to cryptographically transform the stream.
		/// </param>
		/// <param name = "leaveOpen">
		/// A value of <see langword = "true" /> to keep the stream object open after the object has been deleted
		/// <see cref = "ARC4Stream" />; otherwise, the value <see langword = "false" />.
		/// </param> 
		public ARC4Stream(Stream stream, byte[] key, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(key);
		}

		/// <inheritdoc cref="Stream.Flush()"/>
		public override void Flush()
		{
			_stream.Flush();
		}

		/// <inheritdoc cref="Stream.Seek(long, SeekOrigin)"/>
		public override long Seek(long offset, SeekOrigin origin)
		{
			return _stream.Seek(offset, origin);
		}

		/// <inheritdoc cref="Stream.SetLength(long)"/>
		public override void SetLength(long value)
		{
			_stream.SetLength(value);
		}

		/// <inheritdoc cref="Stream.Read(byte[], int, int)"/>
		public override int Read(byte[] buffer, int offset, int count)
		{
			if (!CanRead) throw new NotSupportedException();
			int length = _stream.Read(buffer, offset, count);
			_arc4.Cipher(buffer, offset, count);
			return length;
		}

		/// <inheritdoc cref="Stream.Write(byte[], int, int)"/>
		public override void Write(byte[] buffer, int offset, int count)
		{
			if (!CanWrite) throw new NotSupportedException();
			_arc4.Cipher(buffer, offset, count);
			_stream.Write(buffer, offset, count);
		}

		/// <inheritdoc cref="Stream.Dispose(bool)"/>
		protected override void Dispose(bool disposing)
		{
			if (disposing && !_disposed)
			{
				try
				{
					if (!_leaveOpen) _stream?.Dispose();
					_arc4?.Dispose();
				}
				finally
				{
					_disposed = true;
				}
			}
			_stream = null;
			_arc4 = null;
			base.Dispose(disposing);
		}

		~ARC4Stream()
		{
			Dispose(disposing: false);
		}
	}
}
