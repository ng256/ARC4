using System.Security.Cryptography;
using System.Text;

namespace System.IO
{
	public sealed class ARC4Stream : Stream
	{
		private Stream _stream;

		private ARC4CryptoProvider _arc4;

		private readonly bool _leaveOpen = false;

		private bool _disposed = false;

		public override bool CanRead => _stream.CanRead;

		public override bool CanSeek => _stream.CanSeek;

		public override bool CanWrite => _stream.CanWrite;

		public override long Length => _stream.Length;

		public override long Position
		{
			get
			{
				return _stream.Position;
			}
			set
			{
				_stream.Position = value;
			}
		}

		public ARC4SBlock State => _arc4.State;

		public ARC4Stream(Stream stream, string password, Encoding encoding, byte[] iv, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider((encoding ?? Encoding.UTF8).GetBytes(password), iv);
		}

		public ARC4Stream(Stream stream, string password, Encoding encoding, ARC4SBlock sblock, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider((encoding ?? Encoding.UTF8).GetBytes(password), sblock);
		}

		public ARC4Stream(Stream stream, string password, byte[] iv, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(Encoding.UTF8.GetBytes(password), iv);
		}

		public ARC4Stream(Stream stream, string password, ARC4SBlock sblock, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(Encoding.UTF8.GetBytes(password), sblock);
		}

		public ARC4Stream(Stream stream, string key, Encoding encoding, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider((encoding ?? Encoding.UTF8).GetBytes(key));
		}

		public ARC4Stream(Stream stream, string key, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(Encoding.UTF8.GetBytes(key));
		}

		public ARC4Stream(Stream stream, byte[] key, byte[] iv, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(key, iv);
		}

		public ARC4Stream(Stream stream, byte[] key, ARC4SBlock sblock, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(key, sblock);
		}

		public ARC4Stream(Stream stream, byte[] key, bool leaveOpen = false)
		{
			_leaveOpen = leaveOpen;
			_stream = stream ?? throw new ArgumentNullException("stream");
			_arc4 = new ARC4CryptoProvider(key);
		}

		public override void Flush()
		{
			_stream.Flush();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			return _stream.Seek(offset, origin);
		}

		public override void SetLength(long value)
		{
			_stream.SetLength(value);
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			if (!CanRead)
			{
				throw new NotSupportedException();
			}
			int length = _stream.Read(buffer, offset, count);
			_arc4.Cipher(buffer, offset, count);
			return length;
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			if (!CanWrite)
			{
				throw new NotSupportedException();
			}
			_arc4.Cipher(buffer, offset, count);
			_stream.Write(buffer, offset, count);
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing && !_disposed)
			{
				try
				{
					if (!_leaveOpen)
					{
						_stream?.Dispose();
					}
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
