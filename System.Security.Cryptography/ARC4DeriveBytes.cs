using System.ComponentModel;
using System.Text;

namespace System.Security.Cryptography
{
	public class ARC4DeriveBytes : DeriveBytes
	{
		private ARC4CryptoProvider _arc4;

		private byte[] _key;

		private byte[] _iv;

		private bool _disposed = false;

		public ARC4SBlock State => _arc4.State;

		public ARC4DeriveBytes(byte[] key, byte[] iv = null)
		{
			_key = key;
			_iv = iv ?? ((byte[])ARC4SBlock.DefaultSBlock);
			if (!ARC4SBlock.ValidBytes(iv))
			{
				throw new ArgumentException(AssemblyMessageFormatter.DefaultFormatter.GetMessage("Cryptography_InvalidIVSize"), "iv");
			}
			_arc4 = ((iv == null || iv.Length == 0) ? new ARC4CryptoProvider(_key) : new ARC4CryptoProvider(_key, _iv));
		}

		public ARC4DeriveBytes(byte[] key, ARC4SBlock sblock)
		{
			_key = key;
			_iv = sblock ?? ARC4SBlock.DefaultSBlock;
			_arc4 = new ARC4CryptoProvider(_key, sblock ?? ARC4SBlock.DefaultSBlock);
		}

		public ARC4DeriveBytes(string password, Encoding encoding = null, byte[] iv = null)
		{
			_key = (encoding ?? Encoding.UTF8).GetBytes(password);
			_iv = iv ?? ((byte[])ARC4SBlock.DefaultSBlock);
			if (!ARC4SBlock.ValidBytes(iv))
			{
				throw new ArgumentException(AssemblyMessageFormatter.DefaultFormatter.GetMessage("Cryptography_InvalidIVSize"), "iv");
			}
			_arc4 = ((iv == null || iv.Length == 0) ? new ARC4CryptoProvider(_key) : new ARC4CryptoProvider(_key, _iv));
		}

		public ARC4DeriveBytes(string password, Encoding encoding = null, ARC4SBlock sblock = null)
		{
			_key = (encoding ?? Encoding.UTF8).GetBytes(password);
			_iv = sblock ?? ARC4SBlock.DefaultSBlock;
			_arc4 = new ARC4CryptoProvider(_key, sblock ?? ARC4SBlock.DefaultSBlock);
		}

		public override byte[] GetBytes(int cb)
		{
			if (_arc4 == null)
			{
				throw new ObjectDisposedException("_arc4");
			}
			byte[] result = new byte[cb];
			result.Initialize();
			_arc4.Cipher(result, 0, result.Length);
			return result;
		}

		public override void Reset()
		{
			_arc4 = new ARC4CryptoProvider(_key, _iv);
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing && !_disposed)
			{
				try
				{
					CryptoProvider.EraseArray(_key);
					CryptoProvider.EraseArray(_iv);
					_arc4?.Dispose();
				}
				finally
				{
					_disposed = true;
				}
			}
			_key = null;
			_iv = null;
			_arc4 = null;
			base.Dispose(disposing);
		}

		~ARC4DeriveBytes()
		{
			Dispose(disposing: false);
		}
	}
}
