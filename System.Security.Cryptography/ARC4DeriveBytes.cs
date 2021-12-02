using System.ComponentModel;
using System.Text;

namespace System.Security.Cryptography
{
	/// <summary>
	/// Implements the function of generating a key based on a password using a pseudo-random number generator 
	/// <see cref = "System.Security.Cryptography.ARC4" />.
	/// </summary> 
	public class ARC4DeriveBytes : DeriveBytes
	{
		private ARC4CryptoProvider _arc4;
		private byte[] _key;
		private byte[] _iv;
		private bool _disposed = false;

		/// <summary>
		/// Current internal state of the algorithm <see cref = "ARC4" />.
		/// </summary> 
		public ARC4SBlock State => _arc4.State;

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4DeriveBytes" />, using the specified parameters.
		/// </summary>
		/// <param name = "key"> Encryption key. </param>
		/// <param name = "iv"> Initialization vector. </param> 
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

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4DeriveBytes" />, using the specified parameters.
		/// </summary>
		/// <param name = "key"> Encryption key. </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param> 
		public ARC4DeriveBytes(byte[] key, ARC4SBlock sblock)
		{
			_key = key;
			_iv = sblock ?? ARC4SBlock.DefaultSBlock;
			_arc4 = new ARC4CryptoProvider(_key, sblock ?? ARC4SBlock.DefaultSBlock);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4DeriveBytes" />, using the specified parameters.
		/// </summary>
		/// <param name = "password"> Password. </param>
		/// <param name = "encoding"> Character encoding for password conversion. </param>
		/// <param name = "iv"> Initialization vector. </param> 
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

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4DeriveBytes" />, using the specified parameters.
		/// </summary>
		/// <param name = "password"> Password. </param>
		/// <param name = "encoding"> Character encoding for password conversion. </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param> 
		public ARC4DeriveBytes(string password, Encoding encoding = null, ARC4SBlock sblock = null)
		{
			_key = (encoding ?? Encoding.UTF8).GetBytes(password);
			_iv = sblock ?? ARC4SBlock.DefaultSBlock;
			_arc4 = new ARC4CryptoProvider(_key, sblock ?? ARC4SBlock.DefaultSBlock);
		}
		
		/// <inheritdoc cref="DeriveBytes.GetBytes"/>
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

		/// <inheritdoc cref="DeriveBytes.Reset"/>
		public override void Reset()
		{
			_arc4 = new ARC4CryptoProvider(_key, _iv);
		}

		/// <inheritdoc cref="DeriveBytes.Dispose(bool)"/>
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
