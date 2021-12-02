namespace System.Security.Cryptography
{
	/// <summary>
	/// Performs cryptographic transformation of data using the <see cref = "ARC4CryptoProvider" /> algorithm.
	/// This class could not be inherited.
	/// </summary> 
	public sealed class ARC4CryptoTransform : ICryptoTransform, IDisposable
	{
		private ARC4CryptoProvider _arc4;
		private bool _disposed = false;
		
		/// <summary>
		/// Current internal state of the algorithm <see cref = "ARC4" />.
		/// </summary> 
		public ARC4SBlock State => _arc4.State;

		/// <inheritdoc cref="ICryptoTransform.InputBlockSize"/>
		public int InputBlockSize => 1;

		/// <inheritdoc cref="ICryptoTransform.OutputBlockSize"/>
		public int OutputBlockSize => 1;

		/// <inheritdoc cref="ICryptoTransform.CanTransformMultipleBlocks"/>
		public bool CanTransformMultipleBlocks => true;

		/// <inheritdoc cref="ICryptoTransform.CanReuseTransform"/>
		public bool CanReuseTransform => true;


		/// <summary>
		/// Initializes a new instance <see cref = "ARC4CryptoTransform" />, using the specified parameters.
		/// </summary>
		/// <param name = "key"> Encryption key. </param>
		public ARC4CryptoTransform(byte[] key)
		{
			if (key == null)
			{
				throw new ArgumentNullException("key");
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, "key");
			}
			_arc4 = new ARC4CryptoProvider(key);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4CryptoTransform" />, using the specified parameters.
		/// </summary>
		/// <param name = "key"> Encryption key. </param>
		/// <param name = "iv"> Initialization vector. </param> 
		public ARC4CryptoTransform(byte[] key, byte[] iv)
		{
			if (key == null)
			{
				throw new ArgumentNullException("key");
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, "key");
			}
			if (iv == null)
			{
				throw new ArgumentNullException("iv");
			}
			if (!ARC4SBlock.ValidBytes(iv))
			{
				throw new ArgumentException(null, "iv");
			}
			_arc4 = new ARC4CryptoProvider(key, iv);
		}

		/// <summary>
		/// Initializes a new instance <see cref = "ARC4CryptoTransform" />, using the specified parameters.
		/// </summary>
		/// <param name = "key"> Encryption key. </param>
		/// <param name = "sblock">
		/// <see cref = "ARC4SBlock" /> used as the initial state of the ARC4 algorithm.
		/// </param> 
		public ARC4CryptoTransform(byte[] key, ARC4SBlock sblock)
		{
			if (key == null)
			{
				throw new ArgumentNullException("key");
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, "key");
			}
			if (sblock == null)
			{
				throw new ArgumentNullException("sblock");
			}
			_arc4 = new ARC4CryptoProvider(key, sblock);
		}

		/// <inheritdoc cref="ICryptoTransform.TransformBlock"/>
 		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			if (inputBuffer == null)
			{
				throw new ArgumentNullException("inputBuffer");
			}
			if (outputBuffer == null)
			{
				throw new ArgumentNullException("outputBuffer");
			}
			if (inputOffset < 0)
			{
				throw new ArgumentOutOfRangeException("inputOffset", inputOffset, null);
			}
			if (inputCount <= 0 || inputCount % InputBlockSize != 0 || inputCount > inputBuffer.Length || inputBuffer.Length - inputCount < inputOffset)
			{
				throw new ArgumentException(null, "inputCount");
			}
			Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
			_arc4.Cipher(outputBuffer, outputOffset, inputCount);
			return inputCount;
		}

		/// <inheritdoc cref="ICryptoTransform.TransformFinalBlock"/>
		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			if (inputBuffer == null)
			{
				throw new ArgumentNullException("inputBuffer");
			}
			if (inputOffset < 0)
			{
				throw new ArgumentOutOfRangeException("inputOffset", inputOffset, null);
			}
			if (inputCount < 0 || inputCount > inputBuffer.Length || inputBuffer.Length - inputCount < inputOffset)
			{
				throw new ArgumentException(null, "inputCount");
			}
			byte[] outputBuffer = new byte[inputCount];
			Array.Copy(inputBuffer, inputOffset, outputBuffer, 0, inputCount);
			_arc4.Cipher(outputBuffer, 0, inputCount);
			return outputBuffer;
		}

		/// <inheritdoc cref="IDisposable.Dispose"/>
		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		private void Dispose(bool disposing)
		{
			if (disposing && !_disposed)
			{
				try
				{
					_arc4?.Dispose();
				}
				finally
				{
					_disposed = true;
				}
			}
			_arc4 = null;
		}

		~ARC4CryptoTransform()
		{
			Dispose(disposing: false);
		}
	}
}
