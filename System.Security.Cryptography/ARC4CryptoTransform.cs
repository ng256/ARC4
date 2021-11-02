namespace System.Security.Cryptography
{
	public sealed class ARC4CryptoTransform : ICryptoTransform, IDisposable
	{
		private ARC4CryptoProvider _arc4;

		private bool _disposed = false;

		public ARC4SBlock State => _arc4.State;

		public int InputBlockSize => 1;

		public int OutputBlockSize => 1;

		public bool CanTransformMultipleBlocks => true;

		public bool CanReuseTransform => true;

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

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		public void Dispose(bool disposing)
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
