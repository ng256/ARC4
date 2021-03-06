using static System.ComponentModel.AssemblyMessageFormatter;

namespace System.Security.Cryptography
{
	/// <summary>
	///     Performs cryptographic transformation of data using the <see cref = "ARC4CryptoProvider" /> algorithm.
	///     This class could not be inherited.
	/// </summary> 
	public sealed class ARC4CryptoTransform : ICryptoTransform
	{
		private bool _disposed = false;
        private ARC4CryptoProvider _arc4;

        /// <summary>
        ///     Current internal state of the algorithm <see cref = "ARC4" />.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public ARC4SBlock State =>
            _disposed
                ? throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    DefaultFormatter.GetMessage("ObjectDisposed_Generic"))
                : _arc4.State;

        /// <inheritdoc cref="ICryptoTransform.InputBlockSize"/>
		public int InputBlockSize => 1;

		/// <inheritdoc cref="ICryptoTransform.OutputBlockSize"/>
		public int OutputBlockSize => 1;

		/// <inheritdoc cref="ICryptoTransform.CanTransformMultipleBlocks"/>
		public bool CanTransformMultipleBlocks => true;

		/// <inheritdoc cref="ICryptoTransform.CanReuseTransform"/>
		public bool CanReuseTransform => true;

        /// <summary>
		///     Initializes a new instance <see cref = "ARC4CryptoTransform" />, using the specified parameters.
		/// </summary>
		/// <param name = "key">
		///     The secret key to be used for the symmetric algorithm.
		/// </param>
		public ARC4CryptoTransform(byte[] key)
		{
            if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, nameof(key));
			}
			_arc4 = new ARC4CryptoProvider(key);
		}

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "iv">
        ///     Initialization vector.
        /// </param> 
        public ARC4CryptoTransform(byte[] key, byte[] iv)
		{
            if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, nameof(key));
			}
			if (iv == null)
			{
				throw new ArgumentNullException(nameof(iv));
			}
			if (!ARC4SBlock.ValidBytes(iv))
			{
				throw new ArgumentException(null, nameof(iv));
			}
			_arc4 = new ARC4CryptoProvider(key, iv);
		}

        /// <summary>
        ///     Initializes a new instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="sblock"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "sblock">
        ///     An instance of <see cref = "ARC4SBlock" />
        ///     used as the initial state of the ARC4 algorithm.
        /// </param> 
        public ARC4CryptoTransform(byte[] key, ARC4SBlock sblock)
		{
            if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}
			if (key.Length == 0)
			{
				throw new ArgumentException(null, nameof(key));
			}
			if (sblock == null)
			{
				throw new ArgumentNullException(nameof(sblock));
			}
			_arc4 = new ARC4CryptoProvider(key, sblock);
		}

		/// <inheritdoc cref="ICryptoTransform.TransformBlock"/>
 		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    DefaultFormatter.GetMessage("ObjectDisposed_Generic"));
            }
            if (inputBuffer == null)
			{
				throw new ArgumentNullException(nameof(inputBuffer));
			}
			if (outputBuffer == null)
			{
				throw new ArgumentNullException(nameof(outputBuffer));
			}
			if (inputOffset < 0)
			{
				throw new ArgumentOutOfRangeException(nameof(inputOffset), inputOffset, null);
			}
			if (inputCount <= 0 || inputCount % InputBlockSize != 0 || inputCount > inputBuffer.Length || inputBuffer.Length - inputCount < inputOffset)
			{
				throw new ArgumentException(null, nameof(inputCount));
			}
			Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
			_arc4.Cipher(outputBuffer, outputOffset, inputCount);
			return inputCount;
		}

		/// <inheritdoc cref="ICryptoTransform.TransformFinalBlock"/>
		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    DefaultFormatter.GetMessage("ObjectDisposed_Generic"));
            }
			if (inputBuffer == null)
			{
				throw new ArgumentNullException(nameof(inputBuffer));
			}
			if (inputOffset < 0)
			{
				throw new ArgumentOutOfRangeException(nameof(inputOffset), inputOffset, null);
			}
			if (inputCount < 0 || inputCount > inputBuffer.Length || inputBuffer.Length - inputCount < inputOffset)
			{
				throw new ArgumentException(null, nameof(inputCount));
			}
			byte[] outputBuffer = new byte[inputCount];
			Array.Copy(inputBuffer, inputOffset, outputBuffer, 0, inputCount);
			_arc4.Cipher(outputBuffer, 0, inputCount);
			return outputBuffer;
		}

        /// <summary>
        ///     Reset the instance <see cref = "ARC4CryptoTransform" />
        ///     using the specified <paramref name="key"/> and <paramref name="sblock"/>.
        /// </summary>
        /// <param name = "key">
        ///     The secret key to be used for the symmetric algorithm.
        /// </param>
        /// <param name = "sblock">
        ///     An instance of <see cref = "ARC4SBlock" />
        ///     used as the initial state of the ARC4 algorithm.
        /// </param> 
        /// <exception cref="ObjectDisposedException">
        ///     Thrown if current instance of <see cref="ARC4CryptoTransform"/> is disposed.
        /// </exception> 
        public void Reset(byte[] key, ARC4SBlock sblock)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ARC4CryptoTransform),
                    DefaultFormatter.GetMessage("ObjectDisposed_Generic"));
            }

            _arc4 = new ARC4CryptoProvider(key, sblock);
        }

        private void EraseState()
        {
            if (_disposed) return;
            _arc4?.EraseState();
            _disposed = true;
        }

		/// <inheritdoc cref="IDisposable.Dispose"/>
		public void Dispose()
		{
            EraseState();
			GC.SuppressFinalize(this);
		}

        /// <summary>
        /// <inheritdoc cref="object.Finalize"/>.
        /// </summary>
		~ARC4CryptoTransform()
		{
            EraseState();
		}
	}
}
