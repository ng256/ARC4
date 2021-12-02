using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
        /// <summary>
        /// Represents the initial state of the cryptographic algorithm <see cref = "ARC4" />.
        /// This class is not inherited.
        /// </summary> 
        [Serializable]
	[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 256)]
	public sealed class ARC4SBlock : IDisposable
	{
		public static readonly ARC4SBlock DefaultSBlock = new ARC4SBlock();

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
		private byte[] _bytes = new byte[256];
		
                /// <summary>
                /// Initializes an instance <see cref = "ARC4SBlock" />,
                /// filled with pseudo-random values,
                /// using the linear congruential random.
                /// </summary>
                /// <returns> Instance <see cref = "ARC4SBlock" />. </returns> 
		public static ARC4SBlock GenerateRandom()
		{
			byte[] bytes = new byte[256];
			byte[] random = new byte[4];
			CryptoProvider.InternalRng.GetBytes(random);
			int x = BitConverter.ToInt32(random, 0) % 256;
			int a = 2;
			while ((a - 1) % 4 != 0)
			{
				random = new byte[4];
				CryptoProvider.InternalRng.GetBytes(random);
				int rnd = BitConverter.ToInt32(random, 0);
				a = 5 + rnd % 246;
			}
			for (int i = 0; i < 256; i++)
			{
				bytes[i] = (byte)(x = (a * x + 17) % 256);
			}
			return new ARC4SBlock(bytes);
		}
		
                /// <summary>
                /// Initializes an instance <see cref = "ARC4SBlock" />,
                /// using the specified values.
                /// </summary>
                /// <param name = "bytes"> The initialization vector <see cref = "ARC4SBlock" />, must be filled with 256 non-duplicate values. </param>
                /// <returns> Instance <see cref = "ARC4SBlock" />. </returns> 
		public static ARC4SBlock FromBytes(params byte[] bytes)
		{
			if (!ValidBytes(bytes))
			{
				throw new DuplicateWaitObjectException("bytes");
			}
			return new ARC4SBlock(bytes);
		}
                
                internal static bool ValidBytes(byte[] bytes)
		{
			if (bytes == null || bytes.Length != 256)
			{
				return false;
			}
			for (int i = 0; i < 256; i++)
			{
				for (int j = i; j < 256; j++)
				{
					if (bytes[i] == bytes[j])
					{
						return false;
					}
				}
			}
			return true;
		}

		private ARC4SBlock()
		{
			for (int i = 0; i < 256; i++)
			{
				_bytes[i] = (byte)i;
			}
		}

		internal ARC4SBlock(byte[] bytes)
		{
			_bytes = new byte[256];
			Array.Copy(bytes, _bytes, 256);
		}

		public static implicit operator byte[](ARC4SBlock sblock)
		{
			byte[] bytes = new byte[256];
			Array.Copy(sblock._bytes ?? DefaultSBlock._bytes, bytes, 256);
			return bytes;
		}

		public static explicit operator ARC4SBlock(byte[] bytes)
		{
			if (!ValidBytes(bytes))
			{
				throw new DuplicateWaitObjectException("bytes");
			}
			return new ARC4SBlock(bytes);
		}

                /// <inheritdoc cref="IDisposable.Dispose"/>
		public void Dispose()
		{
			CryptoProvider.EraseArray(_bytes);
			_bytes = null;
			GC.SuppressFinalize(this);
		}
	}
}
