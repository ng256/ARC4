using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
	/// <summary>
	/// Represents the initial state of the cryptographic algorithm <see cref = "ARC4" />.
	/// This class could not be inherited.
	/// </summary> 
	[Serializable]
	[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 256)]
	public sealed class ARC4SBlock : IDisposable
	{
		private static readonly byte[] _A =
		{
			0x09, 0x0D, 0x11, 0x15, 0x19, 0x1D, 0x21, 0x25,
			0x29, 0x2D, 0x31, 0x35, 0x39, 0x3D, 0x41, 0x45,
			0x49, 0x4D, 0x51, 0x55, 0x59, 0x5D, 0x61, 0x65,
			0x69, 0x6D, 0x71, 0x75, 0x79, 0x7D, 0x81, 0x85,
			0x89, 0x8D, 0x91, 0x95, 0x99, 0x9D, 0xA1, 0xA5,
			0xA9, 0xAD, 0xB1, 0xB5, 0xB9, 0xBD, 0xC1, 0xC5,
			0xC9, 0xCD, 0xD1, 0xD5, 0xD9, 0xDD, 0xE1, 0xE5,
			0xE9, 0xED, 0xF1, 0xF5, 0xF9
		};

		private static readonly byte[] _C =
		{
			0x05, 0x07, 0x0B, 0x0D, 0x11, 0x13, 0x17, 0x1D,
			0x1F, 0x25, 0x29, 0x2B, 0x2F, 0x35, 0x3B, 0x3D,
			0x43, 0x47, 0x49, 0x4F, 0x53, 0x59, 0x61, 0x65,
			0x67, 0x6B, 0x6D, 0x71, 0x7F, 0x83, 0x89, 0x8B,
			0x95, 0x97, 0x9D, 0xA3, 0xA7, 0xAD, 0xB3, 0xB5,
			0xBF, 0xC1, 0xC5, 0xC7, 0xD3, 0xDF, 0xE3, 0xE5,
			0xE9, 0xEF, 0xF1, 0xFB
		};

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
			rng.GetBytes(random);
			int r = random[0];
			int x = random[1];
			int a = _A[random[2] % _A.Length];
			int c = _C[random[3] % _C.Length];
			const int m = 256;
			for (int i = 0; i < m; i++)
			{
				bytes[i] = (byte) (r ^ (x = (a * x + c) % m));
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

		internal static bool ValidBytes(byte[] bytes) // Checking that all 256 values should not be duplicated.
		{
			if (bytes == null || bytes.Length != 256)
			{
				return false;
			}

			for (int i = 0; i < 256; i++)
			{
				for (int j = i + 1; j < 256; j++)
				{
					if (bytes[i] == bytes[j])
					{
						return false;
					}
				}
			}

			return true;
		}

		private ARC4SBlock() // Default S-Block
		{
			for (int i = 0; i < 256; i++)
			{
				_bytes[i] = (byte) i;
			}
		}

		internal ARC4SBlock(byte[] bytes) // Specified S-Block.
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
				throw new DuplicateWaitObjectException(nameof(bytes));
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
