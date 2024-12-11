using System;
using System.Text;
using System.Windows.Forms;

namespace ARC4Demo
{
	internal static class Program
	{
		[STAThread]
		internal static void Main()
		{
			Application.Run(new MainForm());
		}

		internal static string Remove(this string str, params char[] charsToRemove)
		{
			return string.Concat(str.Split(charsToRemove));
		}

		internal static string ToHex(this byte[] sblock)
		{
			StringBuilder stringBuilder = new StringBuilder(784);
			for (int i = 0; i < sblock.Length; i++)
			{
                stringBuilder.Append($"{sblock[i]:x2}");
                stringBuilder.Append(i % 16 == 15 ? "\r\n" : " ");
            }
			return stringBuilder.ToString();
		}

		internal static byte[] FromHex(this string hex)
		{
			hex = hex.Remove("\r\n\t\a\v ".ToCharArray());
			byte[] array = new byte[hex.Length / 2];
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
			}
			return array;
		}
	}
}
