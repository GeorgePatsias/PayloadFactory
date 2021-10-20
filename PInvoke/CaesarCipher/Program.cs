using System;
using System.Text;

namespace CaesarCipher
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[] {  };

            //Ceasar Cipher
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] - 18) & 0xFF); // -18 are the Character shifts of the encoding
            }

            StringBuilder newshellcode = new StringBuilder(encoded.Length * 2);
            newshellcode.Append("byte[] encoded = new byte[");
            newshellcode.Append(encoded.Length);
            newshellcode.Append("] { ");
            for (int i = 0; i < encoded.Length; i++)
            {
                newshellcode.Append("0x");
                newshellcode.AppendFormat("{0:x2}", encoded[i]);
                if (i < encoded.Length - 1)
                {
                    newshellcode.Append(", ");
                }
            }
            newshellcode.Append(" };");
            Console.WriteLine(newshellcode.ToString());
        }
    }
}

/*CaesarCipher Decoder
byte[] decoded = new byte[buf.Length];
for (int i = 0; i < buf.Length; i++)
{
    decoded[i] = (byte)(((uint)buf[i] + 18) & 0xFF);
}*/
