using System;
using System.Text;

namespace XOR
{
    class Program
    {
        private static byte[] xor(byte[] cipher, byte[] key)
        {
            byte[] xored = new byte[cipher.Length];

            for (int i = 0; i < cipher.Length; i++)
            {
                xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }

            return xored;
        }

        static void Main(string[] args)
        {
            string key = "key_xor";

            byte[] buf = new byte[] {  };

            byte[] xorshellcode;

            xorshellcode = xor(buf, Encoding.ASCII.GetBytes(key));
            StringBuilder newshellcode = new StringBuilder();
            newshellcode.Append("byte[] buf = new byte[");
            newshellcode.Append(xorshellcode.Length);
            newshellcode.Append("] { ");
            for (int i = 0; i < xorshellcode.Length; i++)
            {
                newshellcode.Append("0x");
                newshellcode.AppendFormat("{0:x2}", xorshellcode[i]);
                if (i < xorshellcode.Length - 1)
                {
                    newshellcode.Append(", ");
                }
            }
            newshellcode.Append(" };");
            Console.WriteLine(newshellcode.ToString());


            /* XOR Decryptor
            string key = "HZzC3ZeX&e$^^9Yhp*5g$PA3E";
            byte[] decoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                decoded[i] = (byte)(buf[i] ^ Encoding.ASCII.GetBytes(key)[i % Encoding.ASCII.GetBytes(key).Length]);
            }*/

        }
    }
}
