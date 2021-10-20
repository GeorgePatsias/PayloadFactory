using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES
{
    class Program
    {
        public static byte[] Encrypt(byte[] buf, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;

                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(buf, encryptor);
                }
            }
        }

        public static byte[] Decrypt(byte[] buf, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;

                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(buf, decryptor);
                }
            }
        }

        private static byte[] PerformCryptography(byte[] buf, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(buf, 0, buf.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }

        static void Main(string[] args)
        {
            Aes main_aes = Aes.Create();

            //Parse key
            StringBuilder hex_key = new StringBuilder(main_aes.KeySize * 2);
            hex_key.Append("byte[] key = new byte[");
            hex_key.Append(main_aes.Key.Length);
            hex_key.Append("] { ");
            foreach (byte b in main_aes.Key)
            {
                hex_key.AppendFormat("0x{0:x2}, ", b);
            }
            hex_key.Remove(hex_key.Length - 2, 1);
            hex_key.Append("};");
            

            //Parse IV
            StringBuilder hex_iv = new StringBuilder(main_aes.IV.Length * 2);
            hex_iv.Append("byte[] iv = new byte[");
            hex_iv.Append(main_aes.IV.Length);
            hex_iv.Append("] { ");
            foreach (byte b in main_aes.IV)
            {
                hex_iv.AppendFormat("0x{0:x2}, ", b);
            }
            hex_iv.Remove(hex_iv.Length - 2, 1);
            hex_iv.Append("};");



            /* length:  bytes */
            byte[] buf = new byte[] {  };

            // Encrypt and Encode the data:
            byte[] encrypted_data = Encrypt(buf, main_aes.Key, main_aes.IV);

            /*Show that shellcode has been encrypted successfully
            StringBuilder encrypting_data = new StringBuilder(buf.Length * 2);
            foreach (byte b in encrypted_data)
            {
                encrypting_data.AppendFormat("0x{0:x2}, ", b);
            }
            Console.WriteLine("[*] Encrypted Data: " + encrypting_data.ToString() + "\n");
            */


            //Generate final payload that will be used in actual shellcode runner
            string finalPayload = Convert.ToBase64String(encrypted_data);
            Console.WriteLine("[*] Final Payload:");
            Console.WriteLine("string finalPayload = \"" + finalPayload + "\";");
            Console.WriteLine(hex_key.ToString());
            Console.WriteLine(hex_iv.ToString());


            /*AES Decryptor
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), main_aes.Key, main_aes.IV);

            //Show that shellcode has been decrypted successfully
            StringBuilder decrypting_data = new StringBuilder(decrypted_data.Length * 2);
            foreach (byte b in decrypted_data)
            {
                decrypting_data.AppendFormat("0x{0:x2}, ", b);
            }
            Console.WriteLine("Decrypted Data: " + decrypting_data.ToString() + "\n\n\n\n");
            */
        }
    }
}
