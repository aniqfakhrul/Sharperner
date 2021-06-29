// Author: Ryan Cobb (@cobbr_io)
// Project: Sharperner (https://github.com/cobbr/Sharperner)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Runtime.InteropServices;

using MW32 = Microsoft.Win32;
using Execute = Sharperner.Execution;

namespace Sharperner.Execution.PlatformInvoke
{
    /// <summary>
    /// Win32 is a library of PInvoke signatures for Win32 API functions.
    /// </summary>
    /// <remarks>
    /// A majority of this library is adapted from signatures found at www.pinvoke.net.
    /// </remarks>
    public static class Win32
    {
        public static class Kernel32
        {
            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentThread();

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            public static extern IntPtr GetProcAddress(
                IntPtr hModule,
                string procName
            );

            [DllImport("kernel32.dll")]
            public static extern void GetSystemInfo(
                out Execute.Win32.WinBase._SYSTEM_INFO lpSystemInfo
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GlobalSize(
                IntPtr hMem
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool IsWow64Process(
                IntPtr hProcess,
                out bool Wow64Process
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(
                Execute.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean OpenProcessToken(
                IntPtr hProcess,
                UInt32 dwDesiredAccess,
                out IntPtr hToken
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean OpenThreadToken(
                IntPtr ThreadHandle,
                UInt32 DesiredAccess,
                Boolean OpenAsSelf,
                ref IntPtr TokenHandle
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenThread(
                UInt32 dwDesiredAccess,
                Boolean bInheritHandle,
                UInt32 dwThreadId
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean ReadProcessMemory(
                IntPtr hProcess,
                UInt32 lpBaseAddress,
                IntPtr lpBuffer,
                UInt32 nSize,
                ref UInt32 lpNumberOfBytesRead
            );

            [DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory")]
            public static extern Boolean ReadProcessMemory64(
                IntPtr hProcess,
                UInt64 lpBaseAddress,
                IntPtr lpBuffer,
                UInt64 nSize,
                ref UInt32 lpNumberOfBytesRead
            );

            [DllImport("kernel32.dll")]
            public static extern UInt32 SearchPath(
                String lpPath,
                String lpFileName,
                String lpExtension,
                UInt32 nBufferLength,
                [MarshalAs(UnmanagedType.LPTStr)]
                StringBuilder lpBuffer,
                ref IntPtr lpFilePart
            );

            [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
            public static extern Int32 VirtualQueryEx32(
                IntPtr hProcess,
                IntPtr lpAddress,
                out Execute.Win32.WinNT._MEMORY_BASIC_INFORMATION32 lpBuffer,
                UInt32 dwLength
            );

            [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
            public static extern Int32 VirtualQueryEx64(
                IntPtr hProcess,
                IntPtr lpAddress,
                out Execute.Win32.WinNT._MEMORY_BASIC_INFORMATION64 lpBuffer,
                UInt32 dwLength
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAlloc(
                IntPtr lpStartAddr,
                uint size,
                uint flAllocationType,
                uint flProtect
            );

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtect(
                IntPtr lpAddress,
                UIntPtr dwSize,
                uint flNewProtect,
                out uint lpflOldProtect
            );

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern IntPtr LoadLibrary(
                string lpFileName
            );

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateThread(
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr param,
                uint dwCreationFlags,
                IntPtr lpThreadId
            );

            [DllImport("kernel32.dll")]
            public static extern UInt32 WaitForSingleObject(
                IntPtr hHandle,
                UInt32 dwMilliseconds
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr LocalFree(
                IntPtr hMem
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean CloseHandle(
                IntPtr hProcess
            );

            [DllImport("kernel32.dll")]
            public static extern void GetNativeSystemInfo(
                ref Execute.Win32.Kernel32.SYSTEM_INFO lpSystemInfo
            );
        }
    }
}
