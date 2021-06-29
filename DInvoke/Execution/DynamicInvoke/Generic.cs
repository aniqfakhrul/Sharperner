// Author: Ryan Cobb (@cobbr_io)
// Project: Sharperner (https://github.com/cobbr/Sharperner)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

using Execute = Sharperner.Execution;
using System.Threading;
using Sharperner.Misc;

namespace Sharperner.Execution.DyInvoke
{

    public class Menyeluruh
    {

        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }

        /// <summary>
        /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }

        /// <summary>
        /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            Execute.Native.UNICODE_STRING uModuleName = new Execute.Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            Execute.Native.NTSTATUS CallResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != Execute.Native.NTSTATUS.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return hModule;
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="FunctionName">Name of the exported procedure.</param>
        /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            return GetExportAddress(hModule, FunctionName);
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="FunctionHash">Hash of the exported procedure.</param>
        /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                ////throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                ////throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }
        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, string ExportName)
        {
            Execute.Native.ANSI_STRING aFunc = new Execute.Native.ANSI_STRING
            {
                Length = (ushort)ExportName.Length,
                MaximumLength = (ushort)(ExportName.Length + 2),
                Buffer = Marshal.StringToCoTaskMemAnsi(ExportName)
            };

            IntPtr pAFunc = Marshal.AllocHGlobal(Marshal.SizeOf(aFunc));
            Marshal.StructureToPtr(aFunc, pAFunc, true);

            IntPtr pFuncAddr = IntPtr.Zero;
            Native.LdrGetProcedureAddress(ModuleBase, pAFunc, IntPtr.Zero, ref pFuncAddr);

            Marshal.FreeHGlobal(pAFunc);

            return pFuncAddr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by calling LdrGetProcedureAddress.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="Ordinal">The ordinal number to search for (e.g. 0x136 -> ntdll!NttttCreatex).</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, short Ordinal)
        {
            IntPtr pFuncAddr = IntPtr.Zero;
            IntPtr pOrd = (IntPtr)Ordinal;

            Native.LdrGetProcedureAddress(ModuleBase, IntPtr.Zero, pOrd, ref pFuncAddr);

            return pFuncAddr;
        }

        /// <summary>
        /// Retrieve PE header information from the module base pointer.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <returns>Pencil.PE_META_DATA</returns>
        public static Pencil.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            Pencil.PE_META_DATA PeMetaData = new Pencil.PE_META_DATA();
            try
            {
                UInt32 e_lfanew = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + 0x3c));
                PeMetaData.Pe = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + e_lfanew));
                PeMetaData.ImageFileHeader = (Pencil.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((UInt64)pModule + e_lfanew + 0x4), typeof(Pencil.IMAGE_FILE_HEADER));
                IntPtr OptHeader = (IntPtr)((UInt64)pModule + e_lfanew + 0x18);
                UInt16 PEArch = (UInt16)Marshal.ReadInt16(OptHeader);
                // Validate PE arch
                if (PEArch == 0x010b) // Image is x32
                {
                    PeMetaData.Is32Bit = true;
                    PeMetaData.OptHeader32 = (Pencil.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(OptHeader, typeof(Pencil.IMAGE_OPTIONAL_HEADER32));
                }
                else if (PEArch == 0x020b) // Image is x64
                {
                    PeMetaData.Is32Bit = false;
                    PeMetaData.OptHeader64 = (Pencil.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(OptHeader, typeof(Pencil.IMAGE_OPTIONAL_HEADER64));
                }
                // Read sections
                Pencil.IMAGE_SECTION_HEADER[] SectionArray = new Pencil.IMAGE_SECTION_HEADER[PeMetaData.ImageFileHeader.NumberOfSections];
                for (int i = 0; i < PeMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    IntPtr SectionPtr = (IntPtr)((UInt64)OptHeader + PeMetaData.ImageFileHeader.SizeOfOptionalHeader + (UInt32)(i * 0x28));
                    SectionArray[i] = (Pencil.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(SectionPtr, typeof(Pencil.IMAGE_SECTION_HEADER));
                }
                PeMetaData.Sections = SectionArray;
            }
            catch
            {
                
            }
            return PeMetaData;
        }

        public static Dictionary<string, string> GetApiSetMapping()
        {
            Execute.Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            UInt32 ApiSetMapOffset = IntPtr.Size == 4 ? (UInt32)0x38 : 0x68;

            // Create mapping dictionary
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();

            IntPtr pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + ApiSetMapOffset));
            Pencil.ApiSetNamespace Namespace = (Pencil.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(Pencil.ApiSetNamespace));
            for (var i = 0; i < Namespace.Count; i++)
            {
                Pencil.ApiSetNamespaceEntry SetEntry = new Pencil.ApiSetNamespaceEntry();
                SetEntry = (Pencil.ApiSetNamespaceEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)Namespace.EntryOffset + (UInt64)(i * Marshal.SizeOf(SetEntry))), typeof(Pencil.ApiSetNamespaceEntry));
                string ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.NameOffset), SetEntry.NameLength/2) + ".dll";

                Pencil.ApiSetValueEntry SetValue = new Pencil.ApiSetValueEntry();
                SetValue = (Pencil.ApiSetValueEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset), typeof(Pencil.ApiSetValueEntry));
                string ApiSetValue = string.Empty;
                if (SetValue.ValueCount != 0)
                {
                    ApiSetValue = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetValue.ValueOffset), SetValue.ValueCount/2);
                }

                // Add pair to dict
                ApiSetDict.Add(ApiSetEntryName, ApiSetValue);
            }

            // Return dict
            return ApiSetDict;
        }

        public static void PanggilMapPEMod(Pencil.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            // Call module by EntryPoint (eg Mimikatz.exe)
            IntPtr hRemoteThread = IntPtr.Zero;
            IntPtr lpStartAddress = PEINFO.Is32Bit ? (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint) :
                                                     (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);

            Thread.Sleep(Helpers.RandomNumber(2500, 5000));

            Native.NtCreateThreadEx(
                ref hRemoteThread,
                Execute.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL,
                IntPtr.Zero, (IntPtr)(-1),
                lpStartAddress, IntPtr.Zero,
                false, 0, 0, 0, IntPtr.Zero
            );

          
        }
    }
}