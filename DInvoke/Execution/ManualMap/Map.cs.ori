using Sharperner.Misc;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Execute = Sharperner.Execution;

namespace Sharperner.Execution.ManMap
{
    public class Peta
    {

        public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
        {
            IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
            return pFile;
        }

        public static void RelocateModule(Pencil.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            Pencil.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.BaseRelocationTable : PEINFO.OptHeader64.BaseRelocationTable;
            Int64 ImageDelta = PEINFO.Is32Bit ? (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader32.ImageBase) :
                                                (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader64.ImageBase);

            // Ptr for the base reloc table
            IntPtr pRelocTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);
            Int32 nextRelocTableBlock = -1;
            // Loop reloc blocks
            while (nextRelocTableBlock != 0)
            {
                Pencil.IMAGE_BASE_RELOCATION ibr = new Pencil.IMAGE_BASE_RELOCATION();
                ibr = (Pencil.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocTable, typeof(Pencil.IMAGE_BASE_RELOCATION));

                Int64 RelocCount = ((ibr.SizeOfBlock - Marshal.SizeOf(ibr)) / 2);
                for (int i = 0; i < RelocCount; i++)
                {
                    // Calculate reloc entry ptr
                    IntPtr pRelocEntry = (IntPtr)((UInt64)pRelocTable + (UInt64)Marshal.SizeOf(ibr) + (UInt64)(i * 2));
                    UInt16 RelocValue = (UInt16)Marshal.ReadInt16(pRelocEntry);

                    // Parse reloc value
                    // The type should only ever be 0x0, 0x3, 0xA
                    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                    UInt16 RelocType = (UInt16)(RelocValue >> 12);
                    UInt16 RelocPatch = (UInt16)(RelocValue & 0xfff);

                    // Perform relocation
                    if (RelocType != 0) // IMAGE_REL_BASED_ABSOLUTE (0 -> skip reloc)
                    {
                        try
                        {

                            IntPtr pPatch = (IntPtr)((UInt64)ModuleMemoryBase + ibr.VirtualAdress + RelocPatch);
                            if (RelocType == 0x3) // IMAGE_REL_BASED_HIGHLOW (x86)
                            {
                                Int32 OriginalPtr = Marshal.ReadInt32(pPatch);
                                Marshal.WriteInt32(pPatch, (OriginalPtr + (Int32)ImageDelta));
                            }
                            else // IMAGE_REL_BASED_DIR64 (x64)
                            {
                                Int64 OriginalPtr = Marshal.ReadInt64(pPatch);
                                Marshal.WriteInt64(pPatch, (OriginalPtr + ImageDelta));
                            }
                        }
                        catch
                        {

                        }
                    }
                }

                // Check for next block
                pRelocTable = (IntPtr)((UInt64)pRelocTable + ibr.SizeOfBlock);
                nextRelocTableBlock = Marshal.ReadInt32(pRelocTable);
            }
        }

        public static void RewriteModuleIAT(Pencil.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            Pencil.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.ImportTable : PEINFO.OptHeader64.ImportTable;

            // Ptr for the base import directory
            IntPtr pImportTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);

            // Get API Set mapping dictionary if on Win10+
            Execute.Native.OSVERSIONINFOEX OSVersion = new Execution.Native.OSVERSIONINFOEX();
            DyInvoke.Native.RtlGetVersion(ref OSVersion);
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();
            if (OSVersion.MajorVersion >= 10)
            {
                ApiSetDict = DyInvoke.Menyeluruh.GetApiSetMapping();
            }

            // Loop IID's
            int counter = 0;
            Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR iid = new Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR();
            iid = (Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                typeof(Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
            );
            while (iid.Name != 0)
            {
                // Get DLL
                string DllName = string.Empty;
                try
                {
                    DllName = Marshal.PtrToStringAnsi((IntPtr)((UInt64)ModuleMemoryBase + iid.Name));
                }
                catch { }

                // Loop imports
                if (DllName == string.Empty)
                {
                    ////throw new InvalidOperationException("Failed to read DLL name.");
                }
                else
                {
                    // API Set DLL?
                    if (OSVersion.MajorVersion >= 10 && (DllName.StartsWith("api-") || DllName.StartsWith("ext-")) &&
                        ApiSetDict.ContainsKey(DllName) && ApiSetDict[DllName].Length > 0)
                    {
                        // Not all API set DLL's have a registered host mapping
                        DllName = ApiSetDict[DllName];
                    }

                    // Check and / or load DLL
                    IntPtr hModule = DyInvoke.Menyeluruh.GetLoadedModuleAddress(DllName);
                    //Console.Write("\r[+] Slowly mapping {0}", DllName.PadRight(20,' '));
                    //Console.Write("\r");

                    if (hModule == IntPtr.Zero)
                    {
                        hModule = DyInvoke.Menyeluruh.LoadModuleFromDisk(DllName);
                        if (hModule == IntPtr.Zero)
                        {
                            //throw new FileNotFoundException(DllName + ", unable to find the specified file.");
                        }
                    }

                    // Loop thunks
                    if (PEINFO.Is32Bit)
                    {
                        Pencil.IMAGE_THUNK_DATA32 oft_itd = new Pencil.IMAGE_THUNK_DATA32();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (Pencil.IMAGE_THUNK_DATA32)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt32)(i * (sizeof(UInt32)))), typeof(Pencil.IMAGE_THUNK_DATA32));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt32))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }


                            //We need to slow this down to be able to bypass AV's
                            Thread.Sleep(Helpers.RandomNumber(5, 20));

                            if (oft_itd.AddressOfData < 0x80000000) // !IMAGE_ORDINAL_FLAG32
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DyInvoke.Menyeluruh.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                // Write ProcAddress
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DyInvoke.Menyeluruh.GetNativeExportAddress(hModule, (short)fOrdinal);

                                // Write ProcAddress
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                        }
                    }
                    else
                    {
                        Pencil.IMAGE_THUNK_DATA64 oft_itd = new Pencil.IMAGE_THUNK_DATA64();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (Pencil.IMAGE_THUNK_DATA64)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt64)(i * (sizeof(UInt64)))), typeof(Pencil.IMAGE_THUNK_DATA64));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt64))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            //We need to slow this down to be able to bypass AV's
                            Thread.Sleep(Helpers.RandomNumber(5, 20));

                            if (oft_itd.AddressOfData < 0x8000000000000000) // !IMAGE_ORDINAL_FLAG64
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DyInvoke.Menyeluruh.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                           

                                // Write pointer
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DyInvoke.Menyeluruh.GetNativeExportAddress(hModule, (short)fOrdinal);

                                // Write pointer
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                        }
                    }
                    counter++;
                    iid = (Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                        (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                        typeof(Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
                    );
                }
            }
        }

        /// <summary>
        /// Set correct module section permissions.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (Pencil.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void SetModuleSectionPermissions(Pencil.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            // Apply RO to the module header
            IntPtr BaseOfCode = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.BaseOfCode : (IntPtr)PEINFO.OptHeader64.BaseOfCode;
            DyInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleMemoryBase, ref BaseOfCode, Execute.Win32.WinNT.PAGE_READONLY);

            // Apply section permissions
            foreach (Pencil.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                bool isRead = (ish.Characteristics & Pencil.DataSectionFlags.MEM_READ) != 0;
                bool isWrite = (ish.Characteristics & Pencil.DataSectionFlags.MEM_WRITE) != 0;
                bool isExecute = (ish.Characteristics & Pencil.DataSectionFlags.MEM_EXECUTE) != 0;
                uint flNewProtect = 0;
                if (isRead & !isWrite & !isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_READONLY;
                }
                else if (isRead & isWrite & !isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_READWRITE;
                }
                else if (isRead & isWrite & isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                }
                else if (isRead & !isWrite & isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_EXECUTE_READ;
                }
                else if (!isRead & !isWrite & isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_EXECUTE;
                }
                else
                {
                    //throw new InvalidOperationException("Unknown section flag, " + ish.Characteristics);
                }

                // Calculate base
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)ModuleMemoryBase + ish.VirtualAddress);
                IntPtr ProtectSize = (IntPtr)ish.VirtualSize;

                // Set protection
                DyInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref pVirtualSectionBase, ref ProtectSize, flNewProtect);
            }
        }

        public static Pencil.PENCIL_MANUAL_MAP MapThisToMemory(byte[] Module)
        {
            // Verify process & architecture
            bool isWOW64 = DyInvoke.Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));

            // Alloc module into memory for parsing
            IntPtr pModule = AllocateBytesToMemory(Module);
            return MapModuleToMemory(pModule);
        }

        public static Pencil.PENCIL_MANUAL_MAP MapModuleToMemory(IntPtr pModule)
        {
            // Fetch PE meta data
            Pencil.PE_META_DATA PEINFO = DyInvoke.Menyeluruh.GetPeMetaData(pModule);

            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
            }

            // Alloc PE image memory -> RW
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            IntPtr pImage = DyInvoke.Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                Execute.Win32.Kernel32.MEM_COMMIT | Execute.Win32.Kernel32.MEM_RESERVE,
                Execute.Win32.WinNT.PAGE_READWRITE
            );
            return MapModuleToMemory(pModule, pImage, PEINFO);
        }


        public static Pencil.PENCIL_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage, Pencil.PE_META_DATA PEINFO)
        {
            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
                //throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            // Write PE header to memory
            UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;
            UInt32 BytesWritten = DyInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

            // Write sections to memory
            foreach (Pencil.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

                // Write data
                BytesWritten = DyInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);

            }

            // Perform relocations
            RelocateModule(PEINFO, pImage);

            // Rewrite IAT
            RewriteModuleIAT(PEINFO, pImage);

            // Set memory protections
            SetModuleSectionPermissions(PEINFO, pImage);

            // Free temp HGlobal
            Marshal.FreeHGlobal(pModule);

            // Prepare return object
            Pencil.PENCIL_MANUAL_MAP ManMapObject = new Pencil.PENCIL_MANUAL_MAP
            {
                ModuleBase = pImage,
                PEINFO = PEINFO
            };

            return ManMapObject;
        }
    }
}
