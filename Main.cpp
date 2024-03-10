#include<Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include<stdio.h>

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);


#define SE_DEBUG_PRIVILEGE 20

char Shell_Code[] =
{
    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00,
    0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8D, 0x93, 0x22, 0x00, 0x00, 0x00,
    0x52, 0xFF, 0xD0, 0x61, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
};

void get_proc_id(const char* window_title, DWORD& process_id)
{
    GetWindowThreadProcessId(FindWindow(NULL, window_title), &process_id);
}

int main()
{
    const char* window_title = "Trove";
    DWORD pid;
    get_proc_id(window_title, pid);

    //To get the registers
    CONTEXT ct;
    ct.ContextFlags = CONTEXT_FULL;


    //For dll injection
    char Dll_Path[MAX_PATH];
    const char* dll_name = "Rain.dll";

    //Adjustin the privilege so we can debug
    BOOLEAN buff;
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &buff);



    //Get Full Path
    GetFullPathName(dll_name, MAX_PATH, Dll_Path, nullptr);
    std::cout << "Dll_Path : " << Dll_Path << std::endl;

    //Get a handle to roblox
    HANDLE hRoblox = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    

    // Create a snapshot of all running threads
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    Thread32First(hSnapshot, &te32);
    while (Thread32Next(hSnapshot, &te32))
    {
        // Check if the thread belongs to the target process
        if (te32.th32OwnerProcessID == pid)
        {
            MessageBoxA(0, "Found a thread", "Injection", 0);
            break;
        }
    }
    CloseHandle(hSnapshot);

    //Allocating enough place in roblox to inject
    PVOID allocated_memory = VirtualAllocEx(hRoblox, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Open the thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
    if (!hThread) {
        MessageBoxA(0, "Failed to open a thread", "Injection", 0);
    }


    //If we dont do that then no registers
    SuspendThread(hThread);
    GetThreadContext(hThread, &ct);


    //Allocating our buffer and copy the shellcode to it
    PVOID buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPBYTE ptr = (LPBYTE)buffer;
    memcpy(buffer, Shell_Code, sizeof(Shell_Code));

    while (1)
    {
        if (*ptr == 0xB8 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
        {
            *(PDWORD)(ptr + 1) = (DWORD)LoadLibraryA;
        }

        if (*ptr == 0x68 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
        {
            *(PDWORD)(ptr + 1) = ct.Eip;
        }

        if (*ptr == 0xC3)
        {
            ptr++;
            break;
        }
        ptr++;
    }

    //We copy the dll path to the right place in our payload
    strcpy((char*)ptr, Dll_Path);

    //Injecting it
    WriteProcessMemory(hRoblox, allocated_memory, buffer, sizeof(Shell_Code) + strlen((char*)ptr), nullptr);

    //Adjust the program flow back to normal
    ct.Eip = (DWORD)allocated_memory;

    //release everything back to normal
    SetThreadContext(hThread, &ct);
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hRoblox);
    VirtualFree(buffer, NULL, MEM_RELEASE);


    MessageBoxA(0, "Successfully injected", "Injection", 0);
}

