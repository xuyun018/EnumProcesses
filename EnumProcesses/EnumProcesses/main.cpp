#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
//---------------------------------------------------------------------------
#pragma comment(lib,"Psapi.lib")
//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
BOOL EnableDebugPrivilege(VOID)
{
	HANDLE htoken;
	TOKEN_PRIVILEGES tkp;
	BOOL result = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &htoken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
		{
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (AdjustTokenPrivileges(htoken, FALSE, &tkp, sizeof(tkp), (PTOKEN_PRIVILEGES)NULL, 0))
			{
				result = TRUE;
			}
		}

		CloseHandle(htoken);
	}

	return(result);
}

//---------------------------------------------------------------------------
typedef BOOL(WINAPI* t_EnumProcesses)(DWORD*, DWORD, LPDWORD);
//---------------------------------------------------------------------------
typedef struct tagUSER_IMPORTS
{
	t_EnumProcesses p_EnumProcesses;
}USER_IMPORTS, * PUSER_IMPORTS;

VOID UserLoadImports(PUSER_IMPORTS puis)
{
	HMODULE hkernel32;
	HMODULE hpsapi;
	const char* function_string;

	hkernel32 = GetModuleHandle(L"kernel32");
	hpsapi = LoadLibrary(L"psapi");

	if (hkernel32)
	{
		function_string = "K32EnumProcesses";
		puis->p_EnumProcesses =
			(t_EnumProcesses)GetProcAddress(hkernel32, function_string);
		if (puis->p_EnumProcesses == NULL)
		{
			if (hpsapi)
			{
				puis->p_EnumProcesses =
					(t_EnumProcesses)GetProcAddress(hpsapi, function_string + 3);
			}
		}
	}
}

int GetProcessName(DWORD processid)
{
	HANDLE hprocess;
	WCHAR filename[1024];
	UINT k;

	hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processid);
	if (hprocess)
	{
		k = GetModuleFileNameEx(hprocess, NULL, filename, sizeof(filename) / sizeof(filename[0]));
		if (k && k < sizeof(filename) / sizeof(filename[0]))
		{
			wprintf(L"%s\r\n", filename);
		}

		CloseHandle(hprocess);
	}
	return(0);
}

unsigned int list_processes(PUSER_IMPORTS puis)
{
	DWORD processids[1024];
	DWORD needed;
	DWORD processid;
	unsigned int i;
	unsigned int count = 0;

	if (puis->p_EnumProcesses(processids, sizeof(processids), &needed))
	{
		processid = GetCurrentProcessId();

		count = needed / sizeof(DWORD);             //计算进程个数
		for (i = 0; i < count; i++)
		{
			if (processids[i])
			{
				if (processids[i] != processid)
				{
					GetProcessName(processids[i]);
				}
			}
		}
	}

	return(count);
}

int wmain(int argc, WCHAR* argv[])
{
	EnableDebugPrivilege();

	USER_IMPORTS puis[1];

	UserLoadImports(puis);

	list_processes(puis);

	getchar();

	return(0);
}