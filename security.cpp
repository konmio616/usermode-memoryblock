#include "security.h"

fNtQuerySystemInformation security::oNtQuerySystemInformation{};
DWORD security::currentPID{};
std::vector<DWORD> security::systemPIDs{};

bool security::initialize()
{
	HMODULE hNtDll = GetModuleHandleA(("ntdll.dll"));
	if (!hNtDll)
		return false;
	oNtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(hNtDll, ("NtQuerySystemInformation"));
	security::currentPID = GetCurrentProcessId();

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) 
	{
		CloseHandle(hProcessSnap);
		return false;
	}

	do 
	{
		if (strstr(pe32.szExeFile, "conhost.exe") != NULL)
			systemPIDs.push_back(pe32.th32ProcessID);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
}

void security::memoryBlock()
{
	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while (oNtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL) == ((NTSTATUS)0xC0000004L))
	{
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	}

	for (auto i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
		HANDLE duplicatedHandle;
		if (hProcess != INVALID_HANDLE_VALUE && DuplicateHandle(hProcess, (HANDLE)handle.Handle, GetCurrentProcess(), &duplicatedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
		{
			if (GetProcessId(duplicatedHandle) == currentPID)
			{
				bool isSystemProcess = false;
				for (auto pid : systemPIDs)
				{
					if (pid == handle.ProcessId)
					{
						isSystemProcess = true;
						break;
					}
				}
				if (!isSystemProcess)
				{
					std::cout << "[+]Handle: " << std::hex << handle.Handle << "/PID: " << handle.ProcessId << std::endl;
					std::cout << "[+]Trying to close target handle..." << std::endl;
					HANDLE hTarget;
					DuplicateHandle(hProcess, (HANDLE)handle.Handle, GetCurrentProcess(), &hTarget, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
					CloseHandle(hTarget);
					std::cout << "[+]Target Handle closed." << std::endl;
				}
			}
			CloseHandle(duplicatedHandle);
		}
		CloseHandle(hProcess);
	}

	free(handleInfo);
}