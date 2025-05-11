#include <windows.h>
#include <stdio.h>
#include <heapapi.h>

int main() {

	// STEP 1 学习3种分配内存的方式

	//// Method 1 - Using malloc()
	//PVOID pAddress = malloc(100);

	//// Method 2 - Using HeapAlloc()
	//PVOID pAddress = HeapAlloc(GetProcessHeap(), 0, 100);

	// Method 3 - Using LocalAlloc()
	//PVOID pAddress = LocalAlloc(LPTR, 100);


	//---------------------------------------------------
	// STEP2 学习如何写内存
	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

	CHAR* cString = "MalDev Academy Is The Best";

	memcpy(pAddress, cString, strlen(cString));


	//---------------------------------------------------
	// STEP 3 释放已分配的内存
	HeapFree(GetProcessHeap(), 0, pAddress);

}