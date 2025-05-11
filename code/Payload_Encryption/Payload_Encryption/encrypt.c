#include <windows.h>
#include <stdio.h>
#include "payload.h"

// 方法一 异或运算
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j >= sKeySize) {
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}

// 方法二 RC4加密
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);

/*
Helper function that calls SystemFunction032
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS = NULL;

	USTRING Data = {
		.Buffer = pPayloadData,
		.Length = sPayloadSize,
		.MaximumLength = sPayloadSize
	};

	USTRING	Key = {
		.Buffer = pRc4Key,
		.Length = dwRc4KeySize,
		.MaximumLength = dwRc4KeySize
	};

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}




// 方法三 AES加密
// The plaintext, in hex format, that will be encrypted
// this is the following string in hex "This is a plain text string, we'll try to encrypt/decrypt !"
unsigned char Data[] = {
	0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x70, 0x6C,
	0x61, 0x69, 0x6E, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x72,
	0x69, 0x6E, 0x67, 0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74,
	0x72, 0x79, 0x20, 0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x2F, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x21
};

int main()
{

	// 以下直接使用1234567890作为硬编码密钥，容易被直接分析掉，可以定义成别的格式
	// Method 1
	unsigned char* key = "maldev123";

	// Method 2
	// This is 'maldev123' represented as an array of hexadecimal bytes
	unsigned char key1[] = {
		0x6D, 0x61, 0x6C, 0x64, 0x65, 0x76, 0x31, 0x32, 0x33
	};

	// Method 3
	// This is 'maldev123' represented in a hex/string form (hexadecimal escape sequence)
	unsigned char* key2 = "\x6D\x61\x6C\x64\x65\x76\x31\x32\x33";

	// Method 4 - better approach (via stack strings)
	// This is 'maldev123' represented in an array of chars
	unsigned char key3[] = {
		'm', 'a', 'l', 'd', 'e', 'v', '1', '2', '3'
	};
	
	// 两次异或，观察内存.data中shellcode变化
	//XorByInputKey(Data_RawData, sizeof(Data_RawData), (PBYTE)"1234567890", 10);
	//XorByInputKey(Data_RawData, sizeof(Data_RawData), (PBYTE)"1234567890", 10);


	// 两次rc4，观察内存.data中shellcode变化，
	Rc4EncryptionViaSystemFunc032( (PBYTE)"1234567890", Data_RawData, 10, sizeof(Data_RawData));
	Rc4EncryptionViaSystemFunc032( (PBYTE)"1234567890", Data_RawData, 10, sizeof(Data_RawData));

	// AES加密


	return 0;
}

