// CryptoTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>
#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

int main()
{
	HCRYPTPROV hProv = NULL;

	if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		printf("CryptAcquireContext() failed. - Error code %d\r\n", GetLastError());
		return 1;
	}

	std::string password;
	printf("Input encryption password...>");

	std::getline(std::cin, password);

	printf("Hashing password to derive AES256 key...\r\n");

	HCRYPTHASH hHash = NULL;
	HCRYPTKEY noKey = 0;    //Not using a keyed algorithm, so we pass zero
	DWORD noFlags = 0;  //Not using any special flags for this hash

	if (!CryptCreateHash(hProv, CALG_SHA_256, noKey, noFlags, &hHash))
	{
		printf("CryptCreateHash() failed - Error: %d\r\n", GetLastError());
		CryptReleaseContext(hProv, 0);
		return 1;
	}

	LPCSTR pass = password.c_str();
	DWORD lenPass = password.length();

	if (!CryptHashData(hHash, (BYTE *)pass, lenPass, noFlags))
	{
		printf("CryptHashData() failed. - Error: %d\r\n", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return 1;
	}

	printf("Attempting to retrieve hash value...\r\n");

	DWORD hashLen = 0;
	DWORD lenBuf = sizeof(hashLen);
	if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&hashLen, &lenBuf, noFlags))
	{
		printf("CryptGetHashParam() failed - unable to get hash size. - Error: %d\r\n", GetLastError());

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return 1;
	}

	printf("Hash size: %d bytes\r\n", hashLen);
	printf("Retreiving hash value...\r\n");

	LPVOID hashValue = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hashLen);
	if (!hashValue)
	{
		printf("Unable to allocate memory for hash. Error: %d\r\n", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return 1;
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE *)hashValue, &hashLen, noFlags))
	{
		printf("CryptGetHashParam() failed - unable to get hash value. - Error: %d\r\n", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return 1;
	}

	printf("Hash value: ");
	unsigned char * hashChars = (unsigned char *)hashValue;
	for (int i = 0; i < hashLen; i++)
	{
		printf("%02X", hashChars[i]);
	}
	printf("\r\n");

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
    std::cout << "Hello World!\n"; 
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
