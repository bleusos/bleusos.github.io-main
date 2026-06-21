#include <stdio.h>
#include <Windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#pragma comment(lib, "bcrypt.lib")

int main(void)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD fileSize = 0;
    DWORD bytesRead = 0;
    PBYTE pShellcode = NULL;
    PBYTE pCiphertext = NULL;

    // open the shellcode bin
    hFile = CreateFileA("calc.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("(!) failed to open shellcode bin\n");
        return 1;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        printf("(!) failed to get file size\n");
        CloseHandle(hFile);
        return 1;
    }

    pShellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (!pShellcode)
    {
        printf("(!) failed to allocate memory\n");
        CloseHandle(hFile);
        return 1;
    }

    // read bin file into buffer
    if (!ReadFile(hFile, pShellcode, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        printf("(!) failed to read file\n");
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        return 1;
    }

    printf("shellcode read successfully, size: %d bytes\n", fileSize);

    // open aes algorithm
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status < 0)   
    {
        printf("(!) failed to open algorithm provider\n");
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }

    // set cbc mode
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status < 0)
    {
        printf("(!) failed to set chaining mode\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }

    BYTE key[32] = {
        0x9f, 0x2e, 0x7c, 0x4b, 0xa1, 0xd5, 0x68, 0x3f,
        0xe6, 0x12, 0x9c, 0x75, 0x4d, 0xb8, 0x03, 0xe1,
        0x2a, 0x6f, 0x9d, 0x14, 0x8b, 0xc7, 0x5e, 0x30,
        0xf4, 0x81, 0x26, 0x5a, 0xd9, 0x7b, 0xc0, 0x18
    }; // 32 bytes for AES-256
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, sizeof(key), 0);
    if (status < 0)
    {
        printf("(!) failed to generate symmetric key\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }

    BYTE iv[16] = { 0 };
    status = BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
    {
        printf("(!) failed to generate IV\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }

    printf("(+) IV generated successfully\n");

    ULONG ciphertextSize = 0;
    ULONG resultSize = 0;

    // calculate required buffer size for ciphertext
    status = BCryptEncrypt(hKey, pShellcode, fileSize, NULL, iv, sizeof(iv), NULL, 0, &ciphertextSize, BCRYPT_BLOCK_PADDING);
    if (status < 0)
    {
        printf("(!) failed to calculate ciphertext size\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }

    pCiphertext = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ciphertextSize);
    if (!pCiphertext)
    {
        printf("(!) failed to allocate memory for ciphertext\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }

    // encrypt
    status = BCryptEncrypt(hKey, pShellcode, fileSize, NULL, iv, sizeof(iv), pCiphertext, ciphertextSize, &resultSize, BCRYPT_BLOCK_PADDING);
    if (status < 0)
    {
        printf("(!) failed to encrypt data\n");
        HeapFree(GetProcessHeap(), 0, pCiphertext);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }

    printf("(+) encryption successful, ciphertext size: %d bytes\n", resultSize);

    // write iv + ciphertext to file
    HANDLE hOutFile = CreateFileA("calc.bin.enc", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile != INVALID_HANDLE_VALUE)
    {
        DWORD bytesWritten = 0;
        WriteFile(hOutFile, iv, sizeof(iv), &bytesWritten, NULL);
        WriteFile(hOutFile, pCiphertext, resultSize, &bytesWritten, NULL);
        CloseHandle(hOutFile);
        printf("(+) encrypted data written to calc.bin.enc\n");
    }
    else printf("(!) failed to create output file\n");

    // cleanup
    HeapFree(GetProcessHeap(), 0, pCiphertext);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, pShellcode);
    CloseHandle(hFile);

    return 0;
}