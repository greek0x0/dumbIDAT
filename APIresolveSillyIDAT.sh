#include <windows.h>
#include <stdio.h>


DWORD HashMath(const char* name, DWORD seed) {
    DWORD hash = seed;
    while (*name) {
        hash = (hash * 2) + (unsigned char)(*name++);
    }
    return hash;
}
void FindExportByHash(const char* dllName, DWORD targetHash, DWORD seed) {

    HMODULE hMod = GetModuleHandleA(dllName);
    if (!hMod) {
        return;
    }


    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!exportDirRVA) {
        return;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exportDirRVA);

    DWORD* nameRVAs = (DWORD*)((BYTE*)hMod + exportDir->AddressOfNames);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* funcName = (const char*)((BYTE*)hMod + nameRVAs[i]);

        DWORD hash = HashMath(funcName, seed);

        if (hash == targetHash) {
            printf("Match found in %s: %s => 0x%08X\n", dllName, funcName, hash);
            return;
        }
    }

}




int main() {
    /*
    dword_506FA132 = 1D035B73h 
dword_506FA19A = 37A0E7C5h ( Used in multiple instances) 
dword_506FA186 = 83A07CA1h 
dword_506FA176 = 82192D69h 
dword_506FA136 = 127A3980h
dword_506FA162 = 0A06F2EDDh 
dword_506FA15E = 5Ch 
dword_506FA1A2  = 740E183h
dword_506FA19A  = 37A0E7C5h
off_506FA152 = aIsozoubclegVd+3
dword_506FA12E = 80000000h
dword_506FA146 = 4
dword_506FA192 = 740D8A5h  
dword_506FA16E = 0A0E81EB1h
byte_506FA156 = 8   
dword_506FA15A  = 0E81EBA3h
dword_506FA16A  = 0B736h  
dword_506FA142  = 3A09A09Eh
zeroCinHex  =  0Ch 
fileName      = aKlureartcikSt
    
    */
    FindExportByHash("kernel32.dll", 0x1D035B73, 0x37A0E7C5);
    FindExportByHash("kernel32.dll", 0x83A07CA1, 0x37A0E7C5);
    FindExportByHash("kernel32.dll", 0x82192D69, 0x37A0E7C5);
    FindExportByHash("kernel32.dll", 0x127A3980, 0x37A0E7C5);
    FindExportByHash("kernel32.dll", 0x0A06F2EDD, 0x37A0E7C5);



    FindExportByHash("kernel32.dll", 0x740E183, 0x37A0E7C5);
    FindExportByHash("kernel32.dll", 0x80000000, 0x37A0E7C5);
    FindExportByHash("kernel32.dll", 0x740D8A5, 0x37A0E7C5);


    FindExportByHash("kernel32.dll", 0x0E81EBA3, 0x37A0E7C5);
    FindExportByHash("kernel32.dll", 0x0A0E81EB1, 0x37A0E7C5);

    FindExportByHash("kernel32.dll", 0x0B736, 0x37A0E7C5);

    FindExportByHash("kernel32.dll", 0x3A09A09E, 0x37A0E7C5);

/*
Match found in kernel32.dll: FatalAppExitW => 0x1D035B73
Match found in kernel32.dll: LocalAlloc => 0x83A07CA1
Match found in kernel32.dll: SetCurrentDirectoryW => 0x82192D69
Match found in kernel32.dll: GetModuleFileNameW => 0xA06F2EDD
Match found in kernel32.dll: CreateFileA => 0x0740E183
Match found in kernel32.dll: GetFileSize => 0x0740D8A5
Match found in kernel32.dll: LoadLibraryA => 0x0E81EBA3
Match found in kernel32.dll: ReadFile => 0xA0E81EB1
Match found in kernel32.dll: VirtualProtect => 0x3A09A09E*/

    return 0;
}
