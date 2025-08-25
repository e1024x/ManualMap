#pragma once
#include <windows.h>

// struct to manage manual mapping
#pragma pack(push, 1)
struct ShellcodeData {
    typedef BOOL(WINAPI* DllMain)(HINSTANCE, DWORD, LPVOID);
    typedef HMODULE(WINAPI* LoadLibraryAPtr)(LPCSTR);
    typedef FARPROC(WINAPI* GetProcAddressPtr)(HMODULE, LPCSTR);

    void* imageBase;                  // base address of mapped DLL
    LoadLibraryAPtr loadLibraryA;     // loadlibrarya address
    GetProcAddressPtr getProcAddress; // GetProcAddress address
    DllMain dllMain;                  // DLL entry point
    BOOL isRelocated;                 // reloc status

    // import data
    PIMAGE_IMPORT_DESCRIPTOR importDirectory;
    // reloc data
    PIMAGE_BASE_RELOCATION relocationDirectory;
    size_t relocationSize;

    // NT Headers for reference
    PIMAGE_NT_HEADERS ntHeaders;
};
#pragma pack(pop)