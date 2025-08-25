#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <TlHelp32.h>

// struct to manage manual mapping
#pragma pack(push, 1)
struct ShellcodeData {
    typedef BOOL(WINAPI* DllMain)(HINSTANCE, DWORD, LPVOID);
    typedef void* (WINAPI* LoadLibraryAPtr)(const char*);
    typedef void* (WINAPI* GetProcAddressPtr)(void*, const char*);

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

class ManualMapper {
private:
    DWORD targetPID;
    HANDLE hProcess;
    std::vector<uint8_t> dllBytes;

    // shellcode that runs in target process
    static void __stdcall ShellcodeEntrypoint(ShellcodeData* data) {
        // fix imports
        auto importDesc = data->importDirectory;
        auto loadLibraryA = data->loadLibraryA;
        auto getProcAddress = data->getProcAddress;

        while (importDesc->Name) {
            char* moduleName = (char*)((uint8_t*)data->imageBase + importDesc->Name);
            HMODULE module = (HMODULE)loadLibraryA(moduleName);

            if (module) {
                auto thunkRef = (ULONG_PTR*)((uint8_t*)data->imageBase + importDesc->FirstThunk);
                auto funcRef = (ULONG_PTR*)((uint8_t*)data->imageBase + importDesc->OriginalFirstThunk);

                if (!funcRef) funcRef = thunkRef;

                for (; *thunkRef; ++thunkRef, ++funcRef) {
                    if (IMAGE_SNAP_BY_ORDINAL(*funcRef)) {
                        *thunkRef = (ULONG_PTR)getProcAddress(
                            module,
                            (const char*)(*funcRef & 0xFFFF)
                        );
                    }
                    else {
                        auto importByName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)data->imageBase + (*funcRef));
                        *thunkRef = (ULONG_PTR)getProcAddress(module, importByName->Name);
                    }
                }
            }
            importDesc++;
        }

        // handle relocations
        if (data->isRelocated) {
            auto reloc = data->relocationDirectory;
            ptrdiff_t delta = (ptrdiff_t)((uint8_t*)data->imageBase -
                data->ntHeaders->OptionalHeader.ImageBase);

            while (reloc->VirtualAddress) {
                auto relocInfo = (WORD*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                auto relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                for (size_t i = 0; i < relocCount; i++) {
                    if (relocInfo[i] >> 12 == IMAGE_REL_BASED_DIR64 ||
                        relocInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                        auto relocAddress = (ULONG_PTR*)((uint8_t*)data->imageBase +
                            reloc->VirtualAddress + (relocInfo[i] & 0xFFF));
                        *relocAddress += delta;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc + reloc->SizeOfBlock);
            }
        }

        // call DllMain
        if (data->dllMain) {
            data->dllMain((HINSTANCE)data->imageBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    std::vector<uint8_t> PrepareShellcode(ShellcodeData& data) {
        // get shellcode bytes
        uint8_t* shellcodeStart = (uint8_t*)ShellcodeEntrypoint;
        uint8_t* shellcodeEnd = (uint8_t*)PrepareShellcode;

        // create shellcode buffer
        std::vector<uint8_t> shellcode(shellcodeEnd - shellcodeStart);
        memcpy(shellcode.data(), shellcodeStart, shellcode.size());

        // append shellcode data structure
        size_t originalSize = shellcode.size();
        shellcode.resize(originalSize + sizeof(ShellcodeData));
        memcpy(shellcode.data() + originalSize, &data, sizeof(ShellcodeData));

        return shellcode;
    }

public:
    ManualMapper(DWORD pid) : targetPID(pid), hProcess(nullptr) {}

    bool MapDLL(const std::string& dllPath) {
        // read DLL file
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file) return false;

        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        dllBytes.resize(fileSize);
        file.read((char*)dllBytes.data(), fileSize);
        file.close();

        // get process handle
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
        if (!hProcess) return false;

        // parse PE headers
        auto dosHeader = (PIMAGE_DOS_HEADER)dllBytes.data();
        auto ntHeaders = (PIMAGE_NT_HEADERS)(dllBytes.data() + dosHeader->e_lfanew);

        // allocate memory in target process
        void* baseAddress = VirtualAllocEx(
            hProcess,
            nullptr,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE  // initial RWX for simplicity
        );

        if (!baseAddress) {
            CloseHandle(hProcess);
            return false;
        }

        // write PE headers
        WriteProcessMemory(
            hProcess,
            baseAddress,
            dllBytes.data(),
            ntHeaders->OptionalHeader.SizeOfHeaders,
            nullptr
        );

        // map sections
        auto section = IMAGE_FIRST_SECTION(ntHeaders);
        for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (section[i].SizeOfRawData) {
                WriteProcessMemory(
                    hProcess,
                    (uint8_t*)baseAddress + section[i].VirtualAddress,
                    dllBytes.data() + section[i].PointerToRawData,
                    section[i].SizeOfRawData,
                    nullptr
                );
            }
        }

        // prepare shellcode data
        ShellcodeData shellcodeData = {};
        shellcodeData.imageBase = baseAddress;
        shellcodeData.loadLibraryA = LoadLibraryA;
        shellcodeData.getProcAddress = GetProcAddress;
        shellcodeData.dllMain = (ShellcodeData::DllMain)((uint8_t*)baseAddress +
            ntHeaders->OptionalHeader.AddressOfEntryPoint);

        // set import directory
        auto importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size) {
            shellcodeData.importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)baseAddress +
                importDir.VirtualAddress);
        }

        // set relocation info
        auto relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size) {
            shellcodeData.relocationDirectory = (PIMAGE_BASE_RELOCATION)((uint8_t*)baseAddress +
                relocDir.VirtualAddress);
            shellcodeData.relocationSize = relocDir.Size;
            shellcodeData.isRelocated = TRUE;
        }

        shellcodeData.ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)baseAddress + dosHeader->e_lfanew);

        // prep and inject shellcode
        auto shellcode = PrepareShellcode(shellcodeData);
        void* shellcodeAddress = VirtualAllocEx(
            hProcess,
            nullptr,
            shellcode.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!shellcodeAddress) {
            VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // write shellcode
        WriteProcessMemory(
            hProcess,
            shellcodeAddress,
            shellcode.data(),
            shellcode.size(),
            nullptr
        );

        // create thread to execute shellcode
        HANDLE hThread = CreateRemoteThread(
            hProcess,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)shellcodeAddress,
            (uint8_t*)shellcodeAddress + shellcode.size() - sizeof(ShellcodeData),
            0,
            nullptr
        );

        if (!hThread) {
            VirtualFreeEx(hProcess, shellcodeAddress, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // wait for shellcode to complete
        WaitForSingleObject(hThread, INFINITE);

        // clean
        VirtualFreeEx(hProcess, shellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return true;
    }
};

int main() {
    const DWORD TARGET_PID = 458;
    ManualMapper mapper(TARGET_PID);

    if (mapper.MapDLL("test.dll")) {
        std::cout << "DLL manual map succes\n";
    }
    else {
        std::cout << "manual mapping failed\n";
    }

    return 0;
}