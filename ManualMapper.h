#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "ShellcodeData.h"

class ManualMapper {
private:
    DWORD targetPID;
    HANDLE hProcess;
    std::vector<uint8_t> dllBytes;

    // shellcode that runs in target process
    static void __stdcall ShellcodeEntrypoint(ShellcodeData* data);

    std::vector<uint8_t> PrepareShellcode(ShellcodeData& data);

public:
    ManualMapper(DWORD pid);
    bool MapDLL(const std::string& dllPath);
};