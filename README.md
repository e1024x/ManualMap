manual map
==========

A tiny, educational manual mapper for Windows.

What this is
------------
This repo is a small demo showing the basic idea of manual DLL mapping into another process on Windows.
It's educational: read a DLL from disk, map its PE image into a target process, fix imports/relocations
with a tiny injected stub, and call the DLL entry point.

Files 
--------------------
- main.cpp               — tiny driver; change the PID / DLL path here.
- ManualMapper.h/.cpp    — mapper implementation (read DLL, allocate remote memory, write headers/sections,
                           inject shellcode that fixes imports/relocs and calls DllMain).
- ShellcodeData.h        — data structure passed into the injected shellcode.
- test.dll               — not included. Put your own DLL beside the EXE or change main.cpp.

Build
-----
1. Open ManualMap.vcxproj in VS (uses VCProjectVersion 17.0 / v143 toolset).
2. Select platform (Win32 or x64) and configuration (Debug/Release).
   IMPORTANT: the mapper, the target process, and the DLL must all be the same architecture:
     - 64-bit DLL -> 64-bit target -> 64-bit mapper.
     - 32-bit DLL -> 32-bit target -> 32-bit mapper.
3. Build the solution. You'll get a console EXE.

Usage
-----
1. Put the DLL you want to map next to the mapper EXE and name it test.dll, OR change the DLL path in main.cpp.
2. Edit main.cpp to set the target PID, e.g.:
   const DWORD TARGET_PID = 458; // change me
3. Run the EXE with enough rights to open the target process (Administrator may be required).
4. The program prints a short result

How it works 
-----------------------------------
1. Read the DLL file into memory and parse PE headers.
2. VirtualAllocEx in the target process for the DLL SizeOfImage.
3. WriteProcessMemory the PE headers and sections into the remote memory.
4. Prepare a small shellcode blob + a ShellcodeData struct containing:
   - remote image base
   - import directory pointer
   - relocation pointer + size
   - pointers to LoadLibraryA, GetProcAddress, and the DLL entrypoint
5. Inject the shellcode into the target and run it via CreateRemoteThread.
6. The injected stub fixes imports, applies relocations, and calls DllMain(DLL_PROCESS_ATTACH).

Ideas for improvement
---------------------
- Replace raw function copy shellcode with a real position independent shellcode blob (handwritten ASM or compiled PIC).
- Apply proper per section memory protections instead of RWX.
- Support forwarded imports, TLS callbacks, and other PE corner cases.

