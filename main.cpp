#include <iostream>
#include "ManualMapper.h"

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