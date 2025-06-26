#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <string>
#include <random>
#include <ctime>
#include <windows.h>
#include <lmcons.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include <thread>
#include <Psapi.h>
#include <array>
#include <memory>
#include <stdexcept>
#include <tlhelp32.h>
#include <mutex>
#include <numeric>
#include <algorithm>
#include <type_traits>

// This protection is under Custom License – Non-Commercial Source Distribution
// Copyright (c) 2025 srungot
/*
    Custom License – Non-Commercial Source Distribution

    Copyright (c) 2025 srungot

    Permission is hereby granted to any person obtaining a copy of this software (the "Software") to use, copy, modify, and distribute both original and modified versions of the source code under the following conditions:

    1. You may:
    - Use the Software for personal, educational, or commercial purposes.
    - Modify the Software and distribute modified versions freely.
    - Include the Software in commercial products, provided the source code itself is not sold.

    2. You may NOT:
    - Sell or license the original or modified source code, on its own or as part of a source distribution.
    - Use the Software in a product where access to the source code is sold or restricted commercially.

    3. Distribution of modified versions must include this license and clearly indicate changes made to the original.

    By using this Software, you agree to these terms.

    This is a custom license and is not OSI-approved.
*/

#define JUNK_ON_OBF 1  
#define JUNK_ON_OBF_LEVEL 1     
#define Name_Of_Sections_watermark ".1337"
#define FAKE_SIGNATURES 1
#define CALL_LEVEL 3  

#ifdef _MSC_VER
    #define SECTION(x) __declspec(allocate(x))
#else
    #define SECTION(x) __attribute__((section(x)))
#endif

#define FAKE_SIG(name, section, sig) \
    SECTION(section) static char * name = (char*)sig;

#define PE_HEADER_SIZE 4096

struct PE_HEADER {
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_OPTIONAL_HEADER optionalHeader;
    PIMAGE_DATA_DIRECTORY dataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    std::vector<PIMAGE_SECTION_HEADER> sectionHeaders;
};

struct REMOTE_PE_HEADER : PE_HEADER {
    BYTE rawData[PE_HEADER_SIZE];
    ULONG_PTR remoteBaseAddress;
};

#if FAKE_SIGNATURES         // taked here https://github.com/ac3ss0r/obfusheader.h/tree/main thank you ac3ss0r
    #ifdef _MSC_VER
        #pragma section(".arch", read)
        #pragma section(".srdata", read)
        #pragma section(".xdata", read)
        #pragma section(".xtls", read)
        #pragma section(".themida", read)
        #pragma section(".vmp0", read)
        #pragma section(".vmp1", read)
        #pragma section(".vmp2", read)
        #pragma section(".enigma1", read)
        #pragma section(".enigma2", read)
        #pragma section(".dsstext", read)
        #pragma section(".NIGGER", read)
        #pragma section(".NIGGER1", read)
        #pragma section(".NIGGER2", read)
        #pragma section(".NIGGER3", read)
        #pragma section(".NIGGER4", read)
        #pragma section(".NIGGER5", read)
        #pragma section(".SEC_0x1A", read)
        #pragma section(".SEC_0x2B", read)
        #pragma section(".SEC_0x3C", read)
        #pragma section(".SEC_0x4D", read)
        #pragma section(".SEC_0x5E", read)
        #pragma section(".SEC_0x6F", read)
        #pragma section(".SEC_0x7G", read)
        #pragma section(".SEC_0x8H", read)
        #pragma section(".SEC_0x9I", read)
        #pragma section(".SEC_0x10J", read)
        #pragma section(".SEC_0x11K", read)
        #pragma section(".SEC_0x12L", read)
        #pragma section(".SEC_0x13M", read)
        #pragma section(".SEC_0x14N", read)
        #pragma section(".SEC_0x15O", read)
        #pragma section(".SEC_0x16P", read)
        #pragma section(".SEC_0x17Q", read)
        #pragma section(".SEC_0x18R", read)
        #pragma section(".SEC_0x19S", read)
        #pragma section(".SEC_0x20T", read)
        #pragma section(".SEC_0x21U", read)
        #pragma section(".SEC_0x22V", read)
        #pragma section(".SEC_0x23W", read)
        #pragma section(".SEC_0x24X", read)
        #pragma section(".SEC_0x25Y", read)
        #pragma section(".SEC_0x26Z", read)
        #pragma section(".SEC_0x27AA", read)
        #pragma section(".SEC_0x28AB", read)
        #pragma section(".SEC_0x29AC", read)
        #pragma section(".SEC_0x30AD", read)
        #pragma section(".SEC_0x31AE", read)
        #pragma section(".SEC_0x32AF", read)
        #pragma section(".SEC_0x33AG", read)
        #pragma section(".SEC_0x34AH", read)
        #pragma section(".SEC_0x35AI", read)
        #pragma section(".SEC_0x36AJ", read)
        #pragma section(".SEC_0x37AK", read)
        #pragma section(".SEC_0x38AL", read)
        #pragma section(".SEC_0x39AM", read)
        #pragma section(".SEC_0x40AN", read)
        #pragma section(".SEC_0x41AO", read)
        #pragma section(".SEC_0x42AP", read)
        #pragma section(".SEC_0x43AQ", read)
        #pragma section(".SEC_0x44AR", read)
        #pragma section(".SEC_0x45AS", read)
        #pragma section(".SEC_0x46AT", read)
        #pragma section(".SEC_0x47AU", read)
        #pragma section(".SEC_0x48AV", read)
        #pragma section(".SEC_0x49AW", read)
        #pragma section(".SEC_0x50AX", read)
        #pragma section(".SEC_0x51AY", read)
        #pragma section(".SEC_0x52AZ", read)
        #pragma section(".SEC_0x53BA", read)
        #pragma section(".SEC_0x54BB", read)
        #pragma section(".SEC_0x55BC", read)
        #pragma section(".SEC_0x56BD", read)
        #pragma section(".SEC_0x57BE", read)
        #pragma section(".SEC_0x58BF", read)
        #pragma section(".SEC_0x59BG", read)
        #pragma section(".SEC_0x60BH", read)
        #pragma section(".SEC_0x61BI", read)
        #pragma section(".SEC_0x62BJ", read)
        #pragma section(".SEC_0x63BK", read)
        #pragma section(".SEC_0x64BL", read)
        #pragma section(".SEC_0x65BM", read)
        #pragma section(".SEC_0x66BN", read)
        #pragma section(".SEC_0x67BO", read)
        #pragma section(".SEC_0x68BP", read)
        #pragma section(".SEC_0x69BQ", read)
        #pragma section(".SEC_0x70BR", read)
        #pragma section(".SEC_0x71BS", read)
        #pragma section(".SEC_0x72BT", read)
        #pragma section(".SEC_0x73BU", read)
        #pragma section(".SEC_0x74BV", read)
        #pragma section(".SEC_0x75BW", read)
        #pragma section(".SEC_0x76BX", read)
        #pragma section(".SEC_0x77BY", read)
        #pragma section(".SEC_0x78BZ", read)
        #pragma section(".SEC_0x79CA", read)
        #pragma section(".SEC_0x80CB", read)
        #pragma section(".SEC_0x81CC", read)
        #pragma section(".SEC_0x82CD", read)
        #pragma section(".SEC_0x83CE", read)
        #pragma section(".SEC_0x84CF", read)
        #pragma section(".SEC_0x85CG", read)
        #pragma section(".SEC_0x86CH", read)
        #pragma section(".SEC_0x87CI", read)
        #pragma section(".SEC_0x88CJ", read)
        #pragma section(".SEC_0x89CK", read)
        #pragma section(".SEC_0x90CL", read)
        #pragma section(".SEC_0x91CM", read)
        #pragma section(".SEC_0x92CN", read)
        #pragma section(".SEC_0x93CO", read)
        #pragma section(".SEC_0x94CP", read)
        #pragma section(".SEC_0x95CQ", read)
        #pragma section(".SEC_0x96CR", read)
        #pragma section(".SEC_0x97CS", read)
        #pragma section(".SEC_0x98CT", read)
        #pragma section(".SEC_0x99CU", read)
        #pragma section(".SEC_0x100CV", read)
    #endif

    FAKE_SIG(_enigma1, ".enigma1", 0); FAKE_SIG(_enigma2, ".enigma2", 0);
    FAKE_SIG(_vmp1, ".vmp0", 0); FAKE_SIG(_vmp2, ".vmp1", 0); FAKE_SIG(_vmp3, ".vmp2", 0);
    FAKE_SIG(_denuvo1, ".arch", 0); FAKE_SIG(_denuvo2, ".srdata", 0); FAKE_SIG(_denuvo3, ".xdata", 0);
    FAKE_SIG(_denuvo5, ".xtls", "\x64\x65\x6E\x75\x76\x6F\x5F\x61\x74\x64\x00\x00\x00\x00\x00\x00");
    FAKE_SIG(_themida1, ".themida", 0);
    FAKE_SIG(_securom1, ".dsstext", 0);
    
    FAKE_SIG(_extra1, ".NIGGER", "\x44\x45\x56\x49\x4C");  
    FAKE_SIG(_extra2, ".NIGGER1", "\x53\x4B\x55\x4C\x4C");  
    FAKE_SIG(_extra3, ".NIGGER2", "\x53\x45\x43\x55\x52\x45");  
    FAKE_SIG(_extra4, ".NIGGER3", "\x46\x4C\x41\x4D\x45");  
    FAKE_SIG(_extra5, ".NIGGER4", "\x53\x59\x53\x54\x45\x4D");  
    FAKE_SIG(_extra6, ".NIGGER5", "\x53\x59\x53\x54\x45\x4D\x4F");  
    FAKE_SIG(_rand1, ".SEC_0x1A", "\x50\x52\x4F\x54\x45\x43\x54"); 
    FAKE_SIG(_rand2, ".SEC_0x2B", "\x53\x45\x43\x55\x52\x45\x44");
    FAKE_SIG(_rand3, ".SEC_0x3C", "\x52\x49\x54\x59\x5F\x4B\x45");
    FAKE_SIG(_rand4, ".SEC_0x4D", "\x43\x4F\x44\x45\x5F\x53\x45");
    FAKE_SIG(_rand5, ".SEC_0x5E", "\x44\x41\x54\x41\x5F\x50\x52");
    FAKE_SIG(_rand6, ".SEC_0x6F", "\x48\x41\x53\x48\x5F\x4B\x45");
    FAKE_SIG(_rand7, ".SEC_0x7G", "\x43\x52\x59\x50\x54\x4F\x53");
    FAKE_SIG(_rand8, ".SEC_0x8H", "\x53\x41\x4C\x54\x5F\x4B\x45");
    FAKE_SIG(_rand9, ".SEC_0x9I", "\x4B\x45\x59\x53\x5F\x53\x45");
    FAKE_SIG(_rand10, ".SEC_0x10J", "\x42\x59\x54\x45\x5F\x43\x4F");
    FAKE_SIG(_rand11, ".SEC_0x11K", "\x48\x45\x58\x5F\x44\x41\x54");
    FAKE_SIG(_rand12, ".SEC_0x12L", "\x43\x4F\x44\x45\x5F\x50\x52");
    FAKE_SIG(_rand13, ".SEC_0x13M", "\x53\x45\x43\x5F\x44\x41\x54");
    FAKE_SIG(_rand14, ".SEC_0x14N", "\x50\x52\x4F\x54\x5F\x4B\x45");
    FAKE_SIG(_rand15, ".SEC_0x15O", "\x4B\x45\x59\x5F\x44\x41\x54");
    FAKE_SIG(_rand16, ".SEC_0x16P", "\x48\x41\x53\x48\x5F\x53\x45");
    FAKE_SIG(_rand17, ".SEC_0x17Q", "\x43\x52\x59\x50\x54\x5F\x4B");
    FAKE_SIG(_rand18, ".SEC_0x18R", "\x53\x41\x4C\x54\x5F\x50\x52");
    FAKE_SIG(_rand19, ".SEC_0x19S", "\x42\x59\x54\x45\x5F\x53\x45");
    FAKE_SIG(_rand20, ".SEC_0x20T", "\x48\x45\x58\x5F\x4B\x45\x59");
    FAKE_SIG(_rand21, ".SEC_0x21U", "\x43\x4F\x44\x45\x5F\x4B\x45");
    FAKE_SIG(_rand22, ".SEC_0x22V", "\x53\x45\x43\x5F\x50\x52\x4F");
    FAKE_SIG(_rand23, ".SEC_0x23W", "\x50\x52\x4F\x54\x5F\x53\x45");
    FAKE_SIG(_rand24, ".SEC_0x24X", "\x4B\x45\x59\x5F\x50\x52\x4F");
    FAKE_SIG(_rand25, ".SEC_0x25Y", "\x48\x41\x53\x48\x5F\x44\x41");
    FAKE_SIG(_rand26, ".SEC_0x26Z", "\x43\x52\x59\x50\x54\x5F\x53");
    FAKE_SIG(_rand27, ".SEC_0x27AA", "\x53\x41\x4C\x54\x5F\x44\x41");
    FAKE_SIG(_rand28, ".SEC_0x28AB", "\x42\x59\x54\x45\x5F\x50\x52");
    FAKE_SIG(_rand29, ".SEC_0x29AC", "\x48\x45\x58\x5F\x53\x45\x43");
    FAKE_SIG(_rand30, ".SEC_0x30AD", "\x43\x4F\x44\x45\x5F\x44\x41");
    FAKE_SIG(_rand31, ".SEC_0x31AE", "\x53\x45\x43\x5F\x4B\x45\x59");
    FAKE_SIG(_rand32, ".SEC_0x32AF", "\x50\x52\x4F\x54\x5F\x44\x41");
    FAKE_SIG(_rand33, ".SEC_0x33AG", "\x4B\x45\x59\x5F\x53\x45\x43");
    FAKE_SIG(_rand34, ".SEC_0x34AH", "\x48\x41\x53\x48\x5F\x50\x52");
    FAKE_SIG(_rand35, ".SEC_0x35AI", "\x43\x52\x59\x50\x54\x5F\x44");
    FAKE_SIG(_rand36, ".SEC_0x36AJ", "\x53\x41\x4C\x54\x5F\x53\x45");
    FAKE_SIG(_rand37, ".SEC_0x37AK", "\x42\x59\x54\x45\x5F\x44\x41");
    FAKE_SIG(_rand38, ".SEC_0x38AL", "\x48\x45\x58\x5F\x50\x52\x4F");
    FAKE_SIG(_rand39, ".SEC_0x39AM", "\x43\x4F\x44\x45\x5F\x53\x45");
    FAKE_SIG(_rand40, ".SEC_0x40AN", "\x53\x45\x43\x5F\x44\x41\x54");
    FAKE_SIG(_rand41, ".SEC_0x41AO", "\x50\x52\x4F\x54\x5F\x4B\x45");
    FAKE_SIG(_rand42, ".SEC_0x42AP", "\x4B\x45\x59\x5F\x44\x41\x54");
    FAKE_SIG(_rand43, ".SEC_0x43AQ", "\x48\x41\x53\x48\x5F\x53\x45");
    FAKE_SIG(_rand44, ".SEC_0x44AR", "\x43\x52\x59\x50\x54\x5F\x4B");
    FAKE_SIG(_rand45, ".SEC_0x45AS", "\x53\x41\x4C\x54\x5F\x50\x52");
    FAKE_SIG(_rand46, ".SEC_0x46AT", "\x42\x59\x54\x45\x5F\x53\x45");
    FAKE_SIG(_rand47, ".SEC_0x47AU", "\x48\x45\x58\x5F\x4B\x45\x59");
    FAKE_SIG(_rand48, ".SEC_0x48AV", "\x43\x4F\x44\x45\x5F\x4B\x45");
    FAKE_SIG(_rand49, ".SEC_0x49AW", "\x53\x45\x43\x5F\x50\x52\x4F");
    FAKE_SIG(_rand50, ".SEC_0x50AX", "\x50\x52\x4F\x54\x5F\x53\x45");
    FAKE_SIG(_rand51, ".SEC_0x51AY", "\x4B\x45\x59\x5F\x50\x52\x4F");
    FAKE_SIG(_rand52, ".SEC_0x52AZ", "\x48\x41\x53\x48\x5F\x44\x41");
    FAKE_SIG(_rand53, ".SEC_0x53BA", "\x43\x52\x59\x50\x54\x5F\x53");
    FAKE_SIG(_rand54, ".SEC_0x54BB", "\x53\x41\x4C\x54\x5F\x44\x41");
    FAKE_SIG(_rand55, ".SEC_0x55BC", "\x42\x59\x54\x45\x5F\x50\x52");
    FAKE_SIG(_rand56, ".SEC_0x56BD", "\x48\x45\x58\x5F\x53\x45\x43");
    FAKE_SIG(_rand57, ".SEC_0x57BE", "\x43\x4F\x44\x45\x5F\x44\x41");
    FAKE_SIG(_rand58, ".SEC_0x58BF", "\x53\x45\x43\x5F\x4B\x45\x59");
    FAKE_SIG(_rand59, ".SEC_0x59BG", "\x50\x52\x4F\x54\x5F\x44\x41");
    FAKE_SIG(_rand60, ".SEC_0x60BH", "\x4B\x45\x59\x5F\x53\x45\x43");
    FAKE_SIG(_rand61, ".SEC_0x61BI", "\x48\x41\x53\x48\x5F\x50\x52");
    FAKE_SIG(_rand62, ".SEC_0x62BJ", "\x43\x52\x59\x50\x54\x5F\x44");
    FAKE_SIG(_rand63, ".SEC_0x63BK", "\x53\x41\x4C\x54\x5F\x53\x45");
    FAKE_SIG(_rand64, ".SEC_0x64BL", "\x42\x59\x54\x45\x5F\x44\x41");
    FAKE_SIG(_rand65, ".SEC_0x65BM", "\x48\x45\x58\x5F\x50\x52\x4F");
    FAKE_SIG(_rand66, ".SEC_0x66BN", "\x43\x4F\x44\x45\x5F\x53\x45");
    FAKE_SIG(_rand67, ".SEC_0x67BO", "\x53\x45\x43\x5F\x44\x41\x54");
    FAKE_SIG(_rand68, ".SEC_0x68BP", "\x50\x52\x4F\x54\x5F\x4B\x45");
    FAKE_SIG(_rand69, ".SEC_0x69BQ", "\x4B\x45\x59\x5F\x44\x41\x54");
    FAKE_SIG(_rand70, ".SEC_0x70BR", "\x48\x41\x53\x48\x5F\x53\x45");
    FAKE_SIG(_rand71, ".SEC_0x71BS", "\x43\x52\x59\x50\x54\x5F\x4B");
    FAKE_SIG(_rand72, ".SEC_0x72BT", "\x53\x41\x4C\x54\x5F\x50\x52");
    FAKE_SIG(_rand73, ".SEC_0x73BU", "\x42\x59\x54\x45\x5F\x53\x45");
    FAKE_SIG(_rand74, ".SEC_0x74BV", "\x48\x45\x58\x5F\x4B\x45\x59");
    FAKE_SIG(_rand75, ".SEC_0x75BW", "\x43\x4F\x44\x45\x5F\x4B\x45");
    FAKE_SIG(_rand76, ".SEC_0x76BX", "\x53\x45\x43\x5F\x50\x52\x4F");
    FAKE_SIG(_rand77, ".SEC_0x77BY", "\x50\x52\x4F\x54\x5F\x53\x45");
    FAKE_SIG(_rand78, ".SEC_0x78BZ", "\x4B\x45\x59\x5F\x50\x52\x4F");
    FAKE_SIG(_rand79, ".SEC_0x79CA", "\x48\x41\x53\x48\x5F\x44\x41");
    FAKE_SIG(_rand80, ".SEC_0x80CB", "\x43\x52\x59\x50\x54\x5F\x53");
    FAKE_SIG(_rand81, ".SEC_0x81CC", "\x53\x41\x4C\x54\x5F\x44\x41");
    FAKE_SIG(_rand82, ".SEC_0x82CD", "\x42\x59\x54\x45\x5F\x50\x52");
    FAKE_SIG(_rand83, ".SEC_0x83CE", "\x48\x45\x58\x5F\x53\x45\x43");
    FAKE_SIG(_rand84, ".SEC_0x84CF", "\x43\x4F\x44\x45\x5F\x44\x41");
    FAKE_SIG(_rand85, ".SEC_0x85CG", "\x53\x45\x43\x5F\x4B\x45\x59");
    FAKE_SIG(_rand86, ".SEC_0x86CH", "\x50\x52\x4F\x54\x5F\x44\x41");
    FAKE_SIG(_rand87, ".SEC_0x87CI", "\x4B\x45\x59\x5F\x53\x45\x43");
    FAKE_SIG(_rand88, ".SEC_0x88CJ", "\x48\x41\x53\x48\x5F\x50\x52");
    FAKE_SIG(_rand89, ".SEC_0x89CK", "\x43\x52\x59\x50\x54\x5F\x44");
    FAKE_SIG(_rand90, ".SEC_0x90CL", "\x53\x41\x4C\x54\x5F\x53\x45");
    FAKE_SIG(_rand91, ".SEC_0x91CM", "\x42\x59\x54\x45\x5F\x44\x41");
    FAKE_SIG(_rand92, ".SEC_0x92CN", "\x48\x45\x58\x5F\x50\x52\x4F");
    FAKE_SIG(_rand93, ".SEC_0x93CO", "\x43\x4F\x44\x45\x5F\x53\x45");
    FAKE_SIG(_rand94, ".SEC_0x94CP", "\x53\x45\x43\x5F\x44\x41\x54");
    FAKE_SIG(_rand95, ".SEC_0x95CQ", "\x50\x52\x4F\x54\x5F\x4B\x45");
    FAKE_SIG(_rand96, ".SEC_0x96CR", "\x4B\x45\x59\x5F\x44\x41\x54");
    FAKE_SIG(_rand97, ".SEC_0x97CS", "\x48\x41\x53\x48\x5F\x53\x45");
    FAKE_SIG(_rand98, ".SEC_0x98CT", "\x43\x52\x59\x50\x54\x5F\x4B");
    FAKE_SIG(_rand99, ".SEC_0x99CU", "\x53\x41\x4C\x54\x5F\x50\x52");
    FAKE_SIG(_rand100, ".SEC_0x100CV", "\x42\x59\x54\x45\x5F\x53\x45");
#endif

#pragma section(Name_Of_Sections_watermark, read)

#define PINK "\033[38;5;213m"
#define CYAN "\033[36m"
#define RESET "\033[0m"

#define INLINE __forceinline

#define JUNK_PRIME_1 0x1337DEAD
#define JUNK_PRIME_2 0xDEADBEEF
#define JUNK_PRIME_3 0xBADC0FEE
#define JUNK_PRIME_4 0xCAFEBABE


#define INTEGRITY_CHECK_FUNC_NAME ________________________________
#define START_INTEGRITY_CHECK std::thread([]() { INTEGRITY_CHECK_FUNC_NAME(); }).detach()

DWORD64 Function_Addressz;
volatile int chaos_seed = 10003;

#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
    );

#define ProcessDebugFlags 0x1F

namespace srungoat_signature {
    __declspec(allocate(Name_Of_Sections_watermark))
        static const unsigned char SIGNATURE[] = {
            0x53, 0x52, 0x55, 0x4E,// signature of the protector please don't change it i want to die detect it xD
            0x47, 0x4F, 0x41, 0x54,// signature of the protector please don't change it i want to die detect it xD
            0x50, 0x52, 0x4F, 0x54,// signature of the protector please don't change it i want to die detect it xD
            0xDE, 0xAD, 0xBE, 0xEF,// signature of the protector please don't change it i want to die detect it xD
            0x76, 0x31, 0x2E, 0x30// signature of the protector please don't change it i want to die detect it xD
    };

    __declspec(allocate(Name_Of_Sections_watermark))
        static const char INFO[] = "Protected by Srungoat Protector v1.0"; // signature of the protector please don't change it i want to die detect it xD

    namespace {
        static const void* const ensure_signature = SIGNATURE;
        static const char* const ensure_info = INFO;
    }
}

inline uint32_t rotl32(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

#define ULTRA_MEGA_JUNK(x) AbTdhF(x)
#define Junkyyyyyyy(x) JkDpomZd(x)

#define AbTdhF(x) do { \
    volatile int _crazy_var1 = 0xDEADC0DE; \
    volatile float _crazy_var2 = 3.14159265358979323846f; \
    volatile double _crazy_var3 = 2.718281828459045; \
    volatile long long _crazy_var4 = 0xCAFEBABEDEADBEEF; \
    volatile short _crazy_arr[128]; \
    volatile char _crazy_char_arr[256]; \
    volatile int _jmp_table[32]; \
    volatile int _jmp_history[64] = {0}; \
    volatile int _jmp_index = 0; \
    volatile int _layer = 0; \
    \
    for (int i = 0; i < 32; i++) { \
        _jmp_table[i] = (chaos_seed ^ i) % 32; \
    } \
    chaos_seed = (chaos_seed * 0x8088405 + 1) & 0xFFFFFFFF; \
    \
    for (volatile int _a_ = 0; _a_ < 100; ++_a_) { \
        _crazy_var1 ^= (_a_ * 0x1337); \
        if (_a_ % 11 == 0 && _layer < 3) { \
            _jmp_history[_jmp_index++ % 64] = _a_; \
            _layer++; \
        } \
        \
        for (volatile int _b_ = 0; _b_ < 30; ++_b_) { \
            _crazy_var2 *= (1.0f + (_b_ * 0.01f)); \
            if (_b_ % 15 == 1 && _layer > 0) { \
                _jmp_history[_jmp_index++ % 64] = _b_; \
                _layer--; \
            } \
            \
            if (((_crazy_var1 ^ _a_) & (_b_ + 1)) % 7 == 0) { \
                _crazy_var3 += _crazy_var2 / (1.0 + _a_); \
                if (((_crazy_var1 + _a_ * _b_) % (_b_ + 5)) == 0) { \
                    _crazy_var4 ^= (0xF00D << (_a_ % 16)); \
                    switch ((_crazy_var1 ^ (_a_ * _b_)) % 20) { \
                        case 0: _crazy_arr[_a_ % 128] = _b_; break; \
                        case 1: _crazy_var1 = ~_crazy_var1; break; \
                        case 2: _crazy_var2 = -_crazy_var2; break; \
                        case 3: _crazy_var3 *= 0.5; break; \
                        case 4: _crazy_var4 >>= 1; break; \
                        case 5: _crazy_char_arr[(_a_ + _b_) % 256] = _a_ ^ _b_; break; \
                        case 6: _crazy_var1 = _crazy_var1 | (1 << (_a_ % 32)); break; \
                        case 7: _crazy_var2 += _crazy_var3 / 1000.0f; break; \
                        case 8: _crazy_var3 = (_crazy_var3 > 1000) ? 0 : _crazy_var3 * 2; break; \
                        case 9: _crazy_var4 = (_crazy_var4 * 7) % 0xFFFFFFFFFFFF; break; \
                        case 10: _crazy_arr[(_a_ * _b_) % 128] = _a_ + _b_; break; \
                        case 11: _crazy_var1 = _crazy_var1 & ~(1 << (_b_ % 32)); break; \
                        case 12: _crazy_var2 *= (_a_ % 2) ? 1.5f : 0.5f; break; \
                        case 13: _crazy_var3 += sin((double)_a_ / (double)(_b_ + 1)); break; \
                        case 14: _crazy_var4 ^= (0x1234ABCD << (_b_ % 8)); break; \
                        case 15: _crazy_arr[(_a_ + _b_ * 3) % 128] = _a_ * _b_; break; \
                        case 16: _jmp_history[_jmp_index++ % 64] = 16; break; \
                        case 17: _crazy_var1 = _crazy_var1 ^ (chaos_seed * _a_ * _b_); break; \
                        case 18: if (_layer < 3) { _layer++; } break; \
                        case 19: _crazy_arr[(_a_ * _b_) % 128] ^= 0xFFFF; break; \
                    } \
                } \
            } \
            \
            if ((_a_ ^ _b_) % 3 == 0) { _crazy_var1 += _a_ * _b_; } \
            if ((_a_ + _b_) % 5 == 0) { _crazy_var3 *= 1.001; } \
            if ((_a_ * _b_) % 7 == 0) { _crazy_var4 ^= (1ULL << (_a_ % 63)); } \
            \
            for (volatile int _c_ = 0; _c_ < 5 && _c_ < _b_; ++_c_) { \
                    _crazy_var1 = (_crazy_var1 * 0x17489 + 0x24A63) & 0xFFFFFFFF; \
                    _crazy_arr[(_a_ + _b_ + _c_) % 128] = _c_ ^ _a_ ^ _b_; \
                if (_c_ % 3 == 0) { \
                    _crazy_var2 *= exp(sin((float)_c_ / 10.0f)); \
                } else if (_c_ % 3 == 1) { \
                    _crazy_var3 = tan(_crazy_var3 / 100.0) * 10.0; \
                } else { \
                    _crazy_var4 ^= (chaos_seed ^ 0xBAADF00D) * _c_; \
                } \
            } \
        } \
    } \
    \
    if (_crazy_var1 == 0x12345678 && _crazy_var4 == 0x87654321) { \
        for (int i = 0; i < 128; i++) { _crazy_arr[i] = 0; } \
    } \
    x; \
} while (0)

#define JkDpomZd(x) do { \
    volatile int _crazy_var1 = 0xDEADC0DE; \
    volatile float _crazy_var2 = 3.14159265358979323846f; \
    volatile double _crazy_var3 = 2.718281828459045; \
    volatile long long _crazy_var4 = 0xCAFEBABEDEADBEEF; \
    volatile short _crazy_arr[128]; \
    volatile char _crazy_char_arr[256]; \
    volatile int _jmp_table[32]; \
    volatile int _jmp_history[64] = {0}; \
    volatile int _jmp_index = 0; \
    volatile int _layer = 0; \
    \
    for (int i = 0; i < 32; i++) { \
        _jmp_table[i] = (chaos_seed ^ i) % 32; \
    } \
    chaos_seed = (chaos_seed * 0x8088405 + 1) & 0xFFFFFFFF; \
    \
    for (volatile int _a_ = 0; _a_ < 100; ++_a_) { \
        _crazy_var1 ^= (_a_ * 0x1337); \
        if (_a_ % 11 == 0 && _layer < 3) { \
            _jmp_history[_jmp_index++ % 64] = _a_; \
            _layer++; \
        } \
        \
        for (volatile int _b_ = 0; _b_ < 30; ++_b_) { \
            _crazy_var2 *= (1.0f + (_b_ * 0.01f)); \
            if (_b_ % 15 == 1 && _layer > 0) { \
                _jmp_history[_jmp_index++ % 64] = _b_; \
                _layer--; \
            } \
            \
            if (((_crazy_var1 ^ _a_) & (_b_ + 1)) % 7 == 0) { \
                _crazy_var3 += _crazy_var2 / (1.0 + _a_); \
                if (((_crazy_var1 + _a_ * _b_) % (_b_ + 5)) == 0) { \
                    _crazy_var4 ^= (0xF00D << (_a_ % 16)); \
                    switch ((_crazy_var1 ^ (_a_ * _b_)) % 20) { \
                        case 0: _crazy_arr[_a_ % 128] = _b_; break; \
                        case 1: _crazy_var1 = ~_crazy_var1; break; \
                        case 2: _crazy_var2 = -_crazy_var2; break; \
                        case 3: _crazy_var3 *= 0.5; break; \
                        case 4: _crazy_var4 >>= 1; break; \
                        case 5: _crazy_char_arr[(_a_ + _b_) % 256] = _a_ ^ _b_; break; \
                        case 6: _crazy_var1 = _crazy_var1 | (1 << (_a_ % 32)); break; \
                        case 7: _crazy_var2 += _crazy_var3 / 1000.0f; break; \
                        case 8: _crazy_var3 = (_crazy_var3 > 1000) ? 0 : _crazy_var3 * 2; break; \
                        case 9: _crazy_var4 = (_crazy_var4 * 7) % 0xFFFFFFFFFFFF; break; \
                        case 10: _crazy_arr[(_a_ * _b_) % 128] = _a_ + _b_; break; \
                        case 11: _crazy_var1 = _crazy_var1 & ~(1 << (_b_ % 32)); break; \
                        case 12: _crazy_var2 *= (_a_ % 2) ? 1.5f : 0.5f; break; \
                        case 13: _crazy_var3 += sin((double)_a_ / (double)(_b_ + 1)); break; \
                        case 14: _crazy_var4 ^= (0x1234ABCD << (_b_ % 8)); break; \
                        case 15: _crazy_arr[(_a_ + _b_ * 3) % 128] = _a_ * _b_; break; \
                        case 16: _jmp_history[_jmp_index++ % 64] = 16; break; \
                        case 17: _crazy_var1 = _crazy_var1 ^ (chaos_seed * _a_ * _b_); break; \
                        case 18: if (_layer < 3) { _layer++; } break; \
                        case 19: _crazy_arr[(_a_ * _b_) % 128] ^= 0xFFFF; break; \
                    } \
                } \
            } \
            \
            if ((_a_ ^ _b_) % 3 == 0) { _crazy_var1 += _a_ * _b_; } \
            if ((_a_ + _b_) % 5 == 0) { _crazy_var3 *= 1.001; } \
            if ((_a_ * _b_) % 7 == 0) { _crazy_var4 ^= (1ULL << (_a_ % 63)); } \
            \
            for (volatile int _c_ = 0; _c_ < 5 && _c_ < _b_; ++_c_) { \
                _crazy_var1 = (_crazy_var1 * 0x17489 + 0x24A63) & 0xFFFFFFFF; \
                _crazy_arr[(_a_ + _b_ + _c_) % 128] = _c_ ^ _a_ ^ _b_; \
                if (_c_ % 3 == 0) { \
                    _crazy_var2 *= exp(sin((float)_c_ / 10.0f)); \
                } else if (_c_ % 3 == 1) { \
                    _crazy_var3 = tan(_crazy_var3 / 100.0) * 10.0; \
                } else { \
                    _crazy_var4 ^= (chaos_seed ^ 0xBAADF00D) * _c_; \
                } \
            } \
        } \
    } \
    \
    if (_crazy_var1 == 0x12345678 && _crazy_var4 == 0x87654321) { \
        for (int i = 0; i < 128; i++) { _crazy_arr[i] = 0; } \
    } \
    x; \
} while (0)

#define dickyy(x) do { \
    ULTRA_MEGA_JUNK(0); \
    ULTRA_MEGA_JUNK(0); \
    ULTRA_MEGA_JUNK(0); \
} while (0)

#define PYRAMID_JUNK do { \
    if (rand() % 2) { \
        dickyy(0); \
    } else { \
        Junkyyyyyyy(0); \
    } \
} while(0)

#define JUNK do { \
    if (rand() % 2) { \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
    } else { \
        Junkyyyyyyy(0); \
    } \
} while(0)

#define BUG_IDA do { \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
    ULTRA_MEGA_JUNK(0); \
    Junkyyyyyyy(0); \
} while(0)

#define ZIGZAG_JUNK do { \
    if (rand() % 2) { \
        Junkyyyyyyy(0); \
        ULTRA_MEGA_JUNK(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
    } else { \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
    } \
} while(0)

#define COOL_JUNK do { \
    if (rand() % 2) { \
        ULTRA_MEGA_JUNK(0); \
        Junkyyyyyyy(0); \
        ULTRA_MEGA_JUNK(0); \
    } else { \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
    } \
} while(0)

#define JUNK_SHIP_SPACIAL do { \
    if (rand() % 2) { \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
    } else { \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
    } \
} while(0)

#define JUNK_FUCK_IDA do { \
    if (rand() % 2) { \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
        ULTRA_MEGA_JUNK(0); \
    } else { \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        ULTRA_MEGA_JUNK(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
        Junkyyyyyyy(0); \
    } \
} while(0)



inline char rotl8(char value, unsigned int count) {
    return (value << count) | (value >> (8 - count));
}

#define JUNK_VAR do { \
    volatile size_t _junk_size = (chaos_seed % 1000) + 1000; \
    volatile uint32_t* _junk_array = new uint32_t[_junk_size]; \
    volatile double* _junk_floats = new double[_junk_size]; \
    volatile uint64_t _junk_state = chaos_seed ^ JUNK_PRIME_1; \
    \
           \
    for(volatile size_t i = 0; i < _junk_size; i++) { \
        _junk_state = (_junk_state * JUNK_PRIME_2 + i) ^ rotl32(_junk_state, 13); \
        _junk_array[i] = _junk_state ^ JUNK_PRIME_3; \
        _junk_floats[i] = sin(static_cast<double>(i) / _junk_size) * cos(_junk_state); \
    } \
    \
          \
    volatile uint32_t _junk_sum = 0; \
    volatile double _junk_product = 1.0; \
    for(volatile size_t i = 0; i < _junk_size; i++) { \
        if((_junk_array[i] & JUNK_PRIME_4) == 0) { \
            _junk_sum += rotl32(_junk_array[i], i % 32); \
            _junk_product *= (1.0 + _junk_floats[i] / 1000000.0); \
        } else { \
            _junk_array[i] ^= rotl32(_junk_sum, 7); \
            _junk_floats[i] += tan(_junk_product) / 1000000.0; \
        } \
    } \
    \
          \
    if(_junk_sum % 2 == 0) { \
        for(volatile size_t i = 0; i < _junk_size / 2; i++) { \
            _junk_array[i] = (_junk_array[i] * JUNK_PRIME_1) ^ _junk_array[_junk_size - i - 1]; \
        } \
    } else { \
        for(volatile size_t i = 0; i < _junk_size / 3; i++) { \
            _junk_floats[i] = sqrt(fabs(_junk_floats[i] + _junk_product)); \
        } \
    } \
    \
               \
    chaos_seed ^= static_cast<uint32_t>(_junk_sum + static_cast<uint32_t>(_junk_product * 1000000)); \
    \
       \
    delete[] _junk_array; \
    delete[] _junk_floats; \
} while(0)

#define JUNK_FUNC(name) \
    INLINE void name() { \
        volatile uint32_t _local_chaos = chaos_seed; \
        JUNK_VAR; \
        if(_local_chaos % 3 == 0) { \
            ULTRA_MEGA_JUNK(0); \
        } else if(_local_chaos % 3 == 1) { \
            Junkyyyyyyy(0); \
        } else { \
            JUNK_VAR; \
        } \
        chaos_seed = _local_chaos ^ 0xDEADBEEF; \
    }

JUNK_FUNC(junk_func_1)
JUNK_FUNC(junk_func_2)
JUNK_FUNC(junk_func_3)
JUNK_FUNC(junk_func_4)
JUNK_FUNC(junk_func_5)
JUNK_FUNC(junk_func_6)
JUNK_FUNC(junk_func_7)
JUNK_FUNC(junk_func_8)
JUNK_FUNC(junk_func_9)
JUNK_FUNC(junk_func_10)

#define CALL_RANDOM_JUNK do { \
    switch(chaos_seed % 10) { \
        case 0: junk_func_1(); break; \
        case 1: junk_func_2(); break; \
        case 2: junk_func_3(); break; \
        case 3: junk_func_4(); break; \
        case 4: junk_func_5(); break; \
        case 5: junk_func_6(); break; \
        case 6: junk_func_7(); break; \
        case 7: junk_func_8(); break; \
        case 8: junk_func_9(); break; \
        case 9: junk_func_10(); break; \
    } \
} while(0)


namespace obffu
{
    template<class _Ty>
    using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

    template <int _size, char _key1, char _key2, typename T>
    class skCrypter
    {
    public:
        __forceinline constexpr skCrypter(T* data)
        {
            crypt(data);
        }

        __forceinline T* get()
        {
            return _storage;
        }

        __forceinline int size()   
        {
            return _size;
        }

        __forceinline  char key()
        {
            return _key1;
        }

        __forceinline  T* encrypt()
        {
            if (!isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline  T* decrypt()
        {
            if (isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline bool isEncrypted()
        {
            return _storage[_size - 1] != 0;
        }

        __forceinline void clear()      
        {
            for (int i = 0; i < _size; i++)
            {
                _storage[i] = 0;
            }
        }

        __forceinline operator T* ()
        {
            decrypt();

            return _storage;
        }

    private:
        __forceinline constexpr void crypt(T* data)
        {
            for (int i = 0; i < _size; i++)
            {
                _storage[i] = data[i] ^ (_key1 + i * (1 + _key2));
            }
            for (int i = _size - 1; i >= 0; i--)
            {
                _storage[i] ^= (_key2 + i * (1 + _key1));
            }
        }

        T _storage[_size]{};
    };
}

#define OBF(val) obffu::obfuscate_any(val, __TIME__[4], __TIME__[7])

#if JUNK_ON_OBF

#if JUNK_ON_OBF_LEVEL == 3
#define KEyy(str, key1, key2) []() { \
            JUNK_VAR; \
            CALL_RANDOM_JUNK; \
            constexpr static auto crypted = obffu::skCrypter<sizeof(str) / sizeof(str[0]), key1, key2, \
                obffu::clean_type<decltype(str[0])>>((obffu::clean_type<decltype(str[0])>*)str); \
            CALL_RANDOM_JUNK; \
            JUNK_VAR; \
            return crypted; \
        }()
#elif JUNK_ON_OBF_LEVEL == 2
#define KEyy(str, key1, key2) []() { \
            COOL_JUNK; \
            constexpr static auto crypted = obffu::skCrypter<sizeof(str) / sizeof(str[0]), key1, key2, \
                obffu::clean_type<decltype(str[0])>>((obffu::clean_type<decltype(str[0])>*)str); \
            COOL_JUNK; \
            return crypted; \
        }()
#elif JUNK_ON_OBF_LEVEL == 1
#define KEyy(str, key1, key2) []() { \
            JUNK; \
            constexpr static auto crypted = obffu::skCrypter<sizeof(str) / sizeof(str[0]), key1, key2, \
                obffu::clean_type<decltype(str[0])>>((obffu::clean_type<decltype(str[0])>*)str); \
            JUNK; \
            return crypted; \
        }()
#elif JUNK_ON_OBF_LEVEL == 0
#define KEyy(str, key1, key2) []() { \
            Junkyyyyyyy(0); \
            constexpr static auto crypted = obffu::skCrypter<sizeof(str) / sizeof(str[0]), key1, key2, \
                obffu::clean_type<decltype(str[0])>>((obffu::clean_type<decltype(str[0])>*)str); \
            Junkyyyyyyy(0); \
            return crypted; \
        }()
#else
#error "Invalid value for JUNK_ON_OBF_LEVEL"
#endif

#else

#define KEyy(str, key1, key2) []() { \
        constexpr static auto crypted = obffu::skCrypter<sizeof(str) / sizeof(str[0]), key1, key2, \
            obffu::clean_type<decltype(str[0])>>((obffu::clean_type<decltype(str[0])>*)str); \
        return crypted; \
    }()

#endif


namespace obffu {

INLINE std::string runtime_xor(std::string str, char k1, char k2) {
    for (size_t i = 0; i < str.size(); ++i)
        str[i] ^= static_cast<unsigned char>(k1 + i * (1 + k2));
    for (size_t i = str.size(); i-- > 0; )
        str[i] ^= static_cast<unsigned char>(k2 + i * (1 + k1));
    return str;
}

INLINE std::wstring runtime_xor(std::wstring str, char k1, char k2) {
    for (size_t i = 0; i < str.size(); ++i)
        str[i] ^= static_cast<wchar_t>(k1 + i * (1 + k2));
    for (size_t i = str.size(); i-- > 0; )
        str[i] ^= static_cast<wchar_t>(k2 + i * (1 + k1));
    return str;
}

template<typename T, typename std::enable_if_t<std::is_integral_v<T> || std::is_floating_point_v<T>, int> = 0>
INLINE std::string obfuscate_any(T value, char k1, char k2) {
    return runtime_xor(std::to_string(value), k1, k2);
}

INLINE std::string obfuscate_any(bool value, char k1, char k2) {
    return runtime_xor(value ? std::string("true") : std::string("false"), k1, k2);
}

INLINE std::string obfuscate_any(const std::string& value, char k1, char k2) {
    return runtime_xor(value, k1, k2);
}

INLINE std::wstring obfuscate_any(const std::wstring& value, char k1, char k2) {
    return runtime_xor(value, k1, k2);
}

template <size_t N>
constexpr auto obfuscate_any(const char (&arr)[N], char k1, char k2) {
    return KEyy(arr, k1, k2).decrypt();
}

template <size_t N>
constexpr auto obfuscate_any(const wchar_t (&arr)[N], char k1, char k2) {
    return KEyy(arr, k1, k2).decrypt();
}

} // namespace obffu


constexpr char convert_accent(char c) {
    switch (static_cast<unsigned char>(c)) {
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5: return 'a';       
        case 0xE8: case 0xE9: case 0xEA: case 0xEB: return 'e';     
        case 0xEC: case 0xED: case 0xEE: case 0xEF: return 'i';     
        case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6: return 'o';      
        case 0xF9: case 0xFA: case 0xFB: case 0xFC: return 'u';     
        case 0xE7: return 'c';  
        case 0xF1: return 'n';  
        case 0xFD: case 0xFF: return 'y';   
        default: return c;
    }
}

#define WATERMARK_UNIQUE_NAME2(prefix, line) prefix##line
#define WATERMARK_UNIQUE_NAME1(prefix, line) WATERMARK_UNIQUE_NAME2(prefix, line)
#define WATERMARK_UNIQUE_NAME(prefix) WATERMARK_UNIQUE_NAME1(prefix, __LINE__)

#define CONVERT_STRING(str) []() { \
    static char converted[1024]; \
    const char* src = str; \
    char* dst = converted; \
    while (*src && (dst - converted) < 1023) { \
        *dst++ = convert_accent(*src++); \
    } \
    *dst = '\0'; \
    return converted; \
}()

#define WATERMARK(watermark) \
    __declspec(allocate(Name_Of_Sections_watermark)) \
    static const char WATERMARK_UNIQUE_NAME(__watermark)[] = \
        watermark; \
    \
    __declspec(allocate(Name_Of_Sections_watermark)) \
    static const unsigned char WATERMARK_UNIQUE_NAME(__pattern)[] = { \
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, \
        OBF('W'), OBF('A'), OBF('T'), OBF('E'), OBF('R'), OBF('M'), OBF('A'), OBF('R'), OBF('K'), OBF(':'), \
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE \
    }; \
    static const char* const volatile WATERMARK_UNIQUE_NAME(__ptr1) = WATERMARK_UNIQUE_NAME(__watermark); \
    static const unsigned char* const volatile WATERMARK_UNIQUE_NAME(__ptr2) = WATERMARK_UNIQUE_NAME(__pattern); \
    (void)WATERMARK_UNIQUE_NAME(__ptr1); \
    (void)WATERMARK_UNIQUE_NAME(__ptr2)


bool bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return false;
    return (*szMask) == 0;
}

DWORD64 FindPatternz(BYTE* bMask, const char* szMask)
{
    MODULEINFO mi{ };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi));

    DWORD64 dwBaseAddress = DWORD64(mi.lpBaseOfDll);
    const auto dwModuleSize = mi.SizeOfImage;

    for (auto i = 0ul; i < dwModuleSize; i++)
    {
        if (bDataCompare(PBYTE(dwBaseAddress + i), bMask, szMask))
            return DWORD64(dwBaseAddress + i);
    }
    return NULL;
}

void error(const std::string& message) {
    std::string cmd = OBF("start cmd /C \"color D && title ") + std::string(".") + OBF("Security Alert") +
        OBF(" && echo ") + std::string(PINK) + message +
        std::string(RESET) + OBF(" && timeout /t 5\"");
    system(cmd.c_str());
    exit(1);
}

void error(const char* message) {
    error(std::string(message));
}

template<size_t _size, char _key1, char _key2, typename T>
void error(std::string& message) {
    error(std::string(message));
}

auto check_section_integrityz(const char* section_name, bool fix = false) -> bool
{
    const auto hmodule = GetModuleHandle(0);
    if (!hmodule) {
        error(OBF("Memory integrity check failed: Invalid module handle"));
        return true;
    }

    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    if (!base_0) {
        error(OBF("Memory integrity check failed: Invalid base address"));
        return true;
    }

    const auto dos_0 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos_0->e_magic != IMAGE_DOS_SIGNATURE) {
        error(OBF("Memory integrity check failed: Invalid DOS signature"));
        return true;
    }

    const auto nt_0 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos_0->e_lfanew);
    if (nt_0->Signature != IMAGE_NT_SIGNATURE) {
        error(OBF("Memory integrity check failed: Invalid NT signature"));
        return true;
    }

    auto section_0 = IMAGE_FIRST_SECTION(nt_0);

    wchar_t filename[MAX_PATH];
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(GetCurrentProcess(), 0, filename, &size);

    const auto file_handle = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (!file_handle || file_handle == INVALID_HANDLE_VALUE) {
        error(OBF("Memory integrity check failed: Unable to open process file"));
        return true;
    }

    const auto file_mapping = CreateFileMapping(file_handle, 0, PAGE_READONLY, 0, 0, 0);
    if (!file_mapping)
    {
        CloseHandle(file_handle);
        error(OBF("Memory integrity check failed: Unable to create file mapping("));
        return true;
    }

    const auto base_1 = reinterpret_cast<std::uintptr_t>(MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0));
    if (!base_1)
    {
        CloseHandle(file_mapping);
        CloseHandle(file_handle);
        error(OBF("Memory integrity check failed: Unable to map view of file"));
        return true;
    }

    const auto dos_1 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_1);
    if (dos_1->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UnmapViewOfFile(reinterpret_cast<void*>(base_1));
        CloseHandle(file_mapping);
        CloseHandle(file_handle);
        error(OBF("Memory integrity check failed: Invalid DOS signature in mapped file"));
        return true;
    }

    const auto nt_1 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_1 + dos_1->e_lfanew);
    if (nt_1->Signature != IMAGE_NT_SIGNATURE ||
        nt_1->FileHeader.TimeDateStamp != nt_0->FileHeader.TimeDateStamp ||
        nt_1->FileHeader.NumberOfSections != nt_0->FileHeader.NumberOfSections)
    {
        UnmapViewOfFile(reinterpret_cast<void*>(base_1));
        CloseHandle(file_mapping);
        CloseHandle(file_handle);
        error(OBF("Memory integrity check failed: Invalid NT headers or timestamps"));
        return true;
    }

    auto section_1 = IMAGE_FIRST_SECTION(nt_1);
    bool patched = false;

    for (auto i = 0; i < nt_1->FileHeader.NumberOfSections; ++i, ++section_0, ++section_1)
    {
        if (strcmp(reinterpret_cast<char*>(section_0->Name), OBF(".text")) ||
            !(section_0->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }

        for (auto j = 0u; j < section_0->SizeOfRawData; ++j)
        {
            const auto old_value = *reinterpret_cast<BYTE*>(base_1 + section_1->PointerToRawData + j);
            const auto current_value = *reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + j);

            if (current_value == old_value) continue;

            if (fix)
            {
                DWORD new_protect{ PAGE_EXECUTE_READWRITE }, old_protect;
                VirtualProtect(reinterpret_cast<void*>(base_0 + section_0->VirtualAddress + j),
                    sizeof(BYTE), new_protect, &old_protect);
                *reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + j) = old_value;
                VirtualProtect(reinterpret_cast<void*>(base_0 + section_0->VirtualAddress + j),
                    sizeof(BYTE), old_protect, &new_protect);
            }

            patched = true;
        }
        break;
    }

    UnmapViewOfFile(reinterpret_cast<void*>(base_1));
    CloseHandle(file_mapping);
    CloseHandle(file_handle);

    if (patched && !fix) {
        error(OBF("Critical security violation: Code integrity check failed"));
    }

    return patched;
}

std::string checksumz()
{
    auto exec = [&](const char* cmd) -> std::string
        {
            uint16_t line = -1;
            std::array<char, 128> buffer;
            std::string result;
            std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
            if (!pipe) {
                throw std::runtime_error(OBF("popen() failed!"));
            }

            while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                result = buffer.data();
            }
            return result;
        };

    char rawPathName[MAX_PATH];
    GetModuleFileNameA(NULL, rawPathName, MAX_PATH);

    return exec((OBF("certutil -hashfile \"") + std::string(rawPathName) + OBF("\" MD5 | find /i /v \"md5\" | find /i /v \"certutil\"")).c_str());
}

#pragma once
#include <Windows.h>
#include <string>
#include <accctrl.h>
#include <aclapi.h>
#include <bcrypt.h>

inline bool LockMemAccessz()
{
    bool bSuccess = false;
    HANDLE hToken = nullptr;
    PTOKEN_USER pTokenUser = nullptr;
    DWORD cbBufferSize = 0;

    PACL pACL = nullptr;
    DWORD cbACL = 0;

    if (!OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY,
        &hToken
    )) {
        goto Cleanup;
    }

    GetTokenInformation(
        hToken,
        TokenUser,
        nullptr,
        0,
        &cbBufferSize
    );

    pTokenUser = static_cast<PTOKEN_USER>(malloc(cbBufferSize));
    if (pTokenUser == nullptr) {
        goto Cleanup;
    }

    if (!GetTokenInformation(
        hToken,
        TokenUser,
        pTokenUser,
        cbBufferSize,
        &cbBufferSize
    )) {
        goto Cleanup;
    }

    if (!IsValidSid(pTokenUser->User.Sid)) {
        goto Cleanup;
    }

    cbACL = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pTokenUser->User.Sid);

    pACL = static_cast<PACL>(malloc(cbACL));
    if (pACL == nullptr) {
        goto Cleanup;
    }

    if (!InitializeAcl(pACL, cbACL, ACL_REVISION)) {
        goto Cleanup;
    }

    if (!AddAccessAllowedAce(
        pACL,
        ACL_REVISION,
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
        pTokenUser->User.Sid
    )) {
        goto Cleanup;
    }

    bSuccess = ERROR_SUCCESS == SetSecurityInfo(
        GetCurrentProcess(),
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        pACL,
        nullptr
    );

Cleanup:

    if (pACL != nullptr) {
        free(pACL);

    }
    if (pTokenUser != nullptr) {
        free(pTokenUser);

    }
    if (hToken != nullptr) {
        CloseHandle(hToken);

    }
    return bSuccess;
}

bool checkAcceleratorIntegrityz() {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(1), RT_ACCELERATOR);

    if (hRsrc) {
        error(OBF("Critical security violation: Unauthorized accelerator table detected"));
        return false;
    }
    return true;
}

void INTEGRITY_CHECK_FUNC_NAME()
{
    check_section_integrityz(".text", true);

    while (true)
    {
        if (!checkAcceleratorIntegrityz()) {
            error(OBF("Critical security violation: Resource tampering detected"));
        }

        if (check_section_integrityz(".text"), false)
        {
            error(OBF("Critical security violation: Memory tampering detected"));
        }

        if (!LockMemAccessz())
        {
            error(OBF("Critical security violation: Memory protection failure"));
        }

        if (Function_Addressz == NULL) {
            BYTE pattern[] = "\x48\x89\x74\x24\x00\x57\x48\x81\xec\x00\x00\x00\x00\x49\x8b\xf0";
            Function_Addressz = FindPatternz(pattern, "xxxx?xxxx????xxx") - 0x5;
        }

        BYTE Instruction = *(BYTE*)Function_Addressz;
        if ((DWORD64)Instruction == 0xE9) {
            error(OBF("Critical security violation: Code execution flow compromised"));
        }
        Sleep(50);
    }
}


#if CALL_LEVEL == 0
#define CALL(expr) \
    [&]() { \
        JUNK; \
        auto&& _result = expr; \
        JUNK; \
        return _result; \
    }()

#elif CALL_LEVEL == 1
#define CALL(expr) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        void (*_fake_func)() = nullptr; \
        _fake_func = (void(*)())junk_func_1; \
        if (chaos_seed % 2) { _fake_func(); } \
        auto&& _result = expr; \
        CALL_RANDOM_JUNK; \
        return _result; \
    }()

#elif CALL_LEVEL == 2
#define CALL(expr) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        void (*_fake_func)() = nullptr; \
        _fake_func = (void(*)())junk_func_1; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
        COOL_JUNK; \
        _fake_func = (void(*)())junk_func_3; \
        if (chaos_seed % 3) { _fake_func(); } \
        auto&& _result = expr; \
        ULTRA_MEGA_JUNK(0); \
        _fake_func = (void(*)())junk_func_5; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
        return _result; \
    }()

#else       
#define CALL(expr) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        void (*_fake_func)() = nullptr; \
        _fake_func = (void(*)())junk_func_1; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
        COOL_JUNK; \
        _fake_func = (void(*)())junk_func_3; \
        if (chaos_seed % 3) { _fake_func(); } \
        JUNK_FUCK_IDA; \
        _fake_func = (void(*)())junk_func_7; \
        if (chaos_seed % 4) { _fake_func(); } \
        auto&& _result = expr; \
        ULTRA_MEGA_JUNK(0); \
        BUG_IDA; \
        _fake_func = (void(*)())junk_func_5; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
        COOL_JUNK; \
        _fake_func = (void(*)())junk_func_9; \
        if (chaos_seed % 5) { _fake_func(); } \
        return _result; \
    }()
#endif

#if CALL_LEVEL == 0
#define CALL_VOID(expr) \
    [&]() { \
        JUNK; \
        expr(); \
        JUNK; \
    }()

#elif CALL_LEVEL == 1
#define CALL_VOID(expr) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        void (*_fake_func)() = nullptr; \
        _fake_func = (void(*)())junk_func_1; \
        if (chaos_seed % 2) { _fake_func(); } \
        expr(); \
        CALL_RANDOM_JUNK; \
    }()

#elif CALL_LEVEL == 2
#define CALL_VOID(expr) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        void (*_fake_func)() = nullptr; \
        _fake_func = (void(*)())junk_func_1; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
        COOL_JUNK; \
        _fake_func = (void(*)())junk_func_3; \
        if (chaos_seed % 3) { _fake_func(); } \
        expr(); \
        ULTRA_MEGA_JUNK(0); \
        _fake_func = (void(*)())junk_func_5; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
    }()

#else       
#define CALL_VOID(expr) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        void (*_fake_func)() = nullptr; \
        _fake_func = (void(*)())junk_func_1; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
        COOL_JUNK; \
        _fake_func = (void(*)())junk_func_3; \
        if (chaos_seed % 3) { _fake_func(); } \
        JUNK_FUCK_IDA; \
        _fake_func = (void(*)())junk_func_7; \
        if (chaos_seed % 4) { _fake_func(); } \
        expr(); \
        ULTRA_MEGA_JUNK(0); \
        BUG_IDA; \
        _fake_func = (void(*)())junk_func_5; \
        if (chaos_seed % 2) { _fake_func(); } \
        CALL_RANDOM_JUNK; \
        COOL_JUNK; \
        _fake_func = (void(*)())junk_func_9; \
        if (chaos_seed % 5) { _fake_func(); } \
    }()
#endif

#define DbgBreakPoint_FUNC_SIZE 0x2
#define DbgUiRemoteBreakin_FUNC_SIZE 0x54
#define NtContinue_FUNC_SIZE 0x18

struct FUNC {
    const char* name;
    FARPROC addr;
    SIZE_T size;
};

FUNC funcList[] = {
    { OBF("DbgBreakPoint"), 0, DbgBreakPoint_FUNC_SIZE },
    { OBF("DbgUiRemoteBreakin"), 0, DbgUiRemoteBreakin_FUNC_SIZE },
    { OBF("NtContinue"), 0, NtContinue_FUNC_SIZE }
};

INLINE void anti_attach() {
    while (true) {
        ULTRA_MEGA_JUNK(0);

        if (IsDebuggerPresent()) {
            error(OBF("Debugger detected!"));
        }

        BOOL isRemoteDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
        if (isRemoteDebuggerPresent) {
            error(OBF("Remote debugger detected!"));
        }

        HANDLE hProcess = GetCurrentProcess();
        DWORD_PTR debugPort = 0;
        NTSTATUS status;

        static auto NtQueryInformationProcess = (NTSTATUS(NTAPI*)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            status = NtQueryInformationProcess(
                hProcess,
                ProcessDebugPort,
                &debugPort,
                sizeof(debugPort),
                NULL
            );

            if (NT_SUCCESS(status) && debugPort != 0) {
                error(OBF("Debugger attachment detected!"));
            }
        }

        DWORD pid = GetCurrentProcessId();
        WCHAR modName[MAX_PATH] = { 0 };
        HANDLE hProcessEx = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

        HMODULE hMod = LoadLibraryA(OBF("ntdll.dll"));
        if (hMod) {
            for (int i = 0; i < _countof(funcList); ++i) {
                funcList[i].addr = GetProcAddress(hMod, funcList[i].name);
            }

            bool result = false;
            auto base_address = GetModuleHandleA(0);
            if (base_address) {
                wchar_t ntdll_lower[] = L"ntdll";
                wchar_t ntdll_upper[] = L"NTDLL";
                if (wcsstr((WCHAR*)base_address, ntdll_lower) || wcsstr((WCHAR*)base_address, ntdll_upper)) {
                    for (int i = 0; i < _countof(funcList); ++i) {
                        if (funcList[i].addr) {
                            DWORD dwOldProtect;
                            VirtualProtectEx(hProcessEx, funcList[i].addr, funcList[i].size, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                            result = WriteProcessMemory(hProcessEx, funcList[i].addr, funcList[i].addr, funcList[i].size, NULL);
                            VirtualProtectEx(hProcessEx, funcList[i].addr, funcList[i].size, dwOldProtect, NULL);

                            if (!result) break;
                        }
                    }
                }
            }
        }

        if (hProcessEx) {
            CloseHandle(hProcessEx);
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_ATTACH std::thread([]() { anti_attach(); }).detach()

struct WindowInfo {
    HWND hwnd;
    std::string title;
};

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    char title[512];
    GetWindowTextA(hwnd, title, sizeof(title));
    if (strlen(title) > 0) {
        std::vector<WindowInfo>* windows = reinterpret_cast<std::vector<WindowInfo>*>(lParam);
        windows->push_back({ hwnd, title });
    }
    return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char title[512];
    GetWindowTextA(hwnd, title, sizeof(title));
    if (strlen(title) > 0) {
        std::vector<WindowInfo>* windows = reinterpret_cast<std::vector<WindowInfo>*>(lParam);
        windows->push_back({ hwnd, title });
    }

    EnumChildWindows(hwnd, EnumChildProc, lParam);
    return TRUE;
}


INLINE void check_window_titles() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    char* exeName = strrchr(exePath, '\\');
    if (exeName) {
        exeName++;    
    } else {
        exeName = exePath;
    }
    
    while (true) {
        ULTRA_MEGA_JUNK(0);
        
        std::vector<WindowInfo> windows;
        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&windows));
        
        HWND ourWindow = GetConsoleWindow();
        if (!ourWindow) {
            ourWindow = GetActiveWindow();
        }
        
        for (const auto& window : windows) {
            if (window.hwnd != ourWindow) {     
                std::string lowerTitle = window.title;
                std::string lowerExe = exeName;
                std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::tolower);
                std::transform(lowerExe.begin(), lowerExe.end(), lowerExe.begin(), ::tolower);

                size_t pos = lowerTitle.rfind(lowerExe);
                if (pos != std::string::npos && pos + lowerExe.length() == lowerTitle.length()) {
                    DWORD windowPid;
                    GetWindowThreadProcessId(window.hwnd, &windowPid);
                    
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, windowPid);
                    if (hProcess) {
                        char processName[MAX_PATH];
                        if (GetModuleFileNameExA(hProcess, NULL, processName, MAX_PATH)) {
                            error(OBF("Suspicious window title detected: ") + window.title + 
                                  OBF(" (Process: ") + processName + OBF(")"));
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        }
        
        CALL_RANDOM_JUNK;
        Sleep(100);
    }
}

#define START_ANTI_WINDOW_TITLE std::thread([]() { check_window_titles(); }).detach()

INLINE void junk_threads_protection() {
    while (true) {
        ULTRA_MEGA_JUNK(0);
        
        int num_threads = rand() % 500 + 50;      
        std::vector<std::thread> junk_threads;
        
        for (int i = 0; i < num_threads; i++) {
            junk_threads.push_back(std::thread([i]() {
                Sleep(rand() % 1000 + 500);
            }));
        }
        
        for (auto& thread : junk_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        CALL_RANDOM_JUNK;
    }
}

#define START_JUNK_THREADS std::thread([]() { junk_threads_protection(); }).detach()

struct ThreadInfo {
    DWORD threadId;
    HANDLE handle;
    std::chrono::steady_clock::time_point lastCheck;
    bool isActive;
};

std::vector<ThreadInfo> protected_threads;
std::mutex threads_mutex;

void update_protected_threads() {
    std::lock_guard<std::mutex> lock(threads_mutex);
    
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD currentPID = GetCurrentProcessId();

    protected_threads.erase(
        std::remove_if(protected_threads.begin(), protected_threads.end(),
            [](const ThreadInfo& info) {
                DWORD exitCode;
                return !GetExitCodeThread(info.handle, &exitCode) || exitCode != STILL_ACTIVE;
            }
        ),
        protected_threads.end()
    );

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentPID) {
                auto it = std::find_if(protected_threads.begin(), protected_threads.end(),
                    [&te32](const ThreadInfo& info) { return info.threadId == te32.th32ThreadID; });
                
                if (it == protected_threads.end()) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        protected_threads.push_back({
                            te32.th32ThreadID,
                            hThread,
                            std::chrono::steady_clock::now(),
                            true
                        });
                    }
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    
    CloseHandle(hThreadSnap);
}

INLINE void anti_pause_thread() {
    while (true) {
        ULTRA_MEGA_JUNK(0);
        update_protected_threads();
        {
            std::lock_guard<std::mutex> lock(threads_mutex);
            for (auto& thread : protected_threads) {
                DWORD suspendCount = 0;
                CONTEXT context = { 0 };
                context.ContextFlags = CONTEXT_ALL;

                HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                if (ntdll) {
                    typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
                        HANDLE ThreadHandle,
                        THREADINFOCLASS ThreadInformationClass,
                        PVOID ThreadInformation,
                        ULONG ThreadInformationLength,
                        PULONG ReturnLength
                    );

                    auto NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(
                        ntdll, "NtQueryInformationThread");

                    if (NtQueryInformationThread) {
                        ULONG suspendCount = 0;
                        if (NT_SUCCESS(NtQueryInformationThread(
                            thread.handle,
                            (THREADINFOCLASS)35,
                            &suspendCount,
                            sizeof(suspendCount),
                            NULL))) {
                            if (suspendCount > 0) {
                                while (ResumeThread(thread.handle) > 0) {}
                            }
                        }
                    }
                }

                DWORD exitCode;
                if (GetExitCodeThread(thread.handle, &exitCode)) {
                    if (exitCode != STILL_ACTIVE) {
                    }
                }
            }
        }
        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

INLINE void anti_terminate_thread() {
    while (true) {
        ULTRA_MEGA_JUNK(0);
        update_protected_threads();
        {
            std::lock_guard<std::mutex> lock(threads_mutex);
            auto now = std::chrono::steady_clock::now();
            
            for (auto& thread : protected_threads) {
                DWORD exitCode;
                if (!GetExitCodeThread(thread.handle, &exitCode) || exitCode != STILL_ACTIVE) {
                    error(OBF("Critical security violation: Thread termination detected!"));
                }

                CONTEXT context = { 0 };
                context.ContextFlags = CONTEXT_ALL;
                if (!GetThreadContext(thread.handle, &context)) {
                    if (GetLastError() != ERROR_GEN_FAILURE) {
                        error(OBF("Critical security violation: Thread context manipulation detected!"));
                    }
                }

                thread.lastCheck = now;
            }
        }
        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_PAUSE_THREAD std::thread([]() { anti_pause_thread(); }).detach()
#define START_ANTI_TERMINATE_THREAD std::thread([]() { anti_terminate_thread(); }).detach()

struct ModuleInfo {
    std::string name;
    DWORD64 baseAddress;
    DWORD size;
};

std::vector<ModuleInfo> legitimate_modules;
std::mutex modules_mutex;

const std::vector<std::string> system_dlls = {
    "KERNEL32.DLL",
    "KERNELBASE.DLL",
    "NTDLL.DLL",
    "USER32.DLL",
    "WIN32U.DLL",
    "GDI32.DLL",
    "GDI32FULL.DLL",
    "ADVAPI32.DLL",
    "MSVCRT.DLL",
    "SECHOST.DLL",
    "RPCRT4.DLL",
    "CRYPTBASE.DLL",
    "BCRYPTPRIMITIVES.DLL",
    "CRYPTSP.DLL",
    "SSPICLI.DLL",
    "CRYPT32.DLL",
    "MSASN1.DLL",
    "WLDAP32.DLL",
    "FLTLIB.DLL",
    "WS2_32.DLL",
    "OLEAUT32.DLL",
    "OLE32.DLL",
    "SHELL32.DLL",
    "SHLWAPI.DLL",
    "SETUPAPI.DLL",
    "CFGMGR32.DLL",
    "POWRPROF.DLL",
    "UMPDC.DLL",
    "VCRUNTIME140.DLL",
    "VCRUNTIME140_1.DLL",
    "MSVCP140.DLL",
    "CONCRT140.DLL",
    "nvldumdx.dll"
};

bool is_system_dll(const std::string& dll_name) {
    std::string upper_dll_name = dll_name;
    std::transform(upper_dll_name.begin(), upper_dll_name.end(), upper_dll_name.begin(), ::toupper);
    
    return std::find(system_dlls.begin(), system_dlls.end(), upper_dll_name) != system_dlls.end();
}

bool is_dll_in_system_directory(const std::string& dll_name) {
    char system_dir[MAX_PATH];
    char system32_dir[MAX_PATH];
    
    if (GetSystemDirectoryA(system_dir, MAX_PATH)) {
        std::string dll_path = std::string(system_dir) + "\\" + dll_name;
        if (GetFileAttributesA(dll_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    
    if (GetSystemWow64DirectoryA(system32_dir, MAX_PATH)) {
        std::string dll_path = std::string(system32_dir) + "\\" + dll_name;
        if (GetFileAttributesA(dll_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    
    return false;
}

bool is_main_executable(const std::string& module_name) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    const char* exeName = strrchr(exePath, '\\');
    exeName = exeName ? exeName + 1 : exePath;
    
    return _stricmp(module_name.c_str(), exeName) == 0;
}

bool is_legitimate_module(const std::string& module_name, DWORD64 base_address) {
    if (is_main_executable(module_name)) {
        return true;
    }

    if (is_system_dll(module_name) || is_dll_in_system_directory(module_name)) {
        return true;
    }

    std::lock_guard<std::mutex> lock(modules_mutex);
    return std::any_of(legitimate_modules.begin(), legitimate_modules.end(),
        [&](const ModuleInfo& info) {
            return _stricmp(info.name.c_str(), module_name.c_str()) == 0 &&
                   info.baseAddress == base_address;
        });
}

void initialize_legitimate_modules() {
    std::lock_guard<std::mutex> lock(modules_mutex);
    legitimate_modules.clear();      
    
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hModuleSnap, &me32)) {
        do {
            char moduleName[MAX_PATH];
            size_t convertedChars = 0;
            wcstombs_s(&convertedChars, moduleName, MAX_PATH, me32.szModule, MAX_PATH);
            
            legitimate_modules.push_back({
                moduleName,
                (DWORD64)me32.modBaseAddr,
                me32.modBaseSize
            });
            
        } while (Module32NextW(hModuleSnap, &me32));
    }

    CloseHandle(hModuleSnap);
}

INLINE void anti_dll_injection() {
    initialize_legitimate_modules();
    
    while (true) {
        ULTRA_MEGA_JUNK(0);
        
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hModuleSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me32;
            me32.dwSize = sizeof(MODULEENTRY32W);

            if (Module32FirstW(hModuleSnap, &me32)) {
                do {
                    char moduleName[MAX_PATH];
                    size_t convertedChars = 0;
                    wcstombs_s(&convertedChars, moduleName, MAX_PATH, me32.szModule, MAX_PATH);
                    
                    if (!is_legitimate_module(moduleName, (DWORD64)me32.modBaseAddr)) {
                        HMODULE hModule = GetModuleHandleA(moduleName);
                        if (hModule) {
                            HANDLE hProcess = GetCurrentProcess();
                            LPVOID lpFreeLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
                            
                            if (lpFreeLibrary) {
                                HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                    (LPTHREAD_START_ROUTINE)lpFreeLibrary,
                                    hModule, 0, NULL);
                                    
                                if (hThread) {
                                    WaitForSingleObject(hThread, 1000);
                                    CloseHandle(hThread);
                                }
                            }
                        }
                        error(OBF("Critical security violation: Unauthorized DLL injection detected: ") + std::string(moduleName));
                    }

                } while (Module32NextW(hModuleSnap, &me32));
            }
            CloseHandle(hModuleSnap);
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_DLL_INJECTION std::thread([]() { anti_dll_injection(); }).detach()

struct CodeSection {
    DWORD64 start;
    DWORD64 end;
    std::vector<BYTE> originalBytes;
};

std::vector<CodeSection> protected_sections;
std::mutex sections_mutex;

void initialize_code_protection() {
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return;

    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, hModule, &modInfo, sizeof(MODULEINFO))) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

    std::lock_guard<std::mutex> lock(sections_mutex);
    protected_sections.clear();

    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            CodeSection codeSection;
            codeSection.start = (DWORD64)hModule + section[i].VirtualAddress;
            codeSection.end = codeSection.start + section[i].Misc.VirtualSize;
            
            size_t size = section[i].Misc.VirtualSize;
            codeSection.originalBytes.resize(size);
            memcpy(codeSection.originalBytes.data(), (void*)codeSection.start, size);
            
            protected_sections.push_back(codeSection);
        }
    }
}

INLINE void anti_code_patch() {
    initialize_code_protection();
    
    while (true) {
        ULTRA_MEGA_JUNK(0);
        
        std::lock_guard<std::mutex> lock(sections_mutex);
        for (const auto& section : protected_sections) {
            std::vector<BYTE> currentBytes(section.originalBytes.size());
            memcpy(currentBytes.data(), (void*)section.start, section.originalBytes.size());
            
            if (memcmp(currentBytes.data(), section.originalBytes.data(), section.originalBytes.size()) != 0) {
                DWORD oldProtect;
                if (VirtualProtect((LPVOID)section.start, section.originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    memcpy((void*)section.start, section.originalBytes.data(), section.originalBytes.size());
                    VirtualProtect((LPVOID)section.start, section.originalBytes.size(), oldProtect, &oldProtect);
                    error(OBF("Critical security violation: Code patching detected and reverted!"));
                }
            }
        }
        
        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_CODE_PATCH std::thread([]() { anti_code_patch(); }).detach()

struct ApiFunction {
    std::string moduleName;
    std::string functionName;
    DWORD64 originalAddress;
    std::vector<BYTE> originalBytes;
};

std::vector<ApiFunction> protected_apis;
std::mutex apis_mutex;

void initialize_api_protection() {
    std::lock_guard<std::mutex> lock(apis_mutex);
    protected_apis.clear();

    const std::vector<std::pair<std::string, std::string>> critical_apis = {
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "WriteProcessMemory"},
        {"kernel32.dll", "CreateRemoteThread"},
        {"ntdll.dll", "NtCreateThreadEx"},
        {"ntdll.dll", "NtMapViewOfSection"},
        {"ntdll.dll", "NtProtectVirtualMemory"},
        {"ntdll.dll", "LdrLoadDll"},
        {"user32.dll", "SetWindowsHookEx"},
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "LoadLibraryW"},
        {"kernel32.dll", "GetProcAddress"}
    };

    for (const auto& api : critical_apis) {
        HMODULE hModule = GetModuleHandleA(api.first.c_str());
        if (!hModule) continue;

        FARPROC procAddress = GetProcAddress(hModule, api.second.c_str());
        if (!procAddress) continue;

        ApiFunction apiFunc;
        apiFunc.moduleName = api.first;
        apiFunc.functionName = api.second;
        apiFunc.originalAddress = (DWORD64)procAddress;
        
        apiFunc.originalBytes.resize(32);        
        memcpy(apiFunc.originalBytes.data(), procAddress, 32);
        
        protected_apis.push_back(apiFunc);
    }
}

bool is_hook_pattern(const BYTE* bytes) {
    if (bytes[0] == 0xE9) return true;
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return true;
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) return true;
    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) return true;
    
    return false;
}

INLINE void anti_api_hook() {
    initialize_api_protection();
    
    while (true) {
        ULTRA_MEGA_JUNK(0);
        
        std::lock_guard<std::mutex> lock(apis_mutex);
        for (const auto& api : protected_apis) {
            FARPROC currentAddress = GetProcAddress(GetModuleHandleA(api.moduleName.c_str()), 
                                                  api.functionName.c_str());
            if (!currentAddress) continue;

            if ((DWORD64)currentAddress != api.originalAddress) {
                error(OBF("Critical security violation: API address modification detected: ") + 
                      api.moduleName + "::" + api.functionName);
                continue;
            }

            std::vector<BYTE> currentBytes(32);
            memcpy(currentBytes.data(), currentAddress, 32);

            if (memcmp(currentBytes.data(), api.originalBytes.data(), 32) != 0 ||
                is_hook_pattern(currentBytes.data())) {
                
                DWORD oldProtect;
                if (VirtualProtect((LPVOID)currentAddress, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    memcpy((void*)currentAddress, api.originalBytes.data(), 32);
                    VirtualProtect((LPVOID)currentAddress, 32, oldProtect, &oldProtect);
                    error(OBF("Critical security violation: API hook detected and removed: ") + 
                          api.moduleName + "::" + api.functionName);
                }
            }
        }
        
        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_API_HOOK std::thread([]() { anti_api_hook(); }).detach()

struct ImportEntry {
    std::string moduleName;
    std::string functionName;
    DWORD64 originalAddress;
    DWORD64* iatEntry;
};

std::vector<ImportEntry> protected_imports;
std::mutex imports_mutex;

void initialize_iat_protection() {
    std::lock_guard<std::mutex> lock(imports_mutex);
    protected_imports.clear();

    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    IMAGE_DATA_DIRECTORY importDirectory = 
        ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
        ((BYTE*)hModule + importDirectory.VirtualAddress);

    for (; importDesc->Name != 0; importDesc++) {
        const char* moduleName = (const char*)((BYTE*)hModule + importDesc->Name);
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)
            ((BYTE*)hModule + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)
            ((BYTE*)hModule + importDesc->FirstThunk);

        for (; originalFirstThunk->u1.AddressOfData != 0; 
               originalFirstThunk++, firstThunk++) {
            
            if (IMAGE_SNAP_BY_ORDINAL(originalFirstThunk->u1.Ordinal)) continue;

            PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)
                ((BYTE*)hModule + originalFirstThunk->u1.AddressOfData);

            ImportEntry entry;
            entry.moduleName = moduleName;
            entry.functionName = (char*)functionName->Name;
            entry.originalAddress = firstThunk->u1.Function;
            entry.iatEntry = &firstThunk->u1.Function;

            protected_imports.push_back(entry);
        }
    }
}

INLINE void anti_iat_hook() {
    initialize_iat_protection();
    
    while (true) {
        ULTRA_MEGA_JUNK(0);
        
        std::lock_guard<std::mutex> lock(imports_mutex);
        for (const auto& import : protected_imports) {
            if (*import.iatEntry != import.originalAddress) {
                DWORD oldProtect;
                if (VirtualProtect(import.iatEntry, sizeof(DWORD64), PAGE_READWRITE, &oldProtect)) {
                    *import.iatEntry = import.originalAddress;
                    VirtualProtect(import.iatEntry, sizeof(DWORD64), oldProtect, &oldProtect);
                    error(OBF("Critical security violation: IAT hook detected and removed: ") + 
                          import.moduleName + "::" + import.functionName);
                }
            }
        }
        
        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_IAT_HOOK std::thread([]() { anti_iat_hook(); }).detach()

struct HardwareBreakpoint {
    DWORD64 address;
    DWORD type;
    bool enabled;
};

std::vector<HardwareBreakpoint> hardware_breakpoints;
std::mutex breakpoints_mutex;

bool check_hardware_breakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    HANDLE thread = GetCurrentThread();
    if (!GetThreadContext(thread, &ctx)) return false;

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        error(OBF("Critical security violation: Hardware breakpoint detected!"));
        return true;
    }

    return false;
}

bool check_software_breakpoints(const BYTE* start, SIZE_T size) {
    std::vector<BYTE> buffer(size);
    memcpy(buffer.data(), start, size);

    for (SIZE_T i = 0; i < size; i++) {
        if (buffer[i] == 0xCC) {    
            error(OBF("Critical security violation: Software breakpoint detected!"));
            return true;
        }
    }
    return false;
}

bool is_blacklisted_process(const std::string& processName) {
    const std::vector<std::string> blacklist = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "ghidra.exe", "dnspy.exe", "cheatengine", "processhacker.exe",
        "httpdebugger.exe", "procmon.exe", "processhacker.exe", "pestudio.exe",
        "regmon.exe", "filemon.exe", "wireshark.exe", "fiddler.exe",
        "procexp.exe", "procmon.exe", "immunitydebugger.exe", "windbg.exe",
        "debugger.exe", "dumpcap.exe", "hookexplorer.exe", "importrec.exe",
        "petools.exe", "lordpe.exe", "sysinspector.exe", "proc_analyzer.exe",
        "sysanalyzer.exe", "sniff_hit.exe", "windbg.exe", "apimonitor.exe",
        "dumpcap.exe", "networktrafficview.exe", "charles.exe", "scylla.exe"
    };

    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    return std::find_if(blacklist.begin(), blacklist.end(),
        [&lowerName](const std::string& blocked) {
            return lowerName.find(blocked) != std::string::npos;
        }) != blacklist.end();
}

bool check_parent_process() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                DWORD parentPID = pe32.th32ParentProcessID;
                Process32FirstW(snapshot, &pe32);
                
                do {
                    if (pe32.th32ProcessID == parentPID) {
                        char processName[MAX_PATH];
                        wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH);
                        
                        if (is_blacklisted_process(processName)) {
                            error(OBF("Critical security violation: Process launched from debugger/analyzer: ") + 
                                  std::string(processName));
                            CloseHandle(snapshot);
                            return true;
                        }
                        break;
                    }
                } while (Process32NextW(snapshot, &pe32));
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

bool check_running_analysis_tools() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    bool found = false;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            char processName[MAX_PATH];
            wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH);
            
            if (is_blacklisted_process(processName)) {
                error(OBF("Critical security violation: Analysis tool detected: ") + std::string(processName));
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return found;
}

INLINE void anti_debug() {
    while (true) {
        ULTRA_MEGA_JUNK(0);

        if (check_hardware_breakpoints()) {
            DWORD oldProtect;
            HANDLE process = GetCurrentProcess();
            for (const auto& bp : hardware_breakpoints) {
                if (VirtualProtect((LPVOID)bp.address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    *(BYTE*)bp.address = 0x90;   
                    VirtualProtect((LPVOID)bp.address, 1, oldProtect, &oldProtect);
                }
            }
        }

        check_parent_process();
        check_running_analysis_tools();

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_DEBUG std::thread([]() { anti_debug(); }).detach()

struct SehEntry {
    DWORD64 handler;
    DWORD64 next;
};

std::vector<SehEntry> protected_seh_entries;
std::mutex seh_mutex;

void initialize_seh_protection() {
    std::lock_guard<std::mutex> lock(seh_mutex);
    protected_seh_entries.clear();

    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    if (!tib) return;

    EXCEPTION_REGISTRATION_RECORD* seh = (EXCEPTION_REGISTRATION_RECORD*)tib->ExceptionList;
    while (seh && seh != (EXCEPTION_REGISTRATION_RECORD*)0xFFFFFFFFFFFFFFFF) {
        SehEntry entry;
        entry.handler = (DWORD64)seh->Handler;
        entry.next = (DWORD64)seh->Next;
        protected_seh_entries.push_back(entry);
        seh = seh->Next;
    }
}

bool check_seh_chain() {
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    if (!tib) return false;

    EXCEPTION_REGISTRATION_RECORD* seh = (EXCEPTION_REGISTRATION_RECORD*)tib->ExceptionList;
    size_t index = 0;

    std::lock_guard<std::mutex> lock(seh_mutex);
    while (seh && seh != (EXCEPTION_REGISTRATION_RECORD*)0xFFFFFFFFFFFFFFFF) {
        if (index >= protected_seh_entries.size()) {
            error(OBF("Critical security violation: SEH chain modification detected (new handler)"));
            return true;
        }

        if ((DWORD64)seh->Handler != protected_seh_entries[index].handler ||
            (DWORD64)seh->Next != protected_seh_entries[index].next) {
            error(OBF("Critical security violation: SEH handler modification detected"));
            return true;
        }

        seh = seh->Next;
        index++;
    }

    if (index != protected_seh_entries.size()) {
        error(OBF("Critical security violation: SEH chain modification detected (handler removed)"));
        return true;
    }

    return false;
}

void protect_against_dump() {
    DWORD oldProtect;
    HANDLE process = GetCurrentProcess();
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return;

    MODULEINFO modInfo;
    if (!GetModuleInformation(process, hModule, &modInfo, sizeof(MODULEINFO))) return;

    if (VirtualProtect(hModule, 0x1000, PAGE_NOACCESS, &oldProtect)) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        
        if (VirtualProtect(hModule, 0x1000, PAGE_READWRITE, &oldProtect)) {
            if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
                DWORD importRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                PVOID importAddr = (PVOID)((DWORD64)hModule + importRVA);
                memset(importAddr, 0, ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
            }

            if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
                DWORD exportRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                PVOID exportAddr = (PVOID)((DWORD64)hModule + exportRVA);
                memset(exportAddr, 0, ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
            }

            ntHeader->FileHeader.NumberOfSections = 0;
            ntHeader->OptionalHeader.AddressOfEntryPoint = 0;
            
            VirtualProtect(hModule, 0x1000, PAGE_NOACCESS, &oldProtect);
        }
    }
}

INLINE void anti_dump_and_seh() {
    initialize_seh_protection();
    protect_against_dump();
    
    while (true) {
        ULTRA_MEGA_JUNK(0);
        
        check_seh_chain();
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            
            if (Process32FirstW(snapshot, &pe32)) {
                do {
                    char processName[MAX_PATH];
                    wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH);
                    std::string procName = processName;
                    std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
                    
                    if (procName.find("dumper") != std::string::npos ||
                        procName.find("dump") != std::string::npos ||
                        procName.find("memdump") != std::string::npos) {
                        error(OBF("Critical security violation: Memory dumping tool detected: ") + procName);
                        protect_against_dump();
                    }
                } while (Process32NextW(snapshot, &pe32));
            }
            CloseHandle(snapshot);
        }
        
        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_DUMP_AND_SEH std::thread([]() { anti_dump_and_seh(); }).detach()

bool IsValidPEHeader(ULONG_PTR BaseAddress)
{
    if (!BaseAddress) return false;
    PIMAGE_DOS_HEADER dosHeader = PIMAGE_DOS_HEADER(BaseAddress);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS(BaseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return false;
    PIMAGE_OPTIONAL_HEADER optionalHeader = PIMAGE_OPTIONAL_HEADER(&ntHeader->OptionalHeader);
    if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
    return true;
}

bool FillPEHeader(ULONG_PTR BaseAddress, PE_HEADER& PEHeader)
{
    if (!IsValidPEHeader(BaseAddress))
        return false;
    PEHeader.dosHeader = PIMAGE_DOS_HEADER(BaseAddress);
    PEHeader.ntHeaders = PIMAGE_NT_HEADERS(ULONG_PTR(PEHeader.dosHeader) + PEHeader.dosHeader->e_lfanew);
    PEHeader.fileHeader = PIMAGE_FILE_HEADER(&PEHeader.ntHeaders->FileHeader);
    PEHeader.optionalHeader = PIMAGE_OPTIONAL_HEADER(&PEHeader.ntHeaders->OptionalHeader);
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        PEHeader.dataDirectory[i] = &PEHeader.ntHeaders->OptionalHeader.DataDirectory[i];
    const ULONG_PTR firstSectionHeader = ULONG_PTR(IMAGE_FIRST_SECTION(PEHeader.ntHeaders));
    for (int i = 0; i < PEHeader.fileHeader->NumberOfSections; i++)
        PEHeader.sectionHeaders.push_back(PIMAGE_SECTION_HEADER(i * sizeof(IMAGE_SECTION_HEADER) + firstSectionHeader));
    return true;
}

bool FillRemotePEHeader(HANDLE ProcessHandle, ULONG_PTR BaseAddress, REMOTE_PE_HEADER& PEHeader)
{
    ZeroMemory(PEHeader.rawData, PE_HEADER_SIZE);
    if (!ReadProcessMemory(ProcessHandle, PVOID(BaseAddress), PEHeader.rawData, PE_HEADER_SIZE, NULL))
        return false;
    if (!FillPEHeader(ULONG_PTR(&PEHeader.rawData), PEHeader))
        return false;
    PEHeader.remoteBaseAddress = BaseAddress;
    return true;
}

const PIMAGE_SECTION_HEADER GetPeSectionByName(const PE_HEADER& HeaderData, const char* SectionName)
{
    for (auto section : HeaderData.sectionHeaders)
        if (!strncmp(PCHAR(section->Name), SectionName, 8))
            return section;
    return 0;
}

DWORD GetSizeOfImage(PVOID BaseAddress)
{
    if (!IsValidPEHeader(ULONG_PTR(BaseAddress)))
        return 0;
    return PIMAGE_NT_HEADERS(ULONG_PTR(BaseAddress) + PIMAGE_DOS_HEADER(BaseAddress)->e_lfanew)->OptionalHeader.SizeOfImage;
}

#define CHECK_PE_HEADER(BaseAddress, ErrorMsg) \
    if (!IsValidPEHeader(BaseAddress)) { \
        error(OBF(ErrorMsg)); \
        return false; \
    }

#define CHECK_PE_SECTION(Section, SectionName, ErrorMsg) \
    if (!GetPeSectionByName(Section, SectionName)) { \
        error(OBF(ErrorMsg)); \
        return false; \
    }

#define VERIFY_PE_STRUCTURE(PEHeader, ErrorMsg) \
    if (!PEHeader.dosHeader || !PEHeader.ntHeaders || !PEHeader.fileHeader || !PEHeader.optionalHeader) { \
        error(OBF(ErrorMsg)); \
        return false; \
    }

#define CHECK_REMOTE_PE(ProcessHandle, BaseAddress, ErrorMsg) \
    if (!ProcessHandle || !BaseAddress) { \
        error(OBF(ErrorMsg)); \
        return false; \
    }

bool VerifyModule(HMODULE hModule) {
    CHECK_PE_HEADER((ULONG_PTR)hModule, "Module PE header is invalid or corrupted");
    
    return true;
}

bool VerifyCodeSection(HMODULE hModule) {
    PE_HEADER peHeader;
    
    CHECK_PE_HEADER((ULONG_PTR)hModule, "Invalid PE structure detected");
    
    if (!FillPEHeader((ULONG_PTR)hModule, peHeader)) {
        return false;
    }
    
    CHECK_PE_SECTION(peHeader, ".text", "Code section is missing or corrupted");
    
    return true;
}

bool PerformFullCheck(HMODULE hModule) {
    PE_HEADER peHeader;
    
    CHECK_PE_HEADER((ULONG_PTR)hModule, "Invalid PE header");
    
    if (!FillPEHeader((ULONG_PTR)hModule, peHeader)) {
        return false;
    }
    
    VERIFY_PE_STRUCTURE(peHeader, "Corrupted PE structure");
    
    CHECK_PE_SECTION(peHeader, ".text", "Missing code section");
    CHECK_PE_SECTION(peHeader, ".rdata", "Missing resource section");
    
    return true;
}

void RunProtection() {
    HMODULE hModule = GetModuleHandle(NULL);
    
    try {
        if (!VerifyModule(hModule)) {
            return;
        }
        
        if (!VerifyCodeSection(hModule)) {
            return;
        }
        
        if (!PerformFullCheck(hModule)) {
            return;
        }
    } catch (...) {
        error(OBF("Critical protection failure"));
    }
}

#define HIDE_CALL(...) \
    [&]() { \
        if (chaos_seed % 2) { __VA_ARGS__; } \
    }()

#define HIDE_CALL_THREAD(func) \
    []() { \
        if (chaos_seed % 2) { func(); } \
    }

#define HIDDEN_ENTRY_POINT(name) \
    void __declspec(safebuffers) WINAPI name##_hidden(); \
    void WINAPI name() { \
        ULTRA_MEGA_JUNK(0); \
        void (*hidden_entry)() = nullptr; \
        hidden_entry = (void(*)())name##_hidden; \
        if (chaos_seed % 2) { \
            CALL_RANDOM_JUNK; \
            hidden_entry(); \
        } else { \
            JUNK_FUCK_IDA; \
            hidden_entry(); \
        } \
    } \
    void __declspec(safebuffers) WINAPI name##_hidden()

#define DECLARE_HIDDEN_ENTRY(name) \
    void WINAPI name(); \
    void WINAPI name##_hidden();

#define HIDDEN_ENTRY(return_type, name, ...) \
    return_type __declspec(safebuffers) name##_hidden(__VA_ARGS__); \
    return_type name(__VA_ARGS__) { \
        ULTRA_MEGA_JUNK(0); \
        return_type (*hidden_entry)(__VA_ARGS__) = nullptr; \
        hidden_entry = (return_type(*)(__VA_ARGS__))name##_hidden; \
        JUNK_FUCK_IDA; \
        if (chaos_seed % 2) { \
            CALL_RANDOM_JUNK; \
            return hidden_entry(__VA_ARGS__); \
        } else { \
            BUG_IDA; \
            return hidden_entry(__VA_ARGS__); \
        } \
    } \
    return_type __declspec(safebuffers) name##_hidden(__VA_ARGS__)

#define HIDDEN_START_IMPL \
    HIDDEN_ENTRY(int, WinMain, HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)

#define HIDDEN_START \
    HIDDEN_ENTRY(int, main)

#define EXPORT_PROTECT(return_type, name, ...) \
    return_type name##_protected(__VA_ARGS__); \
    extern "C" __declspec(dllexport) return_type name(__VA_ARGS__) { \
        ULTRA_MEGA_JUNK(0); \
        return_type (*protected_func)(__VA_ARGS__) = nullptr; \
        protected_func = (return_type(*)(__VA_ARGS__))name##_protected; \
        JUNK_FUCK_IDA; \
        if (chaos_seed % 2) { \
            CALL_RANDOM_JUNK; \
            return protected_func(__VA_ARGS__); \
        } else { \
            BUG_IDA; \
            return protected_func(__VA_ARGS__); \
        } \
    } \
    return_type name##_protected(__VA_ARGS__)

#define PROTECT_CALL(func, ...) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        auto result = func(__VA_ARGS__); \
        JUNK_FUCK_IDA; \
        if (chaos_seed % 3 == 0) { \
            BUG_IDA; \
            return result; \
        } else if (chaos_seed % 3 == 1) { \
            CALL_RANDOM_JUNK; \
            return result; \
        } else { \
            JUNK_VAR; \
            return result; \
        } \
    }()

#define PROTECT_VOID_CALL(func, ...) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        if (chaos_seed % 3 == 0) { \
            BUG_IDA; \
            func(__VA_ARGS__); \
        } else if (chaos_seed % 3 == 1) { \
            CALL_RANDOM_JUNK; \
            func(__VA_ARGS__); \
        } else { \
            JUNK_VAR; \
            func(__VA_ARGS__); \
        } \
    }()

#define PROTECT_CLASS_METHOD(class_name, return_type, method_name, ...) \
    return_type method_name##_protected(__VA_ARGS__); \
    return_type method_name(__VA_ARGS__) { \
        ULTRA_MEGA_JUNK(0); \
        return_type (class_name::*protected_method)(__VA_ARGS__) = &class_name::method_name##_protected; \
        JUNK_FUCK_IDA; \
        if (chaos_seed % 2) { \
            CALL_RANDOM_JUNK; \
            return (this->*protected_method)(__VA_ARGS__); \
        } else { \
            BUG_IDA; \
            return (this->*protected_method)(__VA_ARGS__); \
        } \
    } \
    return_type method_name##_protected(__VA_ARGS__)

#define PROTECT_STRING(str) \
    [&]() { \
        static auto protected_str = obffu::skCrypter<sizeof(str) / sizeof(str[0]), __TIME__[4], __TIME__[7], \
            obffu::clean_type<decltype(str[0])>>((obffu::clean_type<decltype(str[0])>*)str); \
        JUNK_VAR; \
        return protected_str.decrypt(); \
    }()

#define PROTECT_SECTION(name) \
    __declspec(allocate(Name_Of_Sections_watermark)) \
    static const unsigned char name##_protected[] = { \
        0xDE, 0xAD, 0xBE, 0xEF, \
        0xCA, 0xFE, 0xBA, 0xBE, \
        __TIME__[0], __TIME__[1], __TIME__[3], __TIME__[4], \
        __DATE__[0], __DATE__[1], __DATE__[3], __DATE__[4], \
        0xDE, 0xAD, 0xBE, 0xEF \
    }; \
    static void* const name##_ptr = (void*)name##_protected

#define PROTECT_POINTER(ptr) \
    [&]() { \
        static volatile void* protected_ptr = nullptr; \
        if (!protected_ptr) { \
            ULTRA_MEGA_JUNK(0); \
            protected_ptr = (void*)(ptr); \
            JUNK_FUCK_IDA; \
        } \
        if (chaos_seed % 2) { \
            CALL_RANDOM_JUNK; \
            return (decltype(ptr))protected_ptr; \
        } else { \
            BUG_IDA; \
            return (decltype(ptr))protected_ptr; \
        } \
    }()

#define PROTECT_FUNCTION_TABLE(class_name, ...) \
    struct class_name##_vtable { \
        void* entries[64]; \
        class_name##_vtable() { \
            ULTRA_MEGA_JUNK(0); \
            void* funcs[] = { __VA_ARGS__ }; \
            for(int i = 0; i < sizeof(funcs)/sizeof(void*); i++) { \
                entries[i] = PROTECT_POINTER(funcs[i]); \
            } \
            JUNK_FUCK_IDA; \
        } \
        template<typename T> \
        T get(int index) { \
            JUNK_VAR; \
            return (T)entries[index]; \
        } \
    }; \
    static class_name##_vtable vtable_instance

#define PROTECT_CODE_SEGMENT \
    static void __declspec(safebuffers) protect_code() { \
        BYTE* base = (BYTE*)GetModuleHandle(NULL); \
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base; \
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew); \
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt); \
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) { \
            if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) { \
                DWORD old; \
                VirtualProtect(base + section[i].VirtualAddress, \
                    section[i].Misc.VirtualSize, \
                    PAGE_EXECUTE_READWRITE, &old); \
                for (DWORD j = 0; j < section[i].Misc.VirtualSize - 1; j++) { \
                    if (*(WORD*)(base + section[i].VirtualAddress + j) == 0xCCCC) { \
                        *(WORD*)(base + section[i].VirtualAddress + j) = 0x9090; \
                    } \
                } \
                VirtualProtect(base + section[i].VirtualAddress, \
                    section[i].Misc.VirtualSize, old, &old); \
            } \
        } \
    }

#define INIT_PROTECTION \
    JUNK_FUCK_IDA; \
    protect_code(); \
    START_INTEGRITY_CHECK; \
    START_ANTI_ATTACH; \
    START_ANTI_WINDOW_TITLE; \
    START_JUNK_THREADS; \
    START_ANTI_PAUSE_THREAD; \
    START_ANTI_TERMINATE_THREAD; \
    START_ANTI_DLL_INJECTION; \
    START_ANTI_CODE_PATCH; \
    START_ANTI_API_HOOK; \
    START_ANTI_IAT_HOOK; \
    START_ANTI_DEBUG; \
    START_ANTI_DUMP_AND_SEH; \
    JUNK_FUCK_IDA

#define PROTECT_CRITICAL_SECTION(code) \
    [&]() { \
        ULTRA_MEGA_JUNK(0); \
        static volatile bool initialized = false; \
        static volatile void* code_ptr = nullptr; \
        if (!initialized) { \
            code_ptr = &&code_label; \
            initialized = true; \
        } \
        if (chaos_seed % 2) { \
            CALL_RANDOM_JUNK; \
            goto *code_ptr; \
        } else { \
            BUG_IDA; \
            goto *code_ptr; \
        } \
        code_label: \
        JUNK_FUCK_IDA; \
        code; \
        ULTRA_MEGA_JUNK(0); \
    }()

#define KILL_PYQT_APPS \
    std::thread([&]() { \
        while (true) { \
            ULTRA_MEGA_JUNK(0); \
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); \
            if (snapshot != INVALID_HANDLE_VALUE) { \
                PROCESSENTRY32W pe32; \
                pe32.dwSize = sizeof(pe32); \
                if (Process32FirstW(snapshot, &pe32)) { \
                    do { \
                        char processName[MAX_PATH]; \
                        wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH); \
                        std::string procName = processName; \
                        std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower); \
                        \
                        if (procName.find("python") != std::string::npos || \
                            procName.find("pyqt") != std::string::npos || \
                            procName.find("pyside") != std::string::npos || \
                            procName.find("qt5core") != std::string::npos || \
                            procName.find("qt6core") != std::string::npos || \
                            procName.find("qtcore") != std::string::npos || \
                            procName.find("qtwidgets") != std::string::npos) { \
                            \
                            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID); \
                            if (hProcess != NULL) { \
                                TerminateProcess(hProcess, 0); \
                                CloseHandle(hProcess); \
                            } \
                        } \
                    } while (Process32NextW(snapshot, &pe32)); \
                } \
                CloseHandle(snapshot); \
            } \
            CALL_RANDOM_JUNK; \
            Sleep(100); \
        } \
    }).detach()

#define KILL_PYQT_APPS \
    std::thread([&]() { \
        const std::vector<std::string> qt_dlls = { \
            "python", "pyqt", "pyside", \
            "qt5core", "qt6core", "qtcore", "qtwidgets", \
            "qt5gui", "qt6gui", "qtgui", \
            "qt5widgets", "qt6widgets", \
            "qt5network", "qt6network", \
            "sip", "pyqt5", "pyqt6", "pyside2", "pyside6", \
            "qt5qml", "qt6qml", "qtqml", \
            "qt5quick", "qt6quick", "qtquick", \
            "qt5webengine", "qt6webengine", \
            "qt5webkit", "qt6webkit", \
            "qt5multimedia", "qt6multimedia", \
            "python3", "python2", "pythonw", \
            "qt5printsupport", "qt6printsupport", \
            "qt5svg", "qt6svg", \
            "qt5charts", "qt6charts" \
        }; \
        \
        while (true) { \
            ULTRA_MEGA_JUNK(0); \
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); \
            if (snapshot != INVALID_HANDLE_VALUE) { \
                PROCESSENTRY32W pe32; \
                pe32.dwSize = sizeof(pe32); \
                if (Process32FirstW(snapshot, &pe32)) { \
                    do { \
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID); \
                        if (hProcess != NULL) { \
                            HMODULE hMods[1024]; \
                            DWORD cbNeeded; \
                            bool should_kill = false; \
                            \
                            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) { \
                                for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)) && !should_kill; i++) { \
                                    char modName[MAX_PATH]; \
                                    if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) { \
                                        std::string modNameStr = modName; \
                                        std::transform(modNameStr.begin(), modNameStr.end(), modNameStr.begin(), ::tolower); \
                                        \
                                        for (const auto& dll : qt_dlls) { \
                                            if (modNameStr.find(dll) != std::string::npos) { \
                                                should_kill = true; \
                                                break; \
                                            } \
                                        } \
                                    } \
                                } \
                            } \
                            \
                            if (should_kill) { \
                                HANDLE hKillProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID); \
                                if (hKillProcess != NULL) { \
                                    TerminateProcess(hKillProcess, 0); \
                                    CloseHandle(hKillProcess); \
                                } \
                            } \
                            CloseHandle(hProcess); \
                        } \
                    } while (Process32NextW(snapshot, &pe32)); \
                } \
                CloseHandle(snapshot); \
            } \
            CALL_RANDOM_JUNK; \
            Sleep(100); \
        } \
    }).detach()


INLINE bool detect_hypervisor() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

INLINE bool detect_vm() {
    bool vm = false;

    const char* vm_vendors[] = {
        "VMware",
        "VBox",
        "VIRTUAL",
        "QEMU",
        "Xen",
        "Parallels"
    };

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char keyName[256];
        DWORD index = 0;
        DWORD nameSize = sizeof(keyName);

        while (RegEnumKeyExA(hKey, index, keyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            for (const auto& vendor : vm_vendors) {
                if (strstr(keyName, vendor)) {
                    vm = true;
                    break;
                }
            }
            nameSize = sizeof(keyName);
            index++;
        }
        RegCloseKey(hKey);
    }

    return vm;
}

INLINE void anti_vm() {
    while (true) {
        ULTRA_MEGA_JUNK(0);

        if (detect_hypervisor() || detect_vm()) {
            error(OBF("Virtual Machine detected!"));
        }

        CALL_RANDOM_JUNK;
        Sleep(100);
    }
}

#define START_ANTI_VM std::thread([]() { anti_vm(); }).detach()

INLINE void protect_memory_regions() {
    while (true) {
        ULTRA_MEGA_JUNK(0);

        MEMORY_BASIC_INFORMATION mbi;
        PVOID address = 0;

        while (VirtualQuery(address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {

                DWORD oldProtect;
                if (mbi.Protect & PAGE_EXECUTE ||
                    mbi.Protect & PAGE_EXECUTE_READ ||
                    mbi.Protect & PAGE_EXECUTE_READWRITE) {

                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                        PAGE_EXECUTE_READ, &oldProtect);
                }
            }
            address = (PVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        }

        CALL_RANDOM_JUNK;
        Sleep(100);
    }
}

#define START_MEMORY_PROTECTION std::thread([]() { protect_memory_regions(); }).detach()

struct SystemCall {
    const char* name;
    PVOID* address;
    BYTE originalBytes[16];
};

std::vector<SystemCall> protected_syscalls;
std::mutex syscalls_mutex;

INLINE void protect_system_calls() {
    const char* critical_syscalls[] = {
        "NtCreateFile",
        "NtOpenFile",
        "NtReadFile",
        "NtWriteFile",
        "NtDeviceIoControlFile",
        "NtQuerySystemInformation",
        "NtQueryInformationProcess",
        "NtSetInformationProcess"
    };

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    for (const auto& syscall : critical_syscalls) {
        PVOID addr = GetProcAddress(ntdll, syscall);
        if (addr) {
            SystemCall sc;
            sc.name = syscall;
            sc.address = (PVOID*)addr;
            memcpy(sc.originalBytes, addr, 16);
            protected_syscalls.push_back(sc);
        }
    }

    while (true) {
        ULTRA_MEGA_JUNK(0);

        std::lock_guard<std::mutex> lock(syscalls_mutex);
        for (auto& syscall : protected_syscalls) {
            if (memcmp(syscall.address, syscall.originalBytes, 16) != 0) {
                DWORD oldProtect;
                VirtualProtect(syscall.address, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
                memcpy(syscall.address, syscall.originalBytes, 16);
                VirtualProtect(syscall.address, 16, oldProtect, &oldProtect);
                error(OBF("System call hook detected and removed: ") + std::string(syscall.name));
            }
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_SYSCALL_PROTECTION std::thread([]() { protect_system_calls(); }).detach()

struct ApcContext {
    PAPCFUNC apcFunction;
    HANDLE threadHandle;
    DWORD threadId;
};

std::vector<ApcContext> legitimate_apcs;
std::mutex apc_mutex;

INLINE void anti_apc_injection() {
    while (true) {
        ULTRA_MEGA_JUNK(0);

        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hThreadSnap, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            CONTEXT ctx = { 0 };
                            ctx.ContextFlags = CONTEXT_ALL;

                            if (GetThreadContext(hThread, &ctx)) {
                                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                                    error(OBF("APC injection attempt detected!"));
                                }
                            }

                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnap, &te32));
            }
            CloseHandle(hThreadSnap);
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_ANTI_APC std::thread([]() { anti_apc_injection(); }).detach()

#pragma pack(push, 1)
struct GDT_DESCRIPTOR {
    WORD Limit;
    DWORD64 Base;
};

struct GDT_ENTRY {
    WORD LimitLow;
    WORD BaseLow;
    BYTE BaseMid;
    BYTE Access;
    BYTE LimitHigh : 4;
    BYTE Flags : 4;
    BYTE BaseHigh;
};

struct SEGMENT_DESCRIPTOR {
    DWORD64 Base;
    DWORD Limit;
    union {
        struct {
            WORD Type : 4;
            WORD S : 1;
            WORD DPL : 2;
            WORD P : 1;
            WORD AVL : 1;
            WORD L : 1;
            WORD DB : 1;
            WORD G : 1;
            WORD Reserved : 4;
        };
        WORD Flags;
    };
};
#pragma pack(pop)

struct GdtEntry {
    DWORD64 base;
    DWORD limit;
    WORD selector;
    BYTE access;
    BYTE flags;
};

std::vector<GdtEntry> original_gdt;
std::mutex gdt_mutex;

extern "C" void _sgdt(void*);
#pragma intrinsic(_sgdt)

INLINE void protect_gdt() {
    GDT_DESCRIPTOR gdtr = { 0 };
    _sgdt(&gdtr);

    GDT_ENTRY* gdtBase = reinterpret_cast<GDT_ENTRY*>(gdtr.Base);
    WORD gdtLimit = gdtr.Limit;

    if (!gdtBase || gdtLimit == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(gdt_mutex);
    original_gdt.clear();

    for (WORD i = 0; i < (gdtLimit + 1) / sizeof(GDT_ENTRY); i++) {
        GdtEntry entry;
        entry.base = gdtBase[i].BaseLow |
            ((DWORD64)gdtBase[i].BaseMid << 16) |
            ((DWORD64)gdtBase[i].BaseHigh << 24);
        entry.limit = gdtBase[i].LimitLow |
            ((DWORD)gdtBase[i].LimitHigh << 16);
        entry.selector = i * 8;
        entry.access = gdtBase[i].Access;
        entry.flags = gdtBase[i].Flags;
        original_gdt.push_back(entry);
    }

    while (true) {
        ULTRA_MEGA_JUNK(0);

        GDT_DESCRIPTOR current_gdtr = { 0 };
        _sgdt(&current_gdtr);

        if (current_gdtr.Base != gdtr.Base || current_gdtr.Limit != gdtr.Limit) {
            error(OBF("GDT base or limit modification detected!"));
            continue;
        }

        GDT_ENTRY* currentGdtBase = reinterpret_cast<GDT_ENTRY*>(current_gdtr.Base);
        if (!currentGdtBase) {
            continue;
        }

        for (WORD i = 0; i < (gdtLimit + 1) / sizeof(GDT_ENTRY); i++) {
            DWORD64 currentBase = currentGdtBase[i].BaseLow |
                ((DWORD64)currentGdtBase[i].BaseMid << 16) |
                ((DWORD64)currentGdtBase[i].BaseHigh << 24);
            DWORD currentLimit = currentGdtBase[i].LimitLow |
                ((DWORD)currentGdtBase[i].LimitHigh << 16);
            BYTE currentAccess = currentGdtBase[i].Access;
            BYTE currentFlags = currentGdtBase[i].Flags;

            if (currentBase != original_gdt[i].base ||
                currentLimit != original_gdt[i].limit ||
                currentAccess != original_gdt[i].access ||
                currentFlags != original_gdt[i].flags) {
                error(OBF("GDT entry modification detected!"));

                DWORD oldProtect;
                if (VirtualProtect(&currentGdtBase[i], sizeof(GDT_ENTRY), PAGE_READWRITE, &oldProtect)) {
                    currentGdtBase[i].BaseLow = (WORD)(original_gdt[i].base & 0xFFFF);
                    currentGdtBase[i].BaseMid = (BYTE)((original_gdt[i].base >> 16) & 0xFF);
                    currentGdtBase[i].BaseHigh = (BYTE)((original_gdt[i].base >> 24) & 0xFF);
                    currentGdtBase[i].LimitLow = (WORD)(original_gdt[i].limit & 0xFFFF);
                    currentGdtBase[i].LimitHigh = (original_gdt[i].limit >> 16) & 0x0F;
                    currentGdtBase[i].Access = original_gdt[i].access;
                    currentGdtBase[i].Flags = original_gdt[i].flags;
                    VirtualProtect(&currentGdtBase[i], sizeof(GDT_ENTRY), oldProtect, &oldProtect);
                }
            }
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_GDT_PROTECTION std::thread([]() { protect_gdt(); }).detach()

struct DebugRegisterState {
    DWORD64 dr0;
    DWORD64 dr1;
    DWORD64 dr2;
    DWORD64 dr3;
    DWORD64 dr6;
    DWORD64 dr7;
};

std::vector<DebugRegisterState> thread_debug_states;
std::mutex debug_reg_mutex;

INLINE void protect_debug_registers() {
    while (true) {
        ULTRA_MEGA_JUNK(0);

        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hThreadSnap, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            CONTEXT ctx = { 0 };
                            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                            if (GetThreadContext(hThread, &ctx)) {
                                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 ||
                                    ctx.Dr2 != 0 || ctx.Dr3 != 0 ||
                                    ctx.Dr6 != 0 || ctx.Dr7 != 0) {

                                    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
                                    ctx.Dr6 = ctx.Dr7 = 0;
                                    SetThreadContext(hThread, &ctx);

                                    error(OBF("Debug register modification detected and cleared!"));
                                }
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnap, &te32));
            }
            CloseHandle(hThreadSnap);
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_DEBUG_REG_PROTECTION std::thread([]() { protect_debug_registers(); }).detach()

#pragma pack(push, 1)
struct IDT_DESCRIPTOR {
    WORD Limit;
    DWORD64 Base;
};

struct IDT_ENTRY {
    WORD OffsetLow;
    WORD Selector;
    BYTE Reserved;
    BYTE Type;
    WORD OffsetMiddle;
    DWORD OffsetHigh;
    DWORD Reserved2;
};
#pragma pack(pop)

std::vector<IDT_ENTRY> original_idt;
std::mutex idt_mutex;

INLINE void protect_idt() {
    IDT_DESCRIPTOR idtr = { 0 };
    __sidt(&idtr);

    IDT_ENTRY* idtBase = reinterpret_cast<IDT_ENTRY*>(idtr.Base);
    WORD idtLimit = idtr.Limit;

    std::lock_guard<std::mutex> lock(idt_mutex);
    original_idt.assign(idtBase, idtBase + (idtLimit + 1) / sizeof(IDT_ENTRY));

    while (true) {
        ULTRA_MEGA_JUNK(0);

        IDT_DESCRIPTOR current_idtr = { 0 };
        __sidt(&current_idtr);

        if (current_idtr.Base != idtr.Base || current_idtr.Limit != idtr.Limit) {
            error(OBF("IDT modification detected!"));
            continue;
        }

        IDT_ENTRY* currentIdtBase = reinterpret_cast<IDT_ENTRY*>(current_idtr.Base);
        for (size_t i = 0; i < original_idt.size(); i++) {
            if (memcmp(&currentIdtBase[i], &original_idt[i], sizeof(IDT_ENTRY)) != 0) {
                error(OBF("IDT entry modification detected!"));
                DWORD oldProtect;
                if (VirtualProtect(&currentIdtBase[i], sizeof(IDT_ENTRY), PAGE_READWRITE, &oldProtect)) {
                    memcpy(&currentIdtBase[i], &original_idt[i], sizeof(IDT_ENTRY));
                    VirtualProtect(&currentIdtBase[i], sizeof(IDT_ENTRY), oldProtect, &oldProtect);
                }
            }
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_IDT_PROTECTION std::thread([]() { protect_idt(); }).detach()

struct PageEntry {
    PVOID address;
    DWORD protection;
    SIZE_T size;
    std::vector<BYTE> content;
};

std::vector<PageEntry> protected_pages;
std::mutex page_mutex;

INLINE void protect_pages() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    while (true) {
        ULTRA_MEGA_JUNK(0);

        MEMORY_BASIC_INFORMATION mbi;
        PVOID address = 0;

        std::lock_guard<std::mutex> lock(page_mutex);

        while (VirtualQuery(address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {

                auto it = std::find_if(protected_pages.begin(), protected_pages.end(),
                    [&](const PageEntry& entry) { return entry.address == mbi.BaseAddress; });

                if (it != protected_pages.end()) {
                    std::vector<BYTE> currentContent(it->size);
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(GetCurrentProcess(), it->address,
                        currentContent.data(), it->size, &bytesRead)) {

                        if (memcmp(currentContent.data(), it->content.data(), it->size) != 0) {
                            error(OBF("Memory page modification detected!"));
                            DWORD oldProtect;
                            if (VirtualProtect(it->address, it->size, PAGE_READWRITE, &oldProtect)) {
                                memcpy(it->address, it->content.data(), it->size);
                                VirtualProtect(it->address, it->size, it->protection, &oldProtect);
                            }
                        }
                    }
                }
            }
            address = (PVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_PAGE_PROTECTION std::thread([]() { protect_pages(); }).detach()

struct KernelCallback {
    PVOID address;
    BYTE originalBytes[32];
};

std::vector<KernelCallback> protected_callbacks;
std::mutex callback_mutex;

INLINE void protect_kernel_callbacks() {
    const PVOID callbacks[] = {
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserExceptionDispatcher"),
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserApcDispatcher"),
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserCallbackDispatcher")
    };

    for (PVOID callback : callbacks) {
        if (callback) {
            KernelCallback cb;
            cb.address = callback;
            memcpy(cb.originalBytes, callback, sizeof(cb.originalBytes));
            protected_callbacks.push_back(cb);
        }
    }

    while (true) {
        ULTRA_MEGA_JUNK(0);

        std::lock_guard<std::mutex> lock(callback_mutex);
        for (auto& callback : protected_callbacks) {
            if (memcmp(callback.address, callback.originalBytes, sizeof(callback.originalBytes)) != 0) {
                error(OBF("Kernel callback modification detected!"));
                DWORD oldProtect;
                if (VirtualProtect(callback.address, sizeof(callback.originalBytes),
                    PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    memcpy(callback.address, callback.originalBytes, sizeof(callback.originalBytes));
                    VirtualProtect(callback.address, sizeof(callback.originalBytes),
                        oldProtect, &oldProtect);
                }
            }
        }

        CALL_RANDOM_JUNK;
        Sleep(50);
    }
}

#define START_KERNEL_CALLBACK_PROTECTION std::thread([]() { protect_kernel_callbacks(); }).detach()

struct LibraryInfo {
    std::string path;
    DWORD64 baseAddress;
    SIZE_T imageSize;
    std::vector<BYTE> headerHash;
    std::vector<BYTE> codeHash;
};

std::vector<LibraryInfo> protected_libraries;
std::mutex libraries_mutex;

namespace fake_auth {
    static const char* const auth_urls[] = {
        // KeyAuth URLs
        "https://keyauth.win/api/1.0/init?ver=1.0&hash=",
        "https://keyauth.com/api/v2/check?session=",
        "https://keyauth.cc/api/v3/validate?license=",
        "https://keyauth.pro/panel/admin?token=",
        "https://keyauth.cloud/api/1.2/verify?key=",
        "https://keyauth.vip/api/v2/authenticate?session=",
        "https://keyauth.app/api/v1/check?license=",
        "https://api.keyauth.ru/v2/validate?token=",
        "https://panel.keyauth.cc/admin/verify?key=",
        "https://auth.keyauth.win/v3/check?hwid=",
        
        // FluxAuth URLs
        "https://fluxauth.com/api/check?key=",
        "https://fluxauth.net/api/verify?hwid=",
        "https://fluxauth.cc/panel/reseller?user=",
        "https://fluxauth.io/api/session?auth=",
        "https://api.fluxauth.net/v2/validate?token=",
        "https://panel.fluxauth.com/admin/check?key=",
        "https://auth.fluxauth.io/v1/verify?license=",
        "https://flux-auth.com/api/v3/init?session=",
        "https://fluxauth.org/dashboard/user?id=",
        "https://secure.fluxauth.net/api/check?hwid=",
        
        // Auth Systems
        "https://authifly.com/api/v1/check?license=",
        "https://authifly.cc/panel/customer?id=",
        "https://authifly.net/api/validate?token=",
        "https://authifly.co/dashboard?session=",
        "https://auth-panel.com/api/v2/init?ver=",
        "https://auth-service.net/api/check?hwid=",
        "https://auth-system.io/api/v3/verify?key=",
        "https://auth-protect.com/panel/validate?token=",
        "https://auth-secure.net/api/v2/check?license=",
        "https://auth-guard.cc/api/v1/session?hwid=",
        
        // License Systems
        "https://license-api.com/v1/verify?key=",
        "https://license.secure.com/api/check?token=",
        "https://license-system.net/api/v2/validate?key=",
        "https://license.auth.io/v3/verify?hwid=",
        "https://licensing.pro/api/v1/check?session=",
        "https://license-guard.com/panel/verify?key=",
        "https://secure-license.net/api/validate?token=",
        "https://license.protection.cc/v2/check?id=",
        "https://license-verify.com/api/auth?key=",
        "https://license.shield.io/api/v3/validate?hwid=",
        
        // CryptAuth URLs
        "https://cryptauth.com/api/v3/check?uid=",
        "https://cryptauth.net/panel/admin?token=",
        "https://cryptauth.io/api/validate?license=",
        "https://cryptauth.cc/dashboard?session=",
        "https://api.cryptauth.net/v2/verify?key=",
        "https://panel.cryptauth.com/admin/check?hwid=",
        "https://auth.cryptauth.io/v1/session?token=",
        "https://secure.cryptauth.cc/api/v3/validate?id=",
        "https://crypt-auth.com/panel/user?license=",
        "https://cryptauth.org/api/v2/init?auth=",
        
        // SecureAuth URLs
        "https://secureauth.win/api/v2/verify?key=",
        "https://secure-auth.com/api/v1/check?token=",
        "https://secureauth.cc/panel/validate?hwid=",
        "https://secureauth.io/api/v3/session?id=",
        "https://api.secureauth.net/v2/auth?license=",
        "https://panel.secureauth.com/admin/verify?key=",
        "https://auth.secureauth.cc/v1/validate?token=",
        "https://secure.auth-api.com/v3/check?hwid=",
        "https://secureauth.cloud/api/v2/init?session=",
        "https://security-auth.com/panel/user?key=",
        
        // Protection Systems
        "https://protect-auth.com/api/v1/verify?key=",
        "https://protection.cc/api/v2/validate?token=",
        "https://shield-auth.net/api/v3/check?hwid=",
        "https://guard-system.com/panel/auth?id=",
        "https://security-guard.io/api/v1/session?key=",
        "https://protection-api.com/v2/verify?license=",
        "https://shield.auth-api.net/v3/validate?token=",
        "https://guard.secure.cc/api/v2/check?hwid=",
        "https://protect.license.io/v1/auth?session=",
        "https://security.shield.com/api/v3/verify?key="
    };

    static const char* const endpoints[] = {
        // API Endpoints
        "/api/v1/init",
        "/api/v2/check",
        "/api/v3/validate",
        "/api/v1.2/verify",
        "/api/v2.1/authenticate",
        "/api/v3.0/session",
        "/api/beta/validate",
        "/api/stable/check",
        "/api/release/verify",
        "/api/enterprise/auth",
        
        // Panel Endpoints
        "/panel/admin",
        "/panel/reseller",
        "/panel/customer",
        "/panel/moderator",
        "/panel/manager",
        "/panel/support",
        "/panel/developer",
        "/panel/affiliate",
        "/panel/partner",
        "/panel/distributor",
        
        // Dashboard Endpoints
        "/dashboard",
        "/dashboard/home",
        "/dashboard/users",
        "/dashboard/licenses",
        "/dashboard/sessions",
        "/dashboard/analytics",
        "/dashboard/security",
        "/dashboard/settings",
        "/dashboard/logs",
        "/dashboard/webhooks",
        
        // Auth Endpoints
        "/auth/login",
        "/auth/register",
        "/auth/verify",
        "/auth/reset",
        "/auth/session",
        "/auth/token",
        "/auth/refresh",
        "/auth/revoke",
        "/auth/validate",
        "/auth/check",
        
        // License Endpoints
        "/license/create",
        "/license/verify",
        "/license/update",
        "/license/delete",
        "/license/status",
        "/license/extend",
        "/license/transfer",
        "/license/bind",
        "/license/unbind",
        "/license/history"
    };

    static const char* const params[] = {
        // Version Parameters
        "version=1.0",
        "version=2.1",
        "version=3.0",
        "ver=1.2.3",
        "ver=2.0.1",
        "build=1234",
        "build=5678",
        "release=stable",
        "release=beta",
        "channel=prod",
        
        // Authentication Parameters
        "hwid=",
        "session=",
        "token=",
        "license=",
        "key=",
        "auth=",
        "user=",
        "client=",
        "id=",
        "apikey=",
        
        // Additional Parameters
        "timestamp=",
        "nonce=",
        "signature=",
        "hash=",
        "checksum=",
        "fingerprint=",
        "device=",
        "platform=",
        "os=",
        "app=",
        
        // Security Parameters
        "integrity=",
        "antitamper=",
        "security=",
        "protection=",
        "encrypted=",
        "signed=",
        "verified=",
        "trusted=",
        "secure=",
        "safe=",
        
        // User Parameters
        "username=",
        "email=",
        "account=",
        "profile=",
        "role=",
        "group=",
        "level=",
        "rank=",
        "status=",
        "type=",
        
        // License Parameters
        "duration=",
        "expiry=",
        "created=",
        "activated=",
        "subscription=",
        "plan=",
        "package=",
        "product=",
        "feature=",
        "access="
    };

    static const char* const responses[] = {
        // Success Responses
        "{\"success\":true,\"message\":\"Successfully authenticated\",\"token\":\"",
        "{\"status\":\"success\",\"data\":{\"license\":\"valid\",\"expires\":\"",
        "{\"result\":true,\"session\":\"",
        "{\"authenticated\":true,\"user\":{\"id\":\"",
        "{\"valid\":true,\"license\":{\"type\":\"",
        "{\"success\":1,\"info\":{\"hwid\":\"",
        "{\"code\":200,\"data\":{\"key\":\"",
        "{\"ok\":true,\"response\":{\"auth\":\"",
        "{\"status\":\"ok\",\"session\":{\"token\":\"",
        "{\"success\":\"true\",\"license\":\"valid\",\"days\":\"",
        
        // Detailed Success Responses
        "{\"success\":true,\"data\":{\"user\":{\"id\":\"\",\"username\":\"\",\"email\":\"\",\"role\":\"premium\"},\"license\":{\"key\":\"\",\"type\":\"lifetime\",\"expires\":\"never\"},\"session\":{\"token\":\"\",\"expires\":\"3600\"},\"hwid\":\"\"}}",
        "{\"status\":\"success\",\"response\":{\"account\":{\"id\":\"\",\"level\":\"vip\",\"created\":\"2024-01-01\"},\"subscription\":{\"plan\":\"enterprise\",\"features\":[\"premium\",\"priority\"],\"active\":true},\"security\":{\"2fa\":true,\"ip_lock\":true}}}",
        "{\"result\":\"ok\",\"auth\":{\"token\":\"\",\"refresh\":\"\",\"scope\":\"full\",\"permissions\":[\"read\",\"write\",\"admin\"]},\"user\":{\"verified\":true,\"status\":\"active\"},\"app\":{\"version\":\"1.0.0\",\"build\":\"stable\"}}",
        
        // Error Responses
        "{\"success\":false,\"error\":\"Invalid license key\",\"code\":\"AUTH001\"}",
        "{\"status\":\"error\",\"message\":\"Session expired\",\"details\":\"Please login again\"}",
        "{\"result\":false,\"reason\":\"HWID mismatch\",\"expected\":\"",
        "{\"error\":true,\"code\":403,\"message\":\"Access denied\",\"info\":\"IP blocked\"}",
        "{\"success\":0,\"error\":\"Version outdated\",\"required\":\"2.0.0\"}",
        "{\"status\":\"failed\",\"type\":\"security\",\"message\":\"Tampering detected\"}",
        "{\"code\":401,\"error\":\"Unauthorized\",\"details\":\"Invalid token\"}",
        
        // Validation Responses
        "{\"valid\":true,\"type\":\"subscription\",\"expires\":\"2025-01-01\",\"features\":[]}",
        "{\"check\":\"passed\",\"integrity\":true,\"signature\":\"valid\",\"timestamp\":\"",
        "{\"verification\":\"success\",\"level\":\"enterprise\",\"modules\":[\"premium\",\"business\"]}",
        "{\"auth\":\"granted\",\"permissions\":{\"admin\":true,\"modify\":true},\"token\":\"",
        "{\"license\":\"active\",\"plan\":\"premium\",\"restrictions\":{\"ip_lock\":true},\"key\":\"",
        
        // Security Responses
        "{\"security\":{\"integrity\":\"valid\",\"tamper\":\"none\",\"debug\":\"none\",\"vm\":\"none\"}}",
        "{\"protection\":{\"level\":\"maximum\",\"encryption\":\"enabled\",\"monitoring\":\"active\"}}",
        "{\"system\":{\"safe\":true,\"threats\":0,\"scan\":\"completed\",\"hash\":\"",
        "{\"environment\":{\"secure\":true,\"trusted\":true,\"verified\":true},\"token\":\"",
        "{\"check\":{\"memory\":\"clean\",\"process\":\"verified\",\"modules\":\"valid\"},\"session\":\"" 
    };

    static const char* const fake_tokens[] = {
        // JWT Tokens
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiQWxpY2UiLCJhZG1pbiI6dHJ1ZX0",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIiLCJwZXJtcyI6ImFsbCJ9",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicHJlbWl1bSIsInBsYW4iOiJlbnRlcnByaXNlIiwiZXhwIjoxNzA5MjkzMDIxfQ",
        
        // OAuth Tokens
        "ya29.a0AfB_byC-1234567890-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "gho_1234567890abcdefghijklmnopqrstuvwxyzABCD",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
        "xoxb-1234567890-abcdefghijklmnopqrstuvwxyz",
        
        // API Keys
        "sk_live_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "pk_test_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "ak_live_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "pk_live_51234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        
        // Session Tokens
        "sess_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "session_id_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "auth_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        
        // License Keys
        "LICENSE-1234-5678-90AB-CDEF",
        "KEY-ABCD-EFGH-IJKL-MNOP",
        "PREMIUM-1234-5678-9012-3456",
        "ENTERPRISE-ABCD-EFGH-IJKL",
        
        // Security Tokens
        "sec_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "security_token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "access_token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "refresh_token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        
        // Encrypted Tokens
        "U2FsdGVkX1/1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "AES256:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "BASE64:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ENC:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    };

    static const char* const fake_hwids[] = {
        // Windows SIDs
        "S-1-5-21-3623811015-3361044348-30300820-1013",
        "S-1-5-21-1234567890-1234567890-1234567890-1001",
        "S-1-5-21-2222222222-3333333333-4444444444-5555",
        "S-1-5-21-9999999999-8888888888-7777777777-6666",
        "S-1-5-21-1111111111-2222222222-3333333333-4444",
        
        // GUIDs
        "B59BEB45-5557-1234-ABCD-12345ABCDEF0",
        "4876-A012-B345-C678-D901-E234-F567-G890",
        "BFEBFBFF000A0671-01D7641CC6F9E860",
        "A1B2C3D4-E5F6-4321-ABCD-0123456789AB",
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        
        // Hardware IDs
        "PCI\\VEN_10DE&DEV_2484&SUBSYS_39883842",
        "ACPI\\GENUINEINTEL_-_INTEL64",
        "USB\\VID_046D&PID_C52B&REV_2400",
        "DISPLAY\\DELA135\\5&2F4DCAFD&0&UID4352",
        "HID\\VID_046D&PID_C52B&REV_1200",
        
        // MAC Addresses
        "00:1A:2B:3C:4D:5E",
        "FF:FF:FF:FF:FF:FF",
        "01:23:45:67:89:AB",
        "AA:BB:CC:DD:EE:FF",
        "00:00:00:00:00:00",
        
        // CPU IDs
        "BFEBFBFF000A0671",
        "0178BFBFF00100F92",
        "178BFBFF00100F92",
        "000306C3",
        "00000000",
        
        // Volume IDs
        "A8C3-D5E7",
        "1234-5678",
        "ABCD-EFGH",
        "9876-5432",
        "FFFF-FFFF",
        
        // Custom Formats
        "HW-1234-5678-90AB-CDEF",
        "ID-ABCD-EFGH-IJKL-MNOP",
        "HWID-1234-5678-9012-3456",
        "MACHINE-ABCD-EFGH-IJKL",
        "SYSTEM-1234-ABCD-5678-EFGH"
    };

    static volatile struct {
        const char* url;
        const char* token;
        const char* hwid;
        const char* response;
    } active_session = {
        auth_urls[0],
        fake_tokens[0],
        fake_hwids[0],
        responses[0]
    };
}

INLINE void refresh_fake_auth() {
    while (true) {
        int url_idx = rand() % (sizeof(fake_auth::auth_urls) / sizeof(fake_auth::auth_urls[0]));
        int token_idx = rand() % (sizeof(fake_auth::fake_tokens) / sizeof(fake_auth::fake_tokens[0]));
        int hwid_idx = rand() % (sizeof(fake_auth::fake_hwids) / sizeof(fake_auth::fake_hwids[0]));
        int response_idx = rand() % (sizeof(fake_auth::responses) / sizeof(fake_auth::responses[0]));

        fake_auth::active_session.url = fake_auth::auth_urls[url_idx];
        fake_auth::active_session.token = fake_auth::fake_tokens[token_idx];
        fake_auth::active_session.hwid = fake_auth::fake_hwids[hwid_idx];
        fake_auth::active_session.response = fake_auth::responses[response_idx];

        volatile char c = fake_auth::active_session.url[0];
        c = fake_auth::active_session.token[0];
        c = fake_auth::active_session.hwid[0];
        c = fake_auth::active_session.response[0];
    }
}

namespace crash_strings {
    static const size_t NUM_CRASH_STRINGS = 1000;
    static const size_t CRASH_STRING_LENGTH = 65535;
    static char** crash_data = nullptr;
    static size_t* string_lengths = nullptr;
    static void** vtable_ptrs = nullptr;
    static volatile bool is_initialized = false;

    struct CrashVTable {
        volatile void* funcs[50];
    };

    INLINE void create_recursive_vtable(CrashVTable* vtable, size_t depth) {
        if (depth > 0) {
            for (size_t i = 0; i < 50; i++) {
                vtable->funcs[i] = (void*)create_recursive_vtable;
            }
        }
    }

    INLINE void init_crash_strings() {
        if (is_initialized) return;
        
        crash_data = new char*[NUM_CRASH_STRINGS];
        string_lengths = new size_t[NUM_CRASH_STRINGS];
        vtable_ptrs = new void*[NUM_CRASH_STRINGS];

        for (size_t i = 0; i < NUM_CRASH_STRINGS; i++) {
            crash_data[i] = new char[CRASH_STRING_LENGTH];
            char* current_data = crash_data[i];
            
            const char* prefixes[] = {
                "https://keyauth.win/api/v1/init?key=",
                "https://auth.secure.com/validate?token=",
                "https://license.verify.net/check?hwid=",
                "http://localhost:3000/debug?session="
            };
            const char* prefix = prefixes[i % 4];
            strcpy_s(current_data, CRASH_STRING_LENGTH, prefix);
            
            size_t offset = strlen(prefix);
            for (size_t j = offset; j < CRASH_STRING_LENGTH - sizeof(void*); j++) {
                if (j % 16 == 0 && i > 0) {
                    *(void**)(&current_data[j]) = crash_data[rand() % i];
                }
                else if (j % 8 == 0) {
                    current_data[j] = (char)(0xD800 + (j % 0x800));
                }
                else if (j % 4 == 0) {
                    current_data[j] = '\\';
                    if (j + 1 < CRASH_STRING_LENGTH) {
                        current_data[j + 1] = 'x';
                    }
                }
                else {
                    current_data[j] = (j % 3) ? 0 : 0xFF;
                }
            }

            string_lengths[i] = CRASH_STRING_LENGTH * 2;

            CrashVTable* vtable = new CrashVTable();
            create_recursive_vtable(vtable, 10);
            vtable_ptrs[i] = vtable;
            *(void**)current_data = vtable;
        }
        
        is_initialized = true;
    }

    INLINE void update_crash_strings() {
        if (!crash_data || !is_initialized) {
            init_crash_strings();
            return;
        }

        static size_t counter = 0;
        counter++;

        for (size_t i = 0; i < NUM_CRASH_STRINGS; i++) {
            char* current_data = crash_data[i];
            if (!current_data) continue;

            size_t target = (i + counter) % NUM_CRASH_STRINGS;
            size_t offset = counter % (CRASH_STRING_LENGTH - sizeof(void*));
            void* target_ptr = crash_data[target];
            memcpy(&current_data[offset], &target_ptr, sizeof(void*));

            string_lengths[i] = CRASH_STRING_LENGTH * ((counter + i) % 10 + 1);

            volatile char c = current_data[counter % CRASH_STRING_LENGTH];
            (void)c;

            CrashVTable* vtable = (CrashVTable*)vtable_ptrs[i];
            if (vtable) {
                for (size_t j = 0; j < 50; j++) {
                    vtable->funcs[j] = crash_data[(i + j) % NUM_CRASH_STRINGS];
                }
            }
        }
    }
}

#define ADD_FAKE_AUTH_STRINGS \
    srand((unsigned int)time(NULL)); \
    crash_strings::init_crash_strings(); \
    std::string crash_string = std::string("\x00\xFF\x0A\x0D\x1B\x7F", 6); \
    std::cout << crash_string << std::endl; \
    std::string crash_stringz(10000, '\x00'); \
    std::thread([]() { \
        while(true) { \
            refresh_fake_auth(); \
            crash_strings::update_crash_strings(); \
            Sleep(10); \
        } \
    }).detach()
