#include <Windows.h>
#include <cstdio>
#include <vector>

template<typename T> T Min(T a, T b) { return a < b ? a : b; }

//------------------------------------------------------------------------------
std::vector<MEMORY_BASIC_INFORMATION> ScanProcessMemory(HANDLE hProcess)
{
    std::vector<MEMORY_BASIC_INFORMATION> MemoryInfo;
    LPCBYTE AddressPtr = 0;

    do {
        MEMORY_BASIC_INFORMATION mbi;

        SIZE_T MemorySize = VirtualQueryEx(hProcess,        // hProcess
                                           AddressPtr,      // lpAddress
                                           &mbi,            // lpBuffer
                                           sizeof(mbi));    // dwLength

        if (MemorySize == 0) {
            break;
        }

        AddressPtr += mbi.RegionSize;
        MemoryInfo.push_back(mbi);
    } while(true);

    return MemoryInfo;
}

//------------------------------------------------------------------------------
SIZE_T SearchProcessMemory(
    HANDLE hProcess,
    std::vector<MEMORY_BASIC_INFORMATION> const& MemoryInfo,
    LPCVOID lpSearch,
    SIZE_T dwLength)
{
    static BYTE Buffer[0x100000];
    LPCBYTE SearchBytes = (LPCBYTE)lpSearch;

    for (auto const& mbi : MemoryInfo) {
        if (!(mbi.State & MEM_COMMIT)) {
            continue;
        }

        SIZE_T Remaining = mbi.RegionSize;
        LPCBYTE BaseAddress = static_cast<LPCBYTE>(mbi.BaseAddress);

        while (Remaining) {
            SIZE_T Size = 0;
            ReadProcessMemory(
                hProcess,
                BaseAddress,
                Buffer,
                Min(Remaining, sizeof(Buffer)),
                &Size);

            if (Size == 0) {
                break;
            }

            // Brain-dead brute force search.
            for (SIZE_T jj, ii = 0; ii < Size - dwLength; ++ii) {
                for (jj = 0; jj < dwLength; ++jj) {
                    if (Buffer[ii + jj] != SearchBytes[jj]) {
                        break;
                    }
                }
                if (jj < dwLength) {
                    continue;
                }

                // Found a match!
                return reinterpret_cast<SIZE_T>(BaseAddress) + ii;
            }

            Remaining -= Size;
            BaseAddress += Size;
        }
    }

    return 0;
}

//------------------------------------------------------------------------------
BOOL ReadProcessStringPointer(
    HANDLE hProcess,
    SIZE_T Address,
    LPSTR Buffer,
    SIZE_T dwLength)
{
    SIZE_T Pointer, Size;

    ReadProcessMemory(hProcess, (LPCVOID)Address, &Pointer, sizeof(Pointer), &Size);
    if (Size != sizeof(Pointer)) {
        return FALSE;
    }

    ReadProcessMemory(hProcess, (LPCVOID)Pointer, Buffer, dwLength, &Size);
    if (Size == 0) {
        return FALSE;
    }

    return TRUE;
}

//------------------------------------------------------------------------------
BOOL QueryFileVersion(LPWSTR lpFilename, LPSTR lpBuffer, SIZE_T dwBufferSize)
{
    static BYTE Data[0x1000];
    DWORD dwSize = GetFileVersionInfoSizeW(lpFilename, NULL);
    if (GetFileVersionInfoW(lpFilename, NULL, dwSize, &Data) == FALSE) {
        return FALSE;
    }

    VS_FIXEDFILEINFO* lpFileInfo;
    UINT dwLength;
    if (VerQueryValueW(Data, L"\\", (LPVOID*)&lpFileInfo, &dwLength) == FALSE) {
        return FALSE;
    }

    sprintf_s(lpBuffer, dwBufferSize, "%d.%d.%d.%d",
        lpFileInfo->dwProductVersionMS / (1 << 16),
        lpFileInfo->dwProductVersionMS % (1 << 16),
        lpFileInfo->dwProductVersionLS / (1 << 16),
        lpFileInfo->dwProductVersionLS % (1 << 16));

    return TRUE;
}

//------------------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    LPWSTR ExecutablePath = (argc > 1) ? argv[1] : L"G:\\assets\\wow-beta\\WowB-64.exe";
    LPWSTR OutputPath = (argc > 2) ? argv[2] : L"wow-anims.txt";

    CHAR Version[0x100];
    if (QueryFileVersion(ExecutablePath, Version, sizeof(Version)) == FALSE) {
        sprintf_s(Version, "0.0.0.0");
    }

    STARTUPINFOW StartupInfo{
        sizeof(STARTUPINFOW)
    };
    PROCESS_INFORMATION ProcessInfo{};

    CreateProcessW(ExecutablePath,                          // lpApplicationName
                   NULL,                                    // lpCommandLine
                   NULL,                                    // lpProcessAttributes
                   NULL,                                    // lpThreadAttributes
                   FALSE,                                   // bInheritHandles
                   CREATE_SUSPENDED,                        // dwCreationFlags
                   NULL,                                    // lpEnvironment
                   NULL,                                    // lpCurrentDirectory
                   &StartupInfo,                            // lpStartupInfo
                   &ProcessInfo);                           // lpProcessInformation

    if (ProcessInfo.hProcess == NULL || ProcessInfo.hThread == NULL) {
        fprintf_s(stderr, "failed to create process: \"%S\\n", ExecutablePath);
        return -1;
    }

    // Enumerate all regions of addressable memory in the target process.
    std::vector<MEMORY_BASIC_INFORMATION> MemoryInfo = ScanProcessMemory(ProcessInfo.hProcess);

    // Search process memory for the first instance of the string "Stand" which
    // is the name of the animation with id 0.
    SIZE_T AddressOfStand = SearchProcessMemory(ProcessInfo.hProcess,
                                                MemoryInfo,
                                                "Stand",
                                                6);

    // Search process memory for the first instance of a pointer to "Stand" which
    // will be the beginning of the array of animation names.
    SIZE_T Offset = SearchProcessMemory(ProcessInfo.hProcess,
                                        MemoryInfo,
                                        &AddressOfStand,
                                        sizeof(AddressOfStand));

    FILE* f = NULL;
    _wfopen_s(&f, OutputPath, L"w");

    if (f) {
        fprintf(f, "/*\n    The following animation names were extracted from version %s:\n*/\n\n", Version);

        // Read strings in the animation name array up to the first unaddressable value.
        for (int ii = 0; ; ++ii) {
            CHAR String[256];
            CHAR Buffer[256];

            if (ReadProcessStringPointer(ProcessInfo.hProcess, Offset, String, sizeof(String)) == FALSE) {
                break;
            }

            sprintf_s(Buffer, "/* %4d */ \"%s\",\n", ii, String);
            fprintf(f, "%s", Buffer);
            OutputDebugStringA(Buffer);
            Offset += sizeof(Offset);
        }

        fclose(f);
    } else {
        fprintf_s(stderr, "failed to open output file: \"%S\"\n", OutputPath);
    }

    // Terminate the target process and clean up handles.
    TerminateProcess(ProcessInfo.hProcess, 0);
    ResumeThread(ProcessInfo.hThread);

    if (ProcessInfo.hThread) {
        CloseHandle(ProcessInfo.hThread);
    }

    if (ProcessInfo.hProcess) {
        CloseHandle(ProcessInfo.hProcess);
    }

    return 0;
}
