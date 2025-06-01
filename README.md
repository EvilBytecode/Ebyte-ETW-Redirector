# ETW-Redictor 🛡️

A sophisticated Event Tracing for Windows (ETW) redirection tool that enables dynamic ETW bypass through runtime function hooking.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-windows-blue.svg)](https://www.microsoft.com/en-us/windows)
[![C++](https://img.shields.io/badge/language-C++-blue.svg)](https://isocpp.org/)

## 🚀 Features

- Dynamic ETW function hooking at runtime
- Process-specific ETW redirection
- Support for multiple ETW-related functions
- Thread-safe implementation
- Verbose debugging mode
- Clean and modern C++ implementation

## 📋 Prerequisites

- Windows 10/11
- Visual Studio 2019 or later

## 🔧 Installation

1. Open the solution in Visual Studio
2. Build the project in Release/Dbg mode

## 💻 Usage

```bash
ETW-Redictor.exe <PID> [-v|--verbose]
```

### Parameters:
- `PID`: Process ID to target for ETW redirection
- `-v` or `--verbose`: Enable verbose debugging output
- `-h` or `--help`: Display help information

## 🔍 Technical Analysis

### Architecture Overview

ETW-Redictor employs a sophisticated approach to redirect Event Tracing for Windows through dynamic function hooking. Here's how it works:

1. **Process Targeting**
   - Opens target process with full access rights
   - Enumerates and manages process threads

2. **Thread Management**
   - Suspends all threads (except the current one) before modification
   - Safely resumes threads after hooks are in place

3. **Function Hooking**
   - Targets critical ETW functions:
     - `EtwEventWrite`
     - `NtTraceEvent`
   - Implements a trampoline-based hooking mechanism

4. **Memory Operations**
   - Uses Native API (`Nt*` functions) for memory operations
   - Implements proper memory protection handling
   - Ensures thread-safe memory modifications

### Hook Implementation

The hook is implemented through the following steps:

1. **Memory Allocation**
```cpp
// alloc mem for hook
PVOID remoteMemory = NULL;
SIZE_T regionSize = sizeof(etwBypass);
NtAllocateVirtualMemory(
    m_processHandle,
    &remoteMemory,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

2. **Hook Code Injection**
```cpp
// simple ret bypass
unsigned char etwBypass[] = {
    0x48, 0x33, 0xC0,  // xor rax, rax
    0x48, 0xFF, 0xC0,  // inc rax 
    0xC3               // ret
};
```

3. **Jump Implementation**
```cpp
// 14 byte jmp to hook
unsigned char jumpBytes[14] = {
    0x48, 0xB8,                    // mov rax, <addr>
    [8 bytes for address],         // hook address
    0xFF, 0xE0,                    // jmp rax
    0xCC, 0xCC                     // padding
};
```

## ⚠️ Disclaimer

This tool is for educational and research purposes only. Users are responsible for complying with applicable laws and regulations.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
