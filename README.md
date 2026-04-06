# 🐧 Linux Kernel Compatibility Checker

A comprehensive Windows terminal utility that analyzes system hardware and configuration to evaluate compatibility with Linux before migration.

This tool scans your Windows 11 system and produces a detailed compatibility report with actionable recommendations for Linux migration readiness.

---

## Compatibility Scores

Results are categorized on a 4-point scale:

| Score | Level                | Indicator | Meaning |
|-------|----------------------|-----------|---------|
| 0     | Fully Compatible     | ● (Green) | No known compatibility issues |
| 1     | Compatible (Minor)   | ◑ (Yellow) | Minor issues may occur; generally compatible |
| 2     | Possibly Incompatible| ◔ (Orange) | Significant concerns; careful evaluation needed |
| 3     | Incompatible         | ○ (Red)    | Serious compatibility problems expected |

---

## Features & Analyzed Components

The scanner performs deep analysis of the following system components:

- ✅ **CPU** — Vendor (Intel/AMD/ARM), brand string, core count, ISA extensions (SSE2, AVX, VT-x/AMD-V)
- ✅ **RAM** — Total physical memory; Desktop/Laptop/Server adequacy assessment
- ✅ **Storage** — Total capacity, free space, drive type detection (SSD/HDD/NVMe)
- ✅ **Graphics (GPU)** — NVIDIA/AMD/Intel detection; open-source driver availability analysis
- ✅ **Network** — Ethernet and WiFi adapters; chipset detection (Intel, Realtek, Broadcom, Atheros, etc.)
- ✅ **Audio** — Sound card detection; driver compatibility assessment
- ✅ **Firmware** — UEFI vs. Legacy BIOS detection
- ✅ **Secure Boot** — Current status and implications for Linux boot
- ✅ **TPM** — Presence and version detection
- ✅ **Power Management** — Battery/Power detection for laptop configurations
- ✅ **Virtualization** — VMware, Hyper-V, VirtualBox detection
- ✅ **Kernel Version** — Fetches latest stable kernel from kernel.org (requires internet)

---

## Build Instructions

### Requirements

- Windows 10 or later
- C++17 compatible compiler (MSVC 2019+ or GCC 7.0+)
- Optional: Internet connection for kernel.org online queries

### MSVC (Visual Studio 2019+)

```batch
cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /link advapi32.lib setupapi.lib winhttp.lib
```

### GCC / MinGW-w64

```bash
g++ linux_compat_checker.cpp -o linux_compat_checker.exe -std=c++17 -ladvapi32 -lsetupapi -lwinhttp
```

### CMake

```cmake
cmake_minimum_required(VERSION 3.16)
project(LinuxCompatChecker CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(linux_compat_checker linux_compat_checker.cpp)
target_link_libraries(linux_compat_checker advapi32 setupapi winhttp)
```

---

## Usage

1. **Compile** the program using one of the build commands above
2. **Run** the executable:
   ```
   linux_compat_checker.exe
   ```
3. **Run as Administrator** (optional but recommended for complete disk and device detection)

The program will scan your system and display a formatted report with color-coded compatibility ratings.

---

## Output

- Color-coded terminal output using ANSI escape codes (Windows 10+ Virtual Terminal mode)
- Per-component compatibility scores with detailed recommendations
- Overall compatibility percentage based on weighted critical components
- Summary statistics of detected hardware

---

## Privacy & Security

- ✅ **No data transmission** — All analysis is performed locally
- ✅ **Read-only operations** — The program only reads system information, never modifies anything
- ✅ **Optional internet** — Kernel version check requires internet; all other analysis works offline
- ✅ **kernel.org only** — Only contacts kernel.org for the latest stable kernel version

---

## Technical Details

- **Language**: C++17
- **Platform**: Windows 10+
- **Libraries**: Windows API (SetupAPI, WinHTTP, Advapi32)
- **Dependencies**: advapi32.lib, setupapi.lib, winhttp.lib (system libraries, no external downloads required)
