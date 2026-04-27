# 🐧 Linux Kernel Compatibility Checker

A comprehensive Windows terminal utility that analyzes system hardware and configuration to evaluate compatibility with Linux before migration.

This tool scans your Windows 11 system and produces a detailed compatibility report with actionable recommendations for Linux migration readiness.

---

## Compatibility Scores

Results are categorized on a 4-point scale:

| Score | Level                 | Indicator  | Meaning |
|-------|-----------------------|------------|---------|
| 0     | Fully Compatible      | ● (Green)  | No known compatibility issues |
| 1     | Compatible (Minor)    | ◑ (Yellow) | Minor issues may occur; generally compatible |
| 2     | Possibly Incompatible | ◔ (Orange) | Significant concerns; careful evaluation needed |
| 3     | Incompatible          | ○ (Red)    | Serious compatibility problems expected |

---

## Features & Analyzed Components

The scanner performs deep analysis of the following system components:

- ✅ **CPU** — Vendor (Intel/AMD/ARM), brand string, core count, ISA extensions (SSE2, AVX, VT-x/AMD-V, AMD SVM)
- ✅ **RAM** — Total physical memory; adequacy assessment for desktop workloads
- ✅ **Storage** — Total capacity, free space, drive type detection (HDD / SATA SSD / NVMe SSD)
- ✅ **Graphics (GPU)** — NVIDIA/AMD/Intel/Virtual detection; open-source driver availability analysis
- ✅ **Network** — Ethernet and Wi-Fi adapters; chipset detection (Intel, Realtek, Broadcom, Atheros/Killer, MediaTek)
- ✅ **Audio** — Sound card detection; driver compatibility assessment (HDA, Focusrite, Creative)
- ✅ **Firmware** — UEFI vs. Legacy BIOS detection; BIOS vendor and version
- ✅ **Secure Boot** — Current status and implications for Linux boot
- ✅ **TPM** — Presence detection
- ✅ **Power Management** — Battery/power source detection for laptop configurations
- ✅ **Virtualization** — Hypervisor detection (VMware, Hyper-V, VirtualBox, etc.)
- ✅ **Kernel Version** — Fetches latest stable kernel from kernel.org (requires internet)

---

## Build Instructions

### Requirements

- Windows 10 or later
- **C++23** compatible compiler (MSVC 2022+ or GCC 13+)
- Optional: Internet connection for kernel.org online queries

> **Note:** The project uses C++23 features: `std::format`, `std::string_view::contains`, and `std::string::contains`. Earlier standards are not supported.

### MSVC (Visual Studio 2022+)

```batch
cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest /link advapi32.lib setupapi.lib winhttp.lib
```

### GCC / MinGW-w64

```bash
g++ linux_compat_checker.cpp -o linux_compat_checker.exe -std=c++23 -ladvapi32 -lsetupapi -lwinhttp
```

### CMake

```cmake
cmake_minimum_required(VERSION 3.16)
project(LinuxCompatChecker CXX)

set(CMAKE_CXX_STANDARD 23)
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
- Enumeration failures are reported in the output (e.g. if SetupAPI cannot be accessed) rather than silently skipped

---

## Privacy & Security

- ✅ **No data transmission** — All analysis is performed locally
- ✅ **Read-only operations** — The program only reads system information, never modifies anything
- ✅ **Optional internet** — Kernel version check requires internet; all other analysis works offline
- ✅ **kernel.org only** — Only contacts kernel.org for the latest stable kernel version

---

## Technical Details

- **Language**: C++23
- **Platform**: Windows 10+
- **Libraries**: Windows API (SetupAPI, WinHTTP, Advapi32)
- **Dependencies**: advapi32.lib, setupapi.lib, winhttp.lib (system libraries, no external downloads required)

### Notable Implementation Details

- Registry reads use `std::optional<T>` return values; callers use `.value_or()` for safe defaults
- All string formatting uses `std::format` (C++20/23); no `sprintf`/`snprintf` in application logic
- SetupAPI device enumeration is centralized in a single `Analyzer::enumerate_devices()` helper shared by GPU, Network, and Audio analyzers
- WinHTTP responses are read in a loop until `WinHttpReadData` returns 0 bytes, avoiding incomplete reads
- ANSI color codes are `inline constexpr const char*` constants instead of preprocessor macros
- AMD SVM (virtualization) is detected separately from Intel VT-x using the correct CPUID leaf (`0x80000001 ECX bit 2`)
