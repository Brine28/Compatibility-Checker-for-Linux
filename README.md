# 🐧 Linux Kernel Compatibility Checker v2.0

A terminal tool for Windows 11 users to analyze how compatible their system is before migrating to Linux.

---

## Compatibility Scores

| Score | Meaning              | Color   |
|-------|----------------------|---------|
| [0]   | Fully Compatible     | Green   |
| [1]   | Compatible (Minor Issues Possible) | Yellow |
| [2]   | Possibly Incompatible| Orange  |
| [3]   | Incompatible         | Red     |

---

## Analyzed Components

- ✅ CPU (Intel/AMD/ARM detection, SSE2, AVX, VT-x)
- ✅ RAM (size and adequacy)
- ✅ Disk (space check, SSD/HDD/NVMe detection)
- ✅ GPU (NVIDIA/AMD/Intel, open source driver analysis)
- ✅ Network Card / WiFi (Intel, Realtek, Broadcom, Atheros...)
- ✅ Audio Card (HDA, Focusrite, Creative...)
- ✅ Firmware (UEFI / Legacy BIOS)
- ✅ Secure Boot status
- ✅ TPM presence
- ✅ Battery / Power management (laptops)
- ✅ Virtualization detection (VMware, Hyper-V, VirtualBox...)
- ✅ kernel.org → Latest stable kernel version (online)

---

## Build Instructions

### MSVC (Visual Studio — Recommended)

```bat
cl linux_compat_checker.c ^
   /Fe:linux_compat_checker.exe ^
   /link advapi32.lib setupapi.lib winhttp.lib
```

### MinGW / GCC

```bash
gcc linux_compat_checker.c \
    -o linux_compat_checker.exe \
    -ladvapi32 -lsetupapi -lwinhttp \
    -masm=intel
```

### CMake

```cmake
cmake_minimum_required(VERSION 3.16)
project(LinuxCompatChecker C)

add_executable(linux_compat_checker linux_compat_checker.c)
target_link_libraries(linux_compat_checker advapi32 setupapi winhttp)
```

---

## Running

```
linux_compat_checker.exe
```

Running in Administrator (Admin) mode is recommended.
(Required for disk and device detection.)

---

## Requirements

- Windows 10 / 11
- Visual Studio 2019+ or MinGW-w64
- Internet connection (for kernel.org query, optional)

---

## Notes

- The program does not send any data over the internet.
- Only the latest kernel version number is read from kernel.org.
- All analysis is local and read-only operations.
