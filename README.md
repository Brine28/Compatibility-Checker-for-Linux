# Linux Compatibility Checker

Linux Compatibility Checker is a Windows user-mode console application that evaluates whether a Windows PC is ready for a Linux migration. It reads hardware and system information through standard Win32 APIs, assigns a compatibility score to each finding, and prints a migration-readiness report.

The checker does not install a kernel driver, modify firmware or partitions, or change the Windows configuration. It is a read-only assessment tool.

## Features

The application inspects:

- CPU architecture, model, vendor, logical cores, instruction-set features, and hardware virtualization availability
- Installed memory (RAM) capacity
- The Windows system disk, including free space and storage type (HDD, SSD, or NVMe)
- Display adapters and likely Linux driver support
- Network adapters, including common Intel, Realtek, Broadcom, Atheros/Killer, and MediaTek devices
- Audio devices and common Linux audio support
- Firmware mode (UEFI or Legacy BIOS), BIOS information, and Secure Boot state
- TPM presence
- Laptop battery and power status, when a battery is detected
- Hardware virtualization support
- The latest stable Linux kernel reported by `kernel.org`, when an internet connection is available

The program also shows an overall percentage, per-item recommendations, distribution suggestions, and an optional plain-text report.

## Compatibility scores

| Score | Label | Meaning |
|:---:|---|---|
| `0` | Fully compatible | No significant concern was detected |
| `1` | Compatible (minor) | Linux should work, but a small issue or manual setup may be needed |
| `2` | Maybe incompatible | Further research or live USB testing is recommended |
| `3` | Incompatible | A significant migration problem is expected |

The overall percentage is calculated from all findings. Critical items such as the CPU, memory, storage, and graphics adapter receive extra weight.

## Requirements

- Windows 10 or later
- A supported Windows target architecture: x86, x86-64, ARM32, or ARM64
- Administrator approval at runtime
- Internet access is optional; it is used only for the `kernel.org` lookup

The application requests elevation through Windows UAC. If it is started without administrator privileges, it attempts to relaunch itself with the `runas` verb. If elevation is cancelled, the scan does not continue.

## Repository structure

```text
.
├── linux_compat_checker.cpp
├── README.md
└── LICENSE
```

## Building

The source is a C++20 Windows application and is built with MinGW-w64 LLVM Clang cross-compilers. The required Windows import libraries are passed explicitly to the linker:

- `advapi32` for registry and token APIs
- `setupapi` for device enumeration
- `winhttp` for the optional `kernel.org` request
- `shell32` for the UAC elevation relaunch

### x86-64 Windows executable

Run this command in a shell where `x86_64-w64-mingw32-clang++` is available:

```sh
x86_64-w64-mingw32-clang++ \
  -O3 -flto=thin -s -DNDEBUG \
  -ffunction-sections -fdata-sections \
  -Wl,--gc-sections \
  -mconsole \
  -std=c++20 \
  linux_compat_checker.cpp \
  -o linux_compat_checker_x64.exe \
  -static \
  -ladvapi32 -lsetupapi -lwinhttp -lshell32
```

### ARM64 Windows executable

Run this command in a shell where `aarch64-w64-mingw32-clang++` is available:

```sh
aarch64-w64-mingw32-clang++ \
  -O3 -flto=thin -s -DNDEBUG \
  -ffunction-sections -fdata-sections \
  -Wl,--gc-sections \
  -mconsole \
  -std=c++20 \
  linux_compat_checker.cpp \
  -o linux_compat_checker_arm64.exe \
  -static \
  -ladvapi32 -lsetupapi -lwinhttp -lshell32
```

The resulting files are statically linked console executables for their respective Windows architectures. They still use the Windows system DLLs that provide the linked operating-system APIs.

## Usage

Run the matching executable from an elevated Windows terminal, or allow the program to request elevation:

```bat
linux_compat_checker_x64.exe
```

To save the detailed report as a text file:

```bat
linux_compat_checker_x64.exe --save report.txt
```

Use `linux_compat_checker_arm64.exe` instead on an ARM64 Windows system. The `--save` option accepts one output path. If the path cannot be opened, the report remains available in the console and an error is displayed.

When the scan finishes, the program waits for Enter before exiting. Console colors and symbols require a Windows 10 or later terminal with virtual-terminal support.

## Privacy and safety

- The checker performs read-only hardware and system inspection.
- It does not install drivers or services.
- It does not modify the registry, firmware, partitions, or boot configuration.
- No telemetry is collected. Network requests are limited to the optional HTTPS connectivity check and the `www.kernel.org` request for the latest stable kernel version.

## License

Distributed under the terms of the `LICENSE` file in the repository root.
