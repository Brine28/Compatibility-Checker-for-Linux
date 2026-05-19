# 🐧 Linux Compatibility Checker for Windows

A Windows compatibility utility for testing hardware and firmware readiness before migrating a PC to Linux.

This repository includes:
- `driver/linux_compat_checker.cpp` — the user-mode application source
- `driver/lcc_driver_v3.c` — the kernel-mode driver source used for low-level hardware access
- `driver/lcc_shared.h` — shared IOCTL definitions and data structures
- `driver/lcc_driver.inf` / `driver/lcc_driver.vcxproj` — driver install manifest and Visual Studio project
- `driver/lcc_driver/` — driver build artifacts and packaging files

## What it does

The checker gathers system details on Windows and evaluates Linux compatibility across CPU, storage, firmware, graphics, virtualization, and system firmware.
It reports a four-level compatibility score, component-by-component findings, and practical recommendations.

## Key features

- Compatibility scoring for CPU, storage, GPU, network, audio, firmware, Secure Boot, TPM, virtualization, and more
- Optional PCI/MSR/ACPI inspection using a kernel-mode driver
- ACPI table enumeration and firmware analysis
- Optional online kernel.org lookup for the latest stable Linux kernel
- ANSI-colored Windows terminal output in English for readability
- Fully local analysis with no hidden remote telemetry

## Current project structure

- `driver/linux_compat_checker.cpp` — main application source
- `driver/lcc_driver_v3.c` — driver source code
- `driver/lcc_shared.h` — shared IOCTL header
- `driver/lcc_driver.inf` / `driver/lcc_driver.vcxproj` — driver manifest and build project

## Compatibility score legend

| Score | Meaning |
|------:|---------|
| `0`   | Fully compatible |
| `1`   | Compatible with minor concerns |
| `2`   | Possibly incompatible; review carefully |
| `3`   | Incompatible; likely Linux migration issues |

## Build instructions

### Requirements

- Windows 10 or later
- MSVC or another C++ compiler with C++23 support
- Windows SDK libraries: `advapi32`, `setupapi`, `winhttp`
- Windows Driver Kit (WDK) and Visual Studio to build the driver

### Build the user-mode application

Open a Developer Command Prompt and run from the repository root:

```batch
cd driver
cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest /link advapi32.lib setupapi.lib winhttp.lib
```

### Build the driver

Open `driver/lcc_driver.vcxproj` in Visual Studio with WDK support.
Build as an x64 driver and install it with proper code signing or Windows test signing.

### Driver installation notes

For test installations, enable test signing and reboot:

```batch
bcdedit /set testsigning on
```

Then install the driver using standard Windows driver installation workflows.

## Usage

Run the checker from an elevated terminal for the best results.

```batch
cd driver
linux_compat_checker.exe
```

## Output

The tool generates:
- compatibility findings grouped by component
- color-coded scores for each item
- an overall compatibility score
- recommendations for Linux migration
- optional online kernel version lookup if available

## Security and privacy

- Analysis runs locally on the host system
- No disk or firmware changes are made by the tool
- No telemetry is sent without user consent
- Online kernel lookups are optional

## Notes

- The application is designed for Windows 10+ and uses modern C++ features.
- The driver is intended for diagnostic use only and requires administrator rights.

## License

This repository is distributed under the terms of the existing `LICENSE` file.
