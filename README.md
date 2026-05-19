# Linux Compatibility Checker for Windows

A Windows compatibility assessment tool that helps determine whether a PC is ready for Linux migration.

This repository contains a user-mode checker, a kernel-mode driver interface for advanced diagnostics, and the driver installation manifest.

## Repository contents

- `linux_compat_checker.cpp` — user-mode application source file
- `lcc_driver_v3.c` — optional kernel-mode driver source for low-level PCI/MSR/ACPI access
- `lcc_shared.h` — shared IOCTL and data structure definitions
- `lcc_driver.inf` — driver installation manifest
- `lcc_driver.vcxproj` — Visual Studio driver project
- `x64/Release/lcc_driver.sys` — compiled driver output (if built)
- `lcc_driver/` — additional driver packaging and artifact files

## What this project does

The tool scans Windows system information and evaluates Linux compatibility across multiple areas:

- CPU and instruction set compatibility
- Memory and storage subsystem readiness
- Graphics and display support
- Firmware type, Secure Boot, and UEFI readiness
- TPM availability and compatibility
- Virtualization support
- PCI device inventory and ACPI table inspection via optional driver support

It generates a component-level report with a simple score system and practical recommendations.

## Compatibility score legend

| Score | Meaning |
|------:|---------|
| `0`   | Fully compatible |
| `1`   | Compatible with minor concerns |
| `2`   | Possibly incompatible; review carefully |
| `3`   | Incompatible; likely Linux migration issues |

## Requirements

- Windows 10 or later
- Visual Studio with C++ Desktop Development workload
- Windows SDK
- Windows Driver Kit (WDK) for driver compilation
- Administrator privileges for driver installation and elevated runtime checks

## Build instructions

### 1. Build the user-mode application

Open a Visual Studio Developer Command Prompt and run:


cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest /link advapi32.lib setupapi.lib winhttp.lib
```

This creates `linux_compat_checker.exe` in the `driver` folder.

### 2. Build the kernel-mode driver (optional)

The driver is optional and only needed for deeper PCI/MSR/ACPI diagnostics.

1. Open `lcc_driver.vcxproj` in Visual Studio.
2. Choose the x64 platform.
3. Select the `Release` configuration.
4. Build the project.

If successful, the driver binary appears in `x64\Release\lcc_driver.sys`.

## Driver installation

The kernel-mode driver requires a signed driver package or Windows test signing mode.

### Enable test signing mode

From an elevated command prompt:

```batch
bcdedit /set testsigning on
```

Restart the machine.

### Install the driver

Install the driver using the `.inf` file from this folder, or use a driver installation utility.

Example using `pnputil`:

```batch
pnputil /add-driver lcc_driver.inf /install
```

> Warning: Kernel driver installation should only be performed on test or trusted systems.

## Usage

Run the application from an elevated terminal:

```batch
cd path\to\Compatibility-Checker-for-Linux\driver
linux_compat_checker.exe
```

For save-to-file support, pass the optional save argument:

```batch
linux_compat_checker.exe --save report.txt
```

## Output

The checker prints a structured report with:

- component compatibility scores
- per-item findings and warnings
- overall Linux readiness evaluation
- recommendation hints for migration preparation
- optional online kernel.kernel.org lookup when internet connectivity is available

## Troubleshooting

- Run the executable as administrator for best results.
- If driver interaction fails, make sure test signing is enabled and the driver is built for x64.
- If the build fails, verify Visual Studio, Windows SDK, and WDK are installed.
- Confirm `lcc_shared.h` is present alongside `linux_compat_checker.cpp` when building.

## Project details

- The user-mode application uses modern Windows APIs and C++20/C++23 features.
- `lcc_shared.h` exposes the driver interface for PCI, MSR, and ACPI queries.
- The driver project `lcc_driver.vcxproj` is a standard Windows kernel driver project targeting x64.

## Security and privacy

- The checker performs read-only system and hardware analysis.
- It does not modify firmware or system partitions.
- No telemetry is collected by default.

## License

This repository is distributed under the terms of the existing `LICENSE` file.
