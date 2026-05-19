# Linux Compatibility Checker for Windows

A Windows-based diagnostic utility that evaluates a PC's readiness for migration to Linux.

This repository contains the Windows compatibility checker application, optional kernel-mode driver code for low-level hardware access, and the driver installation project.

## Repository contents

- `linux_compat_checker.cpp` — main Windows user-mode application source
- `lcc_driver_v3.c` — kernel-mode driver source used for optional low-level hardware and ACPI access
- `lcc_shared.h` — shared IOCTL definitions and data structures used by both application and driver
- `lcc_driver.inf` — driver installation manifest
- `lcc_driver.vcxproj` — Visual Studio project for building the driver
- `lcc_driver/` — driver build artifacts and packaging output
- `x64/Release/` — compiled runtime driver file `lcc_driver.sys`

## What this tool does

The Linux Compatibility Checker analyzes Windows hardware and firmware to help determine whether a PC is likely to work well under Linux.
It gathers system information and checks compatibility for:

- CPU and instruction set support
- Storage controllers and disk configuration
- Graphics and display capabilities
- Firmware type and Secure Boot state
- TPM presence and firmware support
- Virtualization support and platform readiness
- ACPI tables and low-level platform data (driver-assisted)

The tool reports per-component compatibility statuses and provides a concise overall readiness score.

## Key features

- Local Windows compatibility analysis with no hidden telemetry
- Component-level scoring and human-readable recommendations
- Optional low-level diagnostics through a kernel-mode driver
- ACPI table enumeration and firmware inspection support
- ANSI-colored output in Windows terminal for readability
- Supports manual builds and driver diagnostics for advanced hardware checks

## Compatibility score legend

| Score | Meaning |
|------:|---------|
| `0`   | Fully compatible |
| `1`   | Compatible with minor concerns |
| `2`   | Possibly incompatible; review carefully |
| `3`   | Incompatible; likely Linux migration issues |

## Prerequisites

Before building the project, ensure you have:

- Windows 10 or later
- Visual Studio with C++ Desktop Development workload
- Windows SDK installed
- Windows Driver Kit (WDK) for building the driver
- Elevated command prompt or administrator privileges for driver installation and runtime diagnostics

## Build instructions

### 1. Build the user-mode application

Open a Visual Studio Developer Command Prompt and run:

```batch
cd c:\Users\Muhammed\Desktop\Compatibility-Checker-for-Linux\driver
cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest /link advapi32.lib setupapi.lib winhttp.lib
```

This produces `linux_compat_checker.exe` in the `driver` directory.

### 2. Build the kernel-mode driver (optional)

The kernel-mode driver is optional and provides deeper hardware access when installed.

1. Open `lcc_driver.vcxproj` in Visual Studio.
2. Select the x64 platform.
3. Set the configuration to `Release`.
4. Build the project.

If the driver build succeeds, the compiled `lcc_driver.sys` file appears in the `x64\Release` output folder.

## Driver installation

The driver is intended for diagnostic use only. Installing unsigned drivers on Windows requires test signing mode.

### Enable test signing mode

From an elevated command prompt, run:

```batch
bcdedit /set testsigning on
```

Restart Windows after enabling test signing.

### Install the driver

Use the standard Windows driver installation process for `.inf` files, or install the driver manually with a driver installation utility.

> Note: Installing kernel drivers requires administrator access. Do not install drivers on systems where you cannot safely recover from driver-related issues.

## Usage

Run the checker from an elevated terminal to maximize diagnostic coverage:

```batch
cd c:\Users\Muhammed\Desktop\Compatibility-Checker-for-Linux\driver
linux_compat_checker.exe
```

The application prints a detailed compatibility report to the terminal.

## Expected output

The tool produces:

- A compatibility score per hardware and firmware component
- An overall Linux readiness score
- Component findings and warnings
- Practical recommendations and next steps
- Optional online kernel.org version lookup if the system has internet access

## Troubleshooting

- If the application cannot access low-level data, run it as administrator.
- If driver loading fails, verify that test signing is enabled and the driver is built for x64.
- If Visual Studio cannot build the driver, confirm that the Windows Driver Kit is installed.

## Security and privacy

- The compatibility checker runs locally and does not modify firmware or persistent disk data.
- No telemetry is collected or transmitted without explicit user action.
- Online checks are optional and do not affect the local analysis flow.

## Notes

- This project is designed for Windows diagnostics prior to Linux migration.
- The kernel-mode driver is for advanced diagnostic access only and should be used carefully.
- Use the latest Windows SDK and driver signing settings when building on modern Windows versions.

## License

This repository is distributed under the terms of the existing `LICENSE` file.
