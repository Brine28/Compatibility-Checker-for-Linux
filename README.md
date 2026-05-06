# 🐧 Linux Compatibility Checker for Windows

A Windows terminal utility that scans system hardware and firmware and estimates how well the machine will work with Linux.

This project includes both:
- `linux_compat_checker.cpp` — a C++ user-mode application that gathers system information and computes compatibility scores
- `driver/` — a kernel-mode driver project that exposes low-level PCI, MSR, and ACPI data to the application via IOCTL

## What it does

The compatibility checker inspects Windows system configuration and hardware components to identify possible Linux migration issues.
It reports compatibility using a 4-level score and provides recommendations for common Linux-related compatibility concerns.

## Key Features

- Hardware compatibility scoring for CPU, memory, storage, GPU, network, audio, firmware, Secure Boot, TPM, power, and virtualization
- PCI device enumeration via a kernel-mode driver
- Low-level MSR reads for CPU feature inspection
- ACPI table enumeration for firmware and platform checks
- Optional kernel.org query for latest Linux stable kernel version
- ANSI color output for readable terminal reporting on Windows 10+
- Local, read-only analysis with no hidden remote telemetry

## Project Structure

- `linux_compat_checker.cpp` — main application source
- `driver/lcc_driver.c` — KMDF kernel-mode driver implementation
- `driver/lcc_shared.h` — shared IOCTL definitions and data structures used by both user-mode and driver projects
- `driver/lcc_driver.inf` / `driver/lcc_driver.vcxproj` — driver install manifest and driver build project

## Compatibility Score Legend

| Score | Meaning |
|------:|---------|
| `0`   | Fully compatible |
| `1`   | Compatible with minor concerns |
| `2`   | Possibly incompatible; review carefully |
| `3`   | Incompatible; likely Linux migration issues |

## Build Instructions

### Requirements

- Windows 10 or later
- C++ compiler with C++23 support
- Windows SDK and libraries for `advapi32`, `setupapi`, and `winhttp`
- (Driver only) Windows Driver Kit (WDK) and Visual Studio to build the KMDF driver

### Build the user-mode application

#### MSVC

```batch
cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest /link advapi32.lib setupapi.lib winhttp.lib
```

#### GCC / MinGW-w64

```bash
g++ linux_compat_checker.cpp -o linux_compat_checker.exe -std=c++23 -ladvapi32 -lsetupapi -lwinhttp
```

### Build the driver

The driver is a KMDF project intended for x64 Windows.
Use Visual Studio with WDK support and open `driver/lcc_driver.vcxproj`.

The driver exposes these IOCTL operations:
- `IOCTL_LCC_GET_VERSION` — version handshake
- `IOCTL_LCC_GET_PCI_DEVICES` — raw PCI bus scan
- `IOCTL_LCC_GET_CPU_MSR` — read a CPU Model-Specific Register
- `IOCTL_LCC_GET_ACPI_INFO` — enumerate ACPI tables from RSDT/XSDT

### Driver installation notes

This driver must be installed with proper signing or Windows test-signing enabled.
For test installations, enable test signing and reboot:

```batch
bcdedit /set testsigning on
```

Then load the driver using Windows service or driver install tools.

## Usage

1. Build `linux_compat_checker.exe`
2. Ensure the optional kernel-mode driver is installed and running if you want the lowest-level PCI/MSR/ACPI checks
3. Run the executable from an elevated terminal for best coverage:

```batch
linux_compat_checker.exe
```

The tool prints a compatibility report with component scores and recommendations.

## Output

The application produces:
- a list of compatibility items grouped by component
- a color-coded score for each item
- a computed overall compatibility percentage
- diagnostic details for hardware and firmware checks
- optional online kernel version lookup if internet access is available

## Security and privacy

- All analysis is performed locally on the host system
- The application is read-only and does not modify disk or firmware settings
- No telemetry or remote upload of system data is included
- Online kernel version lookups are optional and limited to `kernel.org`

## Notes

- The project targets Windows 10+ and uses C++23 features such as `std::format`
- The application uses Windows APIs directly and links against `advapi32`, `setupapi`, and `winhttp`
- The driver is intended only for diagnostic use and must be run with administrator privileges

## License

This repository is provided under the terms of the existing `LICENSE` file.
