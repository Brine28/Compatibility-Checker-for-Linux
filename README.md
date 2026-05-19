# Linux Compatibility Checker for Windows

A Windows-based hardware and system assessment tool that evaluates whether a PC is ready for Linux migration. It combines a user-mode application with an optional kernel-mode driver for deep hardware diagnostics that are not accessible from user space.

---

## Repository structure

```
.
├── linux_compat_checker.cpp   # User-mode application (C++20)
├── lcc_driver_v3.c            # Kernel-mode driver source (Pure WDM, C)
├── lcc_shared.h               # Shared IOCTL definitions and data structures
├── lcc_driver.inf             # Driver installation manifest (INF)
├── lcc_driver.vcxproj         # Visual Studio project for the kernel driver
└── x64/
    ├── Release/lcc_driver.sys # Compiled driver binary (Release build output)
    └── Debug/lcc_driver.sys   # Compiled driver binary (Debug build output)
```

---

## What it does

The checker scans hardware and system configuration across multiple categories and produces a scored compatibility report. Each category is evaluated independently:

- **CPU** — instruction set support, virtualization extensions (VMX), microcode revision via MSR
- **Memory** — RAM capacity and configuration
- **Storage** — disk type, controller, and NVMe compatibility
- **Graphics** — GPU vendor detection and driver availability for Linux
- **Networking** — NIC vendor and driver support
- **Audio** — audio subsystem compatibility
- **Firmware** — UEFI vs. legacy BIOS, Secure Boot state, ACPI revision
- **TPM** — TPM presence and version
- **Power/Battery** — power management readiness
- **Virtualization** — hypervisor support flags
- **PCI device inventory** *(driver-assisted)* — full PCI bus scan via kernel access
- **ACPI table inspection** *(driver-assisted)* — RSDP/XSDT presence, table list from firmware
- **MSR queries** *(driver-assisted)* — reads CPU Model-Specific Registers (e.g. microcode revision, feature control, energy/performance bias)
- **Online lookup** — optional kernel version check against kernel.org when internet is available

The driver component (`lcc_driver.sys`) exposes three IOCTL interfaces defined in `lcc_shared.h`:

| IOCTL | Function |
|---|---|
| `IOCTL_LCC_GET_VERSION` | Returns driver ABI version for compatibility check |
| `IOCTL_LCC_GET_PCI_DEVICES` | Enumerates up to 256 PCI functions from the bus |
| `IOCTL_LCC_GET_CPU_MSR` | Reads a 64-bit MSR from a specified logical CPU |
| `IOCTL_LCC_GET_ACPI_INFO` | Returns ACPI table signatures, revisions, and OEM metadata |

The driver is optional. All driver-dependent checks are gracefully skipped if the driver is not loaded.

---

## Compatibility score legend

| Score | Label | Meaning |
|:---:|---|---|
| `0` | Fully compatible | No concerns; no action needed |
| `1` | Compatible (minor) | Works, but minor issues may appear |
| `2` | Possibly incompatible | Review carefully before migrating |
| `3` | Incompatible | Significant Linux migration issues expected |

---

## Requirements

| Component | Requirement |
|---|---|
| OS | Windows 10 or later (x64) |
| Compiler | Visual Studio 2022 (toolset v145) with C++ Desktop Development workload |
| Windows SDK | 10.0.19041.0 or later |
| WDK | Windows Driver Kit 10.0.28000.0 (for driver builds only) |
| Privileges | Administrator for driver installation and elevated runtime checks |

---

## Building the user-mode application

Open a **Visual Studio Developer Command Prompt** and run:

```batch
cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest /link advapi32.lib setupapi.lib winhttp.lib
```

This produces `linux_compat_checker.exe` in the current directory. The binary requires `lcc_shared.h` to be present in the same directory at compile time.

**Linked libraries:** `advapi32.lib` (registry/token APIs), `setupapi.lib` (device enumeration), `winhttp.lib` (optional kernel.org lookup).

---

## Building the kernel-mode driver

The driver is a **pure WDM kernel driver** compiled as C (`/TC`). It does not use KMDF or UMDF frameworks beyond the WDF loader stub.

### Prerequisites

Install the **Windows Driver Kit (WDK) 10.0.28000.0**. The project expects the WDK at the default path:

```
C:\Program Files (x86)\Windows Kits\10\
```

If your WDK is installed elsewhere, edit the `<WDKRoot>` property near the top of `lcc_driver.vcxproj`.

### Build steps

1. Open `lcc_driver.vcxproj` in **Visual Studio 2022**.
2. Set the platform to **x64**.
3. Choose **Release** or **Debug** configuration.
4. Build the project (`Ctrl+Shift+B`).

**Release output:** `x64\Release\lcc_driver.sys`  
**Debug output:** `x64\Debug\lcc_driver.sys`

A PDB file (`lcc_driver.pdb`) is generated alongside the `.sys` binary in both configurations.

> **Note on MSB8012:** The project uses `ConfigurationType=Application` to avoid WDK-specific MSBuild targets, and a post-link step renames the output to `.sys`. A harmless MSB8012 warning may appear during the build; it does not indicate a failure. If the `.sys` file is present in the output directory after building, the build was successful.

### Key compiler settings

| Setting | Value | Reason |
|---|---|---|
| Compile as | C (`/TC`) | WDM headers require C mode |
| Exception handling | Disabled | Not supported in kernel mode |
| Security checks (`/GS`) | Disabled | Not available in kernel mode |
| Control Flow Guard | Disabled | Not compatible with WDM entry points |
| Spectre mitigation | Enabled (Release) | `/Qspectre` |
| Runtime library | `/MT` (MultiThreaded) | No CRT in kernel mode |

---

## Driver architecture

The driver (`lcc_driver_v3.c`) implements the following design decisions:

- **`IoCreateDeviceSecure`** is used instead of `IoCreateDevice`. An SDDL string (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`) restricts device access to SYSTEM and local Administrators at object creation time.
- **IO Remove Lock** (`IO_REMOVE_LOCK`) synchronizes `DriverUnload` with active IRPs. `IoReleaseRemoveLockAndWait` ensures no IRP is in flight when the driver unloads.
- **MSR reads on non-boot CPUs** are performed via DPC (Deferred Procedure Call) dispatched to the target logical processor. A 5-second timeout guards against unresponsive CPUs. The driver uses a whitelist of known-safe MSR addresses rather than SEH (`__try`/`__except`), which is not safe at `DISPATCH_LEVEL` IRQL.
- **ACPI table enumeration** uses `ZwQuerySystemInformation` with `SystemFirmwareTableInformation` (class 76). Buffer offsets are computed using `SFTI_HEADER_SIZE` to correctly address the flexible array member in `SYSTEM_FIRMWARE_TABLE_INFORMATION`.
- **PCI enumeration** reads the configuration space header for each bus/device/function combination using port I/O protected by a spin lock (`g_PciPortLock`).
- All kernel allocations use `ExAllocatePool2` with `POOL_FLAG_NON_PAGED` and the pool tag `'rccL'`.

---

## Driver installation

Kernel drivers must be either **WHQL-signed** or installed under **test signing mode**. For development and testing, use test signing.

### Enable test signing

From an **elevated command prompt**:

```batch
bcdedit /set testsigning on
```

Restart the machine. A "Test Mode" watermark will appear on the desktop.

### Install with pnputil

```batch
pnputil /add-driver lcc_driver.inf /install
```

The INF installs the driver as a **demand-start** (`SERVICE_DEMAND_START`) kernel service named `LccDriver`. The binary is copied to `%SystemRoot%\System32\drivers\lcc_driver.sys`.

### Install manually via sc.exe

```batch
sc create LccDriver type= kernel start= demand binPath= "C:\path\to\lcc_driver.sys"
sc start LccDriver
```

### Uninstall

```batch
sc stop LccDriver
sc delete LccDriver
pnputil /delete-driver lcc_driver.inf /uninstall
```

> **Warning:** Only install kernel drivers on machines you own and control. A driver bug can cause a system crash (BSOD). Use a test machine or virtual machine for development.

---

## Usage

Run from an **elevated terminal**:

```batch
linux_compat_checker.exe
```

To save the report to a file:

```batch
linux_compat_checker.exe --save report.txt
```

The application automatically detects whether the driver is loaded and enables driver-assisted checks accordingly. No arguments are required to use the driver; it is discovered via its symbolic link (`\\.\LinuxCompatCheckerDrv`).

---

## Output

The report prints color-coded results (ANSI escape codes; requires Windows 10 virtual terminal support) with:

- Per-category compatibility score and label
- Detailed findings and warnings for each component
- Flagging of critical items that may block Linux migration
- An overall readiness summary
- Migration preparation hints
- Optional kernel version lookup from kernel.org

---

## Troubleshooting

**Driver is not detected at runtime**  
Confirm test signing is enabled (`bcdedit /enum | findstr testsigning`), the driver is installed and started (`sc query LccDriver`), and the binary was built for x64.

**Build fails with C2059 or C2065**  
These errors indicate the driver source is being compiled as C++. Verify `<CompileAs>CompileAsC</CompileAs>` is set in `lcc_driver.vcxproj` and that `DECLARE_CONST_UNICODE_STRING` is not used (it is intentionally avoided in v3).

**Build fails — WDK headers not found**  
Check that WDK 10.0.28000.0 is installed and the `<WDKRoot>` path in `lcc_driver.vcxproj` matches your installation path.

**User-mode build fails**  
Confirm `lcc_shared.h` is in the same directory as `linux_compat_checker.cpp`. Ensure you are using a Visual Studio Developer Command Prompt with the C++ toolset available.

**MSR query returns `valid = FALSE`**  
The requested MSR is not supported on this CPU. Only MSR addresses on the built-in whitelist are attempted.

---

## Security and privacy

- The checker and driver perform **read-only** hardware and system analysis.
- No firmware, system partitions, or registry keys are modified.
- No telemetry is collected or transmitted.
- Driver access is restricted to SYSTEM and local Administrator accounts via SDDL at device creation.

---

## License

Distributed under the terms of the `LICENSE` file in the repository root.
