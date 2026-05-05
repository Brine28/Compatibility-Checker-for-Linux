/*
 * lcc_shared.h  —  Linux Compat Checker Driver
 * ================================================
 * Shared definitions between the kernel-mode driver (lcc_driver.c)
 * and the user-mode application (linux_compat_checker.cpp).
 *
 * Include this file in BOTH projects.
 * Driver side  : #include "lcc_shared.h"
 * Usermode side: #include "lcc_shared.h"  (after <windows.h>)
 */

#pragma once

/* ─── Symbolic link exposed to user-mode ─── */
#define LCC_DEVICE_NAME     L"\\Device\\LinuxCompatChecker"
#define LCC_SYMLINK_NAME    L"\\DosDevices\\LinuxCompatCheckerDrv"
#define LCC_USERMODE_PATH   "\\\\.\\LinuxCompatCheckerDrv"  /* CreateFileA path */

/* ─── IOCTL code definitions ─────────────────────────────────────────
 *  METHOD_BUFFERED   : kernel copies in/out via system buffer (safe)
 *  FILE_ANY_ACCESS   : no special privilege on the handle itself
 *  Device type 0x8000+ is in the user-defined range (docs.microsoft)
 * ------------------------------------------------------------------ */
#define LCC_DEVICE_TYPE     0x8C00u

#define IOCTL_LCC_GET_PCI_DEVICES \
    CTL_CODE(LCC_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_LCC_GET_CPU_MSR \
    CTL_CODE(LCC_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_LCC_GET_ACPI_INFO \
    CTL_CODE(LCC_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ─── Capacity constants ─────────────────────────────────────────── */
#define LCC_MAX_PCI_DEVICES     256u
#define LCC_MAX_ACPI_TABLES     32u

/* ═══════════════════════════════════════════════════════════════════
 *  PCI — one record per function found on the bus
 *  Fields mirror PCI Spec 3.0 §6.1 (Configuration Space header)
 * ═══════════════════════════════════════════════════════════════════ */
#pragma pack(push, 1)

typedef struct _LCC_PCI_DEVICE {
    UINT8   bus;            /* 0–255                          */
    UINT8   device;         /* 0–31                           */
    UINT8   function;       /* 0–7                            */
    UINT8   header_type;    /* 0 = normal, 1 = bridge, …      */
    UINT16  vendor_id;      /* 0xFFFF = slot empty            */
    UINT16  device_id;
    UINT16  subsystem_vendor_id;
    UINT16  subsystem_id;
    UINT8   class_code;     /* Base class (e.g. 0x02 = NIC)   */
    UINT8   subclass;
    UINT8   prog_if;
    UINT8   revision_id;
    UINT8   capabilities;   /* bit 0 = Capabilities List      */
    UINT8   _pad[3];
} LCC_PCI_DEVICE, *PLCC_PCI_DEVICE;

/* Output buffer for IOCTL_LCC_GET_PCI_DEVICES */
typedef struct _LCC_PCI_RESULT {
    UINT32          count;
    LCC_PCI_DEVICE  devices[LCC_MAX_PCI_DEVICES];
} LCC_PCI_RESULT, *PLCC_PCI_RESULT;

/* ═══════════════════════════════════════════════════════════════════
 *  MSR — input: which register to read; output: 64-bit value
 * ═══════════════════════════════════════════════════════════════════ */

/* Well-known MSR addresses */
#define MSR_IA32_MICROCODE_REV      0x0000008Bu  /* microcode update revision  */
#define MSR_IA32_MISC_ENABLE        0x000001A0u  /* feature enable bits        */
#define MSR_IA32_FEATURE_CONTROL    0x0000003Au  /* VMX / SGX lock bits        */
#define MSR_IA32_PERF_STATUS        0x00000198u  /* current P-state            */
#define MSR_IA32_THERM_STATUS       0x0000019Cu  /* thermal status             */
#define MSR_IA32_ENERGY_PERF_BIAS   0x000001B0u  /* energy/performance bias    */

typedef struct _LCC_MSR_REQUEST {
    UINT32  msr_address;    /* MSR to read (e.g. MSR_IA32_MICROCODE_REV) */
    UINT32  cpu_index;      /* logical CPU to read from (0 = BSP)        */
} LCC_MSR_REQUEST, *PLCC_MSR_REQUEST;

typedef struct _LCC_MSR_RESULT {
    UINT32  msr_address;
    UINT32  cpu_index;
    UINT64  value;
    BOOLEAN valid;          /* FALSE if #GP was intercepted               */
    UINT8   _pad[7];
} LCC_MSR_RESULT, *PLCC_MSR_RESULT;

/* ═══════════════════════════════════════════════════════════════════
 *  ACPI — summary of tables present in the system
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct _LCC_ACPI_TABLE_ENTRY {
    CHAR    signature[4];   /* e.g. "DSDT", "SSDT", "FACP" …  */
    UINT32  length;         /* table size in bytes             */
    UINT8   revision;
    UINT8   oem_id[6];
    UINT8   oem_table_id[8];
    UINT32  oem_revision;
    UINT8   _pad[3];
} LCC_ACPI_TABLE_ENTRY, *PLCC_ACPI_TABLE_ENTRY;

typedef struct _LCC_ACPI_RESULT {
    UINT32                count;
    BOOLEAN               has_rsdp;         /* ACPI 2.0 RSDP found         */
    BOOLEAN               xsdt_present;     /* 64-bit XSDT (vs 32-bit RSDT)*/
    UINT8                 acpi_revision;    /* from FADT                   */
    UINT8                 _pad[1];
    LCC_ACPI_TABLE_ENTRY  tables[LCC_MAX_ACPI_TABLES];
} LCC_ACPI_RESULT, *PLCC_ACPI_RESULT;

#pragma pack(pop)

/* ─── Driver version tag (checked in usermode for ABI compat) ─── */
#define LCC_DRIVER_VERSION  0x0100u   /* 1.0 */

#define IOCTL_LCC_GET_VERSION \
    CTL_CODE(LCC_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _LCC_VERSION_RESULT {
    UINT16  driver_version;
    UINT16  _pad;
} LCC_VERSION_RESULT, *PLCC_VERSION_RESULT;
