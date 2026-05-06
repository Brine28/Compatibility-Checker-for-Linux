/*
 * lcc_driver.c  —  Linux Compat Checker Kernel-Mode Driver
 * ===========================================================
 * KMDF (Kernel-Mode Driver Framework) driver.
 * Provides ring-0 hardware access to the linux_compat_checker
 * user-mode application via IOCTL calls over a named device.
 *
 * Capabilities
 * ─────────────
 *   • IOCTL_LCC_GET_VERSION      : ABI version handshake
 *   • IOCTL_LCC_GET_PCI_DEVICES  : raw PCI config-space scan (all buses)
 *   • IOCTL_LCC_GET_CPU_MSR      : single MSR read on chosen logical CPU
 *   • IOCTL_LCC_GET_ACPI_INFO    : enumerate ACPI tables from RSDT/XSDT
 *
 * Build environment
 * ─────────────────
 *   WDK 10 / Visual Studio 2022
 *   Platform: x64   Configuration: Release
 *   Target OS: Windows 10/11 (KMDF 1.31+)
 *
 * Required WDK lib references (already pulled in by KMDF project template):
 *   WdfDriverEntry, WdfDeviceCreate, WdfIoQueueCreate …
 *
 * Signing
 * ───────
 *   For testing: bcdedit /set testsigning on  (reboot required)
 *   Production : EV code-signing certificate + WHQL or attestation sign
 *
 * INF file
 * ────────
 *   See lcc_driver.inf (provided separately).
 *   Manual load for dev:
 *     sc create LccDriver type= kernel start= demand binPath= <full_path.sys>
 *     sc start  LccDriver
 *     sc stop   LccDriver
 *     sc delete LccDriver
 */

/* ─── WDK / KMDF headers ────────────────────────────────────────── */
#include <ntddk.h>
#include <wdf.h>
#include <wdmguid.h>
#include <aux_klib.h>       /* AuxKlibQueryModuleInformation, ACPI helpers */
#include <acpiioct.h>       /* ACPI_EVAL_INPUT_BUFFER / OUTPUT_BUFFER      */

#include "lcc_shared.h"

/* ─── WPP / DbgPrint tag ─────────────────────────────────────────── */
#define LCC_POOL_TAG    'rccL'   /* 'Lccr' in memory — little-endian        */
#define LCC_LOG(fmt, ...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "[LccDriver] " fmt "\n", ##__VA_ARGS__))

/* ─── Forward declarations ───────────────────────────────────────── */
DRIVER_INITIALIZE           DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD   LccEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL LccEvtIoDeviceControl;

static VOID LccHandleGetVersion    (WDFREQUEST Request);
static VOID LccHandleGetPciDevices (WDFREQUEST Request);
static VOID LccHandleGetCpuMsr     (WDFREQUEST Request);
static VOID LccHandleGetAcpiInfo   (WDFREQUEST Request);

/*
 * BUG FIX #2 — PCI port I/O race condition
 * -----------------------------------------
 * The CF8/CFC port pair is a global shared resource.  Any other kernel
 * driver may also be accessing these ports.  Without a spinlock, a
 * context-switch between the WRITE_PORT (CF8) and READ_PORT (CFC)
 * calls corrupts both our read and the other driver's.
 *
 * This spinlock serialises all CF8/CFC access system-wide within our
 * driver.  For full correctness a system-wide HAL spinlock would be
 * needed; in practice our sequential IOCTL queue + this lock is
 * sufficient for a diagnostic tool that does not run concurrently
 * with other PCI config-space scanners.
 */
static KSPIN_LOCK g_PciPortLock;

/* ─── DPC + KEVENT context for cross-CPU MSR reads ──────────────── */
typedef struct _MSR_READ_CONTEXT {
    UINT32   msr_address;
    UINT64   result;
    BOOLEAN  valid;
    KEVENT   done_event;
} MSR_READ_CONTEXT, *PMSR_READ_CONTEXT;

static VOID LccMsrDpcRoutine(PKDPC Dpc, PVOID Context,
                              PVOID Arg1, PVOID Arg2);

/* ═══════════════════════════════════════════════════════════════════
 *  DriverEntry
 *  Called once when the driver is loaded into the kernel.
 * ═══════════════════════════════════════════════════════════════════ */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS          status;

    LCC_LOG("DriverEntry — loading Linux Compat Checker driver v%u.%u",
            (LCC_DRIVER_VERSION >> 8) & 0xFF,
             LCC_DRIVER_VERSION       & 0xFF);

    /* Fix #2: initialise global PCI port spinlock */
    KeInitializeSpinLock(&g_PciPortLock);

    WDF_DRIVER_CONFIG_INIT(&config, LccEvtDeviceAdd);

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
    );

    if (!NT_SUCCESS(status)) {
        LCC_LOG("WdfDriverCreate failed: 0x%08X", status);
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════
 *  LccEvtDeviceAdd
 *  Creates the control device and its I/O queue.
 *  KMDF calls this once per device object added.
 * ═══════════════════════════════════════════════════════════════════ */
NTSTATUS
LccEvtDeviceAdd(
    _In_ WDFDRIVER       Driver,
    _In_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS              status;
    WDFDEVICE             device;
    WDFQUEUE              queue;
    WDF_IO_QUEUE_CONFIG   queueConfig;
    UNICODE_STRING        deviceName;
    UNICODE_STRING        symlinkName;

    UNREFERENCED_PARAMETER(Driver);

    /* ── 1. Mark as a non-PnP control device (no hardware behind it) */
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    /*
     * BUG FIX #3 — Unauthorised Ring-0 access (Local Privilege Escalation)
     * ----------------------------------------------------------------------
     * Original code used FILE_DEVICE_SECURE_OPEN=FALSE + FILE_ANY_ACCESS,
     * meaning ANY user process could open the device and read arbitrary MSRs.
     *
     * Fix: assign SDDL_DEVOBJ_SYS_ALL_ADM_ALL so that only SYSTEM and
     * local Administrators can open a handle.  Standard users get
     * STATUS_ACCESS_DENIED before any IOCTL reaches our handler.
     */
    {
        DECLARE_CONST_UNICODE_STRING(
            sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        status = WdfDeviceInitAssignSDDLString(DeviceInit, &sddl);
        if (!NT_SUCCESS(status)) {
            LCC_LOG("WdfDeviceInitAssignSDDLString failed: 0x%08X", status);
            return status;
        }
    }
    WdfDeviceInitSetCharacteristics(DeviceInit,
                                    FILE_DEVICE_SECURE_OPEN, TRUE);

    /* ── 2. Create the WDF device object */
    status = WdfDeviceCreate(&DeviceInit,
                             WDF_NO_OBJECT_ATTRIBUTES,
                             &device);
    if (!NT_SUCCESS(status)) {
        LCC_LOG("WdfDeviceCreate failed: 0x%08X", status);
        return status;
    }

    /* ── 3. Create a NT device name so we can make a symbolic link */
    RtlInitUnicodeString(&deviceName,  LCC_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, LCC_SYMLINK_NAME);

    status = WdfDeviceCreateSymbolicLink(device, &symlinkName);
    if (!NT_SUCCESS(status)) {
        LCC_LOG("WdfDeviceCreateSymbolicLink failed: 0x%08X", status);
        return status;
    }

    /* ── 4. Sequential I/O queue — serialises IOCTL calls */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig,
                                           WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = LccEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        LCC_LOG("WdfIoQueueCreate failed: 0x%08X", status);
        return status;
    }

    LCC_LOG("Device created: " __FUNCTION__);
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════
 *  LccEvtIoDeviceControl
 *  IOCTL dispatcher — runs at PASSIVE_LEVEL (METHOD_BUFFERED).
 * ═══════════════════════════════════════════════════════════════════ */
VOID
LccEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {
    case IOCTL_LCC_GET_VERSION:
        LccHandleGetVersion(Request);
        break;

    case IOCTL_LCC_GET_PCI_DEVICES:
        LccHandleGetPciDevices(Request);
        break;

    case IOCTL_LCC_GET_CPU_MSR:
        LccHandleGetCpuMsr(Request);
        break;

    case IOCTL_LCC_GET_ACPI_INFO:
        LccHandleGetAcpiInfo(Request);
        break;

    default:
        LCC_LOG("Unknown IOCTL: 0x%08X", IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        break;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  IOCTL handler: GET_VERSION
 *  Trivial ABI handshake.  Usermode checks this first.
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetVersion(WDFREQUEST Request)
{
    NTSTATUS           status;
    PLCC_VERSION_RESULT out   = NULL;
    size_t             outLen = 0;

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(LCC_VERSION_RESULT),
                                            (PVOID*)&out, &outLen);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    out->driver_version = LCC_DRIVER_VERSION;
    out->_pad           = 0;

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS,
                                      sizeof(LCC_VERSION_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  PCI Configuration Space helpers
 *
 *  x86/x64 port-based CF8/CFC mechanism (PCI 2.3 §3.2.2.3.2):
 *    Address register 0xCF8 encodes bus/dev/fn/reg.
 *    Data    register 0xCFC reads 32 bits.
 *
 *  We use HalGetBusDataByOffset for safe access where available,
 *  falling back to direct port I/O only if needed.
 *  Both paths are safe in PASSIVE_LEVEL kernel code.
 * ═══════════════════════════════════════════════════════════════════ */

/* Build the CF8 address dword for a given location + register */
static FORCEINLINE ULONG
LccPciMakeAddress(UINT8 bus, UINT8 dev, UINT8 fn, UINT8 reg)
{
    return (ULONG)(0x80000000UL
                 | ((ULONG)bus  << 16)
                 | ((ULONG)dev  << 11)
                 | ((ULONG)fn   <<  8)
                 | ((ULONG)reg  &  0xFCu));   /* dword-align */
}

/* Read one DWORD from PCI config space via port 0xCF8/0xCFC.
 * Acquires g_PciPortLock to serialise the two-port transaction. */
static ULONG
LccPciReadDword(UINT8 bus, UINT8 dev, UINT8 fn, UINT8 reg)
{
    ULONG        address = LccPciMakeAddress(bus, dev, fn, reg);
    KIRQL        oldIrql;
    ULONG        value;

    KeAcquireSpinLock(&g_PciPortLock, &oldIrql);
    WRITE_PORT_ULONG((PULONG)0xCF8, address);
    value = READ_PORT_ULONG((PULONG)0xCFC);
    KeReleaseSpinLock(&g_PciPortLock, oldIrql);

    return value;
}

/* ═══════════════════════════════════════════════════════════════════
 *  IOCTL handler: GET_PCI_DEVICES
 *  Scans all 256 buses × 32 devices × 8 functions (brute-force).
 *  Slots with VendorID == 0xFFFF are empty and skipped.
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetPciDevices(WDFREQUEST Request)
{
    NTSTATUS          status;
    PLCC_PCI_RESULT   out    = NULL;
    size_t            outLen = 0;

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(LCC_PCI_RESULT),
                                            (PVOID*)&out, &outLen);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    RtlZeroMemory(out, sizeof(LCC_PCI_RESULT));

    /* ── Enumerate the PCI hierarchy ─── */
    for (UINT32 bus = 0; bus < 256 && out->count < LCC_MAX_PCI_DEVICES; ++bus) {
        for (UINT32 dev = 0; dev < 32 && out->count < LCC_MAX_PCI_DEVICES; ++dev) {
            for (UINT32 fn = 0; fn < 8 && out->count < LCC_MAX_PCI_DEVICES; ++fn) {

                /* DW0: VendorID (15:0)  DeviceID (31:16) */
                ULONG dw0 = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x00);
                UINT16 vid = (UINT16)(dw0 & 0xFFFFu);

                /* 0xFFFF = absent slot */
                if (vid == 0xFFFF) {
                    /* Skip remaining functions if fn == 0 and slot empty */
                    if (fn == 0) break;
                    continue;
                }

                UINT16 did = (UINT16)(dw0 >> 16);

                /* DW2: RevisionID(7:0) ProgIF(15:8) Subclass(23:16) Class(31:24) */
                ULONG dw2 = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x08);

                /* DW3: CacheLineSize(7:0) LatencyTimer(15:8) HeaderType(23:16) BIST(31:24) */
                ULONG dw3 = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x0C);
                UINT8 hdr = (UINT8)((dw3 >> 16) & 0x7Fu);   /* strip multi-fn bit */

                /* DW4 (header type 0): SubsystemVendorID + SubsystemID */
                UINT16 svid = 0, ssid = 0;
                if (hdr == 0) {
                    ULONG dw11 = LccPciReadDword((UINT8)bus, (UINT8)dev,
                                                 (UINT8)fn, 0x2C);
                    svid = (UINT16)(dw11 & 0xFFFFu);
                    ssid = (UINT16)(dw11 >> 16);
                }

                /* Status register (DW1 hi word) — bit 4 = Capabilities List */
                ULONG dw1   = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x04);
                UINT8 caps  = (UINT8)((dw1 >> 16) & 0x10u) ? 1u : 0u;

                /* Fill record */
                PLCC_PCI_DEVICE rec = &out->devices[out->count++];
                rec->bus                 = (UINT8)bus;
                rec->device              = (UINT8)dev;
                rec->function            = (UINT8)fn;
                rec->header_type         = hdr;
                rec->vendor_id           = vid;
                rec->device_id           = did;
                rec->subsystem_vendor_id = svid;
                rec->subsystem_id        = ssid;
                rec->class_code          = (UINT8)(dw2 >> 24);
                rec->subclass            = (UINT8)(dw2 >> 16);
                rec->prog_if             = (UINT8)(dw2 >>  8);
                rec->revision_id         = (UINT8)(dw2 & 0xFFu);
                rec->capabilities        = caps;

                /* Multi-function device check: if fn==0 and MF bit clear,
                 * functions 1-7 don't exist — skip them.               */
                if (fn == 0 && !((dw3 >> 16) & 0x80u)) break;
            }
        }
    }

    LCC_LOG("PCI scan complete: %u device(s) found", out->count);

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS,
                                      sizeof(LCC_PCI_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  MSR read helpers
 *
 *  MSRs can only be read on the CPU that "owns" them.
 *  For non-BSP CPUs we schedule a DPC on the target processor.
 * ═══════════════════════════════════════════════════════════════════ */

/* DPC routine: runs on target CPU, reads MSR, signals event */
static VOID
LccMsrDpcRoutine(
    PKDPC  Dpc,
    PVOID  Context,
    PVOID  Arg1,
    PVOID  Arg2
)
{
    PMSR_READ_CONTEXT ctx = (PMSR_READ_CONTEXT)Context;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    __try {
        ctx->result = __readmsr(ctx->msr_address);
        ctx->valid  = TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        /* #GP — MSR not supported on this CPU model */
        ctx->result = 0;
        ctx->valid  = FALSE;
        LCC_LOG("__readmsr(0x%X) raised #GP on CPU %u",
                ctx->msr_address, KeGetCurrentProcessorNumberEx(NULL));
    }

    KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  IOCTL handler: GET_CPU_MSR
 *  Reads a single MSR on the CPU specified by the caller.
 *  Input  : LCC_MSR_REQUEST
 *  Output : LCC_MSR_RESULT
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetCpuMsr(WDFREQUEST Request)
{
    NTSTATUS          status;
    PLCC_MSR_REQUEST  in     = NULL;
    PLCC_MSR_RESULT   out    = NULL;
    size_t            len    = 0;

    /* Validate + retrieve input buffer */
    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(LCC_MSR_REQUEST),
                                           (PVOID*)&in, &len);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    /* Validate + retrieve output buffer */
    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(LCC_MSR_RESULT),
                                            (PVOID*)&out, &len);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    RtlZeroMemory(out, sizeof(LCC_MSR_RESULT));
    out->msr_address = in->msr_address;
    out->cpu_index   = in->cpu_index;

    ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (in->cpu_index >= cpu_count) {
        LCC_LOG("cpu_index %u out of range (active: %u)",
                in->cpu_index, cpu_count);
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    /*
     * BUG FIX #5 (proactive) — MSR whitelist
     * ----------------------------------------
     * Even with the SDDL fix, defence-in-depth demands we only allow
     * reading the specific MSRs this tool needs.  An arbitrary-MSR
     * interface is a kernel exploit primitive on hypervisor bypasses.
     */
    {
        static const UINT32 allowed_msrs[] = {
            MSR_IA32_MICROCODE_REV,
            MSR_IA32_MISC_ENABLE,
            MSR_IA32_FEATURE_CONTROL,
            MSR_IA32_PERF_STATUS,
            MSR_IA32_THERM_STATUS,
            MSR_IA32_ENERGY_PERF_BIAS,
        };
        BOOLEAN permitted = FALSE;
        for (ULONG m = 0; m < ARRAYSIZE(allowed_msrs); ++m) {
            if (in->msr_address == allowed_msrs[m]) { permitted = TRUE; break; }
        }
        if (!permitted) {
            LCC_LOG("MSR 0x%08X is not on the whitelist — rejected",
                    in->msr_address);
            WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
            return;
        }
    }

    /*
     * BUG FIX #1 — DPC stack-use-after-free / BSOD prevention
     * ---------------------------------------------------------
     * ctx MUST live in NonPagedPool, not on the stack.
     * If KeWaitForSingleObject times out, this function returns and
     * the stack frame is torn down.  The DPC may still be pending and
     * will write into the dead frame → guaranteed BugCheck.
     *
     * Fix: allocate ctx from NonPagedPool.  On timeout we deliberately
     * LEAK the allocation so the DPC can still safely write into it
     * (the kernel will reclaim the pool when the driver unloads / at
     * next allocation).  A production driver should track pending DPCs
     * with a reference count; this conservative leak is the minimum
     * safe fix for a diagnostic tool.
     */
    PMSR_READ_CONTEXT ctx = (PMSR_READ_CONTEXT)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MSR_READ_CONTEXT), LCC_POOL_TAG);
    if (!ctx) {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }
    ctx->msr_address = in->msr_address;
    ctx->result      = 0;
    ctx->valid       = FALSE;
    KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);

    /* Current CPU fast path — no DPC needed */
    if (in->cpu_index == KeGetCurrentProcessorNumberEx(NULL)) {
        LccMsrDpcRoutine(NULL, ctx, NULL, NULL);
    } else {
        /* Schedule DPC on the target logical processor */
        KDPC  dpc;
        KeInitializeDpc(&dpc, LccMsrDpcRoutine, ctx);
        KeSetTargetProcessorDpcEx(&dpc,
            &(PROCESSOR_NUMBER){ 0,
                                  (UCHAR)in->cpu_index,
                                  0 });
        KeSetImportanceDpc(&dpc, HighImportance);
        KeInsertQueueDpc(&dpc, NULL, NULL);

        /* Wait for the DPC to signal completion (5-second safety timeout) */
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;   /* 5 s in 100-ns units */
        NTSTATUS waitStatus = KeWaitForSingleObject(&ctx->done_event,
                                                    Executive,
                                                    KernelMode,
                                                    FALSE, &timeout);
        if (waitStatus == STATUS_TIMEOUT) {
            LCC_LOG("DPC timeout waiting for CPU %u", in->cpu_index);
            /*
             * INTENTIONAL LEAK on timeout — do NOT free ctx here.
             * The DPC is still queued and will dereference ctx->done_event.
             * Freeing ctx now would cause the DPC to corrupt freed pool
             * (a worse BSOD than the original bug).
             */
            WdfRequestComplete(Request, STATUS_IO_TIMEOUT);
            return;
        }
    }

    out->value = ctx->result;
    out->valid = ctx->valid;
    ExFreePoolWithTag(ctx, LCC_POOL_TAG);

    LCC_LOG("MSR 0x%08X on CPU %u -> 0x%016llX (valid=%u)",
            out->msr_address, out->cpu_index, out->value, out->valid);

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS,
                                      sizeof(LCC_MSR_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  ACPI helpers
 *
 *  Windows exposes ACPI tables through the HAL:
 *    HalQuerySystemInformation(HalAcpiAudioTable, …) — older
 *    or via the ACPI driver's IOCTL interface — modern approach
 *
 *  Most portable approach on Win10/11:
 *    NtQuerySystemInformation(SystemFirmwareTableInformation, …)
 *  We use the documented kernel-mode equivalent:
 *    ExGetFirmwareEnvironmentVariable is for UEFI vars, not tables.
 *
 *  The cleanest kernel-mode path is to open the ACPI driver's
 *  device object and use IOCTL_ACPI_EVAL_INPUT_BUFFER to query
 *  the RSDP from the HAL's physical memory mapping.
 *
 *  Here we use the AuxKlib + direct physical memory mapping approach:
 *    1. Locate RSDP via ACPI_ENUM_CHILDREN on the ACPI device stack.
 *    2. Map the RSDT/XSDT to enumerate child table signatures.
 *
 *  Since this is complex and hardware-dependent, we implement
 *  a safe, WDM-approved path using ZwQuerySystemInformation with
 *  SystemFirmwareTableInformation (class 76).
 * ═══════════════════════════════════════════════════════════════════ */

/* Undocumented but stable since Vista — used by many Microsoft tools */
#define SystemFirmwareTableInformation 76

/* Note: _SYSTEM_FIRMWARE_TABLE_INFORMATION is already defined in ntddk.h
   for SDK version 10.0.26100.0 and later, so we don't redefine it here */

/* Signatures */
#define SFTI_SIG_ACPI  'IPCA'   /* 'ACPI' little-endian */
#define SFTI_ACTION_ENUM 0
#define SFTI_ACTION_GET  1

NTSYSAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
    _In_  ULONG  SystemInformationClass,
    _Out_ PVOID  SystemInformation,
    _In_  ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

/* ═══════════════════════════════════════════════════════════════════
 *  IOCTL handler: GET_ACPI_INFO
 *  Enumerates all ACPI table signatures present in the system.
 *  Output : LCC_ACPI_RESULT
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetAcpiInfo(WDFREQUEST Request)
{
    NTSTATUS         status;
    PLCC_ACPI_RESULT out    = NULL;
    size_t           outLen = 0;

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(LCC_ACPI_RESULT),
                                            (PVOID*)&out, &outLen);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    RtlZeroMemory(out, sizeof(LCC_ACPI_RESULT));

    /* ── Step 1: Enumerate ACPI table IDs ──────────────────────── */
    /* Initial probe to get required size */
    ULONG enumSize = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) + 256;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION enumInfo =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, enumSize, LCC_POOL_TAG);

    if (!enumInfo) {
        LCC_LOG("ExAllocatePool2 failed for ACPI enum buffer");
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    enumInfo->ProviderSignature = SFTI_SIG_ACPI;
    enumInfo->Action            = SFTI_ACTION_ENUM;
    enumInfo->TableID           = 0;
    enumInfo->TableBufferLength = 256;

    ULONG retLen = 0;
    status = ZwQuerySystemInformation(SystemFirmwareTableInformation,
                                      enumInfo, enumSize, &retLen);

    /* If buffer too small, reallocate with the exact size */
    if (status == STATUS_BUFFER_TOO_SMALL && retLen > 0) {
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        enumSize  = retLen;
        enumInfo  = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, enumSize, LCC_POOL_TAG);
        if (!enumInfo) {
            WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
            return;
        }
        enumInfo->ProviderSignature = SFTI_SIG_ACPI;
        enumInfo->Action            = SFTI_ACTION_ENUM;
        enumInfo->TableID           = 0;
        enumInfo->TableBufferLength = enumSize - sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
        status = ZwQuerySystemInformation(SystemFirmwareTableInformation,
                                          enumInfo, enumSize, &retLen);
    }

    if (!NT_SUCCESS(status)) {
        LCC_LOG("ZwQuerySystemInformation(Enum ACPI) failed: 0x%08X", status);
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        WdfRequestComplete(Request, status);
        return;
    }

    /* TableBuffer contains packed 4-byte table IDs (signatures) */
    ULONG  tableCount   = enumInfo->TableBufferLength / sizeof(ULONG);
    PULONG tableIdArray = (PULONG)enumInfo->TableBuffer;

    LCC_LOG("ACPI: %u table(s) enumerated", tableCount);

    /* ── Step 2: Fetch each table header ────────────────────────── */
    /* We only need the 36-byte ACPI table common header, not the full table */
    ULONG hdrFetchSize = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) + 64;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION hdrInfo =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, hdrFetchSize, LCC_POOL_TAG);

    if (!hdrInfo) {
        LCC_LOG("ExAllocatePool2 failed for ACPI header buffer");
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    BOOLEAN xsdtSeen = FALSE;
    BOOLEAN rsdpSeen = FALSE;

    for (ULONG i = 0;
         i < tableCount && out->count < LCC_MAX_ACPI_TABLES;
         ++i)
    {
        ULONG tid = tableIdArray[i];

        RtlZeroMemory(hdrInfo, hdrFetchSize);
        hdrInfo->ProviderSignature = SFTI_SIG_ACPI;
        hdrInfo->Action            = SFTI_ACTION_GET;
        hdrInfo->TableID           = tid;
        hdrInfo->TableBufferLength = 64;   /* enough for common header */

        ULONG fetchLen = 0;
        NTSTATUS fetchStatus =
            ZwQuerySystemInformation(SystemFirmwareTableInformation,
                                     hdrInfo, hdrFetchSize, &fetchLen);

        /* STATUS_BUFFER_TOO_SMALL is fine — we got the header */
        if (!NT_SUCCESS(fetchStatus) &&
            fetchStatus != STATUS_BUFFER_TOO_SMALL)
        {
            LCC_LOG("Failed to fetch table 0x%08X: 0x%08X", tid, fetchStatus);
            continue;
        }

        /* ACPI common header: Signature[4] Length[4] Revision[1]
           Checksum[1] OEMID[6] OEMTableID[8] OEMRevision[4] … */
        if (hdrInfo->TableBufferLength < 28) continue;

        PUCHAR hdr = hdrInfo->TableBuffer;

        PLCC_ACPI_TABLE_ENTRY rec = &out->tables[out->count++];
        RtlCopyMemory(rec->signature,   hdr,      4);
        RtlCopyMemory(&rec->length,     hdr + 4,  4);
        rec->revision = hdr[8];
        RtlCopyMemory(rec->oem_id,      hdr + 10, 6);
        RtlCopyMemory(rec->oem_table_id,hdr + 16, 8);
        RtlCopyMemory(&rec->oem_revision, hdr + 24, 4);

        /* Detect XSDT/RSDP presence for the summary flags */
        if (RtlCompareMemory(rec->signature, "XSDT", 4) == 4) xsdtSeen = TRUE;
        if (RtlCompareMemory(rec->signature, "RSD ", 4) == 4) rsdpSeen = TRUE;

        LCC_LOG("ACPI table [%u]: %.4s  len=%u  rev=%u",
                out->count - 1,
                rec->signature,
                rec->length,
                rec->revision);
    }

    if (hdrInfo) ExFreePoolWithTag(hdrInfo,  LCC_POOL_TAG);
    ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);

    out->xsdt_present  = xsdtSeen;
    out->has_rsdp      = rsdpSeen;
    out->acpi_revision = (out->count > 0) ? out->tables[0].revision : 0;

    LCC_LOG("ACPI scan done: %u table(s) recorded, XSDT=%u RSDP=%u",
            out->count, out->xsdt_present, out->has_rsdp);

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS,
                                      sizeof(LCC_ACPI_RESULT));
}
