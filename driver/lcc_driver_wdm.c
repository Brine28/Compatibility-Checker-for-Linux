/*
 * lcc_driver.c  —  Linux Compat Checker Kernel-Mode Driver (Pure WDM)
 * =====================================================================
 * Saf WDM driver — KMDF/WDF bağımlılığı yok.
 * DriverEntry → IoCreateDevice → IoCreateSymbolicLink → IRP_MJ_DEVICE_CONTROL
 */

#include <ntddk.h>
#include <wdm.h>
#include "lcc_shared.h"

/* ─── Pool tag & log ─────────────────────────────────────────────── */
#define LCC_POOL_TAG  'rccL'
#define LCC_LOG(fmt, ...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "[LccDriver] " fmt "\n", ##__VA_ARGS__))

/* ─── Globals ────────────────────────────────────────────────────── */
static PDEVICE_OBJECT g_DeviceObject = NULL;
static KSPIN_LOCK     g_PciPortLock;

/* ─── DPC context for cross-CPU MSR reads ────────────────────────── */
typedef struct _MSR_READ_CONTEXT {
    UINT32  msr_address;
    UINT64  result;
    BOOLEAN valid;
    KEVENT  done_event;
    KDPC    dpc;
} MSR_READ_CONTEXT, *PMSR_READ_CONTEXT;

/* ─── Forward declarations ───────────────────────────────────────── */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     LccDriverUnload;

static NTSTATUS LccDispatchCreate  (PDEVICE_OBJECT DevObj, PIRP Irp);
static NTSTATUS LccDispatchClose   (PDEVICE_OBJECT DevObj, PIRP Irp);
static NTSTATUS LccDispatchControl (PDEVICE_OBJECT DevObj, PIRP Irp);

static VOID LccHandleGetVersion    (PIRP Irp, PIO_STACK_LOCATION Stack);
static VOID LccHandleGetPciDevices (PIRP Irp, PIO_STACK_LOCATION Stack);
static VOID LccHandleGetCpuMsr     (PIRP Irp, PIO_STACK_LOCATION Stack);
static VOID LccHandleGetAcpiInfo   (PIRP Irp, PIO_STACK_LOCATION Stack);
static VOID LccMsrDpcRoutine       (PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2);

/* ═══════════════════════════════════════════════════════════════════
 *  DriverEntry
 * ═══════════════════════════════════════════════════════════════════ */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS       status;
    UNICODE_STRING devName, symLink;

    UNREFERENCED_PARAMETER(RegistryPath);

    LCC_LOG("DriverEntry v%u.%u",
            (LCC_DRIVER_VERSION >> 8) & 0xFF,
             LCC_DRIVER_VERSION       & 0xFF);

    KeInitializeSpinLock(&g_PciPortLock);

    RtlInitUnicodeString(&devName,  LCC_DEVICE_NAME);
    RtlInitUnicodeString(&symLink,  LCC_SYMLINK_NAME);

    /* Create device — DO_BUFFERED_IO so kernel copies buffers for us */
    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        LCC_LOG("IoCreateDevice failed: 0x%08X", status);
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        LCC_LOG("IoCreateSymbolicLink failed: 0x%08X", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    /* Set dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = LccDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = LccDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LccDispatchControl;
    DriverObject->DriverUnload                         = LccDriverUnload;

    LCC_LOG("Device ready: %wZ -> %wZ", &devName, &symLink);
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════
 *  DriverUnload — cleanup
 * ═══════════════════════════════════════════════════════════════════ */
VOID
LccDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    UNREFERENCED_PARAMETER(DriverObject);

    RtlInitUnicodeString(&symLink, LCC_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    LCC_LOG("Driver unloaded");
}

/* ─── Simple IRP handlers ────────────────────────────────────────── */
static NTSTATUS
LccDispatchCreate(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
LccDispatchClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════
 *  IOCTL Dispatcher
 * ═══════════════════════════════════════════════════════════════════ */
static NTSTATUS
LccDispatchControl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

    UNREFERENCED_PARAMETER(DevObj);

    switch (ioctl) {
    case IOCTL_LCC_GET_VERSION:
        LccHandleGetVersion(Irp, stack);
        break;
    case IOCTL_LCC_GET_PCI_DEVICES:
        LccHandleGetPciDevices(Irp, stack);
        break;
    case IOCTL_LCC_GET_CPU_MSR:
        LccHandleGetCpuMsr(Irp, stack);
        break;
    case IOCTL_LCC_GET_ACPI_INFO:
        LccHandleGetAcpiInfo(Irp, stack);
        break;
    default:
        LCC_LOG("Unknown IOCTL: 0x%08X", ioctl);
        Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

    return Irp->IoStatus.Status;
}

/* ─── Helper: complete IRP with status and byte count ─────────────── */
static FORCEINLINE VOID
LccCompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_VERSION
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetVersion(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLen < sizeof(LCC_VERSION_RESULT)) {
        LccCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }

    /* DO_BUFFERED_IO: output buffer is at Irp->AssociatedIrp.SystemBuffer */
    PLCC_VERSION_RESULT out = (PLCC_VERSION_RESULT)Irp->AssociatedIrp.SystemBuffer;
    out->driver_version = LCC_DRIVER_VERSION;
    out->_pad           = 0;

    LccCompleteIrp(Irp, STATUS_SUCCESS, sizeof(LCC_VERSION_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  PCI helpers
 * ═══════════════════════════════════════════════════════════════════ */
static FORCEINLINE ULONG
LccPciMakeAddress(UINT8 bus, UINT8 dev, UINT8 fn, UINT8 reg)
{
    return (ULONG)(0x80000000UL
                 | ((ULONG)bus << 16)
                 | ((ULONG)dev << 11)
                 | ((ULONG)fn  <<  8)
                 | ((ULONG)reg &  0xFCu));
}

static ULONG
LccPciReadDword(UINT8 bus, UINT8 dev, UINT8 fn, UINT8 reg)
{
    ULONG  address = LccPciMakeAddress(bus, dev, fn, reg);
    KIRQL  oldIrql;
    ULONG  value;

    KeAcquireSpinLock(&g_PciPortLock, &oldIrql);
    WRITE_PORT_ULONG((PULONG)(ULONG_PTR)0xCF8, address);
    value = READ_PORT_ULONG((PULONG)(ULONG_PTR)0xCFC);
    KeReleaseSpinLock(&g_PciPortLock, oldIrql);

    return value;
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_PCI_DEVICES
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetPciDevices(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLen < sizeof(LCC_PCI_RESULT)) {
        LccCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }

    PLCC_PCI_RESULT out = (PLCC_PCI_RESULT)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(out, sizeof(LCC_PCI_RESULT));

    for (UINT32 bus = 0; bus < 256 && out->count < LCC_MAX_PCI_DEVICES; ++bus) {
        for (UINT32 dev = 0; dev < 32 && out->count < LCC_MAX_PCI_DEVICES; ++dev) {
            for (UINT32 fn = 0; fn < 8 && out->count < LCC_MAX_PCI_DEVICES; ++fn) {

                ULONG  dw0 = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x00);
                UINT16 vid = (UINT16)(dw0 & 0xFFFFu);

                if (vid == 0xFFFF) { if (fn == 0) break; continue; }

                UINT16 did  = (UINT16)(dw0 >> 16);
                ULONG  dw2  = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x08);
                ULONG  dw3  = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x0C);
                UINT8  hdr  = (UINT8)((dw3 >> 16) & 0x7Fu);
                UINT16 svid = 0, ssid = 0;

                if (hdr == 0) {
                    ULONG dw11 = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x2C);
                    svid = (UINT16)(dw11 & 0xFFFFu);
                    ssid = (UINT16)(dw11 >> 16);
                }

                ULONG dw1  = LccPciReadDword((UINT8)bus, (UINT8)dev, (UINT8)fn, 0x04);
                UINT8 caps = ((dw1 >> 16) & 0x10u) ? 1u : 0u;

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

                if (fn == 0 && !((dw3 >> 16) & 0x80u)) break;
            }
        }
    }

    LCC_LOG("PCI scan: %u device(s)", out->count);
    LccCompleteIrp(Irp, STATUS_SUCCESS, sizeof(LCC_PCI_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  MSR helpers
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccMsrDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    PMSR_READ_CONTEXT ctx = (PMSR_READ_CONTEXT)Context;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    __try {
        ctx->result = __readmsr(ctx->msr_address);
        ctx->valid  = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ctx->result = 0;
        ctx->valid  = FALSE;
    }

    KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_CPU_MSR
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetCpuMsr(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    ULONG inLen  = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inLen < sizeof(LCC_MSR_REQUEST) || outLen < sizeof(LCC_MSR_RESULT)) {
        LccCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }

    PLCC_MSR_REQUEST in  = (PLCC_MSR_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    PLCC_MSR_RESULT  out = (PLCC_MSR_RESULT) Irp->AssociatedIrp.SystemBuffer;

    /* MSR whitelist */
    static const UINT32 allowed_msrs[] = {
        MSR_IA32_MICROCODE_REV,
        MSR_IA32_MISC_ENABLE,
        MSR_IA32_FEATURE_CONTROL,
        MSR_IA32_PERF_STATUS,
        MSR_IA32_THERM_STATUS,
        MSR_IA32_ENERGY_PERF_BIAS,
    };
    BOOLEAN permitted = FALSE;
    UINT32  msr_addr  = in->msr_address;
    UINT32  cpu_idx   = in->cpu_index;

    for (ULONG m = 0; m < ARRAYSIZE(allowed_msrs); ++m) {
        if (msr_addr == allowed_msrs[m]) { permitted = TRUE; break; }
    }
    if (!permitted) {
        LccCompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
        return;
    }

    ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (cpu_idx >= cpu_count) {
        LccCompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
        return;
    }

    PMSR_READ_CONTEXT ctx = (PMSR_READ_CONTEXT)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MSR_READ_CONTEXT), LCC_POOL_TAG);
    if (!ctx) {
        LccCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return;
    }

    ctx->msr_address = msr_addr;
    ctx->result      = 0;
    ctx->valid       = FALSE;
    KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);

    if (cpu_idx == KeGetCurrentProcessorNumberEx(NULL)) {
        LccMsrDpcRoutine(NULL, ctx, NULL, NULL);
    } else {
        KeInitializeDpc(&ctx->dpc, LccMsrDpcRoutine, ctx);
        KeSetTargetProcessorDpcEx(&ctx->dpc,
            &(PROCESSOR_NUMBER){ 0, (UCHAR)cpu_idx, 0 });
        KeSetImportanceDpc(&ctx->dpc, HighImportance);
        KeInsertQueueDpc(&ctx->dpc, NULL, NULL);

        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;
        NTSTATUS ws = KeWaitForSingleObject(&ctx->done_event,
                                            Executive, KernelMode, FALSE, &timeout);
        if (ws == STATUS_TIMEOUT) {
            LCC_LOG("DPC timeout CPU %u", cpu_idx);
            /* intentional leak on timeout */
            LccCompleteIrp(Irp, STATUS_IO_TIMEOUT, 0);
            return;
        }
    }

    /* Write result back — reuse SystemBuffer (buffered I/O) */
    LCC_MSR_RESULT result;
    result.msr_address = msr_addr;
    result.cpu_index   = cpu_idx;
    result.value       = ctx->result;
    result.valid       = ctx->valid;
    RtlZeroMemory(result._pad, sizeof(result._pad));
    RtlCopyMemory(out, &result, sizeof(result));

    ExFreePoolWithTag(ctx, LCC_POOL_TAG);
    LccCompleteIrp(Irp, STATUS_SUCCESS, sizeof(LCC_MSR_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_ACPI_INFO
 * ═══════════════════════════════════════════════════════════════════ */
#define SystemFirmwareTableInformation 76
#define SFTI_SIG_ACPI  'IPCA'
#define SFTI_ACTION_ENUM 0
#define SFTI_ACTION_GET  1

NTSYSAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
    _In_      ULONG  SystemInformationClass,
    _Out_     PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

static VOID
LccHandleGetAcpiInfo(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLen < sizeof(LCC_ACPI_RESULT)) {
        LccCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }

    PLCC_ACPI_RESULT out = (PLCC_ACPI_RESULT)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(out, sizeof(LCC_ACPI_RESULT));

    ULONG enumSize = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) + 256;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION enumInfo =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, enumSize, LCC_POOL_TAG);

    if (!enumInfo) {
        LccCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return;
    }

    enumInfo->ProviderSignature = SFTI_SIG_ACPI;
    enumInfo->Action            = SFTI_ACTION_ENUM;
    enumInfo->TableID           = 0;
    enumInfo->TableBufferLength = 256;

    ULONG    retLen = 0;
    NTSTATUS status = ZwQuerySystemInformation(
        SystemFirmwareTableInformation, enumInfo, enumSize, &retLen);

    if (status == STATUS_BUFFER_TOO_SMALL && retLen > 0) {
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        enumSize = retLen;
        enumInfo = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
                   ExAllocatePool2(POOL_FLAG_NON_PAGED, enumSize, LCC_POOL_TAG);
        if (!enumInfo) {
            LccCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
            return;
        }
        enumInfo->ProviderSignature = SFTI_SIG_ACPI;
        enumInfo->Action            = SFTI_ACTION_ENUM;
        enumInfo->TableID           = 0;
        enumInfo->TableBufferLength = enumSize - sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
        status = ZwQuerySystemInformation(
            SystemFirmwareTableInformation, enumInfo, enumSize, &retLen);
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        LccCompleteIrp(Irp, status, 0);
        return;
    }

    ULONG  tableCount   = enumInfo->TableBufferLength / sizeof(ULONG);
    PULONG tableIdArray = (PULONG)enumInfo->TableBuffer;

    ULONG hdrFetchSize = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) + 64;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION hdrInfo =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, hdrFetchSize, LCC_POOL_TAG);

    if (!hdrInfo) {
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        LccCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return;
    }

    BOOLEAN xsdtSeen = FALSE, rsdpSeen = FALSE;

    for (ULONG i = 0; i < tableCount && out->count < LCC_MAX_ACPI_TABLES; ++i) {
        ULONG tid = tableIdArray[i];

        RtlZeroMemory(hdrInfo, hdrFetchSize);
        hdrInfo->ProviderSignature = SFTI_SIG_ACPI;
        hdrInfo->Action            = SFTI_ACTION_GET;
        hdrInfo->TableID           = tid;
        hdrInfo->TableBufferLength = 64;

        ULONG    fetchLen    = 0;
        NTSTATUS fetchStatus = ZwQuerySystemInformation(
            SystemFirmwareTableInformation, hdrInfo, hdrFetchSize, &fetchLen);

        if (!NT_SUCCESS(fetchStatus) && fetchStatus != STATUS_BUFFER_TOO_SMALL)
            continue;

        ULONG dataAvail = (fetchLen > (ULONG)sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION))
                          ? fetchLen - (ULONG)sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION)
                          : 0;
        if (dataAvail < 28) continue;

        PUCHAR hdr = hdrInfo->TableBuffer;
        PLCC_ACPI_TABLE_ENTRY rec = &out->tables[out->count++];
        RtlCopyMemory(rec->signature,      hdr,      4);
        RtlCopyMemory(&rec->length,        hdr + 4,  4);
        rec->revision = hdr[8];
        RtlCopyMemory(rec->oem_id,         hdr + 10, 6);
        RtlCopyMemory(rec->oem_table_id,   hdr + 16, 8);
        RtlCopyMemory(&rec->oem_revision,  hdr + 24, 4);

        if (RtlCompareMemory(rec->signature, "XSDT", 4) == 4) xsdtSeen = TRUE;
        if (RtlCompareMemory(rec->signature, "RSD ", 4) == 4) rsdpSeen = TRUE;
    }

    ExFreePoolWithTag(hdrInfo,  LCC_POOL_TAG);
    ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);

    out->xsdt_present  = xsdtSeen;
    out->has_rsdp      = rsdpSeen;
    out->acpi_revision = (out->count > 0) ? out->tables[0].revision : 0;

    LCC_LOG("ACPI: %u tables, XSDT=%u RSDP=%u", out->count, xsdtSeen, rsdpSeen);
    LccCompleteIrp(Irp, STATUS_SUCCESS, sizeof(LCC_ACPI_RESULT));
}
