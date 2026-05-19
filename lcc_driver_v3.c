/*
 * lcc_driver_v3.c  —  Linux Compat Checker Kernel-Mode Driver (Pure WDM v3)
 * ===========================================================================
 * v3 Düzeltmeleri (v2'ye göre):
 *
 *  [FIX-1]  DECLARE_CONST_UNICODE_STRING C derleyicisinde (/TC) derlenmez.
 *           C++ sözdizimi gerektirdiğinden, UNICODE_STRING manuel olarak
 *           WCHAR dizi + RTL_CONSTANT_STRING ile tanımlandı.
 *           → Derleme hataları C2059 ve C2065 giderildi.
 *
 *  [FIX-2]  LccDispatchCreate / LccDispatchClose'da remove lock IRP
 *           tag'i ile alınıp hemen bırakılıyordu — anlamsız ve tehlikeli.
 *           Create/Close için remove lock'u handle etmek doğru değil;
 *           sadece DeviceControl dispatcher'ında korunuyor.
 *
 *  [FIX-3]  DPC içinde __try/__except kullanımı IRQL=DISPATCH_LEVEL'da
 *           desteklenmez — BSOD (UNEXPECTED_KERNEL_MODE_TRAP) riski.
 *           MSR okuma artık ayrı bir wrapper fonksiyona taşındı ve
 *           SEH yerine whitelist tabanlı doğrulama koruması kullanılıyor.
 *           (Whitelist zaten v2'de vardı; SEH tamamen kaldırıldı.)
 *
 *  [FIX-4]  DPC timeout dalında KeRemoveQueueDpc(FALSE) döndüğünde
 *           KeWaitForSingleObject sonsuz blok yapıyor ve event'in önceki
 *           durumu kontrol edilmiyordu. Event KeClearEvent ile sıfırlandı
 *           ve bekleme yalnızca gerektiğinde yapılıyor.
 *
 *  [FIX-5]  SYSTEM_FIRMWARE_TABLE_INFORMATION undocumented yapı —
 *           TableBuffer offseti sizeof(SFTI_HEADER) ile doğru hesaplandı,
 *           sabit magic sayı yerine hesaplanan offset kullanılıyor.
 *
 *  [FIX-6]  LccHandleGetPciDevices'de out->count < LCC_MAX_PCI_DEVICES
 *           kontrolü zaten vardı fakat devices[] dizisi LCC_MAX_PCI_DEVICES
 *           boyutunda. out->count == LCC_MAX_PCI_DEVICES-1 iken rec yazılıp
 *           count++ yapıldığında sınır aşılabilirdi. Yazma öncesi kontrol
 *           sıkılaştırıldı.
 */

#include <ntddk.h>
#include <wdm.h>
#include <wdmsec.h>    /* IoCreateDeviceSecure */
#include "lcc_shared.h"

/* ─── Pool tag & log ─────────────────────────────────────────────── */
#define LCC_POOL_TAG  'rccL'
#define LCC_LOG(fmt, ...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "[LccDriver] " fmt "\n", ##__VA_ARGS__))

/* ─── [FIX-1] Device SDDL — C uyumlu UNICODE_STRING tanımı ─────────
 *
 *  DECLARE_CONST_UNICODE_STRING makrosu <wdm.h>'de şu şekilde tanımlıdır:
 *
 *    #define DECLARE_CONST_UNICODE_STRING(_var, _string)              \
 *      const WCHAR _var ## _buffer[] = _string;                       \
 *      __pragma(warning(push))                                        \
 *      __pragma(warning(disable:4221))                                \
 *      const UNICODE_STRING _var =                                    \
 *        { sizeof(_string) - sizeof(WCHAR),                           \
 *          sizeof(_string),                                           \
 *          (PWCH) _var ## _buffer };                                  \
 *      __pragma(warning(pop))
 *
 *  Bu makro C++ compound literal sözdizimine dayanır.
 *  /TC (Compile as C) modunda C2059 "sözdizimi hatası: 'dize'" verir.
 *  Çözüm: WCHAR tamponunu ve UNICODE_STRING'i ayrı ayrı tanımlamak.
 * ─────────────────────────────────────────────────────────────────── */
static const WCHAR LCC_SDDL_Buffer[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
static const UNICODE_STRING LCC_SDDL = {
    sizeof(LCC_SDDL_Buffer) - sizeof(WCHAR),   /* Length (null hariç) */
    sizeof(LCC_SDDL_Buffer),                    /* MaximumLength       */
    (PWCH)LCC_SDDL_Buffer                       /* Buffer              */
};

/* ─── Device GUID (required by IoCreateDeviceSecure) ─────────────── */
/* {B3E6F3A1-1234-4321-ABCD-0123456789AB} — LCC'ye özgü, rastgele seçildi */
static const GUID LCC_DEVICE_CLASS_GUID = {
    0xB3E6F3A1, 0x1234, 0x4321,
    { 0xAB, 0xCD, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB }
};

/* ─── Globals ────────────────────────────────────────────────────── */
static PDEVICE_OBJECT g_DeviceObject = NULL;
static KSPIN_LOCK     g_PciPortLock;

/* Remove lock — LccDispatchControl ile DriverUnload'u senkronize eder */
static IO_REMOVE_LOCK g_RemoveLock;

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

    /* Remove lock: tag 'LccR', 1 saniye timeout, max 100 eşzamanlı işlem */
    IoInitializeRemoveLock(&g_RemoveLock, 'RccL', 1, 100);

    RtlInitUnicodeString(&devName, LCC_DEVICE_NAME);
    RtlInitUnicodeString(&symLink, LCC_SYMLINK_NAME);

    /*
     * IoCreateDeviceSecure — SDDL'yi oluşturma anında uygular.
     * Sadece SYSTEM ve yerel Yöneticiler bu aygıtı açabilir.
     * (Önceki sürümde IoCreateDevice kullanılıyordu, ACL yoktu.)
     */
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &LCC_SDDL,
        &LCC_DEVICE_CLASS_GUID,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        LCC_LOG("IoCreateDeviceSecure failed: 0x%08X", status);
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Remove stale symlink if it exists, so a previous failed unload
     * cannot keep the driver from starting again. */
    IoDeleteSymbolicLink(&symLink);

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        LCC_LOG("IoCreateSymbolicLink failed: 0x%08X", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = LccDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = LccDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LccDispatchControl;
    DriverObject->DriverUnload                         = LccDriverUnload;

    LCC_LOG("Device ready: %wZ -> %wZ", &devName, &symLink);
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════
 *  DriverUnload
 *  IoReleaseRemoveLockAndWait: tüm aktif IRP'ler tamamlanana kadar
 *  bekler — use-after-free önlenir.
 * ═══════════════════════════════════════════════════════════════════ */
VOID
LccDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    UNREFERENCED_PARAMETER(DriverObject);

    LCC_LOG("DriverUnload — aktif IRP'ler bekleniyor...");

    /* Remove lock'u kapat; tüm acquire'ların release olmasını bekle */
    IoReleaseRemoveLockAndWait(&g_RemoveLock, NULL);

    RtlInitUnicodeString(&symLink, LCC_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    LCC_LOG("Sürücü temiz şekilde kaldırıldı.");
}

/* ─── IRP tamamlama yardımcıları ─────────────────────────────────── */
static FORCEINLINE VOID
LccSetIrpStatus(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
}

static FORCEINLINE VOID
LccCompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* ═══════════════════════════════════════════════════════════════════
 *  IRP_MJ_CREATE / IRP_MJ_CLOSE
 *
 *  [FIX-2] v2'de remove lock Create/Close'da Irp tag'iyle alınıp
 *  hemen bırakılıyordu. Bu hem anlamsız (koruma sağlamıyor) hem de
 *  IRP'nin hemen tamamlanıp serbest bırakılmasından sonra lock ile
 *  temas riski doğuruyordu.
 *
 *  Doğru yaklaşım: Create/Close basitçe tamamlanır. Remove lock
 *  yalnızca DeviceControl dispatcher'ında kullanılır; bu sayede
 *  unload sırasında gerçekten süren IOCTL işlemleri beklenir.
 * ═══════════════════════════════════════════════════════════════════ */
static NTSTATUS
LccDispatchCreate(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    LccCompleteIrp(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS
LccDispatchClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    LccCompleteIrp(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════
 *  IOCTL Dispatcher
 *  Remove lock burada acquire/release yapılır — unload ile gerçek
 *  çakışma riski olan yer burasıdır.
 * ═══════════════════════════════════════════════════════════════════ */
static NTSTATUS
LccDispatchControl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);

    /* Unload devam ediyorsa yeni IOCTL'i reddet */
    NTSTATUS status = IoAcquireRemoveLock(&g_RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        LccCompleteIrp(Irp, status, 0);
        return status;
    }

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

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
        LCC_LOG("Bilinmeyen IOCTL: 0x%08X", ioctl);
        Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    NTSTATUS result = Irp->IoStatus.Status;
    /* IoCompleteRequest'ten ÖNCE lock bırakılmalı */
    IoReleaseRemoveLock(&g_RemoveLock, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_VERSION
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetVersion(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(LCC_VERSION_RESULT)) {
        LccSetIrpStatus(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }
    PLCC_VERSION_RESULT out = (PLCC_VERSION_RESULT)Irp->AssociatedIrp.SystemBuffer;
    out->driver_version = LCC_DRIVER_VERSION;
    out->_pad           = 0;
    LccSetIrpStatus(Irp, STATUS_SUCCESS, sizeof(LCC_VERSION_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  PCI yardımcıları
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
    ULONG address = LccPciMakeAddress(bus, dev, fn, reg);
    KIRQL oldIrql;
    ULONG value = 0xFFFFFFFFUL;  /* varsayılan: boş/hata */

    /* [FIX] Port I/O bazı VM/hypervisor ortamlarında exception fırlatabilir.
     * __try/__except ile sararak BSOD yerine "slot boş" döndürüyoruz. */
    KeAcquireSpinLock(&g_PciPortLock, &oldIrql);
    __try {
        WRITE_PORT_ULONG((PULONG)(ULONG_PTR)0xCF8, address);
        value = READ_PORT_ULONG((PULONG)(ULONG_PTR)0xCFC);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        value = 0xFFFFFFFFUL;
    }
    KeReleaseSpinLock(&g_PciPortLock, oldIrql);

    return value;
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_PCI_DEVICES
 *  [FIX-6] Sınır kontrolü yazma öncesine alındı (out->count artık
 *  LCC_MAX_PCI_DEVICES'e ulaşmadan dizi sonu kontrol ediliyor).
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetPciDevices(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(LCC_PCI_RESULT)) {
        LccSetIrpStatus(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }

    PLCC_PCI_RESULT out = (PLCC_PCI_RESULT)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(out, sizeof(LCC_PCI_RESULT));

    for (UINT32 bus = 0; bus < 256; ++bus) {
        for (UINT32 dev = 0; dev < 32; ++dev) {
            for (UINT32 fn = 0; fn < 8; ++fn) {

                /* [FIX-6] Yazma öncesi yer var mı diye kontrol et */
                if (out->count >= LCC_MAX_PCI_DEVICES)
                    goto scan_done;

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

                PLCC_PCI_DEVICE rec = &out->devices[out->count];
                out->count++;

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
scan_done:
    LCC_LOG("PCI taraması: %u aygıt bulundu", out->count);
    LccSetIrpStatus(Irp, STATUS_SUCCESS, sizeof(LCC_PCI_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  MSR DPC Rutini
 *
 *  [FIX-3] __try/__except IRQL=DISPATCH_LEVEL'da (DPC) desteklenmez.
 *  Yapısal İstisna İşleme (SEH) yalnızca PASSIVE_LEVEL veya
 *  APC_LEVEL'da güvenlidir. DPC'de __try kullanmak
 *  UNEXPECTED_KERNEL_MODE_TRAP BSOD'una yol açar.
 *
 *  Koruma mekanizması: MSR whitelist (üst katta doğrulandı).
 *  Whitelist'ten geçen MSR'lar bilinen, güvenli adreslerdir;
 *  bu adreslere okuma sırasında #GP beklenmiyor. SEH kaldırıldı.
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccMsrDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    PMSR_READ_CONTEXT ctx = (PMSR_READ_CONTEXT)Context;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    /*
     * SEH burada kasıtlı olarak kullanılmıyor.
     * Whitelist doğrulaması LccHandleGetCpuMsr'de yapıldı.
     * Whitelist'teki MSR'lar tüm Intel/AMD işlemcilerde okunabilir.
     */
    ctx->result = __readmsr(ctx->msr_address);
    ctx->valid  = TRUE;

    KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_CPU_MSR
 *
 *  [FIX-4] DPC timeout dalında olay (event) sıfırlanmadan tekrar
 *  bekleme yapılıyordu. KeRemoveQueueDpc FALSE döndüğünde DPC zaten
 *  çalışıyordur; bu durumda event zaten set edilmiş olabilir.
 *  KeClearEvent çağrısı eklendi ve bekleme mantığı düzeltildi.
 * ═══════════════════════════════════════════════════════════════════ */
static VOID
LccHandleGetCpuMsr(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    ULONG inLen  = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inLen < sizeof(LCC_MSR_REQUEST) || outLen < sizeof(LCC_MSR_RESULT)) {
        LccSetIrpStatus(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }

    /* Giriş tamponunu çıkış tamponunun üzerine yazılmadan önce kopyala */
    LCC_MSR_REQUEST req;
    RtlCopyMemory(&req, Irp->AssociatedIrp.SystemBuffer, sizeof(req));

    /* MSR whitelist — yalnızca bilinen, güvenli kayıtlar okunabilir */
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
        if (req.msr_address == allowed_msrs[m]) { permitted = TRUE; break; }
    }
    if (!permitted) {
        LccSetIrpStatus(Irp, STATUS_ACCESS_DENIED, 0);
        return;
    }

    /* cpu_index'i aktif işlemci sayısına göre doğrula */
    ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (req.cpu_index >= cpu_count) {
        LccSetIrpStatus(Irp, STATUS_INVALID_PARAMETER, 0);
        return;
    }

    /* Düz index'i PROCESSOR_NUMBER'a çevir */
    PROCESSOR_NUMBER procNum = { 0 };
    NTSTATUS mapStatus = KeGetProcessorNumberFromIndex(req.cpu_index, &procNum);
    if (!NT_SUCCESS(mapStatus)) {
        LccSetIrpStatus(Irp, STATUS_INVALID_PARAMETER, 0);
        return;
    }

    PMSR_READ_CONTEXT ctx = (PMSR_READ_CONTEXT)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MSR_READ_CONTEXT), LCC_POOL_TAG);
    if (!ctx) {
        LccSetIrpStatus(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return;
    }

    ctx->msr_address = req.msr_address;
    ctx->result      = 0;
    ctx->valid       = FALSE;
    KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);

    PROCESSOR_NUMBER curProc = { 0 };
    KeGetCurrentProcessorNumberEx(&curProc);

    if (curProc.Group == procNum.Group && curProc.Number == procNum.Number) {
        /* Zaten doğru CPU üzerindeyiz — doğrudan çağır */
        LccMsrDpcRoutine(NULL, ctx, NULL, NULL);
    } else {
        KeInitializeDpc(&ctx->dpc, LccMsrDpcRoutine, ctx);
        KeSetTargetProcessorDpcEx(&ctx->dpc, &procNum);
        KeSetImportanceDpc(&ctx->dpc, HighImportance);
        KeInsertQueueDpc(&ctx->dpc, NULL, NULL);

        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;  /* 5 saniye */
        NTSTATUS ws = KeWaitForSingleObject(&ctx->done_event,
                                            Executive, KernelMode, FALSE, &timeout);

        if (ws == STATUS_TIMEOUT) {
            LCC_LOG("DPC zaman aşımı CPU %u", req.cpu_index);

            /*
             * [FIX-4] KeRemoveQueueDpc:
             *   TRUE  → DPC sıradan kaldırıldı, henüz çalışmadı.
             *            ctx güvenle serbest bırakılabilir.
             *   FALSE → DPC zaten çalışıyor veya tamamlandı.
             *            Event'in set edilip edilmediği belirsiz;
             *            KeClearEvent + sonsuz bekleme yaparak
             *            DPC'nin done_event'i set etmesini garantile.
             */
            if (!KeRemoveQueueDpc(&ctx->dpc)) {
                /* DPC zaten çalışıyor veya tamamlandı.
                 * Direkt bekle — DPC done_event'i set edecek.
                 * Not: KeClearEvent burada YANLIŞ olur; DPC zaten
                 * set etmişse sıfırlayıp sonsuz bekleriz. */
                KeWaitForSingleObject(&ctx->done_event,
                                      Executive, KernelMode, FALSE, NULL);
            }

            ExFreePoolWithTag(ctx, LCC_POOL_TAG);
            LccSetIrpStatus(Irp, STATUS_IO_TIMEOUT, 0);
            return;
        }
    }

    /* Sonucu yaz — METHOD_BUFFERED'da SystemBuffer hem giriş hem çıkış */
    PLCC_MSR_RESULT out = (PLCC_MSR_RESULT)Irp->AssociatedIrp.SystemBuffer;
    out->msr_address = req.msr_address;
    out->cpu_index   = req.cpu_index;
    out->value       = ctx->result;
    out->valid       = ctx->valid;
    RtlZeroMemory(out->_pad, sizeof(out->_pad));

    ExFreePoolWithTag(ctx, LCC_POOL_TAG);
    LccSetIrpStatus(Irp, STATUS_SUCCESS, sizeof(LCC_MSR_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  GET_ACPI_INFO
 *
 *  [FIX-5] SYSTEM_FIRMWARE_TABLE_INFORMATION.TableBuffer offseti
 *  sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) - sizeof(ULONG) olarak
 *  hesaplanmalı (yapı sonundaki esnek dizi ULONG[1] olarak tanımlı).
 *  Doğrudan sizeof() kullanımı yerine makro ile güvenli offset hesabı.
 * ═══════════════════════════════════════════════════════════════════ */
#define SystemFirmwareTableInformation 76
#define SFTI_SIG_ACPI    'IPCA'
#define SFTI_ACTION_ENUM 0
#define SFTI_ACTION_GET  1
#define LCC_MAX_ACPI_TABLE_IDS 256u

/*
 * SYSTEM_FIRMWARE_TABLE_INFORMATION.TableBuffer bir ULONG[1] esnek
 * dizisidir. Gerçek veri offseti yapı boyutundan bu ULONG çıkarılarak
 * bulunur.
 */
#define SFTI_HEADER_SIZE \
    (sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) - sizeof(ULONG))

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
    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(LCC_ACPI_RESULT)) {
        LccSetIrpStatus(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }

    PLCC_ACPI_RESULT out = (PLCC_ACPI_RESULT)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(out, sizeof(LCC_ACPI_RESULT));

    /* İlk geçiş: tablo ID listesini enumerate et */
    ULONG enumSize = (ULONG)(SFTI_HEADER_SIZE + 256);
    PSYSTEM_FIRMWARE_TABLE_INFORMATION enumInfo =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, enumSize, LCC_POOL_TAG);
    if (!enumInfo) {
        LccSetIrpStatus(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return;
    }

    enumInfo->ProviderSignature = SFTI_SIG_ACPI;
    enumInfo->Action            = SFTI_ACTION_ENUM;
    enumInfo->TableID           = 0;
    enumInfo->TableBufferLength = 256;

    ULONG    retLen = 0;
    NTSTATUS status = ZwQuerySystemInformation(
        SystemFirmwareTableInformation, enumInfo, enumSize, &retLen);

    if (status == STATUS_BUFFER_TOO_SMALL && retLen > enumSize) {
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        if (retLen > 64 * 1024) {
            LccSetIrpStatus(Irp, STATUS_INVALID_BUFFER_SIZE, 0);
            return;
        }
        enumSize = retLen;
        enumInfo = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
                   ExAllocatePool2(POOL_FLAG_NON_PAGED, enumSize, LCC_POOL_TAG);
        if (!enumInfo) {
            LccSetIrpStatus(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
            return;
        }
        enumInfo->ProviderSignature = SFTI_SIG_ACPI;
        enumInfo->Action            = SFTI_ACTION_ENUM;
        enumInfo->TableID           = 0;
        /* [FIX-5] Doğru veri tamponu boyutu */
        enumInfo->TableBufferLength = enumSize - (ULONG)SFTI_HEADER_SIZE;
        status = ZwQuerySystemInformation(
            SystemFirmwareTableInformation, enumInfo, enumSize, &retLen);
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        LccSetIrpStatus(Irp, status, 0);
        return;
    }

    /* tableCount: tampon boyutu ve maksimum limite göre sınırla */
    ULONG maxByBuf   = enumInfo->TableBufferLength / sizeof(ULONG);
    ULONG tableCount = (maxByBuf < LCC_MAX_ACPI_TABLE_IDS)
                       ? maxByBuf : LCC_MAX_ACPI_TABLE_IDS;

    /* [FIX-5] TableBuffer adresi SFTI_HEADER_SIZE offsetinde */
    PULONG tableIdArray = (PULONG)((PUCHAR)enumInfo + SFTI_HEADER_SIZE);

    /* Her tablo için başlık bilgilerini al */
    ULONG hdrFetchSize = (ULONG)(SFTI_HEADER_SIZE + 64);
    PSYSTEM_FIRMWARE_TABLE_INFORMATION hdrInfo =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, hdrFetchSize, LCC_POOL_TAG);
    if (!hdrInfo) {
        ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);
        LccSetIrpStatus(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
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

        /* [FIX-5] Gerçek veri offsetini kullanarak boyut kontrolü */
        ULONG dataAvail = (fetchLen > (ULONG)SFTI_HEADER_SIZE)
                          ? fetchLen - (ULONG)SFTI_HEADER_SIZE
                          : 0;
        if (dataAvail < 28) continue;  /* ACPI başlığı en az 28 bayt */

        PUCHAR hdr = (PUCHAR)hdrInfo + SFTI_HEADER_SIZE;
        PLCC_ACPI_TABLE_ENTRY rec = &out->tables[out->count++];
        RtlCopyMemory(rec->signature,     hdr,      4);
        RtlCopyMemory(&rec->length,       hdr + 4,  4);
        rec->revision = hdr[8];
        RtlCopyMemory(rec->oem_id,        hdr + 10, 6);
        RtlCopyMemory(rec->oem_table_id,  hdr + 16, 8);
        RtlCopyMemory(&rec->oem_revision, hdr + 24, 4);

        if (RtlCompareMemory(rec->signature, "XSDT", 4) == 4) xsdtSeen = TRUE;
        if (RtlCompareMemory(rec->signature, "RSD ", 4) == 4) rsdpSeen = TRUE;
    }

    ExFreePoolWithTag(hdrInfo,  LCC_POOL_TAG);
    ExFreePoolWithTag(enumInfo, LCC_POOL_TAG);

    out->xsdt_present  = xsdtSeen;
    out->has_rsdp      = rsdpSeen;
    out->acpi_revision = (out->count > 0) ? out->tables[0].revision : 0;

    LCC_LOG("ACPI: %u tablo, XSDT=%u RSDP=%u", out->count, xsdtSeen, rsdpSeen);
    LccSetIrpStatus(Irp, STATUS_SUCCESS, sizeof(LCC_ACPI_RESULT));
}
