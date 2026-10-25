/*
 * Windows 11 için Linux Çekirdeği Uyumluluk Denetleyicisi  —  NT Native API sürümü
 * ==============================================================================
 * Bu sürüm Win32 API'si (kernel32/advapi32/setupapi/winhttp/shell32) ÇAĞIRMAZ.
 * Tüm veriler doğrudan ntdll.dll'in Nt ve Rtl fonksiyonlarıyla toplanır.
 * <windows.h> bile dahil edilmez; gereken tüm tipler aşağıda tanımlıdır.
 *
 * Win32 çağrısının NT karşılığı:
 *   RegOpenKeyEx/RegQueryValueEx   -> NtOpenKey / NtQueryValueKey / NtEnumerateKey
 *   SetupDi* (cihaz listesi)       -> Enum kayıt defteri ağacı
 *   NtPlugPlayControl varsayılan olarak kapalıdır; belge dışıdır ve Wine'da
 *   uygulanmamış/kararsız olabilir. Yerel Windows'ta açıkça etkinleştirilebilir.
 *   GlobalMemoryStatusEx           -> NtQuerySystemInformation(SystemBasicInformation)
 *   GetNativeSystemInfo            -> RtlGetNativeSystemInformation + KUSER_SHARED_DATA
 *   IsProcessorFeaturePresent      -> KUSER_SHARED_DATA.ProcessorFeatures
 *   GetDiskFreeSpaceEx             -> NtQueryVolumeInformationFile(FileFsFullSizeInformation)
 *   CreateFile/DeviceIoControl     -> NtCreateFile / NtDeviceIoControlFile
 *   GetSystemPowerStatus           -> NtPowerInformation(SystemBatteryState)
 *   PEFirmwareType / SecureBoot    -> NtQuerySystemInformation(90 / 145)
 *   GetLocalTime / Sleep           -> NtQuerySystemTime+Rtl* / NtDelayExecution
 *   printf / getchar               -> NtWriteFile / NtReadFile (PEB std handle'ları)
 *   OpenProcessToken/GetTokenInfo  -> NtOpenProcessToken / NtQueryInformationToken
 *   GetCommandLineW                -> PEB->ProcessParameters->CommandLine
 *
 * KALDIRILAN: WinHTTP ile kernel.org sorgusu (internet kontrolü + "Online Data").
 *   NT katmanında HTTPS/TLS/DNS yoktur (bunlar schannel/dnsapi/winsock gibi
 *   kullanıcı-modu Win32 kütüphaneleridir), bu yüzden bu bölüm çıkarıldı.
 *
 * YÖNETİCİ YETKİSİ: NT katmanında "runas" ile kendini yükseltme yoktur (bu iş
 * AppInfo servisinin RPC arayüzünde). Bunun yerine yönetici talebi manifest ile
 * EXE'ye gömülür (linux_compat_checker.rc + .manifest), Windows UAC'yi kendisi açar.
 *
 * TEK İSTİSNA (isteğe bağlı): konsolun UTF-8 + ANSI renk moduna alınması için
 * SetConsoleMode/SetConsoleOutputCP. Bunların NT karşılığı yok (conhost'un özel
 * ConDrv protokolü). -DNT_NO_CONSOLE_SETUP ile derlerseniz hiç Win32 çağrısı kalmaz;
 * o zaman terminalde önceden `chcp 65001` yapmanız ve VT modunun açık olması gerekir.
 *
 * Puanlar: 0=Tam Uyumlu | 1=Uyumlu (küçük sorunlar)
 *          2=Olası Uyumsuz | 3=Uyumsuz
 *
 * Kullanım:
 *   linux_compat_checker_nt.exe [--save <rapor.txt>]
 *
 * Derleme (MinGW-w64 / LLVM-mingw) — yalnızca ntdll'e bağlanır:
 *   x86_64-w64-mingw32-windres linux_compat_checker.rc -O coff -o manifest.o
 *   x86_64-w64-mingw32-g++ -O2 -std=c++20 -mconsole linux_compat_checker_nt.cpp manifest.o \
 *       -o linux_compat_checker_nt_x64.exe -lntdll
 *   Wine uyumluluğu için NtPlugPlayControl varsayılan olarak kapalıdır.
 *   Yalnızca yerel Windows'ta filtreyi açmak için -DNT_ENABLE_UNDOCUMENTED_PNP_CONTROL
 *   tanımlanabilir.
 *   (arm64: aarch64-w64-mingw32-*, x86: i686-w64-mingw32-*)
 */

#include <cstdint>
#include <limits>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <format>
#include <vector>
#include <array>
#include <memory>
#include <optional>
#include <functional>
#include <algorithm>
#include <utility>

#ifndef NTAPI
#define NTAPI __stdcall
#endif

/* =================================================================
 * NT tipleri ve prototipleri (windows.h / winternl.h kullanılmıyor)
 * ================================================================= */
namespace nt {

    using NTSTATUS    = int32_t;
    using HANDLE      = void*;
    using ULONG       = uint32_t;
    using USHORT      = uint16_t;
    using BOOLEAN     = uint8_t;
    using WCHAR       = wchar_t;          /* mingw'de 16-bit */
    using ACCESS_MASK = uint32_t;

    inline constexpr NTSTATUS STATUS_SUCCESS         = 0;
    inline constexpr NTSTATUS STATUS_UNSUCCESSFUL    = static_cast<NTSTATUS>(0xC0000001u);
    inline constexpr NTSTATUS STATUS_PENDING         = 0x00000103;
    inline constexpr NTSTATUS STATUS_BUFFER_OVERFLOW = static_cast<NTSTATUS>(0x80000005u);
    inline constexpr NTSTATUS STATUS_NO_MORE_ENTRIES = static_cast<NTSTATUS>(0x8000001Au);
    inline constexpr NTSTATUS STATUS_NO_SUCH_DEVICE  = static_cast<NTSTATUS>(0xC000000Eu);
    inline constexpr NTSTATUS STATUS_BUFFER_TOO_SMALL= static_cast<NTSTATUS>(0xC0000023u);

    [[nodiscard]] constexpr bool success(NTSTATUS s) noexcept { return s >= 0; }

    struct UNICODE_STRING {
        USHORT Length;          /* bayt cinsinden */
        USHORT MaximumLength;
        WCHAR* Buffer;
    };

    struct ANSI_STRING_MIN {
        USHORT Length;
        USHORT MaximumLength;
        char*  Buffer;
    };

    struct OBJECT_ATTRIBUTES {
        ULONG           Length;
        HANDLE          RootDirectory;
        UNICODE_STRING* ObjectName;
        ULONG           Attributes;
        void*           SecurityDescriptor;
        void*           SecurityQualityOfService;
    };
    inline constexpr ULONG OBJ_CASE_INSENSITIVE = 0x40;

    struct IO_STATUS_BLOCK {
        union { NTSTATUS Status; void* Pointer; };
        uintptr_t Information;
    };

    struct TIME_FIELDS {
        int16_t Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday;
    };

    /* PEB / RTL_USER_PROCESS_PARAMETERS — yalnızca ihtiyaç duyulan başlangıç kısmı
     * (x86 ve x64/ARM64 ofsetleri doğal hizalamayla birebir tutar). */
    struct CURDIR { UNICODE_STRING DosPath; HANDLE Handle; };
    struct RTL_USER_PROCESS_PARAMETERS_MIN {
        ULONG MaximumLength, Length, Flags, DebugFlags;
        HANDLE ConsoleHandle;
        ULONG  ConsoleFlags;
        HANDLE StandardInput, StandardOutput, StandardError;
        CURDIR CurrentDirectory;
        UNICODE_STRING DllPath, ImagePathName, CommandLine;
    };
    struct PEB_MIN {
        uint8_t InheritedAddressSpace, ReadImageFileExecOptions, BeingDebugged, BitField;
        HANDLE  Mutant;
        void*   ImageBaseAddress;
        void*   Ldr;
        RTL_USER_PROCESS_PARAMETERS_MIN* ProcessParameters;
    };
    struct PROCESS_BASIC_INFORMATION {
        NTSTATUS  ExitStatus;
        void*     PebBaseAddress;
        uintptr_t AffinityMask;
        int32_t   BasePriority;
        uintptr_t UniqueProcessId;
        uintptr_t InheritedFromUniqueProcessId;
    };

    struct KEY_BASIC_INFORMATION {
        int64_t LastWriteTime;
        ULONG   TitleIndex;
        ULONG   NameLength;     /* bayt */
        WCHAR   Name[1];
    };
    struct KEY_VALUE_PARTIAL_INFORMATION {
        ULONG   TitleIndex;
        ULONG   Type;
        ULONG   DataLength;
        uint8_t Data[1];
    };

    struct SYSTEM_BASIC_INFORMATION {
        ULONG     Reserved;
        ULONG     TimerResolution;
        ULONG     PageSize;
        ULONG     NumberOfPhysicalPages;
        ULONG     LowestPhysicalPageNumber;
        ULONG     HighestPhysicalPageNumber;
        ULONG     AllocationGranularity;
        uintptr_t MinimumUserModeAddress;
        uintptr_t MaximumUserModeAddress;
        uintptr_t ActiveProcessorsAffinityMask;
        int8_t    NumberOfProcessors;
    };
    struct SYSTEM_PROCESSOR_INFORMATION {
        USHORT ProcessorArchitecture, ProcessorLevel, ProcessorRevision, MaximumProcessors;
        ULONG  ProcessorFeatureBits;
    };
    struct SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
        uint8_t  BootIdentifier[16];
        ULONG    FirmwareType;          /* 1 = BIOS, 2 = UEFI */
        ULONG    BootFlags;
    };
    struct SYSTEM_SECUREBOOT_INFORMATION {
        BOOLEAN SecureBootEnabled;
        BOOLEAN SecureBootCapable;
    };
    struct SYSTEM_BATTERY_STATE {
        BOOLEAN AcOnLine, BatteryPresent, Charging, Discharging;
        BOOLEAN Spare1[3];
        uint8_t Tag;
        ULONG   MaxCapacity, RemainingCapacity, Rate, EstimatedTime, DefaultAlert1, DefaultAlert2;
    };
    struct FILE_FS_FULL_SIZE_INFORMATION {
        int64_t TotalAllocationUnits;
        int64_t CallerAvailableAllocationUnits;
        int64_t ActualAvailableAllocationUnits;
        ULONG   SectorsPerAllocationUnit;
        ULONG   BytesPerSector;
    };

    /* IOCTL yapıları (winioctl.h karşılıkları) */
    struct DISK_EXTENT {
        ULONG DiskNumber;
        alignas(8) int64_t StartingOffset;
        alignas(8) int64_t ExtentLength;
    };
    struct VOLUME_DISK_EXTENTS {
        ULONG       NumberOfDiskExtents;
        DISK_EXTENT Extents[1];
    };
    struct STORAGE_PROPERTY_QUERY {
        ULONG   PropertyId;
        ULONG   QueryType;
        uint8_t AdditionalParameters[1];
    };
    struct DEVICE_SEEK_PENALTY_DESCRIPTOR {
        ULONG   Version;
        ULONG   Size;
        BOOLEAN IncursSeekPenalty;
    };
    struct STORAGE_DEVICE_DESCRIPTOR {
        ULONG   Version, Size;
        uint8_t DeviceType, DeviceTypeModifier;
        BOOLEAN RemovableMedia, CommandQueueing;
        ULONG   VendorIdOffset, ProductIdOffset, ProductRevisionOffset, SerialNumberOffset;
        ULONG   BusType;
        ULONG   RawPropertiesLength;
        uint8_t RawDeviceProperties[1];
    };

    /* Belgelenmemiş: NtPlugPlayControl(PlugPlayControlDeviceStatus) — ReactOS/Process Hacker düzeni */
    struct PLUGPLAY_CONTROL_STATUS_DATA {
        UNICODE_STRING DeviceInstance;
        ULONG          Operation;       /* 0 = PNP_GET_DEVICE_STATUS */
        ULONG          DeviceStatus;
        ULONG          DeviceProblem;
    };

    inline constexpr ULONG IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000;
    inline constexpr ULONG IOCTL_STORAGE_QUERY_PROPERTY         = 0x002D1400;
    inline constexpr ULONG StorageDeviceProperty                = 0;
    inline constexpr ULONG StorageDeviceSeekPenaltyProperty     = 7;
    inline constexpr ULONG PropertyStandardQuery                = 0;
    inline constexpr ULONG BusTypeNvme                          = 0x11;

    inline constexpr ULONG SystemBasicInformation            = 0;
    inline constexpr ULONG SystemProcessorInformation        = 1;
    inline constexpr ULONG SystemBootEnvironmentInformation  = 90;
    inline constexpr ULONG SystemSecureBootInformation       = 145;
    inline constexpr ULONG SystemBatteryState                = 5;    /* POWER_INFORMATION_LEVEL */
    inline constexpr ULONG PlugPlayControlDeviceStatus       = 14;
    inline constexpr ULONG FileFsFullSizeInformation         = 7;
    inline constexpr ULONG TokenElevationClass               = 20;
    inline constexpr ULONG SE_LOAD_DRIVER_PRIVILEGE          = 10;

    /* KEY_READ | KEY_WOW64_64KEY: select the 64-bit registry view under WOW64. */
    inline constexpr ACCESS_MASK KEY_READ_       = 0x20119;
    inline constexpr ACCESS_MASK FILE_READ_ATTRIBUTES_ = 0x80;
    inline constexpr ACCESS_MASK FILE_GENERIC_WRITE_   = 0x120116;
    inline constexpr ACCESS_MASK SYNCHRONIZE_    = 0x100000;
    inline constexpr ULONG FILE_DIRECTORY_FILE         = 0x01;
    inline constexpr ULONG FILE_NON_DIRECTORY_FILE     = 0x40;
    inline constexpr ULONG FILE_SYNCHRONOUS_IO_NONALERT= 0x20;
    inline constexpr ULONG FILE_OPEN                   = 1;
    inline constexpr ULONG FILE_OVERWRITE_IF           = 5;
    inline constexpr ULONG FILE_SHARE_ALL              = 7;

    inline constexpr ULONG REG_SZ_        = 1;
    inline constexpr ULONG REG_EXPAND_SZ_ = 2;
    inline constexpr ULONG REG_MULTI_SZ_  = 7;
    inline constexpr ULONG REG_DWORD_     = 4;

} // namespace nt

extern "C" {
using namespace nt;
NTSTATUS NTAPI NtClose(HANDLE);
NTSTATUS NTAPI NtOpenKey(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*);
NTSTATUS NTAPI NtQueryValueKey(HANDLE, UNICODE_STRING*, ULONG, void*, ULONG, ULONG*);
NTSTATUS NTAPI NtEnumerateKey(HANDLE, ULONG, ULONG, void*, ULONG, ULONG*);
NTSTATUS NTAPI NtCreateFile(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, int64_t*,
                            ULONG, ULONG, ULONG, ULONG, void*, ULONG);
NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, void*, void*, IO_STATUS_BLOCK*, void*, ULONG, int64_t*, ULONG*);
NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, void*, void*, IO_STATUS_BLOCK*, const void*, ULONG, int64_t*, ULONG*);
NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, void*, void*, IO_STATUS_BLOCK*, ULONG,
                                     void*, ULONG, void*, ULONG);
NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, IO_STATUS_BLOCK*, void*, ULONG, ULONG);
NTSTATUS NTAPI NtQuerySystemInformation(ULONG, void*, ULONG, ULONG*);
NTSTATUS NTAPI RtlGetNativeSystemInformation(ULONG, void*, ULONG, ULONG*);
NTSTATUS NTAPI NtQuerySystemTime(int64_t*);
NTSTATUS NTAPI RtlSystemTimeToLocalTime(const int64_t*, int64_t*);
void     NTAPI RtlTimeToTimeFields(const int64_t*, TIME_FIELDS*);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN, int64_t*);
NTSTATUS NTAPI NtPowerInformation(ULONG, void*, ULONG, void*, ULONG);
NTSTATUS NTAPI NtOpenProcessToken(HANDLE, ACCESS_MASK, HANDLE*);
NTSTATUS NTAPI NtQueryInformationToken(HANDLE, ULONG, void*, ULONG, ULONG*);
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, ULONG, void*, ULONG, ULONG*);
NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, int64_t*);
NTSTATUS NTAPI NtPlugPlayControl(ULONG, void*, ULONG);
NTSTATUS NTAPI RtlUnicodeToUTF8N(char*, ULONG, ULONG*, const WCHAR*, ULONG);
BOOLEAN  NTAPI RtlDosPathNameToNtPathName_U(const WCHAR*, UNICODE_STRING*, WCHAR**, void*);
void     NTAPI RtlFreeUnicodeString(UNICODE_STRING*);
NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, BOOLEAN*);
NTSTATUS NTAPI LdrGetDllHandle(const WCHAR*, ULONG*, const UNICODE_STRING*, HANDLE*);
NTSTATUS NTAPI LdrGetProcedureAddress(HANDLE, const ANSI_STRING_MIN*, ULONG, void**);
}

#ifndef NT_NO_CONSOLE_SETUP
/* Tek Win32 istisnası (bkz. dosya başı). -DNT_NO_CONSOLE_SETUP ile tamamen kaldırılır. */
extern "C" {
int  __stdcall GetConsoleMode(void*, uint32_t*);
int  __stdcall SetConsoleMode(void*, uint32_t);
int  __stdcall SetConsoleOutputCP(uint32_t);
}
#endif

using namespace nt;

/* =================================================================
 * Süreç / KUSER_SHARED_DATA erişimi
 * ================================================================= */
namespace Proc {

    inline HANDLE const CURRENT_PROCESS = reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1));

    [[nodiscard]] inline RTL_USER_PROCESS_PARAMETERS_MIN* params() noexcept {
        static RTL_USER_PROCESS_PARAMETERS_MIN* p = [] () -> RTL_USER_PROCESS_PARAMETERS_MIN* {
            PROCESS_BASIC_INFORMATION pbi{};
            if (!success(NtQueryInformationProcess(CURRENT_PROCESS, 0 /*ProcessBasicInformation*/,
                                                   &pbi, sizeof(pbi), nullptr)) || !pbi.PebBaseAddress)
                return nullptr;
            return static_cast<PEB_MIN*>(pbi.PebBaseAddress)->ProcessParameters;
        }();
        return p;
    }

    /* KUSER_SHARED_DATA her NT sürümünde/mimarisinde 0x7FFE0000'dedir. */
    [[nodiscard]] inline const volatile uint8_t* shared_data() noexcept {
        return reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(0x7FFE0000));
    }
    [[nodiscard]] inline bool processor_feature(unsigned id) noexcept {      /* ProcessorFeatures @0x274 */
        return id < 64 && shared_data()[0x274 + id] != 0;
    }
    [[nodiscard]] inline uint32_t active_processor_count() noexcept {
        /* Sabit KUSER_SHARED_DATA ofsetine bağımlı kalmadan NT API ile sorgula. */
        SYSTEM_BASIC_INFORMATION sbi{};
        if (!success(NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), nullptr)))
            return 0;
        return sbi.NumberOfProcessors > 0
            ? static_cast<uint32_t>(sbi.NumberOfProcessors)
            : 0;
    }
    [[nodiscard]] inline wchar_t system_drive_letter() noexcept {            /* NtSystemRoot @0x30: "C:\WINDOWS" */
        const volatile wchar_t* root = reinterpret_cast<const volatile wchar_t*>(shared_data() + 0x30);
        const wchar_t c = root[0];
        return (root[1] == L':' && ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z'))) ? c : L'C';
    }

} // namespace Proc

/* =================================================================
 * Çıktı / Girdi — NtWriteFile / NtReadFile ile
 * ================================================================= */
namespace Io {

    inline NTSTATUS wait_if_pending(HANDLE h, NTSTATUS st, IO_STATUS_BLOCK& io) {
        if (st == STATUS_PENDING) {      /* The file object is signaled when the I/O completes. */
            const NTSTATUS wait_status = NtWaitForSingleObject(h, 0, nullptr);
            if (wait_status != STATUS_SUCCESS)
                return success(wait_status) ? STATUS_UNSUCCESSFUL : wait_status;
            st = io.Status;
        }
        return st;
    }

    inline bool write_all(HANDLE h, const char* data, std::size_t len) {
        if (!h || h == reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1))) return false;
        while (len > 0) {
            std::size_t chunk = std::min<std::size_t>(len, 32768);
            /* UTF-8 çok baytlı karakteri ortadan bölme */
            while (chunk < len && chunk > 1 && (static_cast<uint8_t>(data[chunk]) & 0xC0) == 0x80) --chunk;

            IO_STATUS_BLOCK io{};
            NTSTATUS st = NtWriteFile(h, nullptr, nullptr, nullptr, &io, data,
                                      static_cast<ULONG>(chunk), nullptr, nullptr);
            st = wait_if_pending(h, st, io);
            if (!success(st)) return false;
            const std::size_t written = static_cast<std::size_t>(io.Information);
            if (written == 0 || written > chunk || written > len)
                return false;
            data += written;
            len  -= written;
        }
        return true;
    }

    [[nodiscard]] inline HANDLE open_nt(std::wstring_view nt_path, ACCESS_MASK access, ULONG share,
                                        ULONG options, ULONG disposition = FILE_OPEN) {
        constexpr std::size_t max_chars = std::numeric_limits<USHORT>::max() / sizeof(wchar_t);
        if (nt_path.size() > max_chars) return nullptr;
        const auto path_bytes = static_cast<USHORT>(nt_path.size() * sizeof(wchar_t));
        UNICODE_STRING us{ path_bytes, path_bytes, const_cast<wchar_t*>(nt_path.data()) };
        OBJECT_ATTRIBUTES oa{ sizeof(oa), nullptr, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr };
        IO_STATUS_BLOCK io{};
        HANDLE h = nullptr;
        const NTSTATUS st = NtCreateFile(&h, access, &oa, &io, nullptr, 0x80 /*FILE_ATTRIBUTE_NORMAL*/,
                                         share, disposition, options, nullptr, 0);
        return success(st) ? h : nullptr;
    }

    [[nodiscard]] inline bool ioctl(HANDLE h, ULONG code, void* in, ULONG in_len, void* out, ULONG out_len) {
        IO_STATUS_BLOCK io{};
        NTSTATUS st = NtDeviceIoControlFile(h, nullptr, nullptr, nullptr, &io, code, in, in_len, out, out_len);
        st = wait_if_pending(h, st, io);
        return success(st);
    }

} // namespace Io

namespace Out {

    inline std::string& buffer() { static std::string b; return b; }

    inline void flush() {
        auto& b = buffer();
        if (b.empty()) return;
        auto* p = Proc::params();
        if (p) Io::write_all(p->StandardOutput, b.data(), b.size());
        b.clear();
    }

    inline void put(std::string_view s) {
        buffer().append(s);
        if (buffer().size() > 16384) flush();
    }

    template <class... Args>
    inline void print(std::format_string<Args...> fmt, Args&&... args) {
        put(std::format(fmt, std::forward<Args>(args)...));
    }

} // namespace Out

namespace In {

    inline void wait_enter() {
        Out::flush();
        auto* p = Proc::params();
        if (!p || !p->StandardInput ||
            p->StandardInput == reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1))) return;
        char line[256];
        IO_STATUS_BLOCK io{};
        NTSTATUS st = NtReadFile(p->StandardInput, nullptr, nullptr, nullptr, &io, line, sizeof(line), nullptr, nullptr);
        (void)Io::wait_if_pending(p->StandardInput, st, io);
    }

} // namespace In

namespace Time {

    inline void sleep_ms(unsigned ms) {
        int64_t interval = -static_cast<int64_t>(ms) * 10000;   /* negatif = göreli, 100 ns birimi */
        NtDelayExecution(0, &interval);
    }

    [[nodiscard]] inline TIME_FIELDS local_now() {
        int64_t utc = 0, local = 0;
        TIME_FIELDS tf{};
        NtQuerySystemTime(&utc);
        RtlSystemTimeToLocalTime(&utc, &local);
        RtlTimeToTimeFields(&local, &tf);
        return tf;
    }

} // namespace Time

/* =================================================================
 * Yönetici yetkisi kontrolü (yükseltme manifest ile yapılır)
 * ================================================================= */
namespace Elevation {

    [[nodiscard]] inline bool is_process_elevated() noexcept {
        HANDLE token = nullptr;
        if (!success(NtOpenProcessToken(Proc::CURRENT_PROCESS, 0x8 /*TOKEN_QUERY*/, &token)))
            return false;

        ULONG elevated = 0, returned = 0;
        const NTSTATUS st = NtQueryInformationToken(token, TokenElevationClass, &elevated, sizeof(elevated), &returned);
        NtClose(token);
        return success(st) && returned == sizeof(elevated) && elevated != 0;
    }

} // namespace Elevation

/* ─── ANSI renk kodları ─── */
inline constexpr const char* RESET  = "\033[0m";
inline constexpr const char* BOLD   = "\033[1m";
inline constexpr const char* DIM    = "\033[2m";
inline constexpr const char* RED    = "\033[91m";
inline constexpr const char* GREEN  = "\033[92m";
inline constexpr const char* YELLOW = "\033[93m";
inline constexpr const char* BLUE   = "\033[94m";
inline constexpr const char* CYAN   = "\033[96m";
inline constexpr const char* WHITE  = "\033[97m";
inline constexpr const char* ORANGE = "\033[38;5;208m";

/* ─── Kategori ismi sabitleri ─── */
inline constexpr std::string_view CAT_CPU    = "CPU";
inline constexpr std::string_view CAT_RAM    = "Memory (RAM)";
inline constexpr std::string_view CAT_DISK   = "Storage (Disk)";
inline constexpr std::string_view CAT_GPU    = "Graphics (GPU)";
inline constexpr std::string_view CAT_NET    = "Networking";
inline constexpr std::string_view CAT_AUDIO  = "Audio";
inline constexpr std::string_view CAT_FW     = "Firmware";
inline constexpr std::string_view CAT_SB     = "Secure Boot";
inline constexpr std::string_view CAT_TPM    = "TPM";
inline constexpr std::string_view CAT_POWER  = "Power / Battery";
inline constexpr std::string_view CAT_VIRT   = "Virtualization";

/* ─── Aygıt sınıfı GUID'leri (kayıt defterindeki ClassGUID, küçük harf) ─── */
inline constexpr std::string_view CLS_DISPLAY = "{4d36e968-e325-11ce-bfc1-08002be10318}";
inline constexpr std::string_view CLS_NET     = "{4d36e972-e325-11ce-bfc1-08002be10318}";
inline constexpr std::string_view CLS_MEDIA   = "{4d36e96c-e325-11ce-bfc1-08002be10318}";

/* ─── Uyumluluk Puanı Seviyeleri ─── */
enum class CompatScore : int {
    FULL  = 0,   /* Tam uyumlu, hiçbir işleme gerek yok */
    MINOR = 1,   /* Uyumlu, ufak pürüzler olabilir      */
    MAYBE = 2,   /* Olası uyumsuzluk, dikkatle incelenmeli */
    NONE  = 3    /* Uyumsuz, ciddi sorunlar bekleniyor  */
};

inline constexpr int MAX_DEVICES = 256;


struct CompatItem {
    std::string  name;
    std::string  category;
    std::string  detail;
    std::string  recommendation;
    CompatScore  score    = CompatScore::FULL;
    bool         critical = false;
};


class CompatReport {
public:
    std::vector<CompatItem>  items;
    std::array<int, 4>       score_counts{};
    double                   overall_percent = 0.0;

    /* Kapasite sınırına ulaşılırsa nullptr döndürür */
    [[nodiscard]] CompatItem* add_item() {
        if (static_cast<int>(items.size()) >= MAX_DEVICES)
            return nullptr;
        items.emplace_back();
        return &items.back();
    }

    void compute() {
        score_counts.fill(0);
        double weighted     = 0.0;
        double total_weight = 0.0;

        for (const auto& item : items) {
            const int raw_score = static_cast<int>(item.score);
            if (raw_score < 0 || raw_score >= static_cast<int>(score_counts.size()))
                continue;
            const int s = raw_score;
            ++score_counts[static_cast<std::size_t>(s)];
            const double w       = item.critical ? 2.0 : 1.0;
            const double contrib = (3.0 - static_cast<double>(s)) / 3.0;
            weighted      += contrib * w;
            total_weight  += w;
        }

        overall_percent = (total_weight > 0.0)
        ? (weighted / total_weight) * 100.0
        : 0.0;
    }
};


/* =================================================================
 * Registry (Kayıt Defteri) — NtOpenKey / NtQueryValueKey / NtEnumerateKey
 * Yollar NT biçimindedir: \Registry\Machine\...
 * ================================================================= */
namespace Registry {

    [[nodiscard]] inline std::string to_utf8(const wchar_t* w, std::size_t n) {
        if (n == 0) return {};
        std::string out(n * 3 + 4, '\0');
        ULONG written = 0;
        if (!success(RtlUnicodeToUTF8N(out.data(), static_cast<ULONG>(out.size()), &written,
                                       w, static_cast<ULONG>(n * sizeof(wchar_t)))))
            return {};
        out.resize(written);
        return out;
    }

    [[nodiscard]] inline std::optional<UNICODE_STRING> make_us(std::wstring_view s) {
        constexpr std::size_t max_chars = std::numeric_limits<USHORT>::max() / sizeof(wchar_t);
        if (s.size() > max_chars) return std::nullopt;
        const auto bytes = static_cast<USHORT>(s.size() * sizeof(wchar_t));
        return UNICODE_STRING{ bytes, bytes, const_cast<wchar_t*>(s.data()) };
    }

    struct Value {
        ULONG                type = 0;
        std::vector<uint8_t> data;
    };

    class Key {
    public:
        Key() = default;
        Key(const Key&) = delete;
        Key& operator=(const Key&) = delete;
        Key(Key&& o) noexcept : h_(std::exchange(o.h_, nullptr)) {}
        ~Key() { if (h_) NtClose(h_); }

        [[nodiscard]] bool open(std::wstring_view nt_path) {
            if (h_) { NtClose(h_); h_ = nullptr; }
            auto us_opt = make_us(nt_path);
            if (!us_opt) return false;
            UNICODE_STRING us = *us_opt;
            OBJECT_ATTRIBUTES oa{ sizeof(oa), nullptr, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr };
            return success(NtOpenKey(&h_, KEY_READ_, &oa));
        }

        [[nodiscard]] std::optional<Value> value(const wchar_t* name) const {
            auto n_opt = make_us(name);
            if (!n_opt) return std::nullopt;
            UNICODE_STRING n = *n_opt;
            std::vector<uint8_t> buf(512);
            for (;;) {
                ULONG ret = 0;
                const NTSTATUS st = NtQueryValueKey(h_, &n, 2 /*KeyValuePartialInformation*/,
                                                    buf.data(), static_cast<ULONG>(buf.size()), &ret);
                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
                    buf.resize(std::max<std::size_t>(ret, buf.size() * 2));
                    continue;
                }
                if (!success(st)) return std::nullopt;

                constexpr std::size_t type_offset = offsetof(KEY_VALUE_PARTIAL_INFORMATION, Type);
                constexpr std::size_t length_offset = offsetof(KEY_VALUE_PARTIAL_INFORMATION, DataLength);
                constexpr std::size_t data_offset = offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data);
                if (ret < data_offset || buf.size() < data_offset)
                    return std::nullopt;

                ULONG type = 0;
                ULONG data_length = 0;
                std::memcpy(&type, buf.data() + type_offset, sizeof(type));
                std::memcpy(&data_length, buf.data() + length_offset, sizeof(data_length));
                if (data_length > static_cast<std::size_t>(ret) - data_offset)
                    return std::nullopt;

                Value v;
                v.type = type;
                v.data.assign(buf.begin() + static_cast<std::ptrdiff_t>(data_offset),
                              buf.begin() + static_cast<std::ptrdiff_t>(data_offset + data_length));
                return v;
            }
        }

        /* REG_SZ / REG_EXPAND_SZ -> UTF-8 */
        [[nodiscard]] std::optional<std::string> string(const wchar_t* name) const {
            auto v = value(name);
            if (!v || (v->type != REG_SZ_ && v->type != REG_EXPAND_SZ_)) return std::nullopt;
            return first_string(*v);
        }

        /* REG_MULTI_SZ'nin (veya SZ'nin) ilk dizesi -> UTF-8 */
        [[nodiscard]] std::optional<std::string> multi_first(const wchar_t* name) const {
            auto v = value(name);
            if (!v || (v->type != REG_MULTI_SZ_ && v->type != REG_SZ_)) return std::nullopt;
            return first_string(*v);
        }

        [[nodiscard]] std::optional<uint32_t> dword(const wchar_t* name) const {
            auto v = value(name);
            if (!v || v->type != REG_DWORD_ || v->data.size() != sizeof(uint32_t)) return std::nullopt;
            uint32_t x;
            std::memcpy(&x, v->data.data(), sizeof(x));
            return x;
        }

        [[nodiscard]] std::vector<std::wstring> subkeys() const {
            std::vector<std::wstring> names;
            std::vector<uint8_t> buf(1024);
            for (ULONG idx = 0;; ) {
                ULONG ret = 0;
                const NTSTATUS st = NtEnumerateKey(h_, idx, 0 /*KeyBasicInformation*/,
                                                   buf.data(), static_cast<ULONG>(buf.size()), &ret);
                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
                    buf.resize(std::max<std::size_t>(ret, buf.size() * 2));
                    continue;
                }
                if (!success(st)) break;               /* STATUS_NO_MORE_ENTRIES dahil */

                constexpr std::size_t name_length_offset = offsetof(KEY_BASIC_INFORMATION, NameLength);
                constexpr std::size_t name_offset = offsetof(KEY_BASIC_INFORMATION, Name);
                if (ret < name_offset || buf.size() < name_offset)
                    break;
                ULONG name_length = 0;
                std::memcpy(&name_length, buf.data() + name_length_offset, sizeof(name_length));
                if ((name_length % sizeof(wchar_t)) != 0 ||
                    name_length > static_cast<std::size_t>(ret) - name_offset)
                    break;

                std::wstring name(name_length / sizeof(wchar_t), L'\0');
                if (name_length != 0)
                    std::memcpy(name.data(), buf.data() + name_offset, name_length);
                names.push_back(std::move(name));
                ++idx;
            }
            return names;
        }

    private:
        [[nodiscard]] static std::string first_string(const Value& v) {
            const std::size_t max_n = v.data.size() / sizeof(wchar_t);
            if (max_n == 0) return {};

            std::wstring w(max_n, L'\0');
            std::memcpy(w.data(), v.data.data(), max_n * sizeof(wchar_t));
            std::size_t n = 0;
            while (n < max_n && w[n] != L'\0') ++n;
            return to_utf8(w.data(), n);
        }

        HANDLE h_ = nullptr;
    };

    [[nodiscard]] inline std::optional<std::string>
    read_string(std::wstring_view path, const wchar_t* value) {
        Key k;
        if (!k.open(path)) return std::nullopt;
        return k.string(value);
    }

    [[nodiscard]] inline std::optional<uint32_t>
    read_dword(std::wstring_view path, const wchar_t* value) {
        Key k;
        if (!k.open(path)) return std::nullopt;
        return k.dword(value);
    }

} // namespace Registry


/* =================================================================
 * Console — Arayüz Yardımcıları
 * ================================================================= */
namespace Console {

    inline void enable_ansi() {
#ifndef NT_NO_CONSOLE_SETUP
        auto* p = Proc::params();
        if (p && p->StandardOutput) {
            uint32_t mode = 0;
            if (GetConsoleMode(p->StandardOutput, &mode))
                SetConsoleMode(p->StandardOutput, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/);
        }
        SetConsoleOutputCP(65001);
#endif
    }

    inline void print_header() {
        Out::print("\n");
        Out::print("{}{}╔══════════════════════════════════════════════════════════════╗\n{}", CYAN, BOLD, RESET);
        Out::print("{}{}║{}{}{}     🐧  Linux Compatibility Checker v2.2 (NT API)    {}{}║\n{}", CYAN, BOLD, RESET, BLUE, BOLD, CYAN, BOLD, RESET);
        Out::print("{}{}║{}{}     Windows 11 → Linux migration readiness report   {}{}║\n{}", CYAN, BOLD, RESET, DIM, CYAN, BOLD, RESET);
        Out::print("{}{}╚══════════════════════════════════════════════════════════════╝\n{}", CYAN, BOLD, RESET);
        Out::print("\n");
    }

    [[nodiscard]] inline const char* score_label(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return "\033[92m\033[1m[0] FULLY COMPATIBLE      \033[0m";
            case CompatScore::MINOR: return "\033[93m\033[1m[1] COMPATIBLE (minor)    \033[0m";
            case CompatScore::MAYBE: return "\033[38;5;208m\033[1m[2] MAYBE INCOMPATIBLE    \033[0m";
            case CompatScore::NONE:  return "\033[91m\033[1m[3] INCOMPATIBLE          \033[0m";
        }
        return "\033[97m[?] UNKNOWN\033[0m";
    }

    [[nodiscard]] inline const char* score_icon(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return "\033[92m●\033[0m";
            case CompatScore::MINOR: return "\033[93m◑\033[0m";
            case CompatScore::MAYBE: return "\033[38;5;208m◔\033[0m";
            case CompatScore::NONE:  return "\033[91m○\033[0m";
        }
        return "\033[97m?\033[0m";
    }

    inline void loading_bar(const char* msg, int steps, int delay_ms) {
        Out::print("{}  ► {}{} ", CYAN, RESET, msg);
        Out::flush();
        for (int i = 0; i < steps; i++) {
            Out::put("█");
            Out::flush();
            Time::sleep_ms(static_cast<unsigned>(delay_ms));
        }
        Out::print(" {}{}✓\n{}", GREEN, BOLD, RESET);
        Out::flush();
    }

    inline void print_percent_bar(double pct, int width) {
        const int   filled = static_cast<int>(pct / 100.0 * static_cast<double>(width));
        const char* color  = (pct >= 75.0) ? GREEN : (pct >= 50.0) ? YELLOW : RED;
        std::string bar;
        for (int i = 0; i < width; i++)
            bar += (i < filled) ? "█" : "░";
        Out::print("{}{}[{}] %{:.1f}{}", color, BOLD, bar, pct, RESET);
    }

} // namespace Console


/* =================================================================
 * Cihaz listesi — SetupAPI yerine Enum kayıt defteri + NtPlugPlayControl
 * -----------------------------------------------------------------
 * HKLM\SYSTEM\CurrentControlSet\Enum\<BUS>\<AYGIT>\<ÖRNEK> ağacı yürünür;
 * "ClassGUID", "DeviceDesc", "HardwareID" değerleri okunur.
 * Enum ağacı o an takılı olmayan (hayalet) cihazları da tuttuğundan,
 * DIGCF_PRESENT karşılığı olarak her örnek NtPlugPlayControl ile sorgulanır:
 * devnode yoksa (STATUS_NO_SUCH_DEVICE) veya CM_PROB_PHANTOM ise atlanır.
 * Sorgu başka bir hatayla başarısız olursa cihaz "mevcut" sayılır.
 * ================================================================= */
struct Device {
    std::string instance_id;
    std::string class_guid;   /* küçük harf, süslü parantezli */
    std::string name;
    std::string hw_id;        /* HardwareID listesinin ilk girdisi */
};

namespace DeviceDb {

    [[nodiscard]] inline std::string lower(std::string s) {
        for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        return s;
    }

    [[nodiscard]] inline bool icontains(std::string_view hay, std::string_view needle) {
        return lower(std::string(hay)).find(lower(std::string(needle))) != std::string::npos;
    }

    /* "@oem42.inf,%dev%;NVIDIA GeForce RTX 4060"  ->  "NVIDIA GeForce RTX 4060" */
    [[nodiscard]] inline std::string resolve_desc(std::string d) {
        if (!d.empty() && d[0] == '@') {
            const auto pos = d.rfind(';');
            if (pos != std::string::npos) return d.substr(pos + 1);
        }
        return d;
    }

#if defined(NT_ENABLE_UNDOCUMENTED_PNP_CONTROL)
    /* Yalnızca yerel Windows üzerinde, açıkça etkinleştirildiğinde kullanılır.
     * Wine sürümlerinin bir kısmında NtPlugPlayControl uygulanmamıştır; çağrı
     * uygulamayı sonlandırabileceği için varsayılan derlemede kapalıdır. */
    [[nodiscard]] inline bool running_under_wine() {
        static const bool wine = [] {
            wchar_t name[] = L"ntdll.dll";
            UNICODE_STRING dll{ static_cast<USHORT>(sizeof(name) - sizeof(wchar_t)),
                                static_cast<USHORT>(sizeof(name)), name };
            HANDLE mod = nullptr;
            if (!success(LdrGetDllHandle(nullptr, nullptr, &dll, &mod)) || !mod) return false;
            char fn[] = "wine_get_version";
            ANSI_STRING_MIN as{ static_cast<USHORT>(sizeof(fn) - 1),
                                static_cast<USHORT>(sizeof(fn)), fn };
            void* addr = nullptr;
            return success(LdrGetProcedureAddress(mod, &as, 0, &addr)) && addr != nullptr;
        }();
        return wine;
    }

    [[nodiscard]] inline bool is_present(const std::wstring& instance_id) {
        if (running_under_wine()) return true;
        PLUGPLAY_CONTROL_STATUS_DATA d{};
        const auto instance_opt = Registry::make_us(instance_id);
        if (!instance_opt) return false;
        d.DeviceInstance = *instance_opt;
        d.Operation      = 0;
        const NTSTATUS st = NtPlugPlayControl(PlugPlayControlDeviceStatus, &d, sizeof(d));
        if (!success(st)) return false;
        return d.DeviceProblem != 45; /* CM_PROB_PHANTOM */
    }
#else
    /* Enum kayıt defteri hayalet/önceden bağlanmış aygıtlar içerebilir.
     * Çökme riski taşıyan belgelenmemiş NtPlugPlayControl varsayılan olarak
     * çağrılmaz; bu modda mevcutluk filtresi yaklaşık olarak uygulanır. */
    [[nodiscard]] inline bool is_present(const std::wstring& instance_id) {
        (void)instance_id;
        return true;
    }
#endif

    /* Kayıt defteri okunamazsa nullptr */
    [[nodiscard]] inline const std::vector<Device>* all() {
        static bool ok = false;
        static std::vector<Device> devices;
        static const bool once = [] {
#if defined(NT_ENABLE_UNDOCUMENTED_PNP_CONTROL)
            struct PrivilegeScope {
                BOOLEAN previous_enabled = 0;
                bool changed = false;

                PrivilegeScope() noexcept {
                    changed = success(RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, 1, 0,
                                                         &previous_enabled));
                }
                ~PrivilegeScope() {
                    if (changed) {
                        BOOLEAN ignored = 0;
                        (void)RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, previous_enabled, 0,
                                                 &ignored);
                    }
                }
            } privilege_scope; /* Ayrıcalığı yalnızca PnP taraması boyunca etkin tut. */
#endif

            const std::wstring root = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum";
            Registry::Key kroot;
            if (!kroot.open(root)) return false;

            for (const auto& bus : kroot.subkeys()) {
                Registry::Key kbus;
                if (!kbus.open(root + L"\\" + bus)) continue;
                for (const auto& dev : kbus.subkeys()) {
                    Registry::Key kdev;
                    if (!kdev.open(root + L"\\" + bus + L"\\" + dev)) continue;
                    for (const auto& inst : kdev.subkeys()) {
                        const std::wstring rel  = bus + L"\\" + dev + L"\\" + inst;
                        Registry::Key ki;
                        if (!ki.open(root + L"\\" + rel)) continue;

                        auto desc = ki.string(L"FriendlyName");
                        if (!desc || desc->empty()) desc = ki.string(L"DeviceDesc");
                        if (!desc || desc->empty()) continue;
                        if (!is_present(rel)) continue;

                        Device d;
                        d.instance_id = Registry::to_utf8(rel.data(), rel.size());
                        d.class_guid  = lower(ki.string(L"ClassGUID").value_or(""));
                        d.name        = resolve_desc(*desc);
                        d.hw_id       = ki.multi_first(L"HardwareID").value_or("");
                        devices.push_back(std::move(d));
                    }
                }
            }
            ok = true;
            return true;
        }();
        (void)once;
        return ok ? &devices : nullptr;
    }

} // namespace DeviceDb


/* =================================================================
 * Analyzer (Analizör) — Soyut temel sınıf.
 * ================================================================= */
class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void analyze(CompatReport& report) = 0;

protected:
    [[nodiscard]] static CompatItem* new_item(CompatReport& r) { return r.add_item(); }

    /* Returns whether the device database was readable; each analyzer tracks class matches. */
    static bool enumerate_devices(std::string_view class_guid,
                                  const std::function<void(std::string_view name, std::string_view hw_id)>& callback) {
        const auto* list = DeviceDb::all();
        if (!list) return false;
        for (const auto& d : *list)
            if (d.class_guid == class_guid)
                callback(d.name, d.hw_id);
        return true;
    }
};


/* =================================================================
 * Analizörler
 * ================================================================= */

namespace CpuInfo {

    enum class Architecture { X86, X64, ARM, ARM64, IA64, Unknown };

    [[nodiscard]] inline Architecture architecture() noexcept {
        SYSTEM_PROCESSOR_INFORMATION spi{};
        /* WOW64/emülasyon altında bile gerçek (native) mimariyi verir */
        if (!success(RtlGetNativeSystemInformation(SystemProcessorInformation, &spi, sizeof(spi), nullptr)))
            return Architecture::Unknown;

        switch (spi.ProcessorArchitecture) {
            case 0:  return Architecture::X86;     /* PROCESSOR_ARCHITECTURE_INTEL */
            case 9:  return Architecture::X64;     /* AMD64 */
            case 5:  return Architecture::ARM;
            case 12: return Architecture::ARM64;
            case 6:  return Architecture::IA64;
            default: return Architecture::Unknown;
        }
    }

    [[nodiscard]] inline const char* architecture_name(Architecture arch) noexcept {
        switch (arch) {
            case Architecture::X86:   return "x86";
            case Architecture::X64:   return "x86-64";
            case Architecture::ARM:   return "ARM32";
            case Architecture::ARM64: return "ARM64";
            case Architecture::IA64:  return "IA-64";
            default:                  return "Unknown";
        }
    }

    [[nodiscard]] inline std::string processor_registry_string(const wchar_t* value_name) {
        return Registry::read_string(
            L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            value_name
        ).value_or("");
    }

    /* PF_* kimlikleri (KUSER_SHARED_DATA.ProcessorFeatures indeksleri) */
    inline constexpr unsigned PF_ARM_V8               = 29;
    inline constexpr unsigned PF_ARM_V8_CRYPTO        = 30;
    inline constexpr unsigned PF_ARM_V8_CRC32         = 31;
    inline constexpr unsigned PF_ARM_V81_ATOMIC       = 34;
    inline constexpr unsigned PF_ARM_SVE              = 46;
    inline constexpr unsigned PF_ARM_SVE2             = 47;
    inline constexpr unsigned PF_AVX                  = 39;
    inline constexpr unsigned PF_AVX2                 = 40;
    inline constexpr unsigned PF_SSE2                 = 10;
    inline constexpr unsigned PF_VIRT_FIRMWARE        = 21;

    [[nodiscard]] inline bool feature(unsigned id) noexcept { return Proc::processor_feature(id); }

}

class CpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        using namespace CpuInfo;

        const Architecture arch = architecture();
        const std::string arch_name = architecture_name(arch);

        const std::string processor_name = processor_registry_string(L"ProcessorNameString");
        const std::string vendor         = processor_registry_string(L"VendorIdentifier");
        const std::string identifier     = processor_registry_string(L"Identifier");

        const uint32_t cores = Proc::active_processor_count();

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category = std::string(CAT_CPU);
        it.critical = true;
        it.name = !processor_name.empty()
        ? processor_name
        : (!vendor.empty() ? vendor : std::string("CPU (") + arch_name + ")");

        switch (arch) {
            case Architecture::X86:
            case Architecture::X64: {
                const bool has_sse2 = feature(PF_SSE2);
                const bool has_avx  = feature(PF_AVX);
                const bool has_avx2 = feature(PF_AVX2);
                const bool has_vt   = feature(PF_VIRT_FIRMWARE);

                it.score = (arch == Architecture::X64) ? CompatScore::FULL : CompatScore::MAYBE;
                it.detail = std::format(
                    "{} | Architecture: {} | Vendor: {} | {} logical cores | SSE2:{}  AVX:{}  AVX2:{}  HW virtualization:{}{}",
                    !processor_name.empty() ? processor_name : std::string("x86 CPU"),
                    arch_name,
                    !vendor.empty() ? vendor : "unknown",
                    cores,
                    has_sse2 ? "Yes" : "No",
                    has_avx  ? "Yes" : "No",
                    has_avx2 ? "Yes" : "No",
                    has_vt   ? "Available" : "Not reported",
                    identifier.empty() ? "" : std::string(" | Identifier: ") + identifier
                );
                it.recommendation = (arch == Architecture::X64)
                    ? "Excellent Linux support. Any mainstream x86-64 distribution should work well."
                    : "A 32-bit x86 system was detected. Verify that the chosen distribution still provides a supported 32-bit image; many mainstream releases now focus on x86-64.";
                break;
            }

            case Architecture::ARM:
            case Architecture::ARM64: {
                const bool armv8  = feature(PF_ARM_V8);
                const bool crypto = feature(PF_ARM_V8_CRYPTO);
                const bool crc32  = feature(PF_ARM_V8_CRC32);
                const bool atom   = feature(PF_ARM_V81_ATOMIC);
                const bool sve    = feature(PF_ARM_SVE);
                const bool sve2   = feature(PF_ARM_SVE2);

                it.score = (arch == Architecture::ARM64) ? CompatScore::FULL : CompatScore::MAYBE;
                it.detail = std::format(
                    "{} | Architecture: {} | Vendor: {} | {} logical cores | ARMv8:{}  Crypto:{}  CRC32:{}  ARMv8.1 atomics:{}  SVE:{}  SVE2:{}",
                    !processor_name.empty() ? processor_name : std::string("ARM CPU"),
                    arch_name,
                    !vendor.empty() ? vendor : "unknown",
                    cores,
                    armv8 ? "Yes" : "No",
                    crypto ? "Yes" : "No",
                    crc32 ? "Yes" : "No",
                    atom ? "Yes" : "No",
                    sve ? "Yes" : "No",
                    sve2 ? "Yes" : "No"
                );
                it.recommendation = (arch == Architecture::ARM64)
                    ? "ARM64 Linux is broadly supported, but package and driver availability depends on the exact SoC/device. Prefer an image built for your ARM64 platform."
                    : "A 32-bit ARM system was detected. Support varies significantly by board and distribution; verify that an actively maintained image exists for this exact device.";
                break;
            }

            default:
                it.score = CompatScore::MAYBE;
                it.detail = std::format(
                    "Architecture: {} | Vendor: {} | {} logical cores",
                    arch_name,
                    !vendor.empty() ? vendor : "unknown",
                    cores
                );
                it.recommendation =
                "This CPU architecture is not specifically covered by the checker. Verify Linux kernel and distribution support for the target platform.";
                break;
        }
    }
};

class RamAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        SYSTEM_BASIC_INFORMATION sbi{};
        unsigned long long total_mb = 0;
        const bool memory_query_ok =
            success(NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), nullptr)) &&
            sbi.PageSize > 0 && sbi.NumberOfPhysicalPages > 0;
        if (memory_query_ok) {
            total_mb = static_cast<unsigned long long>(sbi.NumberOfPhysicalPages) *
                       static_cast<unsigned long long>(sbi.PageSize) / (1024ULL * 1024);
        }
        const unsigned long long total_gb = total_mb / 1024;

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category    = std::string(CAT_RAM);
        it.name        = memory_query_ok
            ? std::format("System memory: {} MB ({} GB)", total_mb, total_gb)
            : "System memory: unable to query";
        it.critical    = true;

        if (!memory_query_ok) {
            it.score          = CompatScore::MAYBE;
            it.detail         = "NtQuerySystemInformation(SystemBasicInformation) failed or returned invalid memory values.";
            it.recommendation = "Verify the Windows environment and rerun the checker; memory capacity could not be determined.";
        } else if (total_mb < 2048) {
            it.score          = CompatScore::NONE;
            it.detail         = std::format("Only {} MB of RAM detected; most Linux desktop environments need at least 1–2 GB.", total_mb);
            it.recommendation = "At least 4 GB of RAM is recommended. Consider lightweight distributions such as Lubuntu, Xubuntu, or Alpine Linux.";
        } else if (total_mb < 4096) {
            it.score          = CompatScore::MINOR;
            it.detail         = std::format("{} MB of RAM detected; sufficient for basic desktop use.", total_mb);
            it.recommendation = "Prefer distributions using lightweight desktop environments such as Xfce, LXQt, or MATE.";
        } else {
            it.score          = CompatScore::FULL;
            it.detail         = std::format("{} MB ({} GB) of RAM; excellent for desktop workloads.", total_mb, total_gb);
            it.recommendation = "You should be able to run desktop environments such as GNOME or KDE Plasma and use virtual machines comfortably.";
        }
    }
};

class StorageAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        const wchar_t letter = Proc::system_drive_letter();

        /* Boş/toplam alan: kök dizini aç, FileFsFullSizeInformation sor */
        unsigned long long total_bytes = 0, free_bytes = 0;
        bool disk_space_ok = false;
        {
            std::wstring root = L"\\??\\";
            root.push_back(letter);
            root.append(L":\\");
            HANDLE h = Io::open_nt(root, FILE_READ_ATTRIBUTES_ | SYNCHRONIZE_, FILE_SHARE_ALL,
                                   FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            if (h) {
                IO_STATUS_BLOCK io{};
                FILE_FS_FULL_SIZE_INFORMATION fs{};
                const NTSTATUS st = NtQueryVolumeInformationFile(h, &io, &fs, sizeof(fs), FileFsFullSizeInformation);
                if (success(st)) {
                    const unsigned long long unit =
                        static_cast<unsigned long long>(fs.SectorsPerAllocationUnit) * fs.BytesPerSector;
                    total_bytes   = static_cast<unsigned long long>(fs.TotalAllocationUnits) * unit;
                    free_bytes    = static_cast<unsigned long long>(fs.CallerAvailableAllocationUnits) * unit;
                    disk_space_ok = true;
                }
                NtClose(h);
            }
        }

        const unsigned long long total_gb = total_bytes / (1024ULL * 1024 * 1024);
        const unsigned long long free_gb  = free_bytes  / (1024ULL * 1024 * 1024);

        bool is_ssd  = false;
        bool is_nvme = false;
        bool storage_class_known = false;

        /*
         * PhysicalDrive0'ı sabit varsaymak yanlış olurdu. Önce sistem birimini
         * (\??\C:) açıp IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS ile hangi fiziksel
         * diske ait olduğunu öğreniyoruz.
         */
        ULONG phys_drive_number = 0;
        bool phys_drive_known = false;
        {
            std::wstring vol = L"\\??\\";
            vol.push_back(letter);
            vol.append(L":");
            HANDLE hVol = Io::open_nt(vol, FILE_READ_ATTRIBUTES_ | SYNCHRONIZE_, FILE_SHARE_ALL,
                                      FILE_SYNCHRONOUS_IO_NONALERT);
            if (hVol) {
                alignas(8) char ext_buf[sizeof(VOLUME_DISK_EXTENTS) + 3 * sizeof(DISK_EXTENT)]{};
                if (Io::ioctl(hVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, ext_buf, sizeof(ext_buf))) {
                    const auto* vde = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(ext_buf);
                    if (vde->NumberOfDiskExtents > 0) {
                        phys_drive_number = vde->Extents[0].DiskNumber;
                        phys_drive_known = true;
                    }
                }
                NtClose(hVol);
            }
        }

        std::wstring drive_path = L"\\??\\PhysicalDrive";
        drive_path.append(std::to_wstring(phys_drive_number));
        HANDLE hDisk = phys_drive_known
            ? Io::open_nt(drive_path, FILE_READ_ATTRIBUTES_ | SYNCHRONIZE_, FILE_SHARE_ALL,
                          FILE_SYNCHRONOUS_IO_NONALERT)
            : nullptr;
        if (hDisk) {
            STORAGE_PROPERTY_QUERY         spq_seek{};
            DEVICE_SEEK_PENALTY_DESCRIPTOR dsp{};
            spq_seek.PropertyId = StorageDeviceSeekPenaltyProperty;
            spq_seek.QueryType  = PropertyStandardQuery;
            if (Io::ioctl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq_seek, sizeof(spq_seek), &dsp, sizeof(dsp))) {
                is_ssd = !dsp.IncursSeekPenalty;
                storage_class_known = true;
            }

            STORAGE_PROPERTY_QUERY spq_desc{};
            spq_desc.PropertyId = StorageDeviceProperty;
            spq_desc.QueryType  = PropertyStandardQuery;
            alignas(8) char desc_buf[2048]{};
            if (Io::ioctl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq_desc, sizeof(spq_desc), desc_buf, sizeof(desc_buf))) {
                const auto* desc = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(desc_buf);
                is_nvme = (desc->BusType == BusTypeNvme);
            }
            NtClose(hDisk);
        }

        const char* drive_type = is_nvme
        ? "NVMe SSD"
        : is_ssd
        ? "SSD"
        : storage_class_known
        ? "Mechanical hard drive (HDD)"
        : "Storage type could not be determined";

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category    = std::string(CAT_DISK);
        it.name        = std::format("System drive: {} GB total / {} GB free  [{}]", total_gb, free_gb, drive_type);
        it.critical    = true;

        if (!disk_space_ok) {
            it.score          = CompatScore::MAYBE;
            it.detail         = "Free space on the system drive could not be read with NtQueryVolumeInformationFile.";
            it.recommendation = "Make sure the Windows system drive is accessible, then run the application as Administrator.";
        } else if (free_gb < 20) {
            it.score          = CompatScore::NONE;
            it.detail         = std::format("{} GB free; a Linux installation generally needs at least 20 GB.", free_gb);
            it.recommendation = "Free space on the system drive or choose another disk or partition for the installation.";
        } else if (free_gb < 50) {
            it.score          = CompatScore::MINOR;
            it.detail         = std::format("{} GB free; installation is possible, but storage space is tight.", free_gb);
            it.recommendation = "Allocating 50 GB or more is recommended for a comfortable experience with applications and games.";
        } else {
            it.score  = CompatScore::FULL;
            it.detail = std::format("{} GB free; there is ample space for Linux and your data.", free_gb);
            if (is_nvme)
                it.recommendation = "Linux should run very quickly on an NVMe SSD. Consider Ext4 or Btrfs as the filesystem.";
            else if (is_ssd)
                it.recommendation = "An SSD should provide fast startup. Ext4 is a suitable filesystem choice.";
            else
                it.recommendation = "Linux may run more slowly on a mechanical hard drive. Consider configuring adequate swap space.";
        }
    }
};

class GpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool matched = false;
        const bool enumerated = enumerate_devices(CLS_DISPLAY, [&](std::string_view name, std::string_view hw_id) {
            matched = true;
            auto has = [&](std::string_view s) { return DeviceDb::icontains(name, s); };
            auto has_id = [&](std::string_view s) { return DeviceDb::icontains(hw_id, s); };

            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category    = std::string(CAT_GPU);
            it.name        = std::string(name);
            it.critical    = true;

            const bool is_nvidia  = has("NVIDIA") || has("GeForce") || has("Quadro") || has("RTX") || has("GTX") || has_id("VEN_10DE");
            const bool is_amd_gpu = has("AMD")    || has("Radeon")  || has("RX ") || has_id("VEN_1002");
            const bool is_intel_g = has("Intel")  || has("UHD")     || has("Iris") || has("Arc") || has_id("VEN_8086");
            const bool is_virtual = has("VMware") || has("VirtualBox") || has("Microsoft Basic Render") || has("SVGA");

            if (is_nvidia) {
                it.score          = CompatScore::MINOR;
                it.detail         = std::format("NVIDIA graphics card: {}", name);
                it.recommendation = "Install NVIDIA proprietary drivers. Nouveau support is limited. Ubuntu, Linux Mint, or Pop!_OS can simplify this setup.";
            } else if (is_amd_gpu) {
                it.score          = CompatScore::FULL;
                it.detail         = std::format("AMD graphics card: {}", name);
                it.recommendation = "AMDGPU is well supported by the kernel. Expect good out-of-the-box performance.";
            } else if (is_intel_g) {
                it.score          = CompatScore::FULL;
                it.detail         = std::format("Intel graphics device: {}", name);
                it.recommendation = "Intel i915/xe kernel driver works well with both Wayland and X11.";
            } else if (is_virtual) {
                it.score          = CompatScore::MINOR;
                it.detail         = std::format("Virtual/emulated display adapter: {}", name);
                it.recommendation = "A virtual environment is detected. Run on physical hardware to verify your GPU compatibility.";
            } else {
                it.score          = CompatScore::MAYBE;
                it.detail         = std::format("Unknown graphics card: {}", name);
                it.recommendation = "Search online for 'Linux + [GPU model] driver' to verify support.";
            }
        });

        if (!enumerated || !matched) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_GPU);
            itp->name           = enumerated ? "No display adapter found" : "Display adapters could not be enumerated";
            itp->critical       = true;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = enumerated
                ? "No display-class device was found in the enumerated device tree."
                : "The device enumeration tree (Enum registry key) could not be opened.";
            itp->recommendation = enumerated
                ? "Check whether a display adapter is enabled and detected by Windows."
                : "Try running the application as Administrator.";
        }
    }
};

class NetworkAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool matched = false;
        const bool enumerated = enumerate_devices(CLS_NET, [&](std::string_view name, std::string_view hw_id) {
            auto has = [&](std::string_view s) { return DeviceDb::icontains(name, s); };

            if (has("Microsoft") || has("WAN Miniport") || has("Bluetooth") || has("Loopback")) return;
            matched = true;

            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category    = std::string(CAT_NET);
            it.name        = std::string(name);

            const bool is_intel_net = has("Intel") || DeviceDb::icontains(hw_id, "VEN_8086");
            const bool is_realtek   = has("Realtek") || DeviceDb::icontains(hw_id, "VEN_10EC");
            const bool is_broadcom  = has("Broadcom") || DeviceDb::icontains(hw_id, "VEN_14E4");
            const bool is_atheros   = has("Atheros") || has("Killer") || DeviceDb::icontains(hw_id, "VEN_168C") || DeviceDb::icontains(hw_id, "VEN_1969");
            const bool is_mediatek  = has("MediaTek") || has("Ralink") || DeviceDb::icontains(hw_id, "VEN_14C3") || DeviceDb::icontains(hw_id, "VEN_1814");
            const bool is_wifi      = has("Wi-Fi") || has("Wireless") || has("WLAN");

            if (is_intel_net) {
                it.score  = CompatScore::FULL;
                it.detail = std::format("{} adapter: {}", is_wifi ? "Intel Wi-Fi" : "Intel Ethernet", name);
                it.recommendation = is_wifi ? "Intel Wi-Fi (iwlwifi) has excellent Linux kernel support." : "Intel Ethernet is fully supported in the kernel.";
            } else if (is_realtek) {
                it.score  = CompatScore::MINOR;
                it.detail = std::format("Realtek {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = is_wifi ? "Realtek Wi-Fi may require an external DKMS driver package." : "Realtek Ethernet (r8169) usually works reliably.";
            } else if (is_broadcom) {
                it.score  = CompatScore::MAYBE;
                it.detail = std::format("Broadcom {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = "Broadcom adapters can be problematic on Linux. Use a wired connection during install.";
            } else if (is_atheros) {
                it.score  = CompatScore::FULL;
                it.detail = std::format("Atheros/Killer {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = "Atheros and Killer adapters typically work well with ath10k/ath11k drivers.";
            } else if (is_mediatek) {
                it.score  = CompatScore::MINOR;
                it.detail = std::format("MediaTek/Ralink {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = "MediaTek (mt76) support is in the kernel, but very new chips may need extra firmware.";
            } else {
                it.score  = CompatScore::MAYBE;
                it.detail = std::format("{}: {}  [HWID: {}]", is_wifi ? "Wi-Fi" : "Network adapter", name, hw_id.substr(0, std::min(hw_id.size(), std::size_t{80})));
                it.recommendation = "Check the hardware ID on the vendor website or linux-hardware.org for compatibility.";
            }
        });

        if (!enumerated || !matched) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_NET);
            itp->name           = enumerated ? "No suitable network adapter found" : "Network adapters could not be enumerated";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = enumerated
                ? "No non-virtual network adapter remained after filtering."
                : "The device enumeration tree (Enum registry key) could not be opened.";
            itp->recommendation = enumerated
                ? "Check whether a physical network adapter is enabled and detected by Windows."
                : "Try running the application as Administrator.";
        }
    }
};

class AudioAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool matched = false;
        const bool enumerated = enumerate_devices(CLS_MEDIA, [&](std::string_view name, std::string_view /*hw_id*/) {
            auto has = [&](std::string_view s) { return DeviceDb::icontains(name, s); };

            if (has("Virtual") || has("Microsoft")) return;
            matched = true;

            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category    = std::string(CAT_AUDIO);
            it.name        = std::string(name);

            const bool is_hda       = has("Realtek") || has("Intel") || has("AMD") || has("Nvidia");
            const bool is_focusrite = has("Focusrite") || has("Scarlett");
            const bool is_creative  = has("Creative")  || has("Sound Blaster");

            if (is_hda) {
                it.score          = CompatScore::FULL;
                it.detail         = std::format("HDA-compatible audio codec: {}", name);
                it.recommendation = "Should work with ALSA, PulseAudio, or PipeWire without extra configuration.";
            } else if (is_focusrite) {
                it.score          = CompatScore::MINOR;
                it.detail         = std::format("USB audio interface: {}", name);
                it.recommendation = "Focusrite devices usually work well. Use JACK or PipeWire for professional audio.";
            } else if (is_creative) {
                it.score          = CompatScore::MAYBE;
                it.detail         = std::format("Creative sound card: {}", name);
                it.recommendation = "Some Sound Blaster DSP or equalizer features may not be supported on Linux.";
            } else {
                it.score          = CompatScore::MINOR;
                it.detail         = std::format("Audio device: {}", name);
                it.recommendation = "Most standard USB or Bluetooth audio devices are recognized automatically on Linux.";
            }
        });

        if (!enumerated || !matched) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_AUDIO);
            itp->name           = enumerated ? "No suitable audio device found" : "Audio devices could not be enumerated";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = enumerated
                ? "No non-virtual audio device remained after filtering."
                : "Unable to retrieve the media device list.";
            itp->recommendation = enumerated
                ? "Check whether an audio device is enabled and detected by Windows."
                : "Try running the application as Administrator.";
        }
    }
};

class FirmwareAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        /* Firmware türünü sorgu ve kayıt defteri ikisi de doğrulayamıyorsa bilinmiyor bırak. */
        std::optional<bool> is_uefi;
        {
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbe{};
            if (success(NtQuerySystemInformation(SystemBootEnvironmentInformation, &sbe, sizeof(sbe), nullptr)) &&
                (sbe.FirmwareType == 1 || sbe.FirmwareType == 2)) {
                is_uefi = (sbe.FirmwareType == 2);
            } else {
                const auto firmware_type = Registry::read_dword(
                    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control", L"PEFirmwareType");
                if (firmware_type && (*firmware_type == 1 || *firmware_type == 2))
                    is_uefi = (*firmware_type == 2);
            }
        }

        /* Secure Boot: sorgu başarısızsa bunu otomatik olarak DISABLED sayma. */
        std::optional<bool> secure_boot;
        {
            SYSTEM_SECUREBOOT_INFORMATION ssi{};
            if (success(NtQuerySystemInformation(SystemSecureBootInformation, &ssi, sizeof(ssi), nullptr))) {
                secure_boot = (ssi.SecureBootEnabled != 0);
            } else {
                const auto registry_value = Registry::read_dword(
                    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                    L"UEFISecureBootEnabled");
                if (registry_value) secure_boot = (*registry_value != 0);
            }
        }

        /* TPM: aygıt ağacı okunamazsa "yok" sonucu çıkarma. */
        std::optional<bool> has_tpm;
        if (const auto* list = DeviceDb::all()) {
            has_tpm = false;
            for (const auto& d : *list) {
                if (DeviceDb::icontains(d.hw_id, "MSFT0101") || DeviceDb::icontains(d.hw_id, "MSFT0200") ||
                    DeviceDb::icontains(d.name, "Trusted Platform Module") ||
                    DeviceDb::icontains(d.name, "TPM")) {
                    has_tpm = true;
                    break;
                }
            }
        }

        const std::wstring_view bios_key = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS";
        const std::string bios_ver    = Registry::read_string(bios_key, L"BIOSVersion").value_or("");
        const std::string bios_vendor = Registry::read_string(bios_key, L"BIOSVendor").value_or("");

        /* UEFI / BIOS */
        {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category    = std::string(CAT_FW);
            const char* boot_type = !is_uefi ? "Unknown" : (*is_uefi ? "UEFI" : "Legacy BIOS");
            it.name        = std::format("Boot type: {}  |  BIOS: {} {}", boot_type, bios_vendor, bios_ver);
            it.critical    = true;

            if (!is_uefi) {
                it.score          = CompatScore::MAYBE;
                it.detail         = "The firmware boot type could not be determined from the NT API or registry.";
                it.recommendation = "Verify whether Windows was booted in UEFI or Legacy BIOS mode before choosing the Linux installer mode.";
            } else if (*is_uefi) {
                it.score          = CompatScore::FULL;
                it.detail         = "UEFI firmware boot detected. GRUB2 and systemd-boot installers commonly support this mode.";
                it.recommendation = "Install Linux in UEFI mode and ensure the EFI System Partition is selected.";
            } else {
                it.score          = CompatScore::MINOR;
                it.detail         = "Legacy BIOS boot detected. Linux can be installed, but GPT boot and Secure Boot options may be limited.";
                it.recommendation = "Use a partitioning/boot configuration supported by the firmware; MBR may be required on legacy-only systems.";
            }
        }

        /* Güvenli Önyükleme (Secure Boot) */
        {
            CompatItem* itp2 = new_item(report);
            if (!itp2) return;
            CompatItem& it = *itp2;
            it.category    = std::string(CAT_SB);
            it.name        = std::format("Secure Boot: {}", !secure_boot ? "UNKNOWN" : (*secure_boot ? "ENABLED" : "DISABLED"));
            it.critical    = false;

            if (!secure_boot) {
                it.score          = CompatScore::MAYBE;
                it.detail         = "Secure Boot status could not be determined from the NT API or registry.";
                it.recommendation = "Check Secure Boot status in the firmware setup or Windows System Information.";
            } else if (*secure_boot) {
                it.score          = CompatScore::MINOR;
                it.detail         = "Secure Boot is currently ENABLED. Many distributions support it, but custom bootloaders or unsigned modules may need additional steps.";
                it.recommendation = "Check the target distribution's Secure Boot documentation before disabling it.";
            } else {
                it.score          = CompatScore::FULL;
                it.detail         = "Secure Boot is reported as disabled. Most Linux distributions should boot without Secure Boot restrictions.";
                it.recommendation = "No action is required unless you want to enable Secure Boot after installation.";
            }
        }

        /* TPM */
        {
            CompatItem* itp3 = new_item(report);
            if (!itp3) return;
            CompatItem& it    = *itp3;
            it.category       = std::string(CAT_TPM);
            it.name           = std::format("Trusted Platform Module (TPM): {}",
                                            !has_tpm ? "Unknown" : (*has_tpm ? "Present" : "Not detected"));
            it.critical       = false;
            if (!has_tpm) {
                it.score          = CompatScore::MAYBE;
                it.detail         = "The device registry could not be enumerated, so TPM presence could not be verified.";
                it.recommendation = "Check TPM status in Windows Security or firmware settings.";
            } else {
                it.score          = CompatScore::FULL;
                it.detail         = *has_tpm ? "TPM is present — it can be managed with tpm2-tools on Linux."
                                             : "No TPM device was detected in the enumerated device tree.";
                it.recommendation = "TPM can be used for LUKS encryption keys or Secure Boot workflows if desired.";
            }
        }
    }
};

class PowerAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        SYSTEM_BATTERY_STATE sbs{};
        if (!success(NtPowerInformation(SystemBatteryState, nullptr, 0, &sbs, sizeof(sbs))))
            return;
        if (!sbs.BatteryPresent) return;                 // Masaüstü ise atla

        const int pct = (sbs.MaxCapacity > 0)
            ? std::clamp(static_cast<int>(static_cast<unsigned long long>(sbs.RemainingCapacity) * 100 / sbs.MaxCapacity), 0, 100)
            : 0;
        const bool on_ac = (sbs.AcOnLine != 0);

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it    = *itp;
        it.category       = std::string(CAT_POWER);
        it.name           = std::format("Battery: %{}  |  Power source: {}", pct, on_ac ? "AC adapter" : "Running on battery");
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = "A laptop battery was detected. Power management behaves differently on Linux than on Windows.";
        it.recommendation = "Install TLP or power-profiles-daemon after setup to improve battery life.";
    }
};

class VirtualizationAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        /* PF_VIRT_FIRMWARE_ENABLED: donanım sanallaştırma açık ve Windows'a sunuluyor demektir;
         * bir sanal makinede çalıştığımızı tek başına KANITLAMAZ. */
        if (!Proc::processor_feature(CpuInfo::PF_VIRT_FIRMWARE))
            return;

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category       = std::string(CAT_VIRT);
        it.name           = "Hardware virtualization available";
        it.critical       = false;
        it.score          = CompatScore::FULL;
        it.detail         = "Windows reports that hardware virtualization is enabled and available to the operating system.";
        it.recommendation = "Linux KVM/QEMU, Hyper-V based workflows, and other virtualization features can use the available hardware virtualization support.";
    }
};


/* =================================================================
 * ReportPrinter — Çıktı formatlama
 * ================================================================= */
class ReportPrinter {
public:
    void print(CompatReport& report) {
        report.compute();

        Out::print("\n{}{}════════════════════════════════════════════════════════════════\n{}", CYAN, BOLD, RESET);
        Out::print("{}{}  📋 DETAILED HARDWARE COMPATIBILITY REPORT\n{}", BOLD, WHITE, RESET);
        Out::print("{}{}════════════════════════════════════════════════════════════════\n\n{}", CYAN, BOLD, RESET);

        constexpr std::array categories{
            CAT_CPU, CAT_RAM, CAT_DISK, CAT_GPU, CAT_NET,
            CAT_AUDIO, CAT_FW, CAT_SB, CAT_TPM, CAT_POWER, CAT_VIRT
        };

        for (const auto& cat : categories) {
            bool header_printed = false;

            for (const auto& it : report.items) {
                if (it.category != cat) continue;

                if (!header_printed) {
                    Out::print("{}{}  ┌─ {}\n{}", BLUE, BOLD, cat, RESET);
                    header_printed = true;
                }

                Out::print("  │  {}  {}  {}\n", Console::score_icon(it.score), Console::score_label(it.score), it.name);
                Out::print("  │     {}→ {}\n{}", DIM, it.detail, RESET);
                Out::print("  │     {}✦ {}\n{}", CYAN, it.recommendation, RESET);
                Out::print("  │\n");
            }
        }

        Out::print("\n{}{}════════════════════════════════════════════════════════════════\n{}", CYAN, BOLD, RESET);
        Out::print("{}{}  📊 SUMMARY STATISTICS\n{}", BOLD, WHITE, RESET);
        Out::print("{}{}════════════════════════════════════════════════════════════════\n\n{}", CYAN, BOLD, RESET);

        Out::print("  {}●{}  Fully compatible         : {} items\n",  GREEN,  RESET, report.score_counts[0]);
        Out::print("  {}◑{}  Compatible (minor)      : {} items\n",  YELLOW, RESET, report.score_counts[1]);
        Out::print("  {}◔{}  Maybe incompatible      : {} items\n",  ORANGE, RESET, report.score_counts[2]);
        Out::print("  {}○{}  Incompatible            : {} items\n",  RED,    RESET, report.score_counts[3]);
        Out::print("\n  Total compatibility score:\n  ");
        Console::print_percent_bar(report.overall_percent, 40);
        Out::print("\n\n");

        Out::print("{}{}  🧭 OVERALL ASSESSMENT AND RESULT\n\n{}", BOLD, WHITE, RESET);
        if (report.overall_percent >= 85.0) {
            Out::print("{}{}  ✅ Your system is READY for Linux!\n{}", GREEN, BOLD, RESET);
            Out::print("     You can use Ubuntu, Fedora, Mint, or most mainstream distros without much hassle.\n");
        } else if (report.overall_percent >= 65.0) {
            Out::print("{}{}  ⚠️  Your system is LARGELY compatible with Linux.\n{}", YELLOW, BOLD, RESET);
            Out::print("     Some devices may require manual driver setup after installation.\n");
            Out::print("     Ubuntu LTS or Linux Mint are usually easiest for this setup.\n");
        } else if (report.overall_percent >= 40.0) {
            Out::print("{}{}  🔶 Compatibility is MODERATE.\n{}", ORANGE, BOLD, RESET);
            Out::print("     Several components may not work out of the box. Test from a live USB before installing.\n");
        } else {
            Out::print("{}{}  ❌ Your system has serious compatibility issues.\n{}", RED, BOLD, RESET);
            Out::print("     Installing Linux on this machine may not be suitable for daily use.\n");
        }

        Out::print("\n{}{}  🐧 DISTRIBUTION RECOMMENDATIONS\n\n{}", BOLD, WHITE, RESET);
        Out::print("     1. Ubuntu LTS         — wide driver support and easy installation.\n");
        Out::print("     2. Linux Mint         — familiar layout for Windows users and beginner friendly.\n");
        Out::print("     3. Fedora             — current kernel and strong hardware support.\n");
        Out::print("     4. Pop!_OS           — convenient NVIDIA setup when supported by the current release.\n");
        Out::print("     5. EndeavourOS       — Arch-based choice for advanced users who want full control.\n");

        Out::print("\n{}{}════════════════════════════════════════════════════════════════\n{}", CYAN, BOLD, RESET);
        Out::print("{}  Linux Compatibility Checker v2.2 (NT API)  |  linux-hardware.org\n{}", DIM, RESET);
        Out::print("{}{}════════════════════════════════════════════════════════════════\n\n{}", CYAN, BOLD, RESET);
        Out::flush();
    }
};


/* =================================================================
 * Tarama adımları tanımlamaları (Adımlar ve Yükleme Barları)
 * ================================================================= */
struct StepMeta {
    const char* label    = nullptr;
    int         steps    = 0;
    int         delay_ms = 0;
};

inline constexpr std::array<StepMeta, 9> PIPELINE_STEPS{{
    { "Step 1/9: CPU analysis in progress          ",  8, 30 },
    { "Step 2/9: Memory (RAM) analysis            ",  6, 25 },
    { "Step 3/9: Disk and storage analysis        ",  7, 35 },
    { "Step 4/9: Graphics (GPU) scan              ",  9, 40 },
    { "Step 5/9: Networking inspection            ",  8, 35 },
    { "Step 6/9: Audio device inspection          ",  6, 30 },
    { "Step 7/9: Firmware / UEFI check            ",  7, 25 },
    { "Step 8/9: Power and battery status         ",  4, 20 },
    { "Step 9/9: Virtualization environment       ",  4, 20 },
}};


/* =================================================================
 * Komut satırı — PEB->ProcessParameters->CommandLine
 * ================================================================= */
namespace CmdLine {

    /* CommandLineToArgvW kurallarının (çift tırnak / ters bölü) sade uygulaması */
    [[nodiscard]] inline std::vector<std::wstring> args() {
        std::vector<std::wstring> out;
        auto* p = Proc::params();
        if (!p || !p->CommandLine.Buffer) return out;

        const std::wstring_view s(p->CommandLine.Buffer, p->CommandLine.Length / sizeof(wchar_t));
        std::wstring cur;
        bool in_token = false, in_quotes = false;

        for (std::size_t i = 0; i < s.size(); ++i) {
            const wchar_t c = s[i];
            if (c == L'\\') {
                std::size_t n = 0;
                while (i < s.size() && s[i] == L'\\') { ++n; ++i; }
                if (i < s.size() && s[i] == L'"') {
                    cur.append(n / 2, L'\\');
                    if (n % 2) cur.push_back(L'"'); else in_quotes = !in_quotes;
                } else {
                    cur.append(n, L'\\');
                    --i;
                }
                in_token = true;
            } else if (c == L'"') {
                in_quotes = !in_quotes;
                in_token = true;
            } else if ((c == L' ' || c == L'\t') && !in_quotes) {
                if (in_token) { out.push_back(std::move(cur)); cur.clear(); in_token = false; }
            } else {
                cur.push_back(c);
                in_token = true;
            }
        }
        if (in_token) out.push_back(std::move(cur));
        return out;
    }

} // namespace CmdLine

[[nodiscard]] static bool save_text_file(const std::wstring& dos_path, const std::string& text) {
    UNICODE_STRING nt_path{};
    if (!RtlDosPathNameToNtPathName_U(dos_path.c_str(), &nt_path, nullptr, nullptr))
        return false;

    const HANDLE h = Io::open_nt(std::wstring_view(nt_path.Buffer, nt_path.Length / sizeof(wchar_t)),
                                 FILE_GENERIC_WRITE_ | SYNCHRONIZE_, 1 /*FILE_SHARE_READ*/,
                                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_OVERWRITE_IF);
    RtlFreeUnicodeString(&nt_path);
    if (!h) return false;

    const bool ok = Io::write_all(h, text.data(), text.size());
    NtClose(h);
    return ok;
}


/* =================================================================
 * ANA UYGULAMA (ENTRY POINT)
 * ================================================================= */
int main() {
    if (!Elevation::is_process_elevated()) {
        Out::print("This tool requires administrator privileges.\n"
                   "Embed the administrator manifest when building the EXE (which triggers UAC), or choose 'Run as administrator'.\n"
                   "Press Enter to exit...\n");
        In::wait_enter();
        return 1;
    }

    std::wstring save_path;
    {
        const auto argv = CmdLine::args();
        for (std::size_t i = 1; i < argv.size(); ++i)
            if (argv[i] == L"--save" && i + 1 < argv.size())
                save_path = argv[++i];
    }

    Console::enable_ansi();
    Console::print_header();

    std::string os_name = Registry::read_string(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                                L"ProductName").value_or("Windows");
    {   /* Windows 11 kayıt defterinde hâlâ "Windows 10 ..." yazar; build >= 22000 ise düzelt */
        const auto build_str = Registry::read_string(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                                     L"CurrentBuildNumber").value_or("0");
        int build = 0;
        for (char c : build_str) { if (c < '0' || c > '9') break; build = build * 10 + (c - '0'); }
        if (build >= 22000 && os_name.rfind("Windows 10", 0) == 0)
            os_name.replace(0, 10, "Windows 11");
    }

    const std::string computer_name = Registry::read_string(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
        L"ComputerName").value_or("?");

    const TIME_FIELDS st = Time::local_now();

    Out::print("{}  Computer name  : {}\n{}", DIM, computer_name, RESET);
    Out::print("{}  OS version     : {}\n{}", DIM, os_name, RESET);
    Out::print("{}  Date / time    : {:02}/{:02}/{:04}  {:02}:{:02}\n\n{}", DIM, st.Day, st.Month, st.Year, st.Hour, st.Minute, RESET);

    /* Analizörleri sırala */
    std::vector<std::unique_ptr<Analyzer>> analyzers;
    analyzers.reserve(PIPELINE_STEPS.size());
    analyzers.push_back(std::make_unique<CpuAnalyzer>());
    analyzers.push_back(std::make_unique<RamAnalyzer>());
    analyzers.push_back(std::make_unique<StorageAnalyzer>());
    analyzers.push_back(std::make_unique<GpuAnalyzer>());
    analyzers.push_back(std::make_unique<NetworkAnalyzer>());
    analyzers.push_back(std::make_unique<AudioAnalyzer>());
    analyzers.push_back(std::make_unique<FirmwareAnalyzer>());
    analyzers.push_back(std::make_unique<PowerAnalyzer>());
    analyzers.push_back(std::make_unique<VirtualizationAnalyzer>());

    if (analyzers.size() != PIPELINE_STEPS.size()) return 2;   /* sayılar eşleşmeli */

    CompatReport report;

    /* Taramaları yürüt */
    for (std::size_t i = 0; i < analyzers.size(); ++i) {
        const StepMeta& meta = PIPELINE_STEPS[i];
        if (meta.label)
            Console::loading_bar(meta.label, meta.steps, meta.delay_ms);
        analyzers[i]->analyze(report);
    }

    Out::print("\n");
    ReportPrinter printer;
    printer.print(report);

    if (!save_path.empty()) {
        std::string txt;
        txt += "Linux Compatibility Checker v2.2 (NT API) — Report\n";
        txt += std::format("Computer name : {}\n", computer_name);
        txt += std::format("OS version    : {}\n", os_name);
        txt += std::format("Date          : {:02}/{:02}/{:04}  {:02}:{:02}\n\n", st.Day, st.Month, st.Year, st.Hour, st.Minute);

        constexpr const char* score_text[] = {
            "[0] FULLY COMPATIBLE",
            "[1] COMPATIBLE (minor)",
            "[2] MAYBE INCOMPATIBLE",
            "[3] INCOMPATIBLE"
        };
        for (const auto& item : report.items) {
            const int s = static_cast<int>(item.score);
            txt += std::format("{:<26}  {:<30}  {}\n", item.category, score_text[s], item.name);
            txt += std::format("  → {}\n", item.detail);
            txt += std::format("  ✦ {}\n\n", item.recommendation);
        }
        txt += std::format("Overall compatibility score: %{:.1f}\n", report.overall_percent);
        txt += std::format("Fully compatible: {} | Compatible (minor): {} | Maybe incompatible: {} | Incompatible: {}\n",
                           report.score_counts[0], report.score_counts[1], report.score_counts[2], report.score_counts[3]);

        if (save_text_file(save_path, txt))
            Out::print("{}  ✓ Report saved to file.\n{}", GREEN, RESET);
        else
            Out::print("{}  ✗ Failed to save report to file.\n{}", RED, RESET);
        Out::flush();
    }

    Out::print("  Press Enter to exit...\n");
    In::wait_enter();
    return 0;
}
