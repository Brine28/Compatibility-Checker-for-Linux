/*
 * Linux Kernel Compatibility Checker for Windows 11
 * ===================================================
 * Scans hardware and system configuration to evaluate
 * Linux migration readiness and produces a scored report.
 *
 * Scores: 0=Fully Compatible | 1=Compatible (minor issues)
 *         2=Possibly Incompatible | 3=Incompatible
 *
 * Compile (MSVC):
 *   cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest
 *      /link advapi32.lib setupapi.lib winhttp.lib
 *
 * Compile (GCC / MinGW):
 *   g++ linux_compat_checker.cpp -o linux_compat_checker.exe -std=c++23
 *       -ladvapi32 -lsetupapi -lwinhttp
 */

#define _WIN32_WINNT 0x0A00   /* Windows 10+ */
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <initguid.h>
#include <setupapi.h>
#include <devguid.h>
#include <winhttp.h>
#include <intrin.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <format>        /* C++20 */
#include <vector>
#include <array>
#include <memory>
#include <optional>
#include <functional>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "winhttp.lib")

/* ─── ANSI color codes (requires Windows 10+ virtual terminal) ─── */
/* FIX: replaced #define macros with inline constexpr const char*.
   string_view won't work here because printf needs null-terminated
   C strings and these are used in string literal concatenation. */
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

/* ─── Category name constants ─── */
inline constexpr std::string_view CAT_CPU    = "CPU";
inline constexpr std::string_view CAT_RAM    = "RAM";
inline constexpr std::string_view CAT_DISK   = "Disk";
inline constexpr std::string_view CAT_GPU    = "GPU";
inline constexpr std::string_view CAT_NET    = "Network Card";
inline constexpr std::string_view CAT_AUDIO  = "Audio Card";
inline constexpr std::string_view CAT_FW     = "Firmware";
inline constexpr std::string_view CAT_SB     = "Secure Boot";
inline constexpr std::string_view CAT_TPM    = "TPM";
inline constexpr std::string_view CAT_POWER  = "Power/Battery";
inline constexpr std::string_view CAT_VIRT   = "Virtualization";
inline constexpr std::string_view CAT_ONLINE = "Online";

/* ─── Compatibility score levels ─── */
enum class CompatScore : int {
    FULL  = 0,   /* Fully compatible, no action needed     */
    MINOR = 1,   /* Compatible but minor issues may occur  */
    MAYBE = 2,   /* Possibly incompatible, check carefully */
    NONE  = 3    /* Incompatible, serious issues expected  */
};

/* ─── Capacity limit ─── */
inline constexpr int MAX_DEVICES = 256;


/* =================================================================
   CompatItem — per-component compatibility record
   ================================================================= */
struct CompatItem {
    std::string  name;
    std::string  category;
    std::string  detail;
    std::string  recommendation;
    CompatScore  score    = CompatScore::FULL;
    bool         critical = false;
};


/* =================================================================
   CompatReport — aggregated collection of CompatItem results
   ================================================================= */
class CompatReport {
public:
    std::vector<CompatItem>  items;
    std::array<int, 4>       score_counts{};
    double                   overall_percent = 0.0;

    CompatItem& add_item() {
        if (static_cast<int>(items.size()) >= MAX_DEVICES)
            return items.back();
        items.emplace_back();
        return items.back();
    }

    void compute() {
        score_counts.fill(0);
        double weighted     = 0.0;
        double total_weight = 0.0;

        for (const auto& item : items) {
            int s = static_cast<int>(item.score);
            ++score_counts[s];
            double w      = item.critical ? 2.0 : 1.0;
            double contrib = (3.0 - static_cast<double>(s)) / 3.0;
            weighted      += contrib * w;
            total_weight  += w;
        }

        overall_percent = (total_weight > 0.0)
            ? (weighted / total_weight) * 100.0
            : 0.0;
    }
};


/* =================================================================
   Registry — wrappers returning std::optional
   FIX: read_string now uses the returned 'sz' to construct the
        string, avoiding UB when the buffer is full and not
        null-terminated by the API.
   ================================================================= */
namespace Registry {

    [[nodiscard]] inline std::optional<std::string>
    read_string(HKEY root, const char* subkey, const char* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return std::nullopt;

        char  buf[256]{};
        DWORD type = REG_SZ;
        DWORD sz   = sizeof(buf);
        bool  ok   = (RegQueryValueExA(hk, value, nullptr, &type,
                                       reinterpret_cast<LPBYTE>(buf), &sz)
                      == ERROR_SUCCESS);
        RegCloseKey(hk);
        if (!ok) return std::nullopt;

        /* FIX: sz includes the null terminator when present. Strip it. */
        if (sz > 0 && buf[sz - 1] == '\0') --sz;
        return std::string(buf, sz);
    }

    [[nodiscard]] inline std::optional<DWORD>
    read_dword(HKEY root, const char* subkey, const char* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return std::nullopt;

        DWORD val{}, type = REG_DWORD, sz = sizeof(DWORD);
        bool  ok = (RegQueryValueExA(hk, value, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(&val), &sz)
                    == ERROR_SUCCESS);
        RegCloseKey(hk);
        return ok ? std::optional<DWORD>{val} : std::nullopt;
    }

} // namespace Registry


/* =================================================================
   Console — UI helpers
   FIX: ANSI codes are now constexpr const char* pointers, so we
        can no longer use string literal concatenation (e.g. CYAN "text").
        printf calls updated to use %s format specifier.
   ================================================================= */
namespace Console {

    inline void enable_ansi() {
        HANDLE h    = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD  mode = 0;
        GetConsoleMode(h, &mode);
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleOutputCP(CP_UTF8);
    }

    inline void print_header() {
        printf("\n");
        printf("%s%s╔══════════════════════════════════════════════════════════════╗\n%s", CYAN, BOLD, RESET);
        printf("%s%s║%s%s%s     🐧  Linux Kernel Compatibility Checker v2.1           %s%s║\n%s", CYAN, BOLD, RESET, BLUE, BOLD, CYAN, BOLD, RESET);
        printf("%s%s║%s%s     Windows 11 → Linux Migration Readiness Report          %s%s║\n%s", CYAN, BOLD, RESET, DIM, CYAN, BOLD, RESET);
        printf("%s%s╚══════════════════════════════════════════════════════════════╝\n%s", CYAN, BOLD, RESET);
        printf("\n");
    }

    [[nodiscard]] inline const char* score_label(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return "\033[92m\033[1m[0] FULLY COMPATIBLE     \033[0m";
            case CompatScore::MINOR: return "\033[93m\033[1m[1] COMPATIBLE (minor)   \033[0m";
            case CompatScore::MAYBE: return "\033[38;5;208m\033[1m[2] POSSIBLY INCOMPATIBLE\033[0m";
            case CompatScore::NONE:  return "\033[91m\033[1m[3] INCOMPATIBLE         \033[0m";
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
        printf("%s  ► %s%s ", CYAN, RESET, msg);
        fflush(stdout);
        for (int i = 0; i < steps; i++) {
            printf("█");
            fflush(stdout);
            Sleep(static_cast<DWORD>(delay_ms));
        }
        printf(" %s%s✓\n%s", GREEN, BOLD, RESET);
    }

    inline void print_percent_bar(double pct, int width) {
        int         filled = static_cast<int>(pct / 100.0 * static_cast<double>(width));
        const char* color  = (pct >= 75.0) ? GREEN
                           : (pct >= 50.0) ? YELLOW
                           :                 RED;
        printf("%s%s[", color, BOLD);
        for (int i = 0; i < width; i++)
            printf(i < filled ? "█" : "░");
        printf("] %.1f%%%s", pct, RESET);
    }

} // namespace Console


/* =================================================================
   Internet — connectivity check
   ================================================================= */
namespace Internet {

    [[nodiscard]] inline bool check_connection() {
        HINTERNET hSession = WinHttpOpen(
            L"LinuxCompatChecker/2.1",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(
            hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"HEAD", L"/", nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        bool ok = false;
        if (hRequest) {
            ok = WinHttpSendRequest(hRequest,
                     WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
              && WinHttpReceiveResponse(hRequest, nullptr);
            WinHttpCloseHandle(hRequest);
        }

        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return ok;
    }

} // namespace Internet


/* =================================================================
   Analyzer — abstract base class.
   FIX (DRY): Added enumerate_devices() helper to eliminate the
   repeated SetupAPI boilerplate in Gpu/Network/AudioAnalyzer.
   The callback receives a std::string_view of the device name.
   ================================================================= */
class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void analyze(CompatReport& report) = 0;

protected:
    [[nodiscard]] static CompatItem& new_item(CompatReport& r) { return r.add_item(); }

    /* Enumerate present devices of the given class GUID and invoke
       'callback' for each device name found. Returns false if the
       device info set could not be opened (caller may report an error). */
    static bool enumerate_devices(
        const GUID* cls_guid,
        const std::function<void(std::string_view name, std::string_view hw_id)>& callback)
    {
        HDEVINFO devInfo = SetupDiGetClassDevsA(cls_guid, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return false;

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char name_buf[512]{};
        char hwid_buf[512]{};
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                    SPDRP_DEVICEDESC, nullptr,
                    reinterpret_cast<PBYTE>(name_buf), sizeof(name_buf), nullptr))
                continue;

            hwid_buf[0] = '\0';
            SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                SPDRP_HARDWAREID, nullptr,
                reinterpret_cast<PBYTE>(hwid_buf), sizeof(hwid_buf), nullptr);

            callback(std::string_view{name_buf}, std::string_view{hwid_buf});
        }

        SetupDiDestroyDeviceInfoList(devInfo);
        return true;
    }
};


/* =================================================================
   CpuAnalyzer
   ================================================================= */
class CpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        int info[4]{};
        __cpuid(info, 0);

        union { int i[3]; char c[12]; } vendor_raw{};
        vendor_raw.i[0] = info[1];
        vendor_raw.i[1] = info[3];
        vendor_raw.i[2] = info[2];
        std::string vendor(vendor_raw.c, 12);

        char brand[49]{};
        __cpuid(info, 0x80000000);
        if (static_cast<unsigned>(info[0]) >= 0x80000004u) {
            __cpuid(info, 0x80000002); memcpy(brand,      info, 16);
            __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
            __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
        }

        __cpuid(info, 1);
        const bool has_vmx  = (info[2] >> 5)  & 1;
        const bool has_sse2 = (info[3] >> 26) & 1;
        const bool has_avx  = (info[2] >> 28) & 1;

        __cpuid(info, 0x80000001);
        const bool has_svm = (info[2] >> 2) & 1;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const DWORD cores = si.dwNumberOfProcessors;

        const bool is_intel = vendor.contains("GenuineIntel");  /* C++23 */
        const bool is_amd   = vendor.contains("AuthenticAMD");

        CompatItem& it = new_item(report);
        it.category    = std::string(CAT_CPU);
        it.name        = brand[0] ? brand : vendor;
        it.critical    = true;

        if (is_intel || is_amd) {
            it.score = CompatScore::FULL;
            /* FIX: std::format instead of chained string concatenation */
            it.detail = std::format("{} {} | {} logical cores | SSE2:{}  AVX:{}  VT-x/AMD-V:{}",
                is_intel ? "Intel" : "AMD",
                brand[0] ? brand : "",
                cores,
                has_sse2 ? "Yes" : "No",
                has_avx  ? "Yes" : "No",
                (is_intel ? has_vmx : has_svm) ? "Yes" : "No");
            it.recommendation = "Excellent Linux support. Any distribution will work seamlessly.";
        } else {
            it.score  = CompatScore::MAYBE;
            it.detail = std::format("Non-x86 processor detected: vendor='{}', {} logical cores",
                vendor, cores);
            it.recommendation = "ARM Linux support is improving, but some x86-only software "
                                "may not run. Consider Ubuntu ARM or Fedora ARM.";
        }
    }
};


/* =================================================================
   RamAnalyzer
   ================================================================= */
class RamAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);

        const unsigned long long total_mb = ms.ullTotalPhys / (1024ULL * 1024);
        const unsigned long long total_gb = total_mb / 1024;

        CompatItem& it = new_item(report);
        it.category    = std::string(CAT_RAM);
        it.name        = std::format("System Memory: {} MB ({} GB)", total_mb, total_gb);
        it.critical    = true;

        if (total_mb < 2048) {
            it.score          = CompatScore::NONE;
            it.detail         = std::format("Only {} MB RAM detected — Linux requires at least 1 GB to boot.", total_mb);
            it.recommendation = "At least 4 GB is recommended. "
                                "Try ultra-lightweight distros such as Lubuntu or Alpine Linux.";
        } else if (total_mb < 4096) {
            it.score          = CompatScore::MINOR;
            it.detail         = std::format("{} MB RAM available — sufficient for basic desktop use.", total_mb);
            it.recommendation = "Use lightweight desktop environments such as Xfce or LXQt.";
        } else {
            it.score          = CompatScore::FULL;
            it.detail         = std::format("{} MB ({} GB) RAM — excellent for any desktop workload.", total_mb, total_gb);
            it.recommendation = "All desktop environments and virtualization will run comfortably.";
        }
    }
};


/* =================================================================
   StorageAnalyzer
   ================================================================= */
class StorageAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        ULARGE_INTEGER free_bytes{}, total_bytes{};
        GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, nullptr);
        const unsigned long long total_gb = total_bytes.QuadPart / (1024ULL * 1024 * 1024);
        const unsigned long long free_gb  = free_bytes.QuadPart  / (1024ULL * 1024 * 1024);

        bool is_ssd  = false;
        bool is_nvme = false;

        HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);

        if (hDisk != INVALID_HANDLE_VALUE) {
            DWORD bytes_returned = 0;

            STORAGE_PROPERTY_QUERY        spq_seek{};
            DEVICE_SEEK_PENALTY_DESCRIPTOR dsp{};
            spq_seek.PropertyId = StorageDeviceSeekPenaltyProperty;
            spq_seek.QueryType  = PropertyStandardQuery;
            if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                                &spq_seek, sizeof(spq_seek),
                                &dsp, sizeof(dsp),
                                &bytes_returned, nullptr))
                is_ssd = !dsp.IncursSeekPenalty;

            STORAGE_PROPERTY_QUERY spq_desc{};
            spq_desc.PropertyId = StorageDeviceProperty;
            spq_desc.QueryType  = PropertyStandardQuery;
            char desc_buf[2048]{};
            if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                                &spq_desc, sizeof(spq_desc),
                                desc_buf, sizeof(desc_buf),
                                &bytes_returned, nullptr)) {
                auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(desc_buf);
                is_nvme = (desc->BusType == BusTypeNvme);
            }

            CloseHandle(hDisk);
        }

        const char* drive_type = is_nvme ? "NVMe SSD" : is_ssd ? "SATA SSD" : "HDD";

        CompatItem& it = new_item(report);
        it.category    = std::string(CAT_DISK);
        it.name        = std::format("Storage: {} GB total / {} GB free  [{}]", total_gb, free_gb, drive_type);
        it.critical    = true;

        if (free_gb < 20) {
            it.score          = CompatScore::NONE;
            it.detail         = std::format("Free space: {} GB — Linux installation requires at least 20 GB.", free_gb);
            it.recommendation = "Free up disk space or install Linux on a separate drive.";
        } else if (free_gb < 50) {
            it.score          = CompatScore::MINOR;
            it.detail         = std::format("Free space: {} GB — installation is possible but headroom is limited.", free_gb);
            it.recommendation = "Minimum viable migration. 50+ GB is recommended for comfortable use.";
        } else {
            it.score  = CompatScore::FULL;
            it.detail = std::format("Free space: {} GB — ample room for installation and data.", free_gb);
            if (is_nvme)
                it.recommendation = "NVMe SSD + ample space = blazing fast Linux experience. "
                                    "Use Ext4 or Btrfs. Consider enabling zstd compression with Btrfs.";
            else if (is_ssd)
                it.recommendation = "SATA SSD + ample space = fast Linux experience. Use Ext4 or Btrfs.";
            else
                it.recommendation = "HDD may feel slow. Prefer Ext4 and add a swap partition.";
        }
    }
};


/* =================================================================
   GpuAnalyzer
   FIX (DRY): now uses enumerate_devices() helper.
   FIX (C++23): lambda replaced with std::string_view::contains.
   FIX: INVALID_HANDLE_VALUE now reports a CompatScore::MAYBE item
        instead of silently returning.
   ================================================================= */
class GpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_DISPLAY,
            [&](std::string_view name, std::string_view /*hw_id*/) {
                auto has = [&](std::string_view s) { return name.contains(s); };

                CompatItem& it = new_item(report);
                it.category    = std::string(CAT_GPU);
                it.name        = std::string(name);
                it.critical    = true;

                const bool is_nvidia  = has("NVIDIA") || has("GeForce") || has("Quadro")
                                     || has("RTX")    || has("GTX");
                const bool is_amd_gpu = has("AMD")    || has("Radeon")  || has("RX ");
                const bool is_intel_g = has("Intel")  || has("UHD")     || has("Iris") || has("Arc");
                const bool is_virtual = has("VMware") || has("VirtualBox")
                                     || has("Microsoft Basic Render") || has("SVGA");

                if (is_nvidia) {
                    it.score          = CompatScore::MINOR;
                    it.detail         = std::format("NVIDIA GPU: {}", name);
                    it.recommendation = "Install the proprietary NVIDIA driver (nvidia-driver package). "
                                        "The open-source Nouveau driver is limited. "
                                        "Ubuntu and Fedora make this easy via the GUI. "
                                        "Wayland support improved significantly in driver 510+.";
                } else if (is_amd_gpu) {
                    it.score          = CompatScore::FULL;
                    it.detail         = std::format("AMD GPU: {}", name);
                    it.recommendation = "Excellent in-kernel AMDGPU support — no extra drivers needed. "
                                        "Full Wayland and Vulkan support out of the box. "
                                        "GPU compute available via ROCm on supported cards.";
                } else if (is_intel_g) {
                    it.score          = CompatScore::FULL;
                    it.detail         = std::format("Intel GPU: {}", name);
                    it.recommendation = "In-kernel i915/xe driver provides excellent support. "
                                        "Fully compatible with both Wayland and X11.";
                } else if (is_virtual) {
                    it.score          = CompatScore::MINOR;
                    it.detail         = std::format("Virtual/emulated display adapter: {}", name);
                    it.recommendation = "Virtual environment detected. "
                                        "The real GPU will be used when installed on physical hardware.";
                } else {
                    it.score          = CompatScore::MAYBE;
                    it.detail         = std::format("Unrecognized GPU: {}", name);
                    it.recommendation = "Search 'Linux + [GPU name] driver' to verify support.";
                }
            });

        /* FIX: report failure instead of silently returning */
        if (!found) {
            CompatItem& it    = new_item(report);
            it.category       = std::string(CAT_GPU);
            it.name           = "GPU enumeration failed";
            it.critical       = true;
            it.score          = CompatScore::MAYBE;
            it.detail         = "Could not open display device info set (SetupAPI error).";
            it.recommendation = "Run as administrator or check SetupAPI availability.";
        }
    }
};


/* =================================================================
   NetworkAnalyzer
   FIX (DRY): now uses enumerate_devices() helper.
   FIX (C++23): string_view::contains.
   FIX: silent failure reported.
   ================================================================= */
class NetworkAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_NET,
            [&](std::string_view name, std::string_view hw_id) {
                auto has = [&](std::string_view s) { return name.contains(s); };

                if (has("Microsoft") || has("WAN Miniport") ||
                    has("Bluetooth") || has("Loopback"))
                    return;

                CompatItem& it = new_item(report);
                it.category    = std::string(CAT_NET);
                it.name        = std::string(name);

                const bool is_intel_net = has("Intel");
                const bool is_realtek   = has("Realtek");
                const bool is_broadcom  = has("Broadcom");
                const bool is_atheros   = has("Atheros") || has("Killer");
                const bool is_mediatek  = has("MediaTek") || has("Ralink");
                const bool is_wifi      = has("Wi-Fi") || has("Wireless") || has("WLAN");

                if (is_intel_net) {
                    it.score  = CompatScore::FULL;
                    it.detail = std::format("{} adapter: {}", is_wifi ? "Intel Wi-Fi" : "Intel Ethernet", name);
                    it.recommendation = is_wifi
                        ? "Intel Wi-Fi has excellent Linux support via the iwlwifi in-kernel driver."
                        : "Intel Ethernet fully supported in-kernel (e1000e / igb / ixgbe).";
                } else if (is_realtek) {
                    it.score  = CompatScore::MINOR;
                    it.detail = std::format("Realtek {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                    it.recommendation = is_wifi
                        ? "Realtek Wi-Fi may need an out-of-tree driver (rtl88xx series). "
                          "Install via the dkms package from the manufacturer's GitHub."
                        : "Realtek Ethernet generally works (r8169 driver), "
                          "but a small number of models have quirks.";
                } else if (is_broadcom) {
                    it.score  = CompatScore::MAYBE;
                    it.detail = std::format("Broadcom {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                    it.recommendation = "Broadcom adapters can be troublesome on Linux. "
                                        "The b43 or broadcom-sta driver is required and may not be "
                                        "available during installation (no internet access).";
                } else if (is_atheros) {
                    it.score  = CompatScore::FULL;
                    it.detail = std::format("Atheros/Killer {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                    it.recommendation = "Atheros/Killer adapters are fully supported in-kernel "
                                        "via ath10k / ath11k drivers.";
                } else if (is_mediatek) {
                    it.score  = CompatScore::MINOR;
                    it.detail = std::format("MediaTek/Ralink {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                    it.recommendation = "MediaTek mt76 driver is in-kernel but older chipsets "
                                        "may require a firmware package.";
                } else {
                    it.score  = CompatScore::MAYBE;
                    it.detail = std::format("{}: {}  [HWID: {}]",
                        is_wifi ? "Wi-Fi" : "Network Adapter",
                        name,
                        hw_id.substr(0, 80));
                    it.recommendation = "Check the manufacturer's site or linux-hardware.org "
                                        "for driver availability.";
                }
            });

        if (!found) {
            CompatItem& it    = new_item(report);
            it.category       = std::string(CAT_NET);
            it.name           = "Network adapter enumeration failed";
            it.critical       = false;
            it.score          = CompatScore::MAYBE;
            it.detail         = "Could not open network device info set (SetupAPI error).";
            it.recommendation = "Run as administrator or check SetupAPI availability.";
        }
    }
};


/* =================================================================
   AudioAnalyzer
   FIX (DRY): now uses enumerate_devices() helper.
   FIX (C++23): string_view::contains.
   FIX: silent failure reported.
   ================================================================= */
class AudioAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_MEDIA,
            [&](std::string_view name, std::string_view /*hw_id*/) {
                auto has = [&](std::string_view s) { return name.contains(s); };

                if (has("Virtual") || has("Microsoft")) return;

                CompatItem& it = new_item(report);
                it.category    = std::string(CAT_AUDIO);
                it.name        = std::string(name);

                const bool is_hda       = has("Realtek") || has("Intel") || has("AMD") || has("Nvidia");
                const bool is_focusrite = has("Focusrite") || has("Scarlett");
                const bool is_creative  = has("Creative")  || has("Sound Blaster");

                if (is_hda) {
                    it.score          = CompatScore::FULL;
                    it.detail         = std::format("HDA-compatible audio device: {}", name);
                    it.recommendation = "Fully compatible with ALSA / PulseAudio / PipeWire "
                                        "via the in-kernel snd_hda_intel driver.";
                } else if (is_focusrite) {
                    it.score          = CompatScore::MINOR;
                    it.detail         = std::format("USB audio interface: {}", name);
                    it.recommendation = "Focusrite generally works on Linux. "
                                        "Scarlett Gen 2/3/4 are well-supported. "
                                        "Use JACK or PipeWire for pro-audio workflows.";
                } else if (is_creative) {
                    it.score          = CompatScore::MAYBE;
                    it.detail         = std::format("Creative audio device: {}", name);
                    it.recommendation = "Creative Sound Blaster cards have limited Linux support; "
                                        "some DSP features will not function.";
                } else {
                    it.score          = CompatScore::MINOR;
                    it.detail         = std::format("Audio device: {}", name);
                    it.recommendation = "USB and Bluetooth audio devices generally work "
                                        "out of the box on Linux.";
                }
            });

        if (!found) {
            CompatItem& it    = new_item(report);
            it.category       = std::string(CAT_AUDIO);
            it.name           = "Audio device enumeration failed";
            it.critical       = false;
            it.score          = CompatScore::MAYBE;
            it.detail         = "Could not open media device info set (SetupAPI error).";
            it.recommendation = "Run as administrator or check SetupAPI availability.";
        }
    }
};


/* =================================================================
   FirmwareAnalyzer
   ================================================================= */
class FirmwareAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        const auto pe_fw       = Registry::read_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control", "PEFirmwareType");
        const bool is_uefi     = (pe_fw.value_or(0) == 2);

        const auto sb_val      = Registry::read_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            "UEFISecureBootEnabled");
        const bool secure_boot = (sb_val.value_or(0) != 0);

        bool has_tpm = false;
        {
            HDEVINFO tpmDev = SetupDiGetClassDevsA(nullptr, "ROOT\\TPM", nullptr,
                DIGCF_PRESENT | DIGCF_ALLCLASSES);
            if (tpmDev != INVALID_HANDLE_VALUE) {
                SP_DEVINFO_DATA td{};
                td.cbSize = sizeof(td);
                has_tpm   = SetupDiEnumDeviceInfo(tpmDev, 0, &td);
                SetupDiDestroyDeviceInfoList(tpmDev);
            }
        }

        const std::string bios_ver    = Registry::read_string(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion").value_or("");
        const std::string bios_vendor = Registry::read_string(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor").value_or("");

        /* UEFI / BIOS */
        {
            CompatItem& it = new_item(report);
            it.category    = std::string(CAT_FW);
            it.name        = std::format("Boot mode: {}  |  BIOS: {} {}",
                is_uefi ? "UEFI" : "Legacy BIOS", bios_vendor, bios_ver);
            it.critical    = true;

            if (is_uefi) {
                it.score          = CompatScore::FULL;
                it.detail         = "UEFI firmware detected. Modern bootloaders (GRUB2, systemd-boot) "
                                    "require a UEFI system.";
                it.recommendation = "Install Linux in UEFI mode. "
                                    "An EFI System Partition (ESP) will be created.";
            } else {
                it.score          = CompatScore::MINOR;
                it.detail         = "Legacy BIOS detected. Linux can be installed but some features "
                                    "(GPT, secure boot) are unavailable.";
                it.recommendation = "Use an MBR partition scheme during installation.";
            }
        }

        /* Secure Boot */
        {
            CompatItem& it = new_item(report);
            it.category    = std::string(CAT_SB);
            it.name        = std::format("Secure Boot: {}", secure_boot ? "Enabled" : "Disabled");
            it.critical    = false;

            if (secure_boot) {
                it.score          = CompatScore::MINOR;
                it.detail         = "Secure Boot is enabled. Some distros support it; "
                                    "others require it disabled.";
                it.recommendation = "Ubuntu, Fedora, and openSUSE work with Secure Boot. "
                                    "Disable it in BIOS/UEFI settings before installing "
                                    "Arch, Gentoo, or Void.";
            } else {
                it.score          = CompatScore::FULL;
                it.detail         = "Secure Boot is disabled — all Linux distributions "
                                    "will boot without issues.";
                it.recommendation = "No action needed. Any distribution can be installed.";
            }
        }

        /* TPM */
        {
            CompatItem& it    = new_item(report);
            it.category       = std::string(CAT_TPM);
            it.name           = std::format("TPM: {}", has_tpm ? "Present" : "Not detected");
            it.critical       = false;
            it.score          = CompatScore::FULL;
            it.detail         = has_tpm
                ? "TPM chip present — accessible on Linux via tpm2-tools."
                : "No TPM chip detected.";
            it.recommendation = "TPM can be used with LUKS full-disk encryption on Linux.";
        }
    }
};


/* =================================================================
   PowerAnalyzer
   ================================================================= */
class PowerAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        SYSTEM_POWER_STATUS sps{};
        GetSystemPowerStatus(&sps);

        if (sps.BatteryFlag == 128 || sps.BatteryFlag == 255) return;

        const int  pct   = (sps.BatteryLifePercent == 255) ? 0 : sps.BatteryLifePercent;
        const bool on_ac = (sps.ACLineStatus == 1);

        CompatItem& it    = new_item(report);
        it.category       = std::string(CAT_POWER);
        it.name           = std::format("Battery: {}%  |  Power source: {}", pct, on_ac ? "AC adapter" : "Battery");
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = "Laptop detected. Linux power management works differently from Windows.";
        it.recommendation = "Install TLP or power-profiles-daemon after setup. "
                            "Sleep/suspend may need a kernel parameter tweak on some laptops.";
    }
};


/* =================================================================
   VirtualizationAnalyzer
   ================================================================= */
class VirtualizationAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        int info[4]{};
        __cpuid(info, 1);
        if (!((info[2] >> 31) & 1)) return;

        union { int i[3]; char c[12]; } hv_raw{};
        __cpuid(info, 0x40000000);
        hv_raw.i[0] = info[1];
        hv_raw.i[1] = info[2];
        hv_raw.i[2] = info[3];
        const std::string hv_name(hv_raw.c, 12);

        CompatItem& it    = new_item(report);
        it.category       = std::string(CAT_VIRT);
        it.name           = std::format("Virtual Machine Detected: {}", hv_name);
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = std::format("Hypervisor: {} — this analysis is running inside a virtual environment.", hv_name);
        it.recommendation = "Results reflect the virtual hardware profile, not the physical host. "
                            "Re-run the tool on bare metal for an accurate assessment.";
    }
};


/* =================================================================
   OnlineAnalyzer
   FIX: WinHttpReadData now loops until all data is received instead
        of reading only once (incomplete read bug).
   FIX: kernel version parsing uses std::string find/substr instead
        of sscanf + char buffer.
   ================================================================= */
class OnlineAnalyzer : public Analyzer {
public:
    explicit OnlineAnalyzer(bool online) : m_online(online) {}

    void analyze(CompatReport& report) override {
        if (!m_online) return;

        HINTERNET hSession = WinHttpOpen(L"LinuxCompatChecker/2.1",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;

        HINTERNET hConnect = WinHttpConnect(
            hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        HINTERNET hRequest = hConnect
            ? WinHttpOpenRequest(hConnect, L"GET", L"/finger_banner",
                  nullptr, WINHTTP_NO_REFERER,
                  WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
            : nullptr;

        std::string raw_body;

        if (hRequest
         && WinHttpSendRequest(hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
         && WinHttpReceiveResponse(hRequest, nullptr)) {

            /* FIX: loop until WinHttpReadData returns 0 bytes (end of response) */
            char   chunk[512]{};
            DWORD  bytes_read = 0;
            while (WinHttpReadData(hRequest, chunk, sizeof(chunk) - 1, &bytes_read)
                   && bytes_read > 0) {
                chunk[bytes_read] = '\0';
                raw_body += chunk;
            }
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        /* FIX: parse with std::string::find + substr, no sscanf/char buffer */
        std::string kernel_ver;
        {
            const std::string marker = "stable";
            auto pos = raw_body.find(marker);
            if (pos != std::string::npos) {
                pos = raw_body.find(": ", pos);
                if (pos != std::string::npos) {
                    pos += 2;  /* skip ": " */
                    auto end = raw_body.find_first_of(" \t\r\n", pos);
                    kernel_ver = raw_body.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
                }
            }
        }

        if (kernel_ver.empty()) return;

        CompatItem& it    = new_item(report);
        it.category       = std::string(CAT_ONLINE);
        it.name           = std::format("Latest Stable Kernel: {}  (source: kernel.org)", kernel_ver);
        it.critical       = false;
        it.score          = CompatScore::FULL;
        it.detail         = std::format("Kernel {} is the current stable release. "
                            "Hardware compatibility is evaluated against this version's driver set.",
                            kernel_ver);
        it.recommendation = "Choose a distribution that ships or allows installation of "
                            "a recent kernel for the best hardware coverage.";
    }

private:
    bool m_online;
};


/* =================================================================
   ReportPrinter
   ================================================================= */
class ReportPrinter {
public:
    explicit ReportPrinter(bool online) : m_online(online) {}

    void print(CompatReport& report) {
        report.compute();

        printf("\n%s%s════════════════════════════════════════════════════════════════\n%s", CYAN, BOLD, RESET);
        printf("%s%s  📋 DETAILED COMPATIBILITY REPORT\n%s", BOLD, WHITE, RESET);
        printf("%s%s════════════════════════════════════════════════════════════════\n\n%s", CYAN, BOLD, RESET);

        constexpr std::array categories{
            CAT_CPU, CAT_RAM, CAT_DISK, CAT_GPU, CAT_NET,
            CAT_AUDIO, CAT_FW, CAT_SB, CAT_TPM,
            CAT_POWER, CAT_VIRT, CAT_ONLINE
        };

        for (const auto& cat : categories) {
            bool header_printed = false;

            for (const auto& it : report.items) {
                if (it.category != cat) continue;

                if (!header_printed) {
                    printf("%s%s  ┌─ %.*s\n%s", BLUE, BOLD,
                           static_cast<int>(cat.size()), cat.data(), RESET);
                    header_printed = true;
                }

                printf("  │  %s  %s  %s\n",
                       Console::score_icon(it.score),
                       Console::score_label(it.score),
                       it.name.c_str());
                printf("  │     %s→ %s\n%s", DIM, it.detail.c_str(), RESET);
                printf("  │     %s✦ %s\n%s", CYAN, it.recommendation.c_str(), RESET);
                printf("  │\n");
            }
        }

        printf("\n%s%s════════════════════════════════════════════════════════════════\n%s", CYAN, BOLD, RESET);
        printf("%s%s  📊 SUMMARY STATISTICS\n%s", BOLD, WHITE, RESET);
        printf("%s%s════════════════════════════════════════════════════════════════\n\n%s", CYAN, BOLD, RESET);

        printf("  %s●%s  Fully Compatible         : %d component(s)\n",  GREEN,  RESET, report.score_counts[0]);
        printf("  %s◑%s  Compatible (minor issues): %d component(s)\n",  YELLOW, RESET, report.score_counts[1]);
        printf("  %s◔%s  Possibly Incompatible    : %d component(s)\n",  ORANGE, RESET, report.score_counts[2]);
        printf("  %s○%s  Incompatible             : %d component(s)\n",  RED,    RESET, report.score_counts[3]);
        printf("\n  Total components analyzed: %d\n", static_cast<int>(report.items.size()));

        printf("\n  Overall Compatibility Score:\n  ");
        Console::print_percent_bar(report.overall_percent, 40);
        printf("\n\n");

        printf("%s%s  🧭 GENERAL ASSESSMENT\n\n%s", BOLD, WHITE, RESET);
        if (report.overall_percent >= 85.0) {
            printf("%s%s  ✅ Your system is READY for Linux!\n%s", GREEN, BOLD, RESET);
            printf("     Ubuntu, Fedora, Mint, or any major distribution will work seamlessly.\n");
        } else if (report.overall_percent >= 65.0) {
            printf("%s%s  ⚠️  Your system is MOSTLY compatible with Linux.\n%s", YELLOW, BOLD, RESET);
            printf("     A few components may need additional drivers or configuration.\n");
            printf("     Ubuntu LTS or Linux Mint is recommended for the best out-of-box experience.\n");
        } else if (report.overall_percent >= 40.0) {
            printf("%s%s  🔶 Compatibility is MODERATE.\n%s", ORANGE, BOLD, RESET);
            printf("     Several components may cause issues. Test with a live USB before committing.\n");
        } else {
            printf("%s%s  ❌ Your system has serious compatibility issues.\n%s", RED, BOLD, RESET);
            printf("     Consider hardware upgrades before migrating to Linux.\n");
        }

        printf("\n%s%s  🐧 RECOMMENDED DISTRIBUTIONS\n\n%s", BOLD, WHITE, RESET);
        printf("     1. Ubuntu 24.04 LTS  — Widest driver support, easiest installation\n");
        printf("     2. Linux Mint 22     — Windows-like interface, great for beginners\n");
        printf("     3. Fedora 40         — Latest kernel, excellent NVIDIA support\n");
        printf("     4. Pop!_OS 24.04     — Optimised for gamers and NVIDIA users\n");
        printf("     5. EndeavourOS       — Arch-based, full control over the system\n");

        printf("\n%s  🌐 Internet: %s%s\n%s", DIM,
               m_online ? GREEN : YELLOW,
               m_online ? "Connected — live data fetched from kernel.org"
                        : "Offline — local analysis only",
               RESET);

        printf("\n%s%s════════════════════════════════════════════════════════════════\n%s", CYAN, BOLD, RESET);
        printf("%s  Linux Kernel Compatibility Checker v2.1  |  linux-hardware.org\n%s", DIM, RESET);
        printf("%s%s════════════════════════════════════════════════════════════════\n\n%s", CYAN, BOLD, RESET);
    }

private:
    bool m_online;
};


/* =================================================================
   Pipeline step metadata
   FIX: PIPELINE_STEPS is now constexpr. The magic number '10' only
        appears in the static_assert below, not scattered elsewhere.
   ================================================================= */
struct StepMeta {
    const char* label       = nullptr;
    int         steps       = 0;
    int         delay_ms    = 0;
    bool        online_only = false;
};

inline constexpr std::array<StepMeta, 10> PIPELINE_STEPS{{
    { "Step 2/9: Analyzing CPU           ",  8, 30, false },
    { "Step 3/9: Analyzing RAM           ",  6, 25, false },
    { "Step 4/9: Analyzing Disk          ",  7, 35, false },
    { "Step 5/9: Analyzing GPU           ",  9, 40, false },
    { "Step 6/9: Analyzing Network Cards ",  8, 35, false },
    { "Step 7/9: Analyzing Audio Cards   ",  6, 30, false },
    { "Step 8/9: Analyzing Firmware/UEFI ",  7, 25, false },
    { nullptr,                               0,  0, false },   /* PowerAnalyzer       */
    { nullptr,                               0,  0, false },   /* VirtualizationAnal. */
    { "Step 9/9: Fetching kernel.org data", 12, 60, true  },
}};


/* =================================================================
   ENTRY POINT
   ================================================================= */
int main() {
    Console::enable_ansi();
    Console::print_header();

    const std::string os_name = Registry::read_string(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")
        .value_or("Windows");

    char  computer_name[256]{};
    DWORD comp_size = sizeof(computer_name);
    GetComputerNameA(computer_name, &comp_size);

    SYSTEMTIME st{};
    GetLocalTime(&st);

    printf("%s  Computer : %s\n%s", DIM, computer_name, RESET);
    printf("%s  OS       : %s\n%s", DIM, os_name.c_str(), RESET);
    printf("%s  Date     : %02d/%02d/%04d  %02d:%02d\n\n%s",
           DIM, st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, RESET);

    printf("%s  Step 1/9: %sChecking internet connection...\n", CYAN, RESET);
    const bool g_online = Internet::check_connection();
    printf("            %s%s%s\n\n",
           g_online ? GREEN : YELLOW,
           g_online ? "✓ Connected" : "✗ Offline",
           RESET);

    /* Build analyzer pipeline */
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
    analyzers.push_back(std::make_unique<OnlineAnalyzer>(g_online));

    /* FIX: pipeline size validated at compile time — no magic number */
    static_assert(PIPELINE_STEPS.size() == 10,
                  "PIPELINE_STEPS must match the number of analyzers");

    CompatReport report;

    for (std::size_t i = 0; i < analyzers.size(); ++i) {
        const StepMeta& meta = PIPELINE_STEPS[i];

        if (meta.online_only && !g_online) {
            printf("%s  Step 9/9: Offline — kernel.org step skipped.\n%s", DIM, RESET);
            continue;
        }
        if (meta.label)
            Console::loading_bar(meta.label, meta.steps, meta.delay_ms);

        analyzers[i]->analyze(report);
    }

    printf("\n");
    ReportPrinter printer(g_online);
    printer.print(report);

    printf("  Press Enter to exit...\n");
    getchar();
    return 0;
}
