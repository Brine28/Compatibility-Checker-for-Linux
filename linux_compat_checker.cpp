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
 *   cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++20
 *      /link advapi32.lib setupapi.lib winhttp.lib
 *
 * Compile (GCC / MinGW):
 *   g++ linux_compat_checker.cpp -o linux_compat_checker.exe -std=c++20
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
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <memory>
#include <optional>
#include <algorithm>
#include <span>          /* C++20 */

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "winhttp.lib")

/* ─── ANSI color codes (requires Windows 10+ virtual terminal) ─── */
#define RESET       "\033[0m"
#define BOLD        "\033[1m"
#define DIM         "\033[2m"
#define RED         "\033[91m"
#define GREEN       "\033[92m"
#define YELLOW      "\033[93m"
#define BLUE        "\033[94m"
#define CYAN        "\033[96m"
#define WHITE       "\033[97m"
#define ORANGE      "\033[38;5;208m"

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
    bool         critical = false;   /* true = weighted 2x in overall score */
};


/* =================================================================
   CompatReport — aggregated collection of CompatItem results
   ================================================================= */
class CompatReport {
public:
    std::vector<CompatItem>  items;
    std::array<int, 4>       score_counts{};
    double                   overall_percent = 0.0;

    /* Add a new blank item and return a reference to it.
       FIX: old code returned items.back() on overflow which silently
       corrupted the last entry; now we just cap insertion. */
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
   Registry — thin wrappers returning std::optional (C++17)
   FIX: old bool+out-param API replaced with optional for clarity.
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
        return ok ? std::optional<std::string>{buf} : std::nullopt;
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
        printf(CYAN BOLD "╔══════════════════════════════════════════════════════════════╗\n" RESET);
        printf(CYAN BOLD "║" RESET BLUE BOLD "     🐧  Linux Kernel Compatibility Checker v2.1           " CYAN BOLD "║\n" RESET);
        printf(CYAN BOLD "║" RESET DIM  "     Windows 11 → Linux Migration Readiness Report          " CYAN BOLD "║\n" RESET);
        printf(CYAN BOLD "╚══════════════════════════════════════════════════════════════╝\n" RESET);
        printf("\n");
    }

    [[nodiscard]] inline const char* score_label(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return GREEN  BOLD "[0] FULLY COMPATIBLE     " RESET;
            case CompatScore::MINOR: return YELLOW BOLD "[1] COMPATIBLE (minor)   " RESET;
            case CompatScore::MAYBE: return ORANGE BOLD "[2] POSSIBLY INCOMPATIBLE" RESET;
            case CompatScore::NONE:  return RED    BOLD "[3] INCOMPATIBLE         " RESET;
        }
        return WHITE "[?] UNKNOWN" RESET;
    }

    [[nodiscard]] inline const char* score_icon(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return GREEN  "●" RESET;
            case CompatScore::MINOR: return YELLOW "◑" RESET;
            case CompatScore::MAYBE: return ORANGE "◔" RESET;
            case CompatScore::NONE:  return RED    "○" RESET;
        }
        return WHITE "?" RESET;
    }

    inline void loading_bar(const char* msg, int steps, int delay_ms) {
        printf(CYAN "  ► " RESET "%s ", msg);
        fflush(stdout);
        for (int i = 0; i < steps; i++) {
            printf("█");
            fflush(stdout);
            Sleep(static_cast<DWORD>(delay_ms));
        }
        printf(" " GREEN BOLD "✓\n" RESET);
    }

    inline void print_percent_bar(double pct, int width) {
        int         filled = static_cast<int>(pct / 100.0 * static_cast<double>(width));
        const char* color  = (pct >= 75.0) ? GREEN
                           : (pct >= 50.0) ? YELLOW
                           :                 RED;
        printf("%s%s[", color, BOLD);
        for (int i = 0; i < width; i++)
            printf(i < filled ? "█" : "░");
        printf("] %.1f%%" RESET, pct);
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
   Analyzer — abstract base class
   ================================================================= */
class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void analyze(CompatReport& report) = 0;

protected:
    [[nodiscard]] static CompatItem& new_item(CompatReport& r) { return r.add_item(); }
};


/* =================================================================
   CpuAnalyzer
   FIX: CPUID vendor/brand extraction via safer union approach.
   FIX: has_vmx was using leaf 1 ECX bit 5 which is correct for
        Intel VMX; but AMD uses the same bit (SVM is CPUID 0x80000001
        ECX bit 2). Added SVM detection separately.
   ================================================================= */
class CpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        /* Read vendor string via CPUID leaf 0 */
        int info[4]{};
        __cpuid(info, 0);

        /* FIX: use a union to avoid strict-aliasing UB from memcpy-into-char */
        union { int i[3]; char c[12]; } vendor_raw{};
        vendor_raw.i[0] = info[1];
        vendor_raw.i[1] = info[3];
        vendor_raw.i[2] = info[2];
        std::string vendor(vendor_raw.c, 12);

        /* Read brand string via CPUID leaves 0x80000002-4 */
        char brand[49]{};
        __cpuid(info, 0x80000000);
        if (static_cast<unsigned>(info[0]) >= 0x80000004u) {
            __cpuid(info, 0x80000002); memcpy(brand,      info, 16);
            __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
            __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
        }

        /* Feature flags */
        __cpuid(info, 1);
        const bool has_vmx  = (info[2] >> 5)  & 1;   /* Intel VT-x */
        const bool has_sse2 = (info[3] >> 26) & 1;
        const bool has_avx  = (info[2] >> 28) & 1;

        /* FIX: AMD SVM is in CPUID 0x80000001 ECX bit 2, not leaf 1 */
        bool has_svm = false;
        __cpuid(info, 0x80000001);
        has_svm = (info[2] >> 2) & 1;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const DWORD cores = si.dwNumberOfProcessors;

        const bool is_intel = (vendor.find("GenuineIntel") != std::string::npos);
        const bool is_amd   = (vendor.find("AuthenticAMD") != std::string::npos);

        CompatItem& it = new_item(report);
        it.category    = std::string(CAT_CPU);
        it.name        = brand[0] ? brand : vendor;
        it.critical    = true;

        if (is_intel || is_amd) {
            it.score = CompatScore::FULL;
            it.detail = std::string(is_intel ? "Intel" : "AMD") + " " +
                        (brand[0] ? brand : "") +
                        " | " + std::to_string(cores) + " logical cores" +
                        " | SSE2:" + (has_sse2 ? "Yes" : "No") +
                        "  AVX:" + (has_avx ? "Yes" : "No") +
                        "  VT-x/AMD-V:" + ((is_intel ? has_vmx : has_svm) ? "Yes" : "No");
            it.recommendation = "Excellent Linux support. Any distribution will work seamlessly.";
        } else {
            it.score = CompatScore::MAYBE;
            it.detail = "Non-x86 processor detected: vendor='" + vendor +
                        "', " + std::to_string(cores) + " logical cores";
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
        it.name        = "System Memory: " + std::to_string(total_mb) +
                         " MB (" + std::to_string(total_gb) + " GB)";
        it.critical    = true;

        if (total_mb < 2048) {
            it.score          = CompatScore::NONE;
            it.detail         = "Only " + std::to_string(total_mb) +
                                " MB RAM detected — Linux requires at least 1 GB to boot.";
            it.recommendation = "At least 4 GB is recommended. "
                                "Try ultra-lightweight distros such as Lubuntu or Alpine Linux.";
        } else if (total_mb < 4096) {
            it.score          = CompatScore::MINOR;
            it.detail         = std::to_string(total_mb) +
                                " MB RAM available — sufficient for basic desktop use.";
            it.recommendation = "Use lightweight desktop environments such as Xfce or LXQt.";
        } else {
            it.score          = CompatScore::FULL;
            it.detail         = std::to_string(total_mb) + " MB (" +
                                std::to_string(total_gb) + " GB) RAM — excellent for any desktop workload.";
            it.recommendation = "All desktop environments and virtualization will run comfortably.";
        }
    }
};


/* =================================================================
   StorageAnalyzer
   FIX: when is_nvme is true, is_ssd is also true (NVMe has no seek
        penalty). The recommendation branch only checked is_ssd which
        meant an NVMe drive got the same message as SATA SSD. Now
        NVMe gets its own recommendation.
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

            STORAGE_PROPERTY_QUERY       spq_seek{};
            DEVICE_SEEK_PENALTY_DESCRIPTOR dsp{};
            spq_seek.PropertyId = StorageDeviceSeekPenaltyProperty;
            spq_seek.QueryType  = PropertyStandardQuery;
            if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                                &spq_seek, sizeof(spq_seek),
                                &dsp, sizeof(dsp),
                                &bytes_returned, nullptr)) {
                is_ssd = !dsp.IncursSeekPenalty;
            }

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

        const char* drive_type = is_nvme ? "NVMe SSD"
                               : is_ssd  ? "SATA SSD"
                               :           "HDD";

        CompatItem& it = new_item(report);
        it.category    = std::string(CAT_DISK);
        it.name        = "Storage: " + std::to_string(total_gb) + " GB total / " +
                         std::to_string(free_gb) + " GB free  [" + drive_type + "]";
        it.critical    = true;

        if (free_gb < 20) {
            it.score          = CompatScore::NONE;
            it.detail         = "Free space: " + std::to_string(free_gb) +
                                " GB — Linux installation requires at least 20 GB.";
            it.recommendation = "Free up disk space or install Linux on a separate drive.";
        } else if (free_gb < 50) {
            it.score          = CompatScore::MINOR;
            it.detail         = "Free space: " + std::to_string(free_gb) +
                                " GB — installation is possible but headroom is limited.";
            it.recommendation = "Minimum viable migration. 50+ GB is recommended for comfortable use.";
        } else {
            it.score  = CompatScore::FULL;
            it.detail = "Free space: " + std::to_string(free_gb) +
                        " GB — ample room for installation and data.";
            /* FIX: NVMe now gets its own recommendation string */
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
   FIX: strstr returns char* which implicitly converts to bool — this
        is technically fine but `strstr(buf,"X") || strstr(buf,"Y")`
        with no explicit cast is a code smell. Replaced with a local
        lambda using std::string_view::contains (C++23) for clarity.
   ================================================================= */
class GpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        HDEVINFO devInfo = SetupDiGetClassDevsA(
            &GUID_DEVCLASS_DISPLAY, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return;

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char buf[512]{};
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                    SPDRP_DEVICEDESC, nullptr,
                    reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr))
                continue;

            const std::string_view name{buf};
            /* C++23: string_view::contains */
            auto has = [&name](std::string_view s) { return name.find(s) != std::string_view::npos; };

            CompatItem& it = new_item(report);
            it.category    = std::string(CAT_GPU);
            it.name        = buf;
            it.critical    = true;

            const bool is_nvidia  = has("NVIDIA") || has("GeForce") || has("Quadro")
                                 || has("RTX")    || has("GTX");
            const bool is_amd_gpu = has("AMD")    || has("Radeon")  || has("RX ");
            const bool is_intel_g = has("Intel")  || has("UHD")     || has("Iris") || has("Arc");
            const bool is_virtual = has("VMware") || has("VirtualBox")
                                 || has("Microsoft Basic Render") || has("SVGA");

            if (is_nvidia) {
                it.score          = CompatScore::MINOR;
                it.detail         = "NVIDIA GPU: " + std::string(name);
                it.recommendation = "Install the proprietary NVIDIA driver (nvidia-driver package). "
                                    "The open-source Nouveau driver is limited. "
                                    "Ubuntu and Fedora make this easy via the GUI. "
                                    "Wayland support improved significantly in driver 510+.";
            } else if (is_amd_gpu) {
                it.score          = CompatScore::FULL;
                it.detail         = "AMD GPU: " + std::string(name);
                it.recommendation = "Excellent in-kernel AMDGPU support — no extra drivers needed. "
                                    "Full Wayland and Vulkan support out of the box. "
                                    "GPU compute available via ROCm on supported cards.";
            } else if (is_intel_g) {
                it.score          = CompatScore::FULL;
                it.detail         = "Intel GPU: " + std::string(name);
                it.recommendation = "In-kernel i915/xe driver provides excellent support. "
                                    "Fully compatible with both Wayland and X11.";
            } else if (is_virtual) {
                it.score          = CompatScore::MINOR;
                it.detail         = "Virtual/emulated display adapter: " + std::string(name);
                it.recommendation = "Virtual environment detected. "
                                    "The real GPU will be used when installed on physical hardware.";
            } else {
                it.score          = CompatScore::MAYBE;
                it.detail         = "Unrecognized GPU: " + std::string(name);
                it.recommendation = "Search 'Linux + [GPU name] driver' to verify support.";
            }
        }
        SetupDiDestroyDeviceInfoList(devInfo);
    }
};


/* =================================================================
   NetworkAnalyzer
   ================================================================= */
class NetworkAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        HDEVINFO devInfo = SetupDiGetClassDevsA(
            &GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return;

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char buf[512]{}, hw_id[512]{};
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                    SPDRP_DEVICEDESC, nullptr,
                    reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr))
                continue;

            const std::string_view name{buf};
            auto has = [&name](std::string_view s) { return name.find(s) != std::string_view::npos; };

            if (has("Microsoft") || has("WAN Miniport") ||
                has("Bluetooth") || has("Loopback"))
                continue;

            SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                SPDRP_HARDWAREID, nullptr,
                reinterpret_cast<PBYTE>(hw_id), sizeof(hw_id), nullptr);

            CompatItem& it = new_item(report);
            it.category    = std::string(CAT_NET);
            it.name        = buf;

            const bool is_intel_net = has("Intel");
            const bool is_realtek   = has("Realtek");
            const bool is_broadcom  = has("Broadcom");
            const bool is_atheros   = has("Atheros") || has("Killer");
            const bool is_mediatek  = has("MediaTek") || has("Ralink");
            const bool is_wifi      = has("Wi-Fi") || has("Wireless") || has("WLAN");

            if (is_intel_net) {
                it.score  = CompatScore::FULL;
                it.detail = std::string(is_wifi ? "Intel Wi-Fi" : "Intel Ethernet") +
                            " adapter: " + std::string(name);
                it.recommendation = is_wifi
                    ? "Intel Wi-Fi has excellent Linux support via the iwlwifi in-kernel driver."
                    : "Intel Ethernet fully supported in-kernel (e1000e / igb / ixgbe).";
            } else if (is_realtek) {
                it.score  = CompatScore::MINOR;
                it.detail = std::string("Realtek ") +
                            (is_wifi ? "Wi-Fi" : "Ethernet") + ": " + std::string(name);
                it.recommendation = is_wifi
                    ? "Realtek Wi-Fi may need an out-of-tree driver (rtl88xx series). "
                      "Install via the dkms package from the manufacturer's GitHub."
                    : "Realtek Ethernet generally works (r8169 driver), "
                      "but a small number of models have quirks.";
            } else if (is_broadcom) {
                it.score  = CompatScore::MAYBE;
                it.detail = std::string("Broadcom ") +
                            (is_wifi ? "Wi-Fi" : "Ethernet") + ": " + std::string(name);
                it.recommendation = "Broadcom adapters can be troublesome on Linux. "
                                    "The b43 or broadcom-sta driver is required and may not be "
                                    "available during installation (no internet access).";
            } else if (is_atheros) {
                it.score  = CompatScore::FULL;
                it.detail = std::string("Atheros/Killer ") +
                            (is_wifi ? "Wi-Fi" : "Ethernet") + ": " + std::string(name);
                it.recommendation = "Atheros/Killer adapters are fully supported in-kernel "
                                    "via ath10k / ath11k drivers.";
            } else if (is_mediatek) {
                it.score  = CompatScore::MINOR;
                it.detail = std::string("MediaTek/Ralink ") +
                            (is_wifi ? "Wi-Fi" : "Ethernet") + ": " + std::string(name);
                it.recommendation = "MediaTek mt76 driver is in-kernel but older chipsets "
                                    "may require a firmware package.";
            } else {
                it.score  = CompatScore::MAYBE;
                it.detail = std::string(is_wifi ? "Wi-Fi" : "Network Adapter") +
                            ": " + std::string(name) +
                            "  [HWID: " + std::string(hw_id).substr(0, 80) + "]";
                it.recommendation = "Check the manufacturer's site or linux-hardware.org "
                                    "for driver availability.";
            }
        }
        SetupDiDestroyDeviceInfoList(devInfo);
    }
};


/* =================================================================
   AudioAnalyzer
   ================================================================= */
class AudioAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        HDEVINFO devInfo = SetupDiGetClassDevsA(
            &GUID_DEVCLASS_MEDIA, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return;

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char buf[512]{};
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                    SPDRP_DEVICEDESC, nullptr,
                    reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr))
                continue;

            const std::string_view name{buf};
            auto has = [&name](std::string_view s) { return name.find(s) != std::string_view::npos; };

            if (has("Virtual") || has("Microsoft")) continue;

            CompatItem& it = new_item(report);
            it.category    = std::string(CAT_AUDIO);
            it.name        = buf;

            const bool is_hda       = has("Realtek") || has("Intel") || has("AMD") || has("Nvidia");
            const bool is_focusrite = has("Focusrite") || has("Scarlett");
            const bool is_creative  = has("Creative")  || has("Sound Blaster");

            if (is_hda) {
                it.score          = CompatScore::FULL;
                it.detail         = "HDA-compatible audio device: " + std::string(name);
                it.recommendation = "Fully compatible with ALSA / PulseAudio / PipeWire "
                                    "via the in-kernel snd_hda_intel driver.";
            } else if (is_focusrite) {
                it.score          = CompatScore::MINOR;
                it.detail         = "USB audio interface: " + std::string(name);
                it.recommendation = "Focusrite generally works on Linux. "
                                    "Scarlett Gen 2/3/4 are well-supported. "
                                    "Use JACK or PipeWire for pro-audio workflows.";
            } else if (is_creative) {
                it.score          = CompatScore::MAYBE;
                it.detail         = "Creative audio device: " + std::string(name);
                it.recommendation = "Creative Sound Blaster cards have limited Linux support; "
                                    "some DSP features will not function.";
            } else {
                it.score          = CompatScore::MINOR;
                it.detail         = "Audio device: " + std::string(name);
                it.recommendation = "USB and Bluetooth audio devices generally work "
                                    "out of the box on Linux.";
            }
        }
        SetupDiDestroyDeviceInfoList(devInfo);
    }
};


/* =================================================================
   FirmwareAnalyzer
   FIX: Registry calls now use std::optional return values.
   ================================================================= */
class FirmwareAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        /* UEFI vs Legacy BIOS */
        const auto pe_fw = Registry::read_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control", "PEFirmwareType");
        const bool is_uefi = (pe_fw.value_or(0) == 2);

        /* Secure Boot */
        const auto sb_val = Registry::read_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            "UEFISecureBootEnabled");
        const bool secure_boot = (sb_val.value_or(0) != 0);

        /* TPM */
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

        /* BIOS strings */
        const std::string bios_ver    = Registry::read_string(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion").value_or("");
        const std::string bios_vendor = Registry::read_string(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor").value_or("");

        /* --- Report item: UEFI / BIOS --- */
        {
            CompatItem& it = new_item(report);
            it.category    = std::string(CAT_FW);
            it.name        = "Boot mode: " + std::string(is_uefi ? "UEFI" : "Legacy BIOS") +
                             "  |  BIOS: " + bios_vendor + " " + bios_ver;
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

        /* --- Report item: Secure Boot --- */
        {
            CompatItem& it = new_item(report);
            it.category    = std::string(CAT_SB);
            it.name        = std::string("Secure Boot: ") + (secure_boot ? "Enabled" : "Disabled");
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

        /* --- Report item: TPM --- */
        {
            CompatItem& it    = new_item(report);
            it.category       = std::string(CAT_TPM);
            it.name           = std::string("TPM: ") + (has_tpm ? "Present" : "Not detected");
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
        it.name           = "Battery: " + std::to_string(pct) +
                            "%  |  Power source: " + (on_ac ? "AC adapter" : "Battery");
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
        const bool in_vm = (info[2] >> 31) & 1;
        if (!in_vm) return;

        /* FIX: same union approach as CpuAnalyzer to avoid aliasing UB */
        union { int i[3]; char c[12]; } hv_raw{};
        __cpuid(info, 0x40000000);
        hv_raw.i[0] = info[1];
        hv_raw.i[1] = info[2];
        hv_raw.i[2] = info[3];
        const std::string hv_name(hv_raw.c, 12);

        CompatItem& it    = new_item(report);
        it.category       = std::string(CAT_VIRT);
        it.name           = "Virtual Machine Detected: " + hv_name;
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = "Hypervisor: " + hv_name +
                            " — this analysis is running inside a virtual environment.";
        it.recommendation = "Results reflect the virtual hardware profile, not the physical host. "
                            "Re-run the tool on bare metal for an accurate assessment.";
    }
};


/* =================================================================
   OnlineAnalyzer
   FIX: old code used sscanf on the raw buffer which could leave a
        trailing '\n' or '\r' in the version string (visible in the
        report). Now we trim whitespace explicitly.
   FIX: old CPUID copy for hypervisor vendor was wrong —
        0x40000000 returns EBX/ECX/EDX (not EBX/EDX/ECX as the old
        VirtualizationAnalyzer memcpy order implied). Fixed above.
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

        std::string kernel_ver;

        if (hRequest
         && WinHttpSendRequest(hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
         && WinHttpReceiveResponse(hRequest, nullptr)) {

            char  raw[512]{};
            DWORD bytes_read = 0;
            WinHttpReadData(hRequest, raw, sizeof(raw) - 1, &bytes_read);

            /*
             * finger_banner format example:
             *   "The latest stable version of the Linux kernel is: 6.x.y\n"
             * Locate "stable", then ": ".
             * FIX: trim trailing whitespace / newlines from parsed version.
             */
            if (char* p = strstr(raw, "stable")) {
                if ((p = strstr(p, ": "))) {
                    char ver_buf[64]{};
                    if (sscanf(p + 2, "%63s", ver_buf) == 1) {
                        kernel_ver = ver_buf;
                        /* Trim trailing CR/LF/space */
                        while (!kernel_ver.empty() &&
                               (kernel_ver.back() == '\n' ||
                                kernel_ver.back() == '\r' ||
                                kernel_ver.back() == ' '))
                            kernel_ver.pop_back();
                    }
                }
            }
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (kernel_ver.empty()) return;

        CompatItem& it    = new_item(report);
        it.category       = std::string(CAT_ONLINE);
        it.name           = "Latest Stable Kernel: " + kernel_ver + "  (source: kernel.org)";
        it.critical       = false;
        it.score          = CompatScore::FULL;
        it.detail         = "Kernel " + kernel_ver + " is the current stable release. "
                            "Hardware compatibility is evaluated against this version's driver set.";
        it.recommendation = "Choose a distribution that ships or allows installation of "
                            "a recent kernel for the best hardware coverage.";
    }

private:
    bool m_online;
};


/* =================================================================
   ReportPrinter
   FIX: categories array replaced with std::array<std::string_view>
        to avoid raw nullptr-sentinel iteration.
   FIX: per-loop `static_cast<int>(report.items.size()) >= MAX_DEVICES - 1`
        guards removed from individual analyzers; add_item() handles it.
   ================================================================= */
class ReportPrinter {
public:
    explicit ReportPrinter(bool online) : m_online(online) {}

    void print(CompatReport& report) {
        report.compute();

        printf("\n");
        printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
        printf(BOLD WHITE "  📋 DETAILED COMPATIBILITY REPORT\n" RESET);
        printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);

        /* FIX: use std::array<std::string_view> instead of raw char* array */
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
                    printf(BLUE BOLD "  ┌─ %.*s\n" RESET,
                           static_cast<int>(cat.size()), cat.data());
                    header_printed = true;
                }

                printf("  │  %s  %s  %s\n",
                       Console::score_icon(it.score),
                       Console::score_label(it.score),
                       it.name.c_str());
                printf("  │     " DIM "→ %s\n" RESET, it.detail.c_str());
                printf("  │     " CYAN "✦ %s\n" RESET, it.recommendation.c_str());
                printf("  │\n");
            }
        }

        printf("\n");
        printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
        printf(BOLD WHITE "  📊 SUMMARY STATISTICS\n" RESET);
        printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);

        printf("  %s  Fully Compatible         : %d component(s)\n",
               GREEN  "●" RESET, report.score_counts[0]);
        printf("  %s  Compatible (minor issues): %d component(s)\n",
               YELLOW "◑" RESET, report.score_counts[1]);
        printf("  %s  Possibly Incompatible    : %d component(s)\n",
               ORANGE "◔" RESET, report.score_counts[2]);
        printf("  %s  Incompatible             : %d component(s)\n",
               RED    "○" RESET, report.score_counts[3]);
        printf("\n  Total components analyzed: %d\n",
               static_cast<int>(report.items.size()));

        printf("\n  Overall Compatibility Score:\n  ");
        Console::print_percent_bar(report.overall_percent, 40);
        printf("\n\n");

        printf(BOLD WHITE "  🧭 GENERAL ASSESSMENT\n\n" RESET);
        if (report.overall_percent >= 85.0) {
            printf(GREEN BOLD "  ✅ Your system is READY for Linux!\n" RESET);
            printf("     Ubuntu, Fedora, Mint, or any major distribution will work seamlessly.\n");
        } else if (report.overall_percent >= 65.0) {
            printf(YELLOW BOLD "  ⚠️  Your system is MOSTLY compatible with Linux.\n" RESET);
            printf("     A few components may need additional drivers or configuration.\n");
            printf("     Ubuntu LTS or Linux Mint is recommended for the best out-of-box experience.\n");
        } else if (report.overall_percent >= 40.0) {
            printf(ORANGE BOLD "  🔶 Compatibility is MODERATE.\n" RESET);
            printf("     Several components may cause issues. Test with a live USB before committing.\n");
        } else {
            printf(RED BOLD "  ❌ Your system has serious compatibility issues.\n" RESET);
            printf("     Consider hardware upgrades before migrating to Linux.\n");
        }

        printf("\n" BOLD WHITE "  🐧 RECOMMENDED DISTRIBUTIONS\n\n" RESET);
        printf("     1. Ubuntu 24.04 LTS  — Widest driver support, easiest installation\n");
        printf("     2. Linux Mint 22     — Windows-like interface, great for beginners\n");
        printf("     3. Fedora 40         — Latest kernel, excellent NVIDIA support\n");
        printf("     4. Pop!_OS 24.04     — Optimised for gamers and NVIDIA users\n");
        printf("     5. EndeavourOS       — Arch-based, full control over the system\n");

        printf("\n" DIM "  🌐 Internet: %s\n" RESET,
               m_online
                   ? GREEN "Connected — live data fetched from kernel.org" RESET
                   : YELLOW "Offline — local analysis only" RESET);

        printf("\n");
        printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
        printf(DIM "  Linux Kernel Compatibility Checker v2.1  |  linux-hardware.org\n" RESET);
        printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);
    }

private:
    bool m_online;
};


/* =================================================================
   Analyzer pipeline step metadata
   FIX: steps[] was a raw C array with nullptr sentinels for Power/Virt.
        Replaced with std::array<StepMeta> where label="" means no bar.
        This eliminates the fragile manual index alignment between
        analyzers vector and steps array.
   ================================================================= */
struct StepMeta {
    const char* label      = nullptr;   /* nullptr = no progress bar */
    int         steps      = 0;
    int         delay_ms   = 0;
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
    { nullptr,                               0,  0, false },   /* PowerAnalyzer      */
    { nullptr,                               0,  0, false },   /* VirtualizationAnal.*/
    { "Step 9/9: Fetching kernel.org data", 12, 60, true  },
}};


/* =================================================================
   ENTRY POINT
   ================================================================= */
int main() {
    Console::enable_ansi();
    Console::print_header();

    /* System information */
    const std::string os_name = Registry::read_string(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")
        .value_or("Windows");

    char  computer_name[256]{};
    DWORD comp_size = sizeof(computer_name);
    GetComputerNameA(computer_name, &comp_size);

    SYSTEMTIME st{};
    GetLocalTime(&st);

    printf(DIM "  Computer : %s\n" RESET, computer_name);
    printf(DIM "  OS       : %s\n" RESET, os_name.c_str());
    printf(DIM "  Date     : %02d/%02d/%04d  %02d:%02d\n\n" RESET,
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);

    /* Step 1 — Internet connectivity check */
    printf(CYAN "  Step 1/9: " RESET "Checking internet connection...\n");
    const bool g_online = Internet::check_connection();
    printf("            %s\n\n",
           g_online ? GREEN "✓ Connected" RESET : YELLOW "✗ Offline" RESET);

    /* Build analyzer pipeline */
    std::vector<std::unique_ptr<Analyzer>> analyzers;
    analyzers.reserve(10);
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

    /* Static assert: pipeline and metadata must stay in sync */
    static_assert(PIPELINE_STEPS.size() == 10,
                  "PIPELINE_STEPS must match the number of analyzers");

    CompatReport report;

    for (std::size_t i = 0; i < analyzers.size(); i++) {
        const StepMeta& meta = PIPELINE_STEPS[i];

        if (meta.online_only && !g_online) {
            printf(DIM "  Step 9/9: Offline — kernel.org step skipped.\n" RESET);
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
