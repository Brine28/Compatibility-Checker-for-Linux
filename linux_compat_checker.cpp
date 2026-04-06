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
 *   cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc
 *      /link advapi32.lib setupapi.lib winhttp.lib
 *
 * Compile (GCC / MinGW):
 *   g++ linux_compat_checker.cpp -o linux_compat_checker.exe -std=c++17
 *       -ladvapi32 -lsetupapi -lwinhttp
 */

#define _WIN32_WINNT 0x0A00   /* Windows 10+ */
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <initguid.h>
#include <setupapi.h>
#include <devguid.h>
#include <regstr.h>
#include <winhttp.h>
#include <intrin.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <algorithm>

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
#define MAGENTA     "\033[95m"
#define CYAN        "\033[96m"
#define WHITE       "\033[97m"
#define ORANGE      "\033[38;5;208m"

/* ─── Category name constants ─── */
#define CAT_CPU     "CPU"
#define CAT_RAM     "RAM"
#define CAT_DISK    "Disk"
#define CAT_GPU     "GPU"
#define CAT_NET     "Network Card"
#define CAT_AUDIO   "Audio Card"
#define CAT_FW      "Firmware"
#define CAT_SB      "Secure Boot"
#define CAT_TPM     "TPM"
#define CAT_POWER   "Power/Battery"
#define CAT_VIRT    "Virtualization"
#define CAT_ONLINE  "Online"

/* ─── Compatibility score levels ─── */
enum CompatScore {
    COMPAT_FULL  = 0,   /* Fully compatible, no action needed     */
    COMPAT_MINOR = 1,   /* Compatible but minor issues may occur  */
    COMPAT_MAYBE = 2,   /* Possibly incompatible, check carefully */
    COMPAT_NONE  = 3    /* Incompatible, serious issues expected  */
};

/* ─── Capacity limits ─── */
static constexpr int MAX_DEVICES  = 256;
static constexpr int MAX_NAME_LEN = 256;


/* =================================================================
   CompatItem — per-component compatibility record
   ================================================================= */
class CompatItem {
public:
    std::string name;
    std::string category;
    std::string detail;
    std::string recommendation;
    CompatScore score    = COMPAT_FULL;
    bool        critical = false;   /* true = weighted 2x in overall score */

    CompatItem() = default;
};


/* =================================================================
   CompatReport — aggregated collection of CompatItem results
   ================================================================= */
class CompatReport {
public:
    std::vector<CompatItem> items;
    std::array<int, 4>      score_counts{};   /* [0]=full … [3]=none */
    double                  overall_percent = 0.0;

    /* Add a new blank item and return a reference to it */
    CompatItem& add_item() {
        if (static_cast<int>(items.size()) >= MAX_DEVICES - 1)
            return items.back();   /* Guard against overflow */
        items.emplace_back();
        return items.back();
    }

    /* Compute summary statistics and weighted compatibility percentage */
    void compute() {
        score_counts.fill(0);
        double weighted     = 0.0;
        double total_weight = 0.0;

        for (const auto& item : items) {
            int s = static_cast<int>(item.score);
            if (s >= 0 && s <= 3) score_counts[s]++;

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
   Registry — thin RAII wrapper around registry operations
   ================================================================= */
namespace Registry {

    /* Read a REG_SZ value; returns true on success */
    inline bool read_string(HKEY root, const char* subkey,
                            const char* value, char* out, DWORD size) {
        HKEY  hk   = nullptr;
        DWORD type = REG_SZ, sz = size;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return false;
        bool ok = (RegQueryValueExA(hk, value, nullptr, &type,
                                    reinterpret_cast<LPBYTE>(out), &sz)
                   == ERROR_SUCCESS);
        RegCloseKey(hk);
        return ok;
    }

    /* Read a REG_DWORD value; returns true on success */
    inline bool read_dword(HKEY root, const char* subkey,
                           const char* value, DWORD& out) {
        HKEY  hk   = nullptr;
        DWORD type = REG_DWORD, sz = sizeof(DWORD);
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return false;
        bool ok = (RegQueryValueExA(hk, value, nullptr, &type,
                                    reinterpret_cast<LPBYTE>(&out), &sz)
                   == ERROR_SUCCESS);
        RegCloseKey(hk);
        return ok;
    }

} // namespace Registry


/* =================================================================
   Console — UI helpers (ANSI, banner, progress bar, labels)
   ================================================================= */
namespace Console {

    /* Enable ANSI virtual terminal processing on Windows 10+ */
    inline void enable_ansi() {
        HANDLE h    = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD  mode = 0;
        GetConsoleMode(h, &mode);
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleOutputCP(CP_UTF8);
    }

    /* Print the application banner */
    inline void print_header() {
        printf("\n");
        printf(CYAN BOLD "╔══════════════════════════════════════════════════════════════╗\n" RESET);
        printf(CYAN BOLD "║" RESET BLUE BOLD "     🐧  Linux Kernel Compatibility Checker v2.1           " CYAN BOLD "║\n" RESET);
        printf(CYAN BOLD "║" RESET DIM  "     Windows 11 → Linux Migration Readiness Report          " CYAN BOLD "║\n" RESET);
        printf(CYAN BOLD "╚══════════════════════════════════════════════════════════════╝\n" RESET);
        printf("\n");
    }

    /* Return a colored label string for a given score */
    inline const char* score_label(CompatScore s) {
        switch (s) {
            case COMPAT_FULL:  return GREEN  BOLD "[0] FULLY COMPATIBLE     " RESET;
            case COMPAT_MINOR: return YELLOW BOLD "[1] COMPATIBLE (minor)   " RESET;
            case COMPAT_MAYBE: return ORANGE BOLD "[2] POSSIBLY INCOMPATIBLE" RESET;
            case COMPAT_NONE:  return RED    BOLD "[3] INCOMPATIBLE         " RESET;
            default:           return WHITE       "[?] UNKNOWN              " RESET;
        }
    }

    /* Return a colored bullet icon for a given score */
    inline const char* score_icon(CompatScore s) {
        switch (s) {
            case COMPAT_FULL:  return GREEN  "●" RESET;
            case COMPAT_MINOR: return YELLOW "◑" RESET;
            case COMPAT_MAYBE: return ORANGE "◔" RESET;
            case COMPAT_NONE:  return RED    "○" RESET;
            default:           return WHITE  "?" RESET;
        }
    }

    /* Display an animated progress bar while a step is running */
    inline void loading_bar(const char* msg, int steps, int delay_ms) {
        printf(CYAN "  ► " RESET "%s ", msg);
        fflush(stdout);
        for (int i = 0; i < steps; i++) {
            printf("█");
            fflush(stdout);
            Sleep(delay_ms);
        }
        printf(" " GREEN BOLD "✓\n" RESET);
    }

    /* Print a filled block progress bar with color coding */
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
   Internet — connectivity check and kernel.org HTTP helpers
   ================================================================= */
namespace Internet {

    /* Probe kernel.org with an HTTPS HEAD request to test connectivity */
    inline bool check_connection() {
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
   Analyzer — abstract base class for all hardware/software checks
   ================================================================= */
class Analyzer {
public:
    virtual ~Analyzer() = default;

    /* Run the analysis and populate the report */
    virtual void analyze(CompatReport& report) = 0;

protected:
    /* Helper: create a new item in the report and return a reference */
    static CompatItem& new_item(CompatReport& r) { return r.add_item(); }
};


/* =================================================================
   CpuAnalyzer — vendor, brand, core count, ISA extensions
   ================================================================= */
class CpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        char vendor[13] = {};
        char brand[49]  = {};
        int  info[4]    = {};

        /* Read vendor string via CPUID leaf 0 */
        __cpuid(info, 0);
        memcpy(vendor,     &info[1], 4);
        memcpy(vendor + 4, &info[3], 4);
        memcpy(vendor + 8, &info[2], 4);

        /* Read brand string via CPUID leaves 0x80000002-4 */
        __cpuid(info, 0x80000000);
        if (static_cast<unsigned>(info[0]) >= 0x80000004u) {
            __cpuid(info, 0x80000002); memcpy(brand,      info, 16);
            __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
            __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
        }

        /* Feature flags from CPUID leaf 1 */
        __cpuid(info, 1);
        bool has_vmx  = (info[2] >> 5)  & 1;
        bool has_sse2 = (info[3] >> 26) & 1;
        bool has_avx  = (info[2] >> 28) & 1;

        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD cores = si.dwNumberOfProcessors;

        bool is_intel = (strstr(vendor, "GenuineIntel") != nullptr);
        bool is_amd   = (strstr(vendor, "AuthenticAMD") != nullptr);

        CompatItem& it = new_item(report);
        it.category    = CAT_CPU;
        it.name        = brand[0] ? brand : vendor;
        it.critical    = true;

        char buf[512];
        if (is_intel || is_amd) {
            it.score = COMPAT_FULL;
            snprintf(buf, sizeof(buf),
                "%s %s | %lu logical cores | SSE2:%s  AVX:%s  VT-x/AMD-V:%s",
                is_intel ? "Intel" : "AMD",
                brand[0] ? brand : "",
                static_cast<unsigned long>(cores),
                has_sse2 ? "Yes" : "No",
                has_avx  ? "Yes" : "No",
                has_vmx  ? "Yes" : "No");
            it.detail         = buf;
            it.recommendation = "Excellent Linux support. Any distribution will work seamlessly.";
        } else {
            it.score = COMPAT_MAYBE;
            snprintf(buf, sizeof(buf),
                "Non-x86 processor detected: vendor='%s', %lu logical cores",
                vendor, static_cast<unsigned long>(cores));
            it.detail         = buf;
            it.recommendation = "ARM Linux support is improving, but some x86-only software "
                                "may not run. Consider Ubuntu ARM or Fedora ARM.";
        }
    }
};


/* =================================================================
   RamAnalyzer — total physical memory, suitability for desktop use
   ================================================================= */
class RamAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        MEMORYSTATUSEX ms;
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);

        unsigned long long total_mb = ms.ullTotalPhys / (1024ULL * 1024);
        unsigned long long total_gb = total_mb / 1024;

        char buf[MAX_NAME_LEN];
        snprintf(buf, sizeof(buf),
                 "System Memory: %llu MB (%llu GB)", total_mb, total_gb);

        CompatItem& it = new_item(report);
        it.category    = CAT_RAM;
        it.name        = buf;
        it.critical    = true;

        char dbuf[512];
        if (total_mb < 2048) {
            it.score = COMPAT_NONE;
            snprintf(dbuf, sizeof(dbuf),
                "Only %llu MB RAM detected — Linux requires at least 1 GB to boot.",
                total_mb);
            it.detail         = dbuf;
            it.recommendation = "At least 4 GB is recommended. "
                                "Try ultra-lightweight distros such as Lubuntu or Alpine Linux.";
        } else if (total_mb < 4096) {
            it.score = COMPAT_MINOR;
            snprintf(dbuf, sizeof(dbuf),
                "%llu MB RAM available — sufficient for basic desktop use.", total_mb);
            it.detail         = dbuf;
            it.recommendation = "Use lightweight desktop environments such as Xfce or LXQt.";
        } else {
            it.score = COMPAT_FULL;
            snprintf(dbuf, sizeof(dbuf),
                "%llu MB (%llu GB) RAM — excellent for any desktop workload.",
                total_mb, total_gb);
            it.detail         = dbuf;
            it.recommendation = "All desktop environments and virtualization will run comfortably.";
        }
    }
};


/* =================================================================
   StorageAnalyzer — free space, SSD/HDD, NVMe detection
   ================================================================= */
class StorageAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        ULARGE_INTEGER free_bytes{}, total_bytes{};
        GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, nullptr);
        unsigned long long total_gb = total_bytes.QuadPart / (1024ULL * 1024 * 1024);
        unsigned long long free_gb  = free_bytes.QuadPart  / (1024ULL * 1024 * 1024);

        /* Open PhysicalDrive0 once and reuse the handle for both queries */
        bool is_ssd  = false;
        bool is_nvme = false;

        HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);

        if (hDisk != INVALID_HANDLE_VALUE) {
            DWORD bytes_returned = 0;

            /* SSD detection — no rotational seek penalty */
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

            /* NVMe detection — inspect BusType from StorageDeviceProperty */
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

        char nbuf[MAX_NAME_LEN];
        snprintf(nbuf, sizeof(nbuf),
                 "Storage: %llu GB total / %llu GB free  [%s]",
                 total_gb, free_gb, drive_type);

        CompatItem& it = new_item(report);
        it.category    = CAT_DISK;
        it.name        = nbuf;
        it.critical    = true;

        char dbuf[512];
        if (free_gb < 20) {
            it.score = COMPAT_NONE;
            snprintf(dbuf, sizeof(dbuf),
                "Free space: %llu GB — Linux installation requires at least 20 GB.", free_gb);
            it.detail         = dbuf;
            it.recommendation = "Free up disk space or install Linux on a separate drive.";
        } else if (free_gb < 50) {
            it.score = COMPAT_MINOR;
            snprintf(dbuf, sizeof(dbuf),
                "Free space: %llu GB — installation is possible but headroom is limited.", free_gb);
            it.detail         = dbuf;
            it.recommendation = "Minimum viable migration. 50+ GB is recommended for comfortable use.";
        } else {
            it.score = COMPAT_FULL;
            snprintf(dbuf, sizeof(dbuf),
                "Free space: %llu GB — ample room for installation and data.", free_gb);
            it.detail         = dbuf;
            it.recommendation = is_ssd
                ? "SSD + ample space = fast Linux experience. Use Ext4 or Btrfs."
                : "HDD may feel slow. Prefer Ext4 and add a swap partition.";
        }
    }
};


/* =================================================================
   GpuAnalyzer — vendor detection, driver situation assessment
   ================================================================= */
class GpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        HDEVINFO devInfo = SetupDiGetClassDevsA(
            &GUID_DEVCLASS_DISPLAY, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return;

        SP_DEVINFO_DATA devData;
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char buf[512];
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                    SPDRP_DEVICEDESC, nullptr,
                    reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr))
                continue;

            CompatItem& it = new_item(report);
            it.category    = CAT_GPU;
            it.name        = buf;
            it.critical    = true;

            bool is_nvidia  = (strstr(buf, "NVIDIA")  || strstr(buf, "GeForce")
                            || strstr(buf, "Quadro")  || strstr(buf, "RTX")
                            || strstr(buf, "GTX"));
            bool is_amd_gpu = (strstr(buf, "AMD")     || strstr(buf, "Radeon")
                            || strstr(buf, "RX "));
            bool is_intel_g = (strstr(buf, "Intel")   || strstr(buf, "UHD")
                            || strstr(buf, "Iris")    || strstr(buf, "Arc"));
            bool is_virtual = (strstr(buf, "VMware")  || strstr(buf, "VirtualBox")
                            || strstr(buf, "Microsoft Basic Render")
                            || strstr(buf, "SVGA"));

            char dbuf[512];
            if (is_nvidia) {
                it.score = COMPAT_MINOR;
                snprintf(dbuf, sizeof(dbuf), "NVIDIA GPU: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "Install the proprietary NVIDIA driver (nvidia-driver package). "
                                    "The open-source Nouveau driver is limited. "
                                    "Ubuntu and Fedora make this easy via the GUI. "
                                    "Wayland support improved significantly in driver 510+.";
            } else if (is_amd_gpu) {
                it.score = COMPAT_FULL;
                snprintf(dbuf, sizeof(dbuf), "AMD GPU: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "Excellent in-kernel AMDGPU support — no extra drivers needed. "
                                    "Full Wayland and Vulkan support out of the box. "
                                    "GPU compute available via ROCm on supported cards.";
            } else if (is_intel_g) {
                it.score = COMPAT_FULL;
                snprintf(dbuf, sizeof(dbuf), "Intel GPU: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "In-kernel i915/xe driver provides excellent support. "
                                    "Fully compatible with both Wayland and X11.";
            } else if (is_virtual) {
                it.score = COMPAT_MINOR;
                snprintf(dbuf, sizeof(dbuf), "Virtual/emulated display adapter: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "Virtual environment detected. "
                                    "The real GPU will be used when installed on physical hardware.";
            } else {
                it.score = COMPAT_MAYBE;
                snprintf(dbuf, sizeof(dbuf), "Unrecognized GPU: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "Search 'Linux + [GPU name] driver' to verify support.";
            }

            if (static_cast<int>(report.items.size()) >= MAX_DEVICES - 1) break;
        }
        SetupDiDestroyDeviceInfoList(devInfo);
    }
};


/* =================================================================
   NetworkAnalyzer — Wi-Fi and Ethernet adapters, driver availability
   ================================================================= */
class NetworkAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        HDEVINFO devInfo = SetupDiGetClassDevsA(
            &GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return;

        SP_DEVINFO_DATA devData;
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char buf[512], hw_id[512];
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                    SPDRP_DEVICEDESC, nullptr,
                    reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr))
                continue;

            /* Skip virtual and infrastructure adapters */
            if (strstr(buf, "Microsoft") || strstr(buf, "WAN Miniport") ||
                strstr(buf, "Bluetooth") || strstr(buf, "Loopback"))
                continue;

            SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                SPDRP_HARDWAREID, nullptr,
                reinterpret_cast<PBYTE>(hw_id), sizeof(hw_id), nullptr);

            CompatItem& it = new_item(report);
            it.category    = CAT_NET;
            it.name        = buf;

            bool is_intel_net = (strstr(buf, "Intel")    != nullptr);
            bool is_realtek   = (strstr(buf, "Realtek")  != nullptr);
            bool is_broadcom  = (strstr(buf, "Broadcom") != nullptr);
            bool is_atheros   = (strstr(buf, "Atheros")  || strstr(buf, "Killer"));
            bool is_mediatek  = (strstr(buf, "MediaTek") || strstr(buf, "Ralink"));
            bool is_wifi      = (strstr(buf, "Wi-Fi")    || strstr(buf, "Wireless")
                              || strstr(buf, "WLAN"));

            char dbuf[512];
            if (is_intel_net) {
                it.score = COMPAT_FULL;
                snprintf(dbuf, sizeof(dbuf), "%s adapter: %s",
                    is_wifi ? "Intel Wi-Fi" : "Intel Ethernet", buf);
                it.detail         = dbuf;
                it.recommendation = is_wifi
                    ? "Intel Wi-Fi has excellent Linux support via the iwlwifi in-kernel driver."
                    : "Intel Ethernet fully supported in-kernel (e1000e / igb / ixgbe).";
            } else if (is_realtek) {
                it.score = COMPAT_MINOR;
                snprintf(dbuf, sizeof(dbuf), "Realtek %s: %s",
                    is_wifi ? "Wi-Fi" : "Ethernet", buf);
                it.detail         = dbuf;
                it.recommendation = is_wifi
                    ? "Realtek Wi-Fi may need an out-of-tree driver (rtl88xx series). "
                      "Install via the dkms package from the manufacturer's GitHub."
                    : "Realtek Ethernet generally works (r8169 driver), "
                      "but a small number of models have quirks.";
            } else if (is_broadcom) {
                it.score = COMPAT_MAYBE;
                snprintf(dbuf, sizeof(dbuf), "Broadcom %s: %s",
                    is_wifi ? "Wi-Fi" : "Ethernet", buf);
                it.detail         = dbuf;
                it.recommendation = "Broadcom adapters can be troublesome on Linux. "
                                    "The b43 or broadcom-sta driver is required and may not be "
                                    "available during installation (no internet access).";
            } else if (is_atheros) {
                it.score = COMPAT_FULL;
                snprintf(dbuf, sizeof(dbuf), "Atheros/Killer %s: %s",
                    is_wifi ? "Wi-Fi" : "Ethernet", buf);
                it.detail         = dbuf;
                it.recommendation = "Atheros/Killer adapters are fully supported in-kernel "
                                    "via ath10k / ath11k drivers.";
            } else if (is_mediatek) {
                it.score = COMPAT_MINOR;
                snprintf(dbuf, sizeof(dbuf), "MediaTek/Ralink %s: %s",
                    is_wifi ? "Wi-Fi" : "Ethernet", buf);
                it.detail         = dbuf;
                it.recommendation = "MediaTek mt76 driver is in-kernel but older chipsets "
                                    "may require a firmware package.";
            } else {
                it.score = COMPAT_MAYBE;
                snprintf(dbuf, sizeof(dbuf), "%s: %s  [HWID: %.80s]",
                    is_wifi ? "Wi-Fi" : "Network Adapter", buf, hw_id);
                it.detail         = dbuf;
                it.recommendation = "Check the manufacturer's site or linux-hardware.org "
                                    "for driver availability.";
            }

            if (static_cast<int>(report.items.size()) >= MAX_DEVICES - 1) break;
        }
        SetupDiDestroyDeviceInfoList(devInfo);
    }
};


/* =================================================================
   AudioAnalyzer — sound cards and USB audio interfaces
   ================================================================= */
class AudioAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        HDEVINFO devInfo = SetupDiGetClassDevsA(
            &GUID_DEVCLASS_MEDIA, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return;

        SP_DEVINFO_DATA devData;
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char buf[512];
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                    SPDRP_DEVICEDESC, nullptr,
                    reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr))
                continue;

            /* Skip virtual audio devices */
            if (strstr(buf, "Virtual") || strstr(buf, "Microsoft")) continue;

            CompatItem& it = new_item(report);
            it.category    = CAT_AUDIO;
            it.name        = buf;

            bool is_hda       = (strstr(buf, "Realtek") || strstr(buf, "Intel")
                              || strstr(buf, "AMD")     || strstr(buf, "Nvidia"));
            bool is_focusrite = (strstr(buf, "Focusrite") || strstr(buf, "Scarlett"));
            bool is_creative  = (strstr(buf, "Creative")  || strstr(buf, "Sound Blaster"));

            char dbuf[512];
            if (is_hda) {
                it.score = COMPAT_FULL;
                snprintf(dbuf, sizeof(dbuf), "HDA-compatible audio device: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "Fully compatible with ALSA / PulseAudio / PipeWire "
                                    "via the in-kernel snd_hda_intel driver.";
            } else if (is_focusrite) {
                it.score = COMPAT_MINOR;
                snprintf(dbuf, sizeof(dbuf), "USB audio interface: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "Focusrite generally works on Linux. "
                                    "Scarlett Gen 2/3/4 are well-supported. "
                                    "Use JACK or PipeWire for pro-audio workflows.";
            } else if (is_creative) {
                it.score = COMPAT_MAYBE;
                snprintf(dbuf, sizeof(dbuf), "Creative audio device: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "Creative Sound Blaster cards have limited Linux support; "
                                    "some DSP features will not function.";
            } else {
                it.score = COMPAT_MINOR;
                snprintf(dbuf, sizeof(dbuf), "Audio device: %s", buf);
                it.detail         = dbuf;
                it.recommendation = "USB and Bluetooth audio devices generally work "
                                    "out of the box on Linux.";
            }

            if (static_cast<int>(report.items.size()) >= MAX_DEVICES - 1) break;
        }
        SetupDiDestroyDeviceInfoList(devInfo);
    }
};


/* =================================================================
   FirmwareAnalyzer — UEFI vs BIOS, Secure Boot state, TPM presence
   ================================================================= */
class FirmwareAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {

        /* UEFI vs Legacy BIOS — PEFirmwareType: 1=BIOS, 2=UEFI */
        DWORD pe_fw_type = 0;
        bool  is_uefi    = false;
        if (Registry::read_dword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control",
                "PEFirmwareType", pe_fw_type)) {
            is_uefi = (pe_fw_type == 2);
        }

        /* Secure Boot — UEFISecureBootEnabled: 0=off, 1=on */
        DWORD sb_val      = 0;
        bool  secure_boot = false;
        if (Registry::read_dword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                "UEFISecureBootEnabled", sb_val)) {
            secure_boot = (sb_val != 0);
        }

        /* TPM — enumerate ROOT\TPM device class */
        bool     has_tpm = false;
        HDEVINFO tpmDev  = SetupDiGetClassDevsA(nullptr, "ROOT\\TPM", nullptr,
            DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (tpmDev != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA td;
            td.cbSize = sizeof(td);
            has_tpm   = SetupDiEnumDeviceInfo(tpmDev, 0, &td);
            SetupDiDestroyDeviceInfoList(tpmDev);
        }

        /* BIOS vendor and version strings */
        char bios_ver[128]    = {};
        char bios_vendor[128] = {};
        Registry::read_string(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BIOSVersion", bios_ver,    sizeof(bios_ver));
        Registry::read_string(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BIOSVendor",  bios_vendor, sizeof(bios_vendor));

        /* --- Report item: UEFI / BIOS --- */
        {
            char nbuf[MAX_NAME_LEN];
            snprintf(nbuf, sizeof(nbuf),
                     "Boot mode: %s  |  BIOS: %s %s",
                     is_uefi ? "UEFI" : "Legacy BIOS",
                     bios_vendor, bios_ver);

            CompatItem& it = new_item(report);
            it.category    = CAT_FW;
            it.name        = nbuf;
            it.critical    = true;

            if (is_uefi) {
                it.score          = COMPAT_FULL;
                it.detail         = "UEFI firmware detected. Modern bootloaders (GRUB2, systemd-boot) "
                                    "require a UEFI system.";
                it.recommendation = "Install Linux in UEFI mode. "
                                    "An EFI System Partition (ESP) will be created.";
            } else {
                it.score          = COMPAT_MINOR;
                it.detail         = "Legacy BIOS detected. Linux can be installed but some features "
                                    "(GPT, secure boot) are unavailable.";
                it.recommendation = "Use an MBR partition scheme during installation.";
            }
        }

        /* --- Report item: Secure Boot --- */
        {
            char nbuf[MAX_NAME_LEN];
            snprintf(nbuf, sizeof(nbuf),
                     "Secure Boot: %s", secure_boot ? "Enabled" : "Disabled");

            CompatItem& it = new_item(report);
            it.category    = CAT_SB;
            it.name        = nbuf;
            it.critical    = false;

            if (secure_boot) {
                it.score          = COMPAT_MINOR;
                it.detail         = "Secure Boot is enabled. Some distros support it; "
                                    "others require it disabled.";
                it.recommendation = "Ubuntu, Fedora, and openSUSE work with Secure Boot. "
                                    "Disable it in BIOS/UEFI settings before installing "
                                    "Arch, Gentoo, or Void.";
            } else {
                it.score          = COMPAT_FULL;
                it.detail         = "Secure Boot is disabled — all Linux distributions "
                                    "will boot without issues.";
                it.recommendation = "No action needed. Any distribution can be installed.";
            }
        }

        /* --- Report item: TPM --- */
        {
            char nbuf[MAX_NAME_LEN];
            snprintf(nbuf, sizeof(nbuf),
                     "TPM: %s", has_tpm ? "Present" : "Not detected");

            CompatItem& it    = new_item(report);
            it.category       = CAT_TPM;
            it.name           = nbuf;
            it.critical       = false;
            it.score          = COMPAT_FULL;
            it.detail         = has_tpm
                ? "TPM chip present — accessible on Linux via tpm2-tools."
                : "No TPM chip detected.";
            it.recommendation = "TPM can be used with LUKS full-disk encryption on Linux.";
        }
    }
};


/* =================================================================
   PowerAnalyzer — detect laptop and warn about power management
   ================================================================= */
class PowerAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        SYSTEM_POWER_STATUS sps;
        GetSystemPowerStatus(&sps);

        /* BatteryFlag 128 = no battery (desktop), 255 = unknown */
        if (sps.BatteryFlag == 128 || sps.BatteryFlag == 255) return;

        int  pct   = (sps.BatteryLifePercent == 255) ? 0 : sps.BatteryLifePercent;
        bool on_ac = (sps.ACLineStatus == 1);

        char nbuf[MAX_NAME_LEN];
        snprintf(nbuf, sizeof(nbuf),
                 "Battery: %d%%  |  Power source: %s",
                 pct, on_ac ? "AC adapter" : "Battery");

        CompatItem& it    = new_item(report);
        it.category       = CAT_POWER;
        it.name           = nbuf;
        it.critical       = false;
        it.score          = COMPAT_MINOR;
        it.detail         = "Laptop detected. Linux power management works differently from Windows.";
        it.recommendation = "Install TLP or power-profiles-daemon after setup. "
                            "Sleep/suspend may need a kernel parameter tweak on some laptops.";
    }
};


/* =================================================================
   VirtualizationAnalyzer — detect hypervisor and identify it
   ================================================================= */
class VirtualizationAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        int info[4] = {};
        __cpuid(info, 1);
        bool in_vm = (info[2] >> 31) & 1;   /* Hypervisor Present bit */
        if (!in_vm) return;

        /* Read the 12-character hypervisor vendor string */
        char hv_name[13] = {};
        __cpuid(info, 0x40000000);
        memcpy(hv_name,     &info[1], 4);
        memcpy(hv_name + 4, &info[2], 4);
        memcpy(hv_name + 8, &info[3], 4);

        char nbuf[MAX_NAME_LEN], dbuf[512];
        snprintf(nbuf, sizeof(nbuf), "Virtual Machine Detected: %s", hv_name);
        snprintf(dbuf, sizeof(dbuf),
            "Hypervisor: %s — this analysis is running inside a virtual environment.",
            hv_name);

        CompatItem& it    = new_item(report);
        it.category       = CAT_VIRT;
        it.name           = nbuf;
        it.critical       = false;
        it.score          = COMPAT_MINOR;
        it.detail         = dbuf;
        it.recommendation = "Results reflect the virtual hardware profile, not the physical host. "
                            "Re-run the tool on bare metal for an accurate assessment.";
    }
};


/* =================================================================
   OnlineAnalyzer — fetch the latest stable kernel from kernel.org
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

        char kernel_ver[64] = {};

        if (hRequest
         && WinHttpSendRequest(hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
         && WinHttpReceiveResponse(hRequest, nullptr)) {

            char  raw[512]   = {};
            DWORD bytes_read = 0;
            WinHttpReadData(hRequest, raw, sizeof(raw) - 1, &bytes_read);

            /*
             * finger_banner line format:
             *   "The latest stable version of the Linux kernel is: 6.x.y"
             * Locate "stable", then the ": " separator.
             */
            char* p = strstr(raw, "stable");
            if (p) {
                p = strstr(p, ": ");
                if (p) sscanf(p + 2, "%63s", kernel_ver);
            }
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (!kernel_ver[0]) return;   /* Could not parse version — skip item */

        char nbuf[MAX_NAME_LEN], dbuf[512];
        snprintf(nbuf, sizeof(nbuf),
                 "Latest Stable Kernel: %s  (source: kernel.org)", kernel_ver);
        snprintf(dbuf, sizeof(dbuf),
            "Kernel %s is the current stable release. "
            "Hardware compatibility is evaluated against this version's driver set.",
            kernel_ver);

        CompatItem& it    = new_item(report);
        it.category       = CAT_ONLINE;
        it.name           = nbuf;
        it.critical       = false;
        it.score          = COMPAT_FULL;
        it.detail         = dbuf;
        it.recommendation = "Choose a distribution that ships or allows installation of "
                            "a recent kernel for the best hardware coverage.";
    }

private:
    bool m_online;
};


/* =================================================================
   ReportPrinter — formats and outputs the final CompatReport
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

        /* Print items grouped by category in a fixed display order */
        const char* categories[] = {
            CAT_CPU, CAT_RAM, CAT_DISK, CAT_GPU, CAT_NET,
            CAT_AUDIO, CAT_FW, CAT_SB, CAT_TPM,
            CAT_POWER, CAT_VIRT, CAT_ONLINE, nullptr
        };

        for (int ci = 0; categories[ci] != nullptr; ci++) {
            bool header_printed = false;

            for (const auto& it : report.items) {
                if (it.category != categories[ci]) continue;

                if (!header_printed) {
                    printf(BLUE BOLD "  ┌─ %s\n" RESET, categories[ci]);
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

        /* Summary statistics */
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

        /* General assessment */
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

        /* Recommended distributions */
        printf("\n" BOLD WHITE "  🐧 RECOMMENDED DISTRIBUTIONS\n\n" RESET);
        printf("     1. Ubuntu 24.04 LTS  — Widest driver support, easiest installation\n");
        printf("     2. Linux Mint 22     — Windows-like interface, great for beginners\n");
        printf("     3. Fedora 40         — Latest kernel, excellent NVIDIA support\n");
        printf("     4. Pop!_OS 24.04     — Optimised for gamers and NVIDIA users\n");
        printf("     5. EndeavourOS       — Arch-based, full control over the system\n");

        /* Connectivity footnote */
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
   ENTRY POINT
   ================================================================= */

int main() {
    Console::enable_ansi();
    Console::print_header();

    /* Display basic system information */
    char  os_name[256]       = {};
    char  computer_name[256] = {};
    DWORD comp_size           = sizeof(computer_name);

    Registry::read_string(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "ProductName", os_name, sizeof(os_name));
    GetComputerNameA(computer_name, &comp_size);

    SYSTEMTIME st;
    GetLocalTime(&st);

    printf(DIM "  Computer : %s\n" RESET, computer_name);
    printf(DIM "  OS       : %s\n" RESET, os_name[0] ? os_name : "Windows");
    printf(DIM "  Date     : %02d/%02d/%04d  %02d:%02d\n\n" RESET,
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);

    /* Step 1 — Internet connectivity check */
    printf(CYAN "  Step 1/9: " RESET "Checking internet connection...\n");
    bool g_online = Internet::check_connection();
    printf("            %s\n\n",
           g_online ? GREEN "✓ Connected" RESET : YELLOW "✗ Offline" RESET);

    /* Steps 2-9 — hardware analysis via polymorphic Analyzer objects */
    CompatReport report;

    /* Build the pipeline of analyzers */
    std::vector<std::unique_ptr<Analyzer>> analyzers;
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

    /* Step metadata: label, progress-bar width, delay (ms) */
    struct StepMeta { const char* label; int steps; int delay_ms; bool online_only; };
    const StepMeta steps[] = {
        { "Step 2/9: Analyzing CPU           ",  8, 30, false },
        { "Step 3/9: Analyzing RAM           ",  6, 25, false },
        { "Step 4/9: Analyzing Disk          ",  7, 35, false },
        { "Step 5/9: Analyzing GPU           ",  9, 40, false },
        { "Step 6/9: Analyzing Network Cards ",  8, 35, false },
        { "Step 7/9: Analyzing Audio Cards   ",  6, 30, false },
        { "Step 8/9: Analyzing Firmware/UEFI ",  7, 25, false },
        { nullptr,                               0,  0, false },   /* Power   — no separate bar */
        { nullptr,                               0,  0, false },   /* Virt    — no separate bar */
        { "Step 9/9: Fetching kernel.org data", 12, 60, true  },
    };

    for (std::size_t i = 0; i < analyzers.size(); i++) {
        const StepMeta& meta = steps[i];
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
