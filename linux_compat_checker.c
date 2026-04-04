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
 *   cl linux_compat_checker.c /Fe:linux_compat_checker.exe
 *      /link advapi32.lib setupapi.lib winhttp.lib
 *
 * Compile (GCC / MinGW):
 *   gcc linux_compat_checker.c -o linux_compat_checker.exe
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>
#include <time.h>
#include <winhttp.h>
#include <intrin.h>

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

/* ─── Compatibility score levels ─── */
#define COMPAT_FULL    0   /* Fully compatible, no action needed      */
#define COMPAT_MINOR   1   /* Compatible but minor issues may occur   */
#define COMPAT_MAYBE   2   /* Possibly incompatible, check carefully  */
#define COMPAT_NONE    3   /* Incompatible, serious issues expected   */

/* ─── Capacity limits ─── */
#define MAX_DEVICES    256
#define MAX_NAME_LEN   256

/* ─── Category name constants — shared between analyzers and report ─── */
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

/* ─── Per-component compatibility record ─── */
typedef struct {
    char name[MAX_NAME_LEN];   /* Human-readable component name         */
    char category[64];         /* Category tag (must match CAT_* above) */
    char detail[512];          /* What was detected                     */
    char recommendation[512];  /* Actionable advice for the user        */
    int  score;                /* COMPAT_FULL … COMPAT_NONE             */
    int  critical;             /* 1 = weighted 2x in overall score      */
} CompatItem;

/* ─── Aggregated report ─── */
typedef struct {
    CompatItem items[MAX_DEVICES];
    int        count;
    int        score_counts[4];  /* [0]=full [1]=minor [2]=maybe [3]=none */
    double     overall_percent;  /* 0-100, higher is better               */
} CompatReport;

/* ─── Global state ─── */
static int g_online = 0;   /* 1 if kernel.org was reachable */

/* =================================================================
   HELPER UTILITIES
   ================================================================= */

/* Enable ANSI virtual terminal processing on Windows 10+ */
static void enable_ansi(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

/* Print the application banner */
static void print_header(void) {
    printf("\n");
    printf(CYAN BOLD "╔══════════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN BOLD "║" RESET BLUE BOLD "     🐧  Linux Kernel Compatibility Checker v2.1           " CYAN BOLD "║\n" RESET);
    printf(CYAN BOLD "║" RESET DIM  "     Windows 11 → Linux Migration Readiness Report          " CYAN BOLD "║\n" RESET);
    printf(CYAN BOLD "╚══════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
}

/* Return a colored label string for a given score */
static const char* score_label(int s) {
    switch (s) {
        case COMPAT_FULL:  return GREEN  BOLD "[0] FULLY COMPATIBLE     " RESET;
        case COMPAT_MINOR: return YELLOW BOLD "[1] COMPATIBLE (minor)   " RESET;
        case COMPAT_MAYBE: return ORANGE BOLD "[2] POSSIBLY INCOMPATIBLE" RESET;
        case COMPAT_NONE:  return RED    BOLD "[3] INCOMPATIBLE         " RESET;
        default:           return WHITE       "[?] UNKNOWN              " RESET;
    }
}

/* Return a colored bullet icon for a given score */
static const char* score_icon(int s) {
    switch (s) {
        case COMPAT_FULL:  return GREEN  "●" RESET;
        case COMPAT_MINOR: return YELLOW "◑" RESET;
        case COMPAT_MAYBE: return ORANGE "◔" RESET;
        case COMPAT_NONE:  return RED    "○" RESET;
        default:           return WHITE  "?" RESET;
    }
}

/* Display an animated progress bar while a step is running */
static void loading_bar(const char* msg, int steps, int delay_ms) {
    printf(CYAN "  ► " RESET "%s ", msg);
    fflush(stdout);
    for (int i = 0; i < steps; i++) {
        printf("█");
        fflush(stdout);
        Sleep(delay_ms);
    }
    printf(" " GREEN BOLD "✓\n" RESET);
}

/* Read a REG_SZ value from the registry; returns 1 on success */
static int reg_read_string(HKEY root, const char* subkey,
                            const char* value, char* out, DWORD size) {
    HKEY  hk;
    DWORD type = REG_SZ, sz = size;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;
    int ok = (RegQueryValueExA(hk, value, NULL, &type, (LPBYTE)out, &sz)
              == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

/* Read a REG_DWORD value from the registry; returns 1 on success */
static int reg_read_dword(HKEY root, const char* subkey,
                           const char* value, DWORD* out) {
    HKEY  hk;
    DWORD type = REG_DWORD, sz = sizeof(DWORD);
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;
    int ok = (RegQueryValueExA(hk, value, NULL, &type, (LPBYTE)out, &sz)
              == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

/* Probe kernel.org with an HTTPS HEAD request to test connectivity */
static int check_internet(void) {
    HINTERNET hSession = WinHttpOpen(
        L"LinuxCompatChecker/2.1",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 0;

    HINTERNET hConnect = WinHttpConnect(
        hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return 0;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"HEAD", L"/", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    int ok = 0;
    if (hRequest) {
        ok = WinHttpSendRequest(hRequest,
                 WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
          && WinHttpReceiveResponse(hRequest, NULL);
        WinHttpCloseHandle(hRequest);
    }

    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

/* =================================================================
   ANALYSIS FUNCTIONS
   ================================================================= */

/* 1. CPU — vendor, brand, core count, instruction set extensions */
static void analyze_cpu(CompatReport* r) {
    char vendor[13] = {0};
    char brand[49]  = {0};
    int  info[4];

    /* Read vendor string via CPUID leaf 0 */
    __cpuid(info, 0);
    memcpy(vendor,     &info[1], 4);
    memcpy(vendor + 4, &info[3], 4);
    memcpy(vendor + 8, &info[2], 4);

    /* Read brand string via CPUID leaves 0x80000002-4 */
    __cpuid(info, 0x80000000);
    if ((unsigned)info[0] >= 0x80000004) {
        __cpuid(info, 0x80000002); memcpy(brand,      info, 16);
        __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
        __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
    }

    /* Feature flags from CPUID leaf 1 */
    __cpuid(info, 1);
    int has_vmx  = (info[2] >> 5)  & 1;   /* Intel VT-x / AMD-V  */
    int has_sse2 = (info[3] >> 26) & 1;
    int has_avx  = (info[2] >> 28) & 1;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;

    int is_intel = (strstr(vendor, "GenuineIntel") != NULL);
    int is_amd   = (strstr(vendor, "AuthenticAMD") != NULL);

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, CAT_CPU, sizeof(it->category) - 1);
    snprintf(it->name, MAX_NAME_LEN - 1, "%.240s",
             brand[0] ? brand : vendor);
    it->critical = 1;

    if (is_intel || is_amd) {
        it->score = COMPAT_FULL;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "%s %s | %lu logical cores | SSE2:%s  AVX:%s  VT-x/AMD-V:%s",
            is_intel ? "Intel" : "AMD",
            brand[0] ? brand : "",
            (unsigned long)cores,
            has_sse2 ? "Yes" : "No",
            has_avx  ? "Yes" : "No",
            has_vmx  ? "Yes" : "No");
        strncpy(it->recommendation,
            "Excellent Linux support. Any distribution will work seamlessly.",
            sizeof(it->recommendation) - 1);
    } else {
        /* ARM or unknown architecture */
        it->score = COMPAT_MAYBE;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "Non-x86 processor detected: vendor='%s', %lu logical cores",
            vendor, (unsigned long)cores);
        strncpy(it->recommendation,
            "ARM Linux support is improving, but some x86-only software may not run. "
            "Consider Ubuntu ARM or Fedora ARM.",
            sizeof(it->recommendation) - 1);
    }
}

/* 2. RAM — total physical memory and suitability for desktop use */
static void analyze_ram(CompatReport* r) {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    DWORDLONG total_mb = ms.ullTotalPhys / (1024ULL * 1024);
    DWORDLONG total_gb = total_mb / 1024;

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, CAT_RAM, sizeof(it->category) - 1);
    snprintf(it->name, MAX_NAME_LEN - 1,
             "System Memory: %llu MB (%llu GB)",
             (unsigned long long)total_mb,
             (unsigned long long)total_gb);
    it->critical = 1;

    if (total_mb < 2048) {
        it->score = COMPAT_NONE;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "Only %llu MB RAM detected — Linux requires at least 1 GB to boot.",
            (unsigned long long)total_mb);
        strncpy(it->recommendation,
            "At least 4 GB is recommended. "
            "Try ultra-lightweight distros such as Lubuntu or Alpine Linux.",
            sizeof(it->recommendation) - 1);
    } else if (total_mb < 4096) {
        it->score = COMPAT_MINOR;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "%llu MB RAM available — sufficient for basic desktop use.",
            (unsigned long long)total_mb);
        strncpy(it->recommendation,
            "Use lightweight desktop environments such as Xfce or LXQt.",
            sizeof(it->recommendation) - 1);
    } else {
        it->score = COMPAT_FULL;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "%llu MB (%llu GB) RAM — excellent for any desktop workload.",
            (unsigned long long)total_mb,
            (unsigned long long)total_gb);
        strncpy(it->recommendation,
            "All desktop environments and virtualization will run comfortably.",
            sizeof(it->recommendation) - 1);
    }
}

/* 3. Disk — free space, drive type (SSD/HDD), NVMe detection */
static void analyze_storage(CompatReport* r) {
    ULARGE_INTEGER free_bytes, total_bytes;
    GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, NULL);
    ULONGLONG total_gb = total_bytes.QuadPart / (1024ULL * 1024 * 1024);
    ULONGLONG free_gb  = free_bytes.QuadPart  / (1024ULL * 1024 * 1024);

    /* Open PhysicalDrive0 once and reuse the handle for both queries */
    int is_ssd  = 0;
    int is_nvme = 0;

    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk != INVALID_HANDLE_VALUE) {
        DWORD bytes_returned = 0;

        /* SSD detection — no rotational seek penalty */
        STORAGE_PROPERTY_QUERY       spq_seek = {0};
        DEVICE_SEEK_PENALTY_DESCRIPTOR dsp      = {0};
        spq_seek.PropertyId = StorageDeviceSeekPenaltyProperty;
        spq_seek.QueryType  = PropertyStandardQuery;
        if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                            &spq_seek, sizeof(spq_seek),
                            &dsp, sizeof(dsp),
                            &bytes_returned, NULL)) {
            is_ssd = !dsp.IncursSeekPenalty;
        }

        /* NVMe detection — query StorageDeviceProperty and inspect BusType */
        STORAGE_PROPERTY_QUERY spq_desc = {0};
        spq_desc.PropertyId = StorageDeviceProperty;
        spq_desc.QueryType  = PropertyStandardQuery;
        char desc_buf[2048] = {0};
        if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                            &spq_desc, sizeof(spq_desc),
                            desc_buf, sizeof(desc_buf),
                            &bytes_returned, NULL)) {
            STORAGE_DEVICE_DESCRIPTOR* desc =
                (STORAGE_DEVICE_DESCRIPTOR*)desc_buf;
            is_nvme = (desc->BusType == BusTypeNvme);
        }

        CloseHandle(hDisk);
    }

    const char* drive_type = is_nvme ? "NVMe SSD"
                           : is_ssd  ? "SATA SSD"
                           :           "HDD";

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, CAT_DISK, sizeof(it->category) - 1);
    snprintf(it->name, MAX_NAME_LEN - 1,
             "Storage: %llu GB total / %llu GB free  [%s]",
             (unsigned long long)total_gb,
             (unsigned long long)free_gb,
             drive_type);
    it->critical = 1;

    if (free_gb < 20) {
        it->score = COMPAT_NONE;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "Free space: %llu GB — Linux installation requires at least 20 GB.",
            (unsigned long long)free_gb);
        strncpy(it->recommendation,
            "Free up disk space or install Linux on a separate drive.",
            sizeof(it->recommendation) - 1);
    } else if (free_gb < 50) {
        it->score = COMPAT_MINOR;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "Free space: %llu GB — installation is possible but headroom is limited.",
            (unsigned long long)free_gb);
        strncpy(it->recommendation,
            "Minimum viable migration. 50+ GB is recommended for comfortable use.",
            sizeof(it->recommendation) - 1);
    } else {
        it->score = COMPAT_FULL;
        snprintf(it->detail, sizeof(it->detail) - 1,
            "Free space: %llu GB — ample room for installation and data.",
            (unsigned long long)free_gb);
        if (is_ssd)
            strncpy(it->recommendation,
                "SSD + ample space = fast Linux experience. Use Ext4 or Btrfs.",
                sizeof(it->recommendation) - 1);
        else
            strncpy(it->recommendation,
                "HDD may feel slow. Prefer Ext4 and add a swap partition.",
                sizeof(it->recommendation) - 1);
    }
}

/* 4. GPU — detect vendor and assess open-source / proprietary driver situation */
static void analyze_gpu(CompatReport* r) {
    HDEVINFO devInfo = SetupDiGetClassDevsA(
        &GUID_DEVCLASS_DISPLAY, NULL, NULL, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(SP_DEVINFO_DATA);
    char buf[512];
    int  idx = 0;

    while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
        if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                SPDRP_DEVICEDESC, NULL,
                (PBYTE)buf, sizeof(buf), NULL))
            continue;

        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, CAT_GPU, sizeof(it->category) - 1);
        strncpy(it->name, buf, MAX_NAME_LEN - 1);
        it->critical = 1;

        int is_nvidia  = (strstr(buf, "NVIDIA")   || strstr(buf, "GeForce")
                       || strstr(buf, "Quadro")   || strstr(buf, "RTX")
                       || strstr(buf, "GTX"));
        int is_amd_gpu = (strstr(buf, "AMD")      || strstr(buf, "Radeon")
                       || strstr(buf, "RX "));
        int is_intel_g = (strstr(buf, "Intel")    || strstr(buf, "UHD")
                       || strstr(buf, "Iris")     || strstr(buf, "Arc"));
        int is_virtual = (strstr(buf, "VMware")   || strstr(buf, "VirtualBox")
                       || strstr(buf, "Microsoft Basic Render")
                       || strstr(buf, "SVGA"));

        if (is_nvidia) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, sizeof(it->detail) - 1, "NVIDIA GPU: %s", buf);
            strncpy(it->recommendation,
                "Install the proprietary NVIDIA driver (nvidia-driver package). "
                "The open-source Nouveau driver is limited. "
                "Ubuntu and Fedora make this easy via the GUI. "
                "Wayland support improved significantly in driver 510+.",
                sizeof(it->recommendation) - 1);
        } else if (is_amd_gpu) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, sizeof(it->detail) - 1, "AMD GPU: %s", buf);
            strncpy(it->recommendation,
                "Excellent in-kernel AMDGPU support — no extra drivers needed. "
                "Full Wayland and Vulkan support out of the box. "
                "GPU compute available via ROCm on supported cards.",
                sizeof(it->recommendation) - 1);
        } else if (is_intel_g) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, sizeof(it->detail) - 1, "Intel GPU: %s", buf);
            strncpy(it->recommendation,
                "In-kernel i915/xe driver provides excellent support. "
                "Fully compatible with both Wayland and X11.",
                sizeof(it->recommendation) - 1);
        } else if (is_virtual) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "Virtual/emulated display adapter: %s", buf);
            strncpy(it->recommendation,
                "Virtual environment detected. "
                "The real GPU will be used when installed on physical hardware.",
                sizeof(it->recommendation) - 1);
        } else {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, sizeof(it->detail) - 1, "Unrecognized GPU: %s", buf);
            strncpy(it->recommendation,
                "Search 'Linux + [GPU name] driver' to verify support.",
                sizeof(it->recommendation) - 1);
        }

        if (r->count >= MAX_DEVICES - 1) break;
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

/* 5. Network — Wi-Fi and Ethernet adapters, driver availability */
static void analyze_network(CompatReport* r) {
    HDEVINFO devInfo = SetupDiGetClassDevsA(
        &GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(SP_DEVINFO_DATA);
    char buf[512], hw_id[512];
    int  idx = 0;

    while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
        if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                SPDRP_DEVICEDESC, NULL,
                (PBYTE)buf, sizeof(buf), NULL))
            continue;

        /* Skip virtual and infrastructure adapters */
        if (strstr(buf, "Microsoft") || strstr(buf, "WAN Miniport") ||
            strstr(buf, "Bluetooth") || strstr(buf, "Loopback"))
            continue;

        SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
            SPDRP_HARDWAREID, NULL, (PBYTE)hw_id, sizeof(hw_id), NULL);

        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, CAT_NET, sizeof(it->category) - 1);
        strncpy(it->name, buf, MAX_NAME_LEN - 1);

        int is_intel_net = (strstr(buf, "Intel")    != NULL);
        int is_realtek   = (strstr(buf, "Realtek")  != NULL);
        int is_broadcom  = (strstr(buf, "Broadcom") != NULL);
        int is_atheros   = (strstr(buf, "Atheros")  || strstr(buf, "Killer"));
        int is_mediatek  = (strstr(buf, "MediaTek") || strstr(buf, "Ralink"));
        int is_wifi      = (strstr(buf, "Wi-Fi")    || strstr(buf, "Wireless")
                         || strstr(buf, "WLAN"));

        if (is_intel_net) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "%s adapter: %s",
                is_wifi ? "Intel Wi-Fi" : "Intel Ethernet", buf);
            strncpy(it->recommendation,
                is_wifi
                    ? "Intel Wi-Fi has excellent Linux support via the iwlwifi in-kernel driver."
                    : "Intel Ethernet fully supported in-kernel (e1000e / igb / ixgbe).",
                sizeof(it->recommendation) - 1);
        } else if (is_realtek) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "Realtek %s: %s", is_wifi ? "Wi-Fi" : "Ethernet", buf);
            strncpy(it->recommendation,
                is_wifi
                    ? "Realtek Wi-Fi may need an out-of-tree driver (rtl88xx series). "
                      "Install via the dkms package from the manufacturer's GitHub."
                    : "Realtek Ethernet generally works (r8169 driver), "
                      "but a small number of models have quirks.",
                sizeof(it->recommendation) - 1);
        } else if (is_broadcom) {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "Broadcom %s: %s", is_wifi ? "Wi-Fi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "Broadcom adapters can be troublesome on Linux. "
                "The b43 or broadcom-sta driver is required and may not be "
                "available during installation (no internet access).",
                sizeof(it->recommendation) - 1);
        } else if (is_atheros) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "Atheros/Killer %s: %s", is_wifi ? "Wi-Fi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "Atheros/Killer adapters are fully supported in-kernel "
                "via ath10k / ath11k drivers.",
                sizeof(it->recommendation) - 1);
        } else if (is_mediatek) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "MediaTek/Ralink %s: %s", is_wifi ? "Wi-Fi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "MediaTek mt76 driver is in-kernel but older chipsets "
                "may require a firmware package.",
                sizeof(it->recommendation) - 1);
        } else {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "%s: %s  [HWID: %.80s]",
                is_wifi ? "Wi-Fi" : "Network Adapter", buf, hw_id);
            strncpy(it->recommendation,
                "Check the manufacturer's site or linux-hardware.org for driver availability.",
                sizeof(it->recommendation) - 1);
        }

        if (r->count >= MAX_DEVICES - 1) break;
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

/* 6. Audio — sound cards and USB audio interfaces */
static void analyze_audio(CompatReport* r) {
    HDEVINFO devInfo = SetupDiGetClassDevsA(
        &GUID_DEVCLASS_MEDIA, NULL, NULL, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(SP_DEVINFO_DATA);
    char buf[512];
    int  idx = 0;

    while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
        if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
                SPDRP_DEVICEDESC, NULL,
                (PBYTE)buf, sizeof(buf), NULL))
            continue;

        /* Skip virtual audio devices */
        if (strstr(buf, "Virtual") || strstr(buf, "Microsoft")) continue;

        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, CAT_AUDIO, sizeof(it->category) - 1);
        strncpy(it->name, buf, MAX_NAME_LEN - 1);

        int is_hda       = (strstr(buf, "Realtek") || strstr(buf, "Intel")
                         || strstr(buf, "AMD")     || strstr(buf, "Nvidia"));
        int is_focusrite = (strstr(buf, "Focusrite") || strstr(buf, "Scarlett"));
        int is_creative  = (strstr(buf, "Creative")  || strstr(buf, "Sound Blaster"));

        if (is_hda) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "HDA-compatible audio device: %s", buf);
            strncpy(it->recommendation,
                "Fully compatible with ALSA / PulseAudio / PipeWire "
                "via the in-kernel snd_hda_intel driver.",
                sizeof(it->recommendation) - 1);
        } else if (is_focusrite) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "USB audio interface: %s", buf);
            strncpy(it->recommendation,
                "Focusrite generally works on Linux. "
                "Scarlett Gen 2/3/4 are well-supported. "
                "Use JACK or PipeWire for pro-audio workflows.",
                sizeof(it->recommendation) - 1);
        } else if (is_creative) {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, sizeof(it->detail) - 1,
                "Creative audio device: %s", buf);
            strncpy(it->recommendation,
                "Creative Sound Blaster cards have limited Linux support; "
                "some DSP features will not function.",
                sizeof(it->recommendation) - 1);
        } else {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, sizeof(it->detail) - 1, "Audio device: %s", buf);
            strncpy(it->recommendation,
                "USB and Bluetooth audio devices generally work out of the box on Linux.",
                sizeof(it->recommendation) - 1);
        }

        if (r->count >= MAX_DEVICES - 1) break;
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

/* 7. Firmware — UEFI vs legacy BIOS, Secure Boot state, TPM presence */
static void analyze_firmware(CompatReport* r) {

    /* UEFI vs Legacy BIOS — PEFirmwareType: 1=BIOS, 2=UEFI */
    DWORD pe_fw_type = 0;
    int   is_uefi    = 0;
    if (reg_read_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control",
            "PEFirmwareType", &pe_fw_type)) {
        is_uefi = (pe_fw_type == 2);
    }

    /* Secure Boot — UEFISecureBootEnabled: 0=off, 1=on */
    DWORD sb_val      = 0;
    int   secure_boot = 0;
    if (reg_read_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            "UEFISecureBootEnabled", &sb_val)) {
        secure_boot = (sb_val != 0);
    }

    /* TPM — enumerate ROOT\TPM device class */
    int      has_tpm = 0;
    HDEVINFO tpmDev  = SetupDiGetClassDevsA(NULL, "ROOT\\TPM", NULL,
        DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (tpmDev != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA td;
        td.cbSize = sizeof(td);
        has_tpm   = SetupDiEnumDeviceInfo(tpmDev, 0, &td);
        SetupDiDestroyDeviceInfoList(tpmDev);
    }

    /* BIOS vendor and version strings */
    char bios_ver[128]    = {0};
    char bios_vendor[128] = {0};
    reg_read_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "BIOSVersion", bios_ver,    sizeof(bios_ver));
    reg_read_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "BIOSVendor",  bios_vendor, sizeof(bios_vendor));

    /* --- Report item: UEFI / BIOS --- */
    {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, CAT_FW, sizeof(it->category) - 1);
        snprintf(it->name, MAX_NAME_LEN - 1,
                 "Boot mode: %s  |  BIOS: %s %s",
                 is_uefi ? "UEFI" : "Legacy BIOS",
                 bios_vendor, bios_ver);
        it->critical = 1;

        if (is_uefi) {
            it->score = COMPAT_FULL;
            strncpy(it->detail,
                "UEFI firmware detected. Modern bootloaders (GRUB2, systemd-boot) "
                "require a UEFI system.",
                sizeof(it->detail) - 1);
            strncpy(it->recommendation,
                "Install Linux in UEFI mode. An EFI System Partition (ESP) will be created.",
                sizeof(it->recommendation) - 1);
        } else {
            it->score = COMPAT_MINOR;
            strncpy(it->detail,
                "Legacy BIOS detected. Linux can be installed but some features "
                "(GPT, secure boot) are unavailable.",
                sizeof(it->detail) - 1);
            strncpy(it->recommendation,
                "Use an MBR partition scheme during installation.",
                sizeof(it->recommendation) - 1);
        }
    }

    /* --- Report item: Secure Boot --- */
    {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, CAT_SB, sizeof(it->category) - 1);
        snprintf(it->name, MAX_NAME_LEN - 1,
                 "Secure Boot: %s", secure_boot ? "Enabled" : "Disabled");
        it->critical = 0;

        if (secure_boot) {
            it->score = COMPAT_MINOR;
            strncpy(it->detail,
                "Secure Boot is enabled. Some distros support it; others require it disabled.",
                sizeof(it->detail) - 1);
            strncpy(it->recommendation,
                "Ubuntu, Fedora, and openSUSE work with Secure Boot. "
                "Disable it in BIOS/UEFI settings before installing Arch, Gentoo, or Void.",
                sizeof(it->recommendation) - 1);
        } else {
            it->score = COMPAT_FULL;
            strncpy(it->detail,
                "Secure Boot is disabled — all Linux distributions will boot without issues.",
                sizeof(it->detail) - 1);
            strncpy(it->recommendation,
                "No action needed. Any distribution can be installed.",
                sizeof(it->recommendation) - 1);
        }
    }

    /* --- Report item: TPM --- */
    {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, CAT_TPM, sizeof(it->category) - 1);
        snprintf(it->name, MAX_NAME_LEN - 1,
                 "TPM: %s", has_tpm ? "Present" : "Not detected");
        it->critical = 0;
        it->score    = COMPAT_FULL;
        strncpy(it->detail,
            has_tpm
                ? "TPM chip present — accessible on Linux via tpm2-tools."
                : "No TPM chip detected.",
            sizeof(it->detail) - 1);
        strncpy(it->recommendation,
            "TPM can be used with LUKS full-disk encryption on Linux.",
            sizeof(it->recommendation) - 1);
    }
}

/* 8. Power / Battery — detect laptop and warn about power management quirks */
static void analyze_power(CompatReport* r) {
    SYSTEM_POWER_STATUS sps;
    GetSystemPowerStatus(&sps);

    /* BatteryFlag 128 = no battery (desktop), 255 = unknown */
    if (sps.BatteryFlag == 128 || sps.BatteryFlag == 255) return;

    int pct   = (sps.BatteryLifePercent == 255) ? 0 : sps.BatteryLifePercent;
    int on_ac = (sps.ACLineStatus == 1);

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, CAT_POWER, sizeof(it->category) - 1);
    snprintf(it->name, MAX_NAME_LEN - 1,
             "Battery: %d%%  |  Power source: %s",
             pct, on_ac ? "AC adapter" : "Battery");
    it->critical = 0;
    it->score    = COMPAT_MINOR;
    strncpy(it->detail,
        "Laptop detected. Linux power management works differently from Windows.",
        sizeof(it->detail) - 1);
    strncpy(it->recommendation,
        "Install TLP or power-profiles-daemon after setup. "
        "Sleep/suspend may need a kernel parameter tweak on some laptops.",
        sizeof(it->recommendation) - 1);
}

/* 9. Virtualization — detect hypervisor and identify it by vendor string */
static void analyze_virtualization(CompatReport* r) {
    int info[4];
    __cpuid(info, 1);
    int in_vm = (info[2] >> 31) & 1;   /* Hypervisor Present bit */
    if (!in_vm) return;

    /* Read the 12-character hypervisor vendor string */
    char hv_name[13] = {0};
    __cpuid(info, 0x40000000);
    memcpy(hv_name,     &info[1], 4);
    memcpy(hv_name + 4, &info[2], 4);
    memcpy(hv_name + 8, &info[3], 4);

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, CAT_VIRT, sizeof(it->category) - 1);
    snprintf(it->name, MAX_NAME_LEN - 1,
             "Virtual Machine Detected: %s", hv_name);
    it->critical = 0;
    it->score    = COMPAT_MINOR;
    snprintf(it->detail, sizeof(it->detail) - 1,
        "Hypervisor: %s — this analysis is running inside a virtual environment.",
        hv_name);
    strncpy(it->recommendation,
        "Results reflect the virtual hardware profile, not the physical host. "
        "Re-run the tool on bare metal for an accurate assessment.",
        sizeof(it->recommendation) - 1);
}

/* 10. Online — fetch the latest stable kernel version from kernel.org */
static void analyze_online(CompatReport* r) {
    if (!g_online) return;

    HINTERNET hSession = WinHttpOpen(L"LinuxCompatChecker/2.1",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(
        hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = hConnect
        ? WinHttpOpenRequest(hConnect, L"GET", L"/finger_banner",
              NULL, WINHTTP_NO_REFERER,
              WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
        : NULL;

    char kernel_ver[64] = {0};

    if (hRequest
     && WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
     && WinHttpReceiveResponse(hRequest, NULL)) {

        char  raw[512]   = {0};
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

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, CAT_ONLINE, sizeof(it->category) - 1);
    snprintf(it->name, MAX_NAME_LEN - 1,
             "Latest Stable Kernel: %s  (source: kernel.org)", kernel_ver);
    it->critical = 0;
    it->score    = COMPAT_FULL;
    snprintf(it->detail, sizeof(it->detail) - 1,
        "Kernel %s is the current stable release. "
        "Hardware compatibility is evaluated against this version's driver set.",
        kernel_ver);
    strncpy(it->recommendation,
        "Choose a distribution that ships or allows installation of "
        "a recent kernel for the best hardware coverage.",
        sizeof(it->recommendation) - 1);
}

/* =================================================================
   REPORT COMPUTATION AND DISPLAY
   ================================================================= */

/* Compute summary statistics and overall weighted compatibility percentage */
static void compute_report(CompatReport* r) {
    memset(r->score_counts, 0, sizeof(r->score_counts));

    double weighted     = 0.0;
    double total_weight = 0.0;

    for (int i = 0; i < r->count; i++) {
        int s = r->items[i].score;
        if (s >= 0 && s <= 3) r->score_counts[s]++;

        double w      = r->items[i].critical ? 2.0 : 1.0;
        double contrib = (3.0 - (double)s) / 3.0;  /* 1.0=perfect, 0.0=worst */
        weighted      += contrib * w;
        total_weight  += w;
    }

    r->overall_percent = (total_weight > 0.0)
        ? (weighted / total_weight) * 100.0
        : 0.0;
}

/* Print a filled block progress bar with color coding */
static void print_percent_bar(double pct, int width) {
    int         filled = (int)(pct / 100.0 * (double)width);
    const char* color  = (pct >= 75.0) ? GREEN
                       : (pct >= 50.0) ? YELLOW
                       :                 RED;
    printf("%s%s[", color, BOLD);
    for (int i = 0; i < width; i++)
        printf(i < filled ? "█" : "░");
    printf("] %.1f%%" RESET, pct);
}

static void print_report(CompatReport* r) {
    compute_report(r);

    printf("\n");
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
    printf(BOLD WHITE "  📋 DETAILED COMPATIBILITY REPORT\n" RESET);
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);

    /* Print items grouped by category in a fixed display order.
     * The CAT_* constants guarantee the category strings match exactly. */
    const char* categories[] = {
        CAT_CPU, CAT_RAM, CAT_DISK, CAT_GPU, CAT_NET,
        CAT_AUDIO, CAT_FW, CAT_SB, CAT_TPM,
        CAT_POWER, CAT_VIRT, CAT_ONLINE, NULL
    };

    for (int ci = 0; categories[ci] != NULL; ci++) {
        int header_printed = 0;

        for (int i = 0; i < r->count; i++) {
            if (strcmp(r->items[i].category, categories[ci]) != 0) continue;

            if (!header_printed) {
                printf(BLUE BOLD "  ┌─ %s\n" RESET, categories[ci]);
                header_printed = 1;
            }

            CompatItem* it = &r->items[i];
            printf("  │  %s  %s  %s\n",
                   score_icon(it->score),
                   score_label(it->score),
                   it->name);
            printf("  │     " DIM "→ %s\n" RESET, it->detail);
            printf("  │     " CYAN "✦ %s\n" RESET, it->recommendation);
            printf("  │\n");
        }
    }

    /* Summary statistics */
    printf("\n");
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
    printf(BOLD WHITE "  📊 SUMMARY STATISTICS\n" RESET);
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);

    printf("  %s  Fully Compatible         : %d component(s)\n",
           GREEN  "●" RESET, r->score_counts[0]);
    printf("  %s  Compatible (minor issues): %d component(s)\n",
           YELLOW "◑" RESET, r->score_counts[1]);
    printf("  %s  Possibly Incompatible    : %d component(s)\n",
           ORANGE "◔" RESET, r->score_counts[2]);
    printf("  %s  Incompatible             : %d component(s)\n",
           RED    "○" RESET, r->score_counts[3]);
    printf("\n  Total components analyzed: %d\n", r->count);

    printf("\n  Overall Compatibility Score:\n  ");
    print_percent_bar(r->overall_percent, 40);
    printf("\n\n");

    /* General assessment */
    printf(BOLD WHITE "  🧭 GENERAL ASSESSMENT\n\n" RESET);
    if (r->overall_percent >= 85.0) {
        printf(GREEN BOLD "  ✅ Your system is READY for Linux!\n" RESET);
        printf("     Ubuntu, Fedora, Mint, or any major distribution will work seamlessly.\n");
    } else if (r->overall_percent >= 65.0) {
        printf(YELLOW BOLD "  ⚠️  Your system is MOSTLY compatible with Linux.\n" RESET);
        printf("     A few components may need additional drivers or configuration.\n");
        printf("     Ubuntu LTS or Linux Mint is recommended for the best out-of-box experience.\n");
    } else if (r->overall_percent >= 40.0) {
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
           g_online
               ? GREEN "Connected — live data fetched from kernel.org" RESET
               : YELLOW "Offline — local analysis only" RESET);

    printf("\n");
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
    printf(DIM "  Linux Kernel Compatibility Checker v2.1  |  linux-hardware.org\n" RESET);
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);
}

/* =================================================================
   ENTRY POINT
   ================================================================= */

int main(void) {
    enable_ansi();
    print_header();

    /* Display basic system information */
    char  os_name[256]       = {0};
    char  computer_name[256] = {0};
    DWORD comp_size           = sizeof(computer_name);

    reg_read_string(HKEY_LOCAL_MACHINE,
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
    g_online = check_internet();
    printf("            %s\n\n",
           g_online ? GREEN "✓ Connected" RESET : YELLOW "✗ Offline" RESET);

    /* Steps 2-9 — hardware analysis */
    CompatReport report = {0};

    loading_bar("Step 2/9: Analyzing CPU           ", 8,  30);
    analyze_cpu(&report);

    loading_bar("Step 3/9: Analyzing RAM           ", 6,  25);
    analyze_ram(&report);

    loading_bar("Step 4/9: Analyzing Disk          ", 7,  35);
    analyze_storage(&report);

    loading_bar("Step 5/9: Analyzing GPU           ", 9,  40);
    analyze_gpu(&report);

    loading_bar("Step 6/9: Analyzing Network Cards ", 8,  35);
    analyze_network(&report);

    loading_bar("Step 7/9: Analyzing Audio Cards   ", 6,  30);
    analyze_audio(&report);

    loading_bar("Step 8/9: Analyzing Firmware/UEFI ", 7,  25);
    analyze_firmware(&report);
    analyze_power(&report);           /* Appended to step 8 — no separate bar needed */
    analyze_virtualization(&report);  /* Same */

    if (g_online) {
        loading_bar("Step 9/9: Fetching kernel.org data", 12, 60);
        analyze_online(&report);
    } else {
        printf(DIM "  Step 9/9: Offline — kernel.org step skipped.\n" RESET);
    }

    printf("\n");
    print_report(&report);

    printf("  Press Enter to exit...\n");
    getchar();
    return 0;
}
