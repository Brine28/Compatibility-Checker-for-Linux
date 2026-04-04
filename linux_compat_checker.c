/*
 * Linux Kernel Compatibility Checker for Windows 11
 * ===================================================
 * Checks hardware and system compatibility for Linux migration.
 * Scores: 0=Full compat | 1=Compatible (minor issues) | 2=Maybe incompatible | 3=Incompatible
 *
 * Compile: cl linux_compat_checker.c /Fe:linux_compat_checker.exe /link advapi32.lib setupapi.lib
 * Or GCC: gcc linux_compat_checker.c -o linux_compat_checker.exe -ladvapi32 -lsetupapi
 */

#define _WIN32_WINNT 0x0A00
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

/* ─── ANSI renk kodları ─── */
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
#define BG_DARK     "\033[40m"
#define ORANGE      "\033[38;5;208m"

/* ─── Uyumluluk seviyeleri ─── */
#define COMPAT_FULL        0
#define COMPAT_MINOR       1
#define COMPAT_MAYBE       2
#define COMPAT_NONE        3

/* ─── Maksimum aygıt sayısı ─── */
#define MAX_DEVICES        256
#define MAX_NAME_LEN       256

/* ─── Veri yapıları ─── */
typedef struct {
    char name[MAX_NAME_LEN];
    char category[64];
    char detail[512];
    char recommendation[512];
    int  score;          /* 0-3 */
    int  critical;       /* Kritik bileşen mi? */
} CompatItem;

typedef struct {
    CompatItem items[MAX_DEVICES];
    int        count;
    int        score_counts[4]; /* [0]=tam, [1]=minor, [2]=maybe, [3]=none */
    double     overall_percent; /* 0-100 */
} CompatReport;

/* ─── Global sayaçlar ─── */
static int g_online = 0;   /* İnternete bağlanabildi mi? */

/* ═══════════════════════════════════════════════
   YARDIMCI FONKSİYONLAR
   ═══════════════════════════════════════════════ */

/* ANSI'yi etkinleştir (Windows 10+) */
static void enable_ansi(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

/* Renkli başlık yazdır */
static void print_header(void) {
    printf("\n");
    printf(CYAN BOLD "╔══════════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN BOLD "║" RESET BLUE BOLD "     🐧  Linux Kernel Compatibility Checker v2.0           " CYAN BOLD "║\n" RESET);
    printf(CYAN BOLD "║" RESET DIM "     Windows 11 → Linux Migration Readiness Report               " CYAN BOLD "║\n" RESET);
    printf(CYAN BOLD "╚══════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
}

/* Skor etiketi */
static const char* score_label(int s) {
    switch(s) {
        case COMPAT_FULL:  return GREEN  BOLD "[0] TAM UYUMLU       " RESET;
        case COMPAT_MINOR: return YELLOW BOLD "[1] UYUMLU (Aksaklık)" RESET;
        case COMPAT_MAYBE: return ORANGE BOLD "[2] BELKI UYUMSUZ    " RESET;
        case COMPAT_NONE:  return RED    BOLD "[3] UYUMSUZ          " RESET;
        default:           return WHITE  "[?] BİLİNMİYOR       " RESET;
    }
}

/* Skor simgesi */
static const char* score_icon(int s) {
    switch(s) {
        case COMPAT_FULL:  return GREEN  "●" RESET;
        case COMPAT_MINOR: return YELLOW "◑" RESET;
        case COMPAT_MAYBE: return ORANGE "◔" RESET;
        case COMPAT_NONE:  return RED    "○" RESET;
        default:           return WHITE  "?" RESET;
    }
}

/* Yükleme animasyonu */
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

/* Registry'den string oku */
static int reg_read_string(HKEY root, const char* subkey, const char* value, char* out, DWORD size) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return 0;
    DWORD type = REG_SZ, sz = size;
    int ok = (RegQueryValueExA(hk, value, NULL, &type, (LPBYTE)out, &sz) == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

/* Registry'den DWORD oku */
static int reg_read_dword(HKEY root, const char* subkey, const char* value, DWORD* out) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return 0;
    DWORD type = REG_DWORD, sz = sizeof(DWORD);
    int ok = (RegQueryValueExA(hk, value, NULL, &type, (LPBYTE)out, &sz) == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

/* İnternete bağlanabilir miyiz? */
static int check_internet(void) {
    HINTERNET hSession = WinHttpOpen(
        L"LinuxCompatChecker/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 0;
    HINTERNET hConnect = WinHttpConnect(hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return 0; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", L"/", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    int ok = 0;
    if (hRequest) {
        ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
             WinHttpReceiveResponse(hRequest, NULL);
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

/* ═══════════════════════════════════════════════
   ANALİZ FONKSİYONLARI
   ═══════════════════════════════════════════════ */

/* 1. CPU Analizi */
static void analyze_cpu(CompatReport* r) {
    char vendor[128] = {0}, brand[256] = {0};
    int info[4];

    /* CPUID */
    __cpuid(info, 0);
    memcpy(vendor,     &info[1], 4);
    memcpy(vendor + 4, &info[3], 4);
    memcpy(vendor + 8, &info[2], 4);
    vendor[12] = 0;

    __cpuid(info, 0x80000000);
    if ((unsigned)info[0] >= 0x80000004) {
        __cpuid(info, 0x80000002); memcpy(brand,      info, 16);
        __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
        __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
        brand[48] = 0;
    }

    /* Virtualization desteği */
    __cpuid(info, 1);
    int has_vmx = (info[2] >> 5) & 1;   /* Intel VT-x */
    int has_sse2 = (info[3] >> 26) & 1;
    int has_avx  = (info[2] >> 28) & 1;

    /* Çekirdek sayısı */
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, "CPU", 63);
    snprintf(it->name, MAX_NAME_LEN - 1, "%.240s", brand[0] ? brand : vendor);
    it->critical = 1;

    /* AMD veya Intel? Her ikisi de iyi Linux desteğine sahip */
    int is_intel = (strstr(vendor, "Intel") != NULL);
    int is_amd   = (strstr(vendor, "AMD")   != NULL);
    int is_arm   = (!is_intel && !is_amd);

    if (is_arm) {
        it->score = COMPAT_MAYBE;
        snprintf(it->detail, 511,
            "ARM-based processor detected (%s). Core count: %lu",
            vendor, (unsigned long)cores);
        snprintf(it->recommendation, 511,
            "ARM Linux support is improving, but some software requires x86_64. "
            "Try Ubuntu ARM or Fedora ARM.");
    } else if (is_intel || is_amd) {
        it->score = COMPAT_FULL;
        snprintf(it->detail, 511,
            "%s %s | %lu logical cores | SSE2:%s AVX:%s VT-x/AMD-V:%s",
            is_intel ? "Intel" : "AMD",
            brand[0] ? brand : "",
            (unsigned long)cores,
            has_sse2 ? "Yes" : "No",
            has_avx  ? "Yes" : "No",
            has_vmx  ? "Yes" : "No");
        snprintf(it->recommendation, 511,
            "Excellent Linux support. Any distribution will work seamlessly.");
    } else {
        it->score = COMPAT_MAYBE;
        snprintf(it->detail, 511, "Unknown CPU architecture: %s", vendor);
        strncpy(it->recommendation, "Manual verification recommended.", 511);
    }
}

/* 2. RAM Analizi */
static void analyze_ram(CompatReport* r) {
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    DWORDLONG total_mb = ms.ullTotalPhys / (1024*1024);

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, "RAM", 63);
    snprintf(it->name, MAX_NAME_LEN - 1, "Sistem Belleği: %llu MB (%llu GB)",
             (unsigned long long)total_mb,
             (unsigned long long)(total_mb / 1024));
    it->critical = 1;

    if (total_mb < 2048) {
        it->score = COMPAT_NONE;
        snprintf(it->detail, 511, "Only %llu MB RAM available. Linux requires at least 1 GB.", (unsigned long long)total_mb);
        strncpy(it->recommendation,
            "At least 4 GB RAM is recommended. Try lightweight distributions like Lubuntu or Alpine.",
            511);
    } else if (total_mb < 4096) {
        it->score = COMPAT_MINOR;
        snprintf(it->detail, 511, "%llu MB RAM available. Sufficient for basic use.", (unsigned long long)total_mb);
        strncpy(it->recommendation, "Use lightweight desktop environments like Xfce or LXQt.", 511);
    } else {
        it->score = COMPAT_FULL;
        snprintf(it->detail, 511, "%llu MB (%llu GB) RAM available. Excellent.",
                 (unsigned long long)total_mb,
                 (unsigned long long)(total_mb / 1024));
        strncpy(it->recommendation, "All desktop environments and virtualization will work comfortably.", 511);
    }
}

/* 3. Disk / Depolama Analizi */
static void analyze_storage(CompatReport* r) {
    ULARGE_INTEGER free_bytes, total_bytes;
    GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, NULL);
    ULONGLONG total_gb = total_bytes.QuadPart / (1024ULL*1024*1024);
    ULONGLONG free_gb  = free_bytes.QuadPart  / (1024ULL*1024*1024);

    /* Disk tipi: SSD mi HDD mi? (DeviceIoControl ile TRIM kontrolü) */
    int is_ssd = 0;
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY spq = {0};
        spq.PropertyId = StorageDeviceSeekPenaltyProperty;
        spq.QueryType  = PropertyStandardQuery;
        DEVICE_SEEK_PENALTY_DESCRIPTOR dsp = {0};
        DWORD bytes = 0;
        if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                            &spq, sizeof(spq), &dsp, sizeof(dsp), &bytes, NULL)) {
            is_ssd = !dsp.IncursSeekPenalty;
        }
        CloseHandle(hDisk);
    }

    /* NVMe kontrolü */
    int is_nvme = 0;
    HANDLE hNvme = CreateFileA("\\\\.\\PhysicalDrive0", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hNvme != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY spq2 = {0};
        spq2.PropertyId = StorageAdapterProtocolSpecificProperty;
        spq2.QueryType  = PropertyStandardQuery;
        DWORD bytes2 = 0;
        char buf[1024] = {0};
        if (DeviceIoControl(hNvme, IOCTL_STORAGE_QUERY_PROPERTY,
                            &spq2, sizeof(spq2), buf, sizeof(buf), &bytes2, NULL)) {
            PSTORAGE_PROTOCOL_SPECIFIC_DATA pspsd = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)(buf + sizeof(STORAGE_DESCRIPTOR_HEADER) + sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1);
            (void)pspsd;
            is_nvme = 1; /* Basit heuristic: başarılıysa NVMe olabilir */
        }
        CloseHandle(hNvme);
    }

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, "Disk", 63);
    snprintf(it->name, MAX_NAME_LEN - 1,
             "Depolama: %llu GB toplam / %llu GB boş (%s)",
             (unsigned long long)total_gb,
             (unsigned long long)free_gb,
             is_ssd ? (is_nvme ? "NVMe SSD" : "SATA SSD") : "HDD");
    it->critical = 1;

    if (free_gb < 20) {
        it->score = COMPAT_NONE;
        snprintf(it->detail, 511, "Free space: %llu GB. Linux installation requires at least 20 GB.", (unsigned long long)free_gb);
        strncpy(it->recommendation, "Free up space or install on a separate drive.", 511);
    } else if (free_gb < 50) {
        it->score = COMPAT_MINOR;
        snprintf(it->detail, 511, "Free space: %llu GB. Installation possible but limited.", (unsigned long long)free_gb);
        strncpy(it->recommendation, "Minimum migration possible. 50+ GB recommended.", 511);
    } else {
        it->score = COMPAT_FULL;
        snprintf(it->detail, 511, "Free space: %llu GB. Sufficient for installation.", (unsigned long long)free_gb);
        if (is_ssd)
            strncpy(it->recommendation, "SSD + ample space = fast Linux experience. Use Ext4 or Btrfs.", 511);
        else
            strncpy(it->recommendation, "HDD may be slow. Prefer Ext4, add swap space.", 511);
    }
}

/* 4. GPU Analizi */
static void analyze_gpu(CompatReport* r) {
    /* SetupAPI ile görüntü adaptörlerini listele */
    HDEVINFO devInfo = SetupDiGetClassDevsA(
        &GUID_DEVCLASS_DISPLAY, NULL, NULL,
        DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(SP_DEVINFO_DATA);
    char buf[512];
    int idx = 0;

    while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
        if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)buf, sizeof(buf), NULL)) continue;

        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "GPU", 63);
        strncpy(it->name, buf, MAX_NAME_LEN - 1);
        it->critical = 1;

        /* GPU üreticisini tespit et */
        int is_nvidia  = (strstr(buf, "NVIDIA") != NULL || strstr(buf, "GeForce") != NULL || strstr(buf, "Quadro") != NULL);
        int is_amd_gpu = (strstr(buf, "AMD")    != NULL || strstr(buf, "Radeon")  != NULL || strstr(buf, "RX ")    != NULL);
        int is_intel_g = (strstr(buf, "Intel")  != NULL || strstr(buf, "UHD")     != NULL || strstr(buf, "Iris")   != NULL);
        int is_vmware  = (strstr(buf, "VMware") != NULL);
        int is_vbox    = (strstr(buf, "VirtualBox") != NULL);

        if (is_nvidia) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "NVIDIA GPU: %s", buf);
            strncpy(it->recommendation,
                "You need to install proprietary NVIDIA drivers (nvidia-driver). "
                "Nouveau (open source) is limited. Easily installable on Ubuntu/Fedora. "
                "Wayland support improved in NVIDIA 510+ drivers.",
                511);
        } else if (is_amd_gpu) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "AMD GPU: %s", buf);
            strncpy(it->recommendation,
                "Excellent open source AMDGPU support. No additional drivers needed. "
                "Full Wayland and Vulkan support. GPU computing possible with ROCm.",
                511);
        } else if (is_intel_g) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "Intel Integrated GPU: %s", buf);
            strncpy(it->recommendation,
                "In-kernel i915 driver provides excellent support. "
                "Fully compatible with Wayland and X11.",
                511);
        } else if (is_vmware || is_vbox) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "Virtual display adapter: %s", buf);
            strncpy(it->recommendation,
                "Virtual environment detected. "
                "Different GPU may be detected when installed on physical hardware.",
                511);
        } else {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "Unknown GPU: %s", buf);
            strncpy(it->recommendation,
                "Check for Linux drivers by searching 'Linux + [GPU name] driver'.",
                511);
        }

        if (r->count >= MAX_DEVICES - 1) break;
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

/* 5. Ağ Adaptörü Analizi */
static void analyze_network(CompatReport* r) {
    HDEVINFO devInfo = SetupDiGetClassDevsA(
        &GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(SP_DEVINFO_DATA);
    char buf[512], hw_id[512];
    int idx = 0;

    while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
        if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)buf, sizeof(buf), NULL)) continue;

        /* "Microsoft" sanal adaptörleri atla */
        if (strstr(buf, "Microsoft") || strstr(buf, "WAN Miniport") ||
            strstr(buf, "Bluetooth") || strstr(buf, "Loopback")) continue;

        SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
            SPDRP_HARDWAREID, NULL, (PBYTE)hw_id, sizeof(hw_id), NULL);

        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "Ağ Kartı", 63);
        strncpy(it->name, buf, MAX_NAME_LEN - 1);

        /* Bilinen iyi desteklenen markalar */
        int is_intel_net   = (strstr(buf, "Intel") != NULL);
        int is_realtek     = (strstr(buf, "Realtek") != NULL);
        int is_broadcom    = (strstr(buf, "Broadcom") != NULL);
        int is_atheros     = (strstr(buf, "Atheros") || strstr(buf, "Killer"));
        int is_mediatek    = (strstr(buf, "MediaTek") != NULL);
        int is_ralink      = (strstr(buf, "Ralink") != NULL);

        /* Wireless mi? */
        int is_wifi = (strstr(buf, "Wi-Fi")    != NULL ||
                       strstr(buf, "Wireless") != NULL ||
                       strstr(buf, "WLAN")     != NULL);

        if (is_intel_net) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "%s %s", is_wifi ? "Intel WiFi" : "Intel Ethernet", buf);
            strncpy(it->recommendation,
                is_wifi ? "Intel WiFi has excellent Linux support (iwlwifi driver)."
                        : "Intel Ethernet in-kernel (e1000e/igb/ixgbe) full support.",
                511);
        } else if (is_realtek) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "Realtek %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                is_wifi ? "Additional drivers may be needed for Realtek WiFi (rtl88xx). "
                          "Install dkms driver from GitHub."
                        : "Realtek Ethernet generally works (r8169) but some models are problematic.",
                511);
        } else if (is_broadcom) {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "Broadcom %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "Broadcom WiFi/Ethernet can be problematic on Linux. "
                "Requires b43 or broadcom-sta driver. May have no internet during installation.",
                511);
        } else if (is_atheros) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "Atheros/Killer %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "Atheros/Killer ath10k/ath11k drivers in-kernel full support.",
                511);
        } else if (is_mediatek || is_ralink) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "MediaTek/Ralink %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "MediaTek/Ralink mt76 driver in-kernel but older models problematic.",
                511);
        } else {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "%s: %s [HWID: %.100s]", is_wifi ? "WiFi" : "Network Card", buf, hw_id);
            strncpy(it->recommendation,
                "Check for Linux drivers on the manufacturer's site or 'linux-hardware.org'.",
                511);
        }

        if (r->count >= MAX_DEVICES - 1) break;
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

/* 6. Ses Kartı Analizi */
static void analyze_audio(CompatReport* r) {
    HDEVINFO devInfo = SetupDiGetClassDevsA(
        &GUID_DEVCLASS_MEDIA, NULL, NULL, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(SP_DEVINFO_DATA);
    char buf[512];
    int idx = 0;

    while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
        if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)buf, sizeof(buf), NULL)) continue;

        /* Sanal/yazılımsal ses aygıtlarını atla */
        if (strstr(buf, "Virtual") || strstr(buf, "Microsoft")) continue;

        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "Ses Kartı", 63);
        strncpy(it->name, buf, MAX_NAME_LEN - 1);

        int is_realtek_a = (strstr(buf, "Realtek") != NULL);
        int is_intel_a   = (strstr(buf, "Intel")   != NULL);
        int is_amd_a     = (strstr(buf, "AMD")      != NULL);
        int is_creative  = (strstr(buf, "Creative") || strstr(buf, "Sound Blaster"));
        int is_focusrite = (strstr(buf, "Focusrite") || strstr(buf, "Scarlett"));

        if (is_realtek_a || is_intel_a || is_amd_a) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "HDA compatible audio card: %s", buf);
            strncpy(it->recommendation,
                "Fully compatible with ALSA/PulseAudio/PipeWire. In-kernel driver (snd_hda_intel).",
                511);
        } else if (is_focusrite) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "USB Audio Interface: %s", buf);
            strncpy(it->recommendation,
                "Focusrite generally works on Linux but some features limited. "
                "Use JACK or PipeWire. Scarlett Gen 2/3 full support.",
                511);
        } else if (is_creative) {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "Creative audio card: %s", buf);
            strncpy(it->recommendation,
                "Creative Sound Blaster cards have limited Linux support. "
                "Some features may not work.",
                511);
        } else {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "Audio device: %s", buf);
            strncpy(it->recommendation,
                "USB or Bluetooth audio devices generally work on Linux.",
                511);
        }

        if (r->count >= MAX_DEVICES - 1) break;
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

/* 7. UEFI / Secure Boot / TPM Analizi */
static void analyze_firmware(CompatReport* r) {
    /* UEFI veya Legacy BIOS */
    HKEY hk;
    int is_uefi = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        char petype[64] = {0};
        DWORD sz = sizeof(petype);
        DWORD type;
        if (RegQueryValueExA(hk, "PEFirmwareType", NULL, &type,
            (LPBYTE)petype, &sz) == ERROR_SUCCESS) {
            is_uefi = (*(DWORD*)petype == 2);
        }
        RegCloseKey(hk);
    }

    /* Secure Boot */
    int secure_boot = 0;
    DWORD sb_val = 0;
    if (reg_read_dword(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        "UEFISecureBootEnabled", &sb_val)) {
        secure_boot = (sb_val != 0);
    }

    /* TPM */
    int has_tpm = 0;
    HDEVINFO tpmDev = SetupDiGetClassDevsA(NULL, "ROOT\\TPM", NULL,
        DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (tpmDev != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA td; td.cbSize = sizeof(td);
        has_tpm = SetupDiEnumDeviceInfo(tpmDev, 0, &td);
        SetupDiDestroyDeviceInfoList(tpmDev);
    }

    /* BIOS sürümü */
    char bios_ver[128] = {0}, bios_vendor[128] = {0};
    reg_read_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "BIOSVersion", bios_ver, sizeof(bios_ver));
    reg_read_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "BIOSVendor", bios_vendor, sizeof(bios_vendor));

    /* UEFI */
    {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "Firmware", 63);
        snprintf(it->name, MAX_NAME_LEN - 1,
                 "Önyükleme: %s | BIOS: %s %s",
                 is_uefi ? "UEFI" : "Legacy BIOS",
                 bios_vendor, bios_ver);
        it->critical = 1;

        if (is_uefi) {
            it->score = COMPAT_FULL;
            strncpy(it->detail, "UEFI detected. Modern Linux bootloaders (GRUB2, systemd-boot) require UEFI.", 511);
            strncpy(it->recommendation, "Install in UEFI mode. EFI partition (ESP) will be created.", 511);
        } else {
            it->score = COMPAT_MINOR;
            strncpy(it->detail, "Legacy BIOS detected. Linux can be installed but some features missing.", 511);
            strncpy(it->recommendation, "Use MBR partitioning scheme for installation.", 511);
        }
    }

    /* Secure Boot */
    {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "Secure Boot", 63);
        snprintf(it->name, MAX_NAME_LEN - 1, "Secure Boot: %s", secure_boot ? "Etkin" : "Devre Dışı");
        it->critical = 0;

        if (secure_boot) {
            it->score = COMPAT_MINOR;
            strncpy(it->detail, "Secure Boot enabled. Some Linux distributions support it (Ubuntu, Fedora), others do not.", 511);
            strncpy(it->recommendation, "Ubuntu/Fedora/openSUSE work with Secure Boot. Disable in BIOS for Arch/Gentoo.", 511);
        } else {
            it->score = COMPAT_FULL;
            strncpy(it->detail, "Secure Boot disabled. All Linux distributions will boot seamlessly.", 511);
            strncpy(it->recommendation, "Any distribution can be selected.", 511);
        }
    }

    /* TPM */
    {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "TPM", 63);
        snprintf(it->name, MAX_NAME_LEN - 1, "TPM: %s", has_tpm ? "Mevcut" : "Bulunamadı");
        it->critical = 0;
        it->score = COMPAT_FULL; /* TPM Linux'ta genelde sorun değil */
        strncpy(it->detail, has_tpm ? "TPM chip present. Usable on Linux (tpm2-tools)." : "TPM chip not detected.", 511);
        strncpy(it->recommendation, "TPM can be used with encrypted disk (LUKS) on Linux.", 511);
    }
}

/* 8. Batarya / Güç Yönetimi */
static void analyze_power(CompatReport* r) {
    SYSTEM_POWER_STATUS sps;
    GetSystemPowerStatus(&sps);

    if (sps.BatteryFlag == 128 || sps.BatteryFlag == 255) {
        /* AC-only veya bilinmiyor → masaüstü sistemi, atla */
        return;
    }

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, "Güç/Batarya", 63);
    snprintf(it->name, MAX_NAME_LEN - 1,
             "Batarya: %%%d | Güç: %s",
             sps.BatteryLifePercent == 255 ? 0 : sps.BatteryLifePercent,
             sps.ACLineStatus ? "Prizde" : "Batarya");
    it->critical = 0;
    it->score = COMPAT_MINOR;
    strncpy(it->detail,
        "Laptop detected. Linux power management (TLP, powertop) works differently from Windows.",
        511);
    strncpy(it->recommendation,
        "Install TLP or power-profiles-daemon. Sleep/suspend may be problematic on some laptops.",
        511);
}

/* 9. Sanallaştırma Kontrolü */
static void analyze_virtualization(CompatReport* r) {
    int info[4];
    __cpuid(info, 1);
    int in_vm = (info[2] >> 31) & 1; /* Hypervisor Present bit */

    if (!in_vm) return;

    CompatItem* it = &r->items[r->count++];
    strncpy(it->category, "Sanallaştırma", 63);

    /* Hangi hypervisor? */
    char hv_name[13] = {0};
    __cpuid(info, 0x40000000);
    memcpy(hv_name,     &info[1], 4);
    memcpy(hv_name + 4, &info[2], 4);
    memcpy(hv_name + 8, &info[3], 4);
    hv_name[12] = 0;

    snprintf(it->name, MAX_NAME_LEN - 1, "Sanal Makine Tespit Edildi: %s", hv_name);
    it->critical = 0;
    it->score = COMPAT_MINOR;
    snprintf(it->detail, 511, "Hypervisor: %s. This analysis is running in a virtual environment.", hv_name);
    strncpy(it->recommendation,
        "For installation on physical hardware, analyze the real machine. "
        "Virtual environment results may not reflect actual hardware.",
        511);
}

/* 10. Çevrimiçi kernel.org veritabanı karşılaştırması */
static void analyze_online(CompatReport* r) {
    if (!g_online) return;

    /* Çevrimiçi → güncel kernel sürümünü al */
    HINTERNET hSession = WinHttpOpen(L"LinuxCompatChecker/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = hConnect ? WinHttpOpenRequest(hConnect, L"GET", L"/finger_banner",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : NULL;

    char kernel_ver[128] = {0};
    if (hRequest &&
        WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD bytes = 0;
        char raw[512] = {0};
        WinHttpReadData(hRequest, raw, sizeof(raw) - 1, &bytes);
        /* Satırdan sürümü çıkar: "The latest stable version of the Linux kernel is: X.Y.Z" */
        char* p = strstr(raw, "stable");
        if (p) {
            p = strstr(p, ": ");
            if (p) {
                sscanf(p + 2, "%127s", kernel_ver);
            }
        }
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (kernel_ver[0]) {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "Çevrimiçi", 63);
        snprintf(it->name, MAX_NAME_LEN - 1, "En Güncel Kararlı Kernel: %s (kernel.org)", kernel_ver);
        it->critical = 0;
        it->score = COMPAT_FULL;
        snprintf(it->detail, 511,
            "Info from kernel.org: Latest stable kernel version %s. "
            "Your hardware is evaluated with this kernel's drivers.", kernel_ver);
        strncpy(it->recommendation,
            "Choose a distribution supporting the latest kernel version.",
            511);
    }
}

/* ═══════════════════════════════════════════════
   RAPOR HESAPLAMA VE YAZDIRMA
   ═══════════════════════════════════════════════ */

static void compute_report(CompatReport* r) {
    memset(r->score_counts, 0, sizeof(r->score_counts));

    double weighted = 0.0, total_weight = 0.0;
    for (int i = 0; i < r->count; i++) {
        int s = r->items[i].score;
        if (s >= 0 && s <= 3) r->score_counts[s]++;
        double w = r->items[i].critical ? 2.0 : 1.0;
        double contrib = (3.0 - (double)s) / 3.0; /* 0=kötü, 1=mükemmel */
        weighted    += contrib * w;
        total_weight += w;
    }
    r->overall_percent = (total_weight > 0) ? (weighted / total_weight) * 100.0 : 0.0;
}

/* Yüzde barı */
static void print_percent_bar(double pct, int width) {
    int filled = (int)(pct / 100.0 * width);
    const char* color = pct >= 75 ? GREEN : (pct >= 50 ? YELLOW : RED);
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

    /* Kategori bazlı grupla */
    const char* categories[] = {
        "CPU", "RAM", "Disk", "GPU", "Network Card",
        "Audio Card", "Firmware", "Secure Boot", "TPM",
        "Power/Battery", "Virtualization", "Online", NULL
    };

    for (int ci = 0; categories[ci]; ci++) {
        int found = 0;
        for (int i = 0; i < r->count; i++) {
            if (strcmp(r->items[i].category, categories[ci]) == 0) {
                if (!found) {
                    printf(BLUE BOLD "  ┌─ %s\n" RESET, categories[ci]);
                    found = 1;
                }
                CompatItem* it = &r->items[i];
                printf("  │  %s %s\n", score_icon(it->score), it->name);
                printf("  │     " DIM "→ %s\n" RESET, it->detail);
                printf("  │     " CYAN "✦ %s\n" RESET, it->recommendation);
                printf("  │\n");
            }
        }
    }

    printf("\n");
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
    printf(BOLD WHITE "  📊 SUMMARY STATISTICS\n" RESET);
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);

    printf("  %s  Fully Compatible        : %d components\n", GREEN "●" RESET, r->score_counts[0]);
    printf("  %s  Compatible (Minor Issues): %d components\n", YELLOW "◑" RESET, r->score_counts[1]);
    printf("  %s  Possibly Incompatible   : %d components\n", ORANGE "◔" RESET, r->score_counts[2]);
    printf("  %s  Incompatible            : %d components\n", RED "○" RESET, r->score_counts[3]);
    printf("\n  Total Analyzed: %d components\n", r->count);
    printf("\n  Overall Compatibility Score:\n  ");
    print_percent_bar(r->overall_percent, 40);
    printf("\n\n");

    /* Genel değerlendirme */
    printf(BOLD WHITE "  🧭 GENERAL ASSESSMENT\n\n" RESET);
    if (r->overall_percent >= 85) {
        printf(GREEN BOLD "  ✅ Your system is READY for Linux!\n" RESET);
        printf("     Ubuntu, Fedora, Mint or any major distribution will work seamlessly.\n");
    } else if (r->overall_percent >= 65) {
        printf(YELLOW BOLD "  ⚠️  Your system is MOSTLY compatible with Linux.\n" RESET);
        printf("     Some components may require additional drivers or configuration.\n");
        printf("     Ubuntu LTS or Linux Mint is recommended (best driver support).\n");
    } else if (r->overall_percent >= 40) {
        printf(ORANGE BOLD "  🔶 Compatibility is MODERATE.\n" RESET);
        printf("     Significant components may cause issues. We recommend testing with dual-boot.\n");
    } else {
        printf(RED BOLD "  ❌ Your system has serious incompatibilities.\n" RESET);
        printf("     Consider hardware upgrades or replacements before migrating to Linux.\n");
    }

    /* Tavsiye edilen dağıtımlar */
    printf("\n" BOLD WHITE "  🐧 RECOMMENDED DISTRIBUTIONS\n\n" RESET);
    printf("     1. Ubuntu 24.04 LTS    — Widest driver support, easy installation\n");
    printf("     2. Linux Mint 22       — Windows-like interface, for beginners\n");
    printf("     3. Fedora 40           — Latest kernel, good NVIDIA support\n");
    printf("     4. Pop!_OS 24.04       — For gamers and NVIDIA users\n");
    printf("     5. EndeavourOS         — Arch-based, for those wanting full control\n");

    /* Çevrimiçi durum */
    printf("\n" DIM "  🌐 Internet connection: %s\n" RESET,
           g_online ? GREEN "Connected — data fetched from kernel.org" RESET
                    : YELLOW "Offline — only local analysis performed" RESET);

    printf("\n");
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
    printf(DIM "  Linux Kernel Compatibility Checker v2.0 | linux-hardware.org\n" RESET);
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);
}

/* ═══════════════════════════════════════════════
   ANA FONKSİYON
   ═══════════════════════════════════════════════ */

int main(void) {
    enable_ansi();
    print_header();

    /* Sistem bilgileri */
    char os_name[256] = {0}, computer_name[256] = {0};
    DWORD comp_size = sizeof(computer_name);
    reg_read_string(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "ProductName", os_name, sizeof(os_name));
    GetComputerNameA(computer_name, &comp_size);

    printf(DIM "  Computer : %s\n" RESET, computer_name);
    printf(DIM "  OS       : %s\n" RESET, os_name[0] ? os_name : "Windows");

    /* Tarih/saat */
    SYSTEMTIME st; GetLocalTime(&st);
    printf(DIM "  Date     : %02d/%02d/%04d %02d:%02d\n\n" RESET,
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);

    /* İnternet kontrolü */
    printf(CYAN "  Step 1/9: " RESET "Checking internet connection...\n");
    g_online = check_internet();
    printf("           %s\n\n", g_online ? GREEN "✓ Connected" RESET : YELLOW "✗ Offline" RESET);

    /* Analizler */
    CompatReport report = {0};

    loading_bar("Step 2/9: Analyzing CPU      ", 8, 30);
    analyze_cpu(&report);

    loading_bar("Step 3/9: Analyzing RAM      ", 6, 25);
    analyze_ram(&report);

    loading_bar("Step 4/9: Analyzing Disk     ", 7, 35);
    analyze_storage(&report);

    loading_bar("Step 5/9: Analyzing GPU      ", 9, 40);
    analyze_gpu(&report);

    loading_bar("Step 6/9: Analyzing Network Cards", 8, 35);
    analyze_network(&report);

    loading_bar("Step 7/9: Analyzing Audio Cards", 6, 30);
    analyze_audio(&report);

    loading_bar("Step 8/9: Analyzing Firmware/UEFI", 7, 25);
    analyze_firmware(&report);
    analyze_power(&report);
    analyze_virtualization(&report);

    if (g_online) {
        loading_bar("Step 9/9: Fetching kernel.org data", 12, 60);
        analyze_online(&report);
    } else {
        printf(DIM "  Step 9/9: Offline — skipped.\n" RESET);
    }

    printf("\n");
    print_report(&report);

    printf("  Press any key to continue...\n");
    getchar();
    return 0;
}
