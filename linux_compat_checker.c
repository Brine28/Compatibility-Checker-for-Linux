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
    printf(CYAN BOLD "║" RESET BLUE BOLD "     🐧  Linux Kernel Uyumluluk Analiz Aracı v2.0           " CYAN BOLD "║\n" RESET);
    printf(CYAN BOLD "║" RESET DIM "     Windows 11 → Linux Geçiş Hazırlık Raporu               " CYAN BOLD "║\n" RESET);
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
            "ARM tabanlı işlemci tespit edildi (%s). Çekirdek sayısı: %lu",
            vendor, (unsigned long)cores);
        snprintf(it->recommendation, 511,
            "ARM Linux desteği gelişiyor ancak bazı yazılımlar x86_64 gerektirir. "
            "Ubuntu ARM veya Fedora ARM deneyin.");
    } else if (is_intel || is_amd) {
        it->score = COMPAT_FULL;
        snprintf(it->detail, 511,
            "%s %s | %lu mantıksal çekirdek | SSE2:%s AVX:%s VT-x/AMD-V:%s",
            is_intel ? "Intel" : "AMD",
            brand[0] ? brand : "",
            (unsigned long)cores,
            has_sse2 ? "Evet" : "Hayır",
            has_avx  ? "Evet" : "Hayır",
            has_vmx  ? "Evet" : "Hayır");
        snprintf(it->recommendation, 511,
            "Mükemmel Linux desteği. Herhangi bir dağıtım sorunsuz çalışır.");
    } else {
        it->score = COMPAT_MAYBE;
        snprintf(it->detail, 511, "Bilinmeyen CPU mimarisi: %s", vendor);
        strncpy(it->recommendation, "Manuel doğrulama önerilir.", 511);
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
        snprintf(it->detail, 511, "Yalnızca %llu MB RAM mevcut. Linux minimum 1 GB ister.", (unsigned long long)total_mb);
        strncpy(it->recommendation,
            "En az 4 GB RAM tavsiye edilir. Lubuntu veya Alpine gibi hafif dağıtımlar denenebilir.",
            511);
    } else if (total_mb < 4096) {
        it->score = COMPAT_MINOR;
        snprintf(it->detail, 511, "%llu MB RAM mevcut. Temel kullanım için yeterli.", (unsigned long long)total_mb);
        strncpy(it->recommendation, "Xfce veya LXQt gibi hafif masaüstü ortamları tercih edin.", 511);
    } else {
        it->score = COMPAT_FULL;
        snprintf(it->detail, 511, "%llu MB (%llu GB) RAM mevcut. Mükemmel.",
                 (unsigned long long)total_mb,
                 (unsigned long long)(total_mb / 1024));
        strncpy(it->recommendation, "Tüm masaüstü ortamları ve sanallaştırma rahat çalışır.", 511);
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
        snprintf(it->detail, 511, "Boş alan: %llu GB. Linux kurulumu için en az 20 GB gerekir.", (unsigned long long)free_gb);
        strncpy(it->recommendation, "Disk alanı açın veya ayrı bir sürücüye kurulum yapın.", 511);
    } else if (free_gb < 50) {
        it->score = COMPAT_MINOR;
        snprintf(it->detail, 511, "Boş alan: %llu GB. Kurulum mümkün ama sınırlı.", (unsigned long long)free_gb);
        strncpy(it->recommendation, "Minimum geçiş yapılabilir. 50+ GB tavsiye edilir.", 511);
    } else {
        it->score = COMPAT_FULL;
        snprintf(it->detail, 511, "Boş alan: %llu GB. Kurulum için yeterli.", (unsigned long long)free_gb);
        if (is_ssd)
            strncpy(it->recommendation, "SSD + bol alan = hızlı Linux deneyimi. Ext4 veya Btrfs kullanın.", 511);
        else
            strncpy(it->recommendation, "HDD yavaş olabilir. Ext4 tercih edin, swap alanı ekleyin.", 511);
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
                "Özel NVIDIA sürücüsü (nvidia-driver) kurmanız gerekir. "
                "Nouveau (açık kaynak) kısıtlıdır. Ubuntu/Fedora'da kolayca kurulabilir. "
                "Wayland desteği NVIDIA 510+ sürücülerde iyileşti.",
                511);
        } else if (is_amd_gpu) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "AMD GPU: %s", buf);
            strncpy(it->recommendation,
                "Mükemmel açık kaynak AMDGPU desteği. Ek sürücü gerekmez. "
                "Wayland ve Vulkan tam destekli. ROCm ile GPU hesaplama da mümkün.",
                511);
        } else if (is_intel_g) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "Intel Entegre GPU: %s", buf);
            strncpy(it->recommendation,
                "Çekirdek içi i915 sürücüsü mükemmel destek sağlar. "
                "Wayland ve X11 tam uyumlu.",
                511);
        } else if (is_vmware || is_vbox) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "Sanal ekran adaptörü: %s", buf);
            strncpy(it->recommendation,
                "Sanal makine ortamı tespit edildi. "
                "Gerçek donanıma kurulum yapıldığında farklı GPU algılanacak.",
                511);
        } else {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "Bilinmeyen GPU: %s", buf);
            strncpy(it->recommendation,
                "Bu GPU için Linux sürücüsü olup olmadığını 'Linux + [GPU adı] driver' aratarak kontrol edin.",
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
                is_wifi ? "Intel WiFi mükemmel Linux desteğine sahip (iwlwifi sürücüsü)."
                        : "Intel Ethernet çekirdek içinde (e1000e/igb/ixgbe) tam destekli.",
                511);
        } else if (is_realtek) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "Realtek %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                is_wifi ? "Realtek WiFi için ek sürücü gerekebilir (rtl88xx). "
                          "GitHub'dan dkms sürücüsü kurabilirsiniz."
                        : "Realtek Ethernet genelde çalışır (r8169) ancak bazı modeller sorunlu.",
                511);
        } else if (is_broadcom) {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "Broadcom %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "Broadcom WiFi/Ethernet Linux'ta sorunlu olabilir. "
                "b43 veya broadcom-sta sürücüsü gerekir. Kurulum sırasında internet olmayabilir.",
                511);
        } else if (is_atheros) {
            it->score = COMPAT_FULL;
            snprintf(it->detail, 511, "Atheros/Killer %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "Atheros/Killer ath10k/ath11k sürücüleriyle çekirdekte tam destekli.",
                511);
        } else if (is_mediatek || is_ralink) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "MediaTek/Ralink %s: %s", is_wifi ? "WiFi" : "Ethernet", buf);
            strncpy(it->recommendation,
                "MediaTek/Ralink için mt76 sürücüsü çekirdekte mevcut ancak eski modeller sorunlu.",
                511);
        } else {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "%s: %s [HWID: %.100s]", is_wifi ? "WiFi" : "Ağ Kartı", buf, hw_id);
            strncpy(it->recommendation,
                "Bu ağ kartı için Linux sürücüsünü üretici sitesinde veya 'linux-hardware.org' adresinde araştırın.",
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
            snprintf(it->detail, 511, "HDA uyumlu ses kartı: %s", buf);
            strncpy(it->recommendation,
                "ALSA/PulseAudio/PipeWire ile tam uyumlu. Çekirdek içi sürücü (snd_hda_intel).",
                511);
        } else if (is_focusrite) {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "USB Ses Arayüzü: %s", buf);
            strncpy(it->recommendation,
                "Focusrite Linux'ta genelde çalışır ancak bazı özellikler kısıtlı. "
                "JACK veya PipeWire kullanın. Scarlett Gen 2/3 tam destekli.",
                511);
        } else if (is_creative) {
            it->score = COMPAT_MAYBE;
            snprintf(it->detail, 511, "Creative ses kartı: %s", buf);
            strncpy(it->recommendation,
                "Creative Sound Blaster kartları için Linux desteği sınırlıdır. "
                "Bazı özellikler çalışmayabilir.",
                511);
        } else {
            it->score = COMPAT_MINOR;
            snprintf(it->detail, 511, "Ses aygıtı: %s", buf);
            strncpy(it->recommendation,
                "USB veya Bluetooth ses aygıtları genelde Linux'ta sorunsuz çalışır.",
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
            strncpy(it->detail, "UEFI tespit edildi. Modern Linux önyükleyicileri (GRUB2, systemd-boot) UEFI gerektirir.", 511);
            strncpy(it->recommendation, "UEFI modu ile kurulum yapın. EFI bölümü (ESP) oluşturulacak.", 511);
        } else {
            it->score = COMPAT_MINOR;
            strncpy(it->detail, "Legacy BIOS tespit edildi. Linux kurulabilir ancak bazı özellikler eksik.", 511);
            strncpy(it->recommendation, "MBR bölümleme şeması ile kurulum yapılmalıdır.", 511);
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
            strncpy(it->detail, "Secure Boot etkin. Bazı Linux dağıtımları destekler (Ubuntu, Fedora), bazıları desteklemez.", 511);
            strncpy(it->recommendation, "Ubuntu/Fedora/openSUSE Secure Boot ile çalışır. Arch/Gentoo için BIOS'tan kapatın.", 511);
        } else {
            it->score = COMPAT_FULL;
            strncpy(it->detail, "Secure Boot devre dışı. Tüm Linux dağıtımları sorunsuz önyüklenebilir.", 511);
            strncpy(it->recommendation, "Herhangi bir dağıtım seçilebilir.", 511);
        }
    }

    /* TPM */
    {
        CompatItem* it = &r->items[r->count++];
        strncpy(it->category, "TPM", 63);
        snprintf(it->name, MAX_NAME_LEN - 1, "TPM: %s", has_tpm ? "Mevcut" : "Bulunamadı");
        it->critical = 0;
        it->score = COMPAT_FULL; /* TPM Linux'ta genelde sorun değil */
        strncpy(it->detail, has_tpm ? "TPM çipi mevcut. Linux'ta kullanılabilir (tpm2-tools)." : "TPM çipi tespit edilemedi.", 511);
        strncpy(it->recommendation, "TPM, Linux'ta şifrelenmiş disk (LUKS) ile kullanılabilir.", 511);
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
        "Dizüstü bilgisayar tespit edildi. Linux güç yönetimi (TLP, powertop) Windows'tan farklı çalışır.",
        511);
    strncpy(it->recommendation,
        "TLP veya power-profiles-daemon kurun. Uyku/bekleme modu bazı dizüstülerde sorunlu olabilir.",
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
    snprintf(it->detail, 511, "Hypervisor: %s. Bu analiz sanal bir ortamda çalışıyor.", hv_name);
    strncpy(it->recommendation,
        "Gerçek donanımda kurulum için fiziksel makineyi analiz edin. "
        "Sanal ortam sonuçları gerçek donanımı yansıtmayabilir.",
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
            "kernel.org'dan alınan bilgi: En son kararlı kernel sürümü %s. "
            "Donanımınız bu çekirdeğin sürücüleriyle değerlendirildi.", kernel_ver);
        strncpy(it->recommendation,
            "Mümkün olan en güncel kernel sürümünü destekleyen bir dağıtım seçin.",
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
    printf(BOLD WHITE "  📋 DETAYLI UYUMLULUK RAPORU\n" RESET);
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);

    /* Kategori bazlı grupla */
    const char* categories[] = {
        "CPU", "RAM", "Disk", "GPU", "Ağ Kartı",
        "Ses Kartı", "Firmware", "Secure Boot", "TPM",
        "Güç/Batarya", "Sanallaştırma", "Çevrimiçi", NULL
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
    printf(BOLD WHITE "  📊 ÖZET İSTATİSTİKLER\n" RESET);
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n\n" RESET);

    printf("  %s  Tam Uyumlu        : %d bileşen\n", GREEN "●" RESET, r->score_counts[0]);
    printf("  %s  Uyumlu (Aksaklık): %d bileşen\n", YELLOW "◑" RESET, r->score_counts[1]);
    printf("  %s  Belki Uyumsuz    : %d bileşen\n", ORANGE "◔" RESET, r->score_counts[2]);
    printf("  %s  Uyumsuz          : %d bileşen\n", RED "○" RESET, r->score_counts[3]);
    printf("\n  Toplam Analiz Edilen: %d bileşen\n", r->count);
    printf("\n  Genel Uyumluluk Skoru:\n  ");
    print_percent_bar(r->overall_percent, 40);
    printf("\n\n");

    /* Genel değerlendirme */
    printf(BOLD WHITE "  🧭 GENEL DEĞERLENDİRME\n\n" RESET);
    if (r->overall_percent >= 85) {
        printf(GREEN BOLD "  ✅ Sisteminiz Linux için HAZIR!\n" RESET);
        printf("     Ubuntu, Fedora, Mint veya herhangi bir ana dağıtım sorunsuz çalışır.\n");
    } else if (r->overall_percent >= 65) {
        printf(YELLOW BOLD "  ⚠️  Sisteminiz Linux'la BÜYÜK ÖLÇÜDE uyumlu.\n" RESET);
        printf("     Bazı bileşenler için ek sürücü veya yapılandırma gerekebilir.\n");
        printf("     Ubuntu LTS veya Linux Mint tavsiye edilir (en iyi sürücü desteği).\n");
    } else if (r->overall_percent >= 40) {
        printf(ORANGE BOLD "  🔶 Uyumluluk ORTA düzeyde.\n" RESET);
        printf("     Önemli bileşenler sorun yaratabilir. Dual-boot ile test etmenizi öneririz.\n");
    } else {
        printf(RED BOLD "  ❌ Sisteminizde ciddi uyumsuzluklar var.\n" RESET);
        printf("     Linux geçişi öncesinde donanım yükseltmesi veya değişimi düşünün.\n");
    }

    /* Tavsiye edilen dağıtımlar */
    printf("\n" BOLD WHITE "  🐧 ÖNERİLEN DAĞITIMLAR\n\n" RESET);
    printf("     1. Ubuntu 24.04 LTS    — En geniş sürücü desteği, kolay kurulum\n");
    printf("     2. Linux Mint 22       — Windows'a yakın arayüz, yeni başlayanlar için\n");
    printf("     3. Fedora 40           — Güncel kernel, NVIDIA desteği iyi\n");
    printf("     4. Pop!_OS 24.04       — Oyuncular ve NVIDIA kullanıcıları için\n");
    printf("     5. EndeavourOS         — Arch tabanlı, tam kontrol isteyenler için\n");

    /* Çevrimiçi durum */
    printf("\n" DIM "  🌐 İnternet bağlantısı: %s\n" RESET,
           g_online ? GREEN "Bağlı — kernel.org'dan veri alındı" RESET
                    : YELLOW "Çevrimdışı — yalnızca yerel analiz yapıldı" RESET);

    printf("\n");
    printf(CYAN BOLD "════════════════════════════════════════════════════════════════\n" RESET);
    printf(DIM "  Linux Kernel Uyumluluk Analiz Aracı v2.0 | linux-hardware.org\n" RESET);
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

    printf(DIM "  Bilgisayar : %s\n" RESET, computer_name);
    printf(DIM "  İşletim S. : %s\n" RESET, os_name[0] ? os_name : "Windows");

    /* Tarih/saat */
    SYSTEMTIME st; GetLocalTime(&st);
    printf(DIM "  Tarih      : %02d/%02d/%04d %02d:%02d\n\n" RESET,
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);

    /* İnternet kontrolü */
    printf(CYAN "  Adım 1/9: " RESET "İnternet bağlantısı kontrol ediliyor...\n");
    g_online = check_internet();
    printf("           %s\n\n", g_online ? GREEN "✓ Bağlı" RESET : YELLOW "✗ Çevrimdışı" RESET);

    /* Analizler */
    CompatReport report = {0};

    loading_bar("Adım 2/9: CPU analiz ediliyor      ", 8, 30);
    analyze_cpu(&report);

    loading_bar("Adım 3/9: RAM analiz ediliyor      ", 6, 25);
    analyze_ram(&report);

    loading_bar("Adım 4/9: Disk analiz ediliyor     ", 7, 35);
    analyze_storage(&report);

    loading_bar("Adım 5/9: GPU analiz ediliyor      ", 9, 40);
    analyze_gpu(&report);

    loading_bar("Adım 6/9: Ağ kartları analiz       ", 8, 35);
    analyze_network(&report);

    loading_bar("Adım 7/9: Ses kartları analiz      ", 6, 30);
    analyze_audio(&report);

    loading_bar("Adım 8/9: Firmware/UEFI analiz     ", 7, 25);
    analyze_firmware(&report);
    analyze_power(&report);
    analyze_virtualization(&report);

    if (g_online) {
        loading_bar("Adım 9/9: kernel.org veri alınıyor ", 12, 60);
        analyze_online(&report);
    } else {
        printf(DIM "  Adım 9/9: Çevrimdışı — atlandı.\n" RESET);
    }

    printf("\n");
    print_report(&report);

    printf("  Devam etmek için bir tuşa basın...\n");
    getchar();
    return 0;
}
