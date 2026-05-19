/*
 * Windows 11 için Linux Çekirdeği Uyumluluk Denetleyicisi
 * =======================================================
 * Donanım ve sistem yapılandırmasını tarayarak Linux'a geçiş 
 * uygunluğunu değerlendirir ve puanlanmış bir rapor üretir.
 * AYRICA: Donanım detaylarına Ring-0 erişimi sağlamak için
 * 'LccDriver' (lcc_driver.sys) çekirdek modu sürücüsüyle haberleşir!
 *
 * Puanlar: 0=Tam Uyumlu | 1=Uyumlu (küçük sorunlar)
 * 2=Olası Uyumsuz | 3=Uyumsuz
 *
 * Kullanım:
 * linux_compat_checker.exe [--save <rapor.txt>]
 *
 * Derleme (MSVC):
 * cl linux_compat_checker.cpp /Fe:linux_compat_checker.exe /EHsc /std:c++latest /link advapi32.lib setupapi.lib winhttp.lib
 */
#define NOMINMAX
#define _WIN32_WINNT 0x0A00   /* Windows 10+ */
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <algorithm>
#include <initguid.h>
#include <setupapi.h>
#include <devguid.h>
#include <winhttp.h>
#include <intrin.h>
#include <winioctl.h>    /* DeviceIoControl için gerekli */

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

/* SÜRÜCÜ BAŞLIK DOSYASI (Aynı dizinde bulunmalı) */
#include "lcc_shared.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "winhttp.lib")

/* ─── ANSI renk kodları (Windows 10+ sanal terminal gerektirir) ─── */
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
inline constexpr std::string_view CAT_ONLINE = "Online Data";
inline constexpr std::string_view CAT_DRV_PCI= "Driver PCI Scan";
inline constexpr std::string_view CAT_DRV_ACP= "Driver ACPI Read";
inline constexpr std::string_view CAT_DRV_MSR= "Driver MSR Query";

/* ─── Uyumluluk Puanı Seviyeleri ─── */
enum class CompatScore : int {
    FULL  = 0,   /* Tam uyumlu, hiçbir işleme gerek yok */
    MINOR = 1,   /* Uyumlu, ufak pürüzler olabilir      */
    MAYBE = 2,   /* Olası uyumsuzluk, dikkatle incelenmeli */
    NONE  = 3    /* Uyumsuz, ciddi sorunlar bekleniyor  */
};

/* ─── Kapasite limiti ─── */
inline constexpr int MAX_DEVICES = 256;


/* =================================================================
 * CompatItem — Donanım bileşeni uyumluluk kaydı
 * ================================================================= */
struct CompatItem {
    std::string  name;
    std::string  category;
    std::string  detail;
    std::string  recommendation;
    CompatScore  score    = CompatScore::FULL;
    bool         critical = false;
};


/* =================================================================
 * CompatReport — CompatItem sonuçlarının toplanmış hali
 * ================================================================= */
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
            int s = static_cast<int>(item.score);
            ++score_counts[s];
            double w       = item.critical ? 2.0 : 1.0;
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
 * Registry (Kayıt Defteri) Yardımcıları
 * ================================================================= */
namespace Registry {

    [[nodiscard]] inline std::optional<std::string>
    read_string(HKEY root, const char* subkey, const char* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return std::nullopt;

        char  buf[256]{};
        DWORD type = 0;
        DWORD sz   = sizeof(buf);
        bool  ok   = (RegQueryValueExA(hk, value, nullptr, &type,
                                       reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS)
                     && (type == REG_SZ || type == REG_EXPAND_SZ);
        RegCloseKey(hk);
        if (!ok) return std::nullopt;

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
                                     reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS);
        RegCloseKey(hk);
        return ok ? std::optional<DWORD>{val} : std::nullopt;
    }

} // namespace Registry


/* =================================================================
 * Console — Arayüz Yardımcıları
 * ================================================================= */
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
        printf("%s%s║%s%s%s     🐧  Linux Compatibility Checker v2.1           %s%s║\n%s", CYAN, BOLD, RESET, BLUE, BOLD, CYAN, BOLD, RESET);
        printf("%s%s║%s%s     Windows 11 → Linux migration readiness report   %s%s║\n%s", CYAN, BOLD, RESET, DIM, CYAN, BOLD, RESET);
        printf("%s%s╚══════════════════════════════════════════════════════════════╝\n%s", CYAN, BOLD, RESET);
        printf("\n");
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
        printf("%s  ► %s%s ", CYAN, RESET, msg);
        fflush(stdout);
        for (int i = 0; i < steps; i++) {
            printf("█");
            fflush(stdout);
            Sleep(static_cast<DWORD>(delay_ms));
        }
        printf(" %s%s✓\n%s", GREEN, BOLD, RESET);
        fflush(stdout);
    }

    inline void print_percent_bar(double pct, int width) {
        int         filled = static_cast<int>(pct / 100.0 * static_cast<double>(width));
        const char* color  = (pct >= 75.0) ? GREEN : (pct >= 50.0) ? YELLOW : RED;
        printf("%s%s[", color, BOLD);
        for (int i = 0; i < width; i++)
            printf(i < filled ? "█" : "░");
        printf("] %%%.1f%s", pct, RESET);
    }

} // namespace Console


/* =================================================================
 * Internet — Bağlantı kontrolü
 * ================================================================= */
namespace Internet {

    [[nodiscard]] inline bool check_connection() {
        HINTERNET hSession = WinHttpOpen(L"LinuxCompatChecker/2.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", L"/", nullptr,
                                                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

        bool ok = false;
        if (hRequest) {
            ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
              && WinHttpReceiveResponse(hRequest, nullptr);
            WinHttpCloseHandle(hRequest);
        }

        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return ok;
    }

} // namespace Internet


/* =================================================================
 * Analyzer (Analizör) — Soyut temel sınıf.
 * ================================================================= */
class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void analyze(CompatReport& report) = 0;

protected:
    [[nodiscard]] static CompatItem* new_item(CompatReport& r) { return r.add_item(); }

    static bool try_item(CompatReport& r, CompatItem*& out) {
        out = r.add_item();
        return out != nullptr;
    }

    static bool enumerate_devices(const GUID* cls_guid, const std::function<void(std::string_view name, std::string_view hw_id)>& callback) {
        HDEVINFO devInfo = SetupDiGetClassDevsA(cls_guid, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return false;

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(SP_DEVINFO_DATA);
        char name_buf[512]{};
        char hwid_buf[512]{};
        int  idx = 0;

        while (SetupDiEnumDeviceInfo(devInfo, idx++, &devData)) {
            if (!SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, SPDRP_DEVICEDESC, nullptr,
                                                   reinterpret_cast<PBYTE>(name_buf), sizeof(name_buf), nullptr))
                continue;

            hwid_buf[0] = '\0';
            SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, SPDRP_HARDWAREID, nullptr,
                                              reinterpret_cast<PBYTE>(hwid_buf), sizeof(hwid_buf), nullptr);

            callback(std::string_view{name_buf}, std::string_view{hwid_buf});
        }

        SetupDiDestroyDeviceInfoList(devInfo);
        return true;
    }
};

/* =================================================================
 * ÖZEL ANALİZÖRLER - ÇEKİRDEK SÜRÜCÜSÜ (DRIVER) ILE KONUŞANLAR
 * ================================================================= */

class DriverPciAnalyzer : public Analyzer {
    HANDLE m_hDriver;
public:
    explicit DriverPciAnalyzer(HANDLE hDriver) : m_hDriver(hDriver) {}
    void analyze(CompatReport& report) override {
        if (m_hDriver == INVALID_HANDLE_VALUE) return;

        auto res = std::make_unique<LCC_PCI_RESULT>();
        DWORD bytesReturned = 0;

        if (DeviceIoControl(m_hDriver, IOCTL_LCC_GET_PCI_DEVICES, nullptr, 0, res.get(), sizeof(LCC_PCI_RESULT), &bytesReturned, nullptr)) {
            bool ok = false;
            if (bytesReturned >= sizeof(UINT32)) {
                if (res->count <= LCC_MAX_PCI_DEVICES) {
                    size_t expected = sizeof(UINT32) + (size_t)res->count * sizeof(LCC_PCI_DEVICE);
                    if ((size_t)bytesReturned >= expected && (size_t)bytesReturned <= sizeof(LCC_PCI_RESULT)) {
                        ok = true;
                    }
                }
            }

            if (ok) {
                CompatItem* itp = new_item(report);
                if (!itp) return;
                itp->category = std::string(CAT_DRV_PCI);
                itp->name = std::format("Hardware scan: {} PCI devices found", res->count);
                itp->score = CompatScore::FULL;
                itp->detail = "Raw PCI configuration space was successfully read through the kernel driver.";
                itp->recommendation = "Direct hardware access is available. Driver communication appears healthy.";
                itp->critical = false;
            } else {
                CompatItem* itp = new_item(report);
                if (!itp) return;
                itp->category = std::string(CAT_DRV_PCI);
                itp->name = "PCI Taraması Başarısız (malformed response)";
                itp->score = CompatScore::MAYBE;
                itp->detail = std::format("Sürücüden gelen yanıt doğrulanamadı (bytes=%u, count=%u)", bytesReturned, res->count);
                itp->recommendation = "Sürücünün doğru çalıştığından ve ABI uyumlu olduğundan emin olun.";
            }
        } else {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category = std::string(CAT_DRV_PCI);
            itp->name = "PCI Taraması Başarısız";
            itp->score = CompatScore::MAYBE;
            itp->detail = std::format("Sürücüye gönderilen IOCTL_LCC_GET_PCI_DEVICES isteği başarısız oldu. Hata: {}", GetLastError());
            itp->recommendation = "Sürücünün doğru çalıştığından ve yüklenmiş olduğundan emin olun.";
        }
    }
};

class DriverAcpiAnalyzer : public Analyzer {
    HANDLE m_hDriver;
public:
    explicit DriverAcpiAnalyzer(HANDLE hDriver) : m_hDriver(hDriver) {}
    void analyze(CompatReport& report) override {
        if (m_hDriver == INVALID_HANDLE_VALUE) return;

        auto res = std::make_unique<LCC_ACPI_RESULT>();
        DWORD bytesReturned = 0;

        if (DeviceIoControl(m_hDriver, IOCTL_LCC_GET_ACPI_INFO, nullptr, 0, res.get(), sizeof(LCC_ACPI_RESULT), &bytesReturned, nullptr)) {
            bool ok = (bytesReturned >= sizeof(LCC_ACPI_RESULT)) && (res->count <= LCC_MAX_ACPI_TABLES);
            if (ok) {
                CompatItem* itp = new_item(report);
                if (!itp) return;
                itp->category = std::string(CAT_DRV_ACP);
                itp->name = std::format("ACPI tables: {} entries found", res->count);
                itp->score = res->xsdt_present ? CompatScore::FULL : CompatScore::MINOR;
                itp->detail = std::format("ACPI version: {}, XSDT: {}, RSDP: {}", 
                                          res->acpi_revision, res->xsdt_present ? "Yes" : "No", res->has_rsdp ? "Yes" : "No");
                itp->recommendation = res->xsdt_present 
                    ? "Modern XSDT is available. Linux power and hardware management should work well." 
                    : "Only legacy RSDT is available. Some modern power management features may be limited.";
                itp->critical = false;
            } else {
                CompatItem* itp = new_item(report);
                if (!itp) return;
                itp->category = std::string(CAT_DRV_ACP);
                itp->name = "ACPI read failed (malformed response)";
                itp->score = CompatScore::MAYBE;
                itp->detail = std::format("Driver ACPI response could not be validated (bytes=%u, count=%u)", bytesReturned, res->count);
                itp->recommendation = "Ensure the driver supports ACPI queries and returns valid data.";
            }
        }
    }
};

class DriverMsrAnalyzer : public Analyzer {
    HANDLE m_hDriver;
public:
    explicit DriverMsrAnalyzer(HANDLE hDriver) : m_hDriver(hDriver) {}
    void analyze(CompatReport& report) override {
        if (m_hDriver == INVALID_HANDLE_VALUE) return;

        LCC_MSR_REQUEST req{};
        req.msr_address = MSR_IA32_FEATURE_CONTROL; // 0x3A (VMX / Sanallaştırma kilidi vb.)
        req.cpu_index = 0;

        LCC_MSR_RESULT res{};
        DWORD bytesReturned = 0;

        if (DeviceIoControl(m_hDriver, IOCTL_LCC_GET_CPU_MSR, &req, sizeof(req), &res, sizeof(res), &bytesReturned, nullptr)) {
            if (bytesReturned >= sizeof(LCC_MSR_RESULT)) {
                CompatItem* itp = new_item(report);
                if (!itp) return;
                itp->category = std::string(CAT_DRV_MSR);

                if (res.valid) {
                bool isLocked = (res.value & 1) != 0;
                bool vmxEnabled = (res.value & 4) != 0;

                itp->name = std::format("MSR 0x3A (Feature Control): 0x{:X}", res.value);

                if (isLocked && !vmxEnabled) {
                    itp->score = CompatScore::MINOR;
                    itp->detail = "Hardware virtualization (VT-x/VMX) is disabled or locked in BIOS.";
                    itp->recommendation = "Reboot and enable virtualization support in BIOS/UEFI to use KVM/QEMU.";
                } else {
                    itp->score = CompatScore::FULL;
                    itp->detail = "Hardware virtualization (VT-x/VMX) is enabled and accessible.";
                    itp->recommendation = "KVM/QEMU virtualization tools are ready for full performance on Linux.";
                }
                } else {
                    itp->score = CompatScore::MINOR;
                    itp->name = "MSR 0x3A (Feature Control): Unsupported / unreadable";
                    itp->detail = "The processor does not support this register or a hypervisor is blocking access.";
                    itp->recommendation = "MSR access may fail on AMD CPUs or inside VirtualBox/VMware. This is expected in some cases.";
                }
                itp->critical = false;
            } else {
                CompatItem* itp = new_item(report);
                if (!itp) return;
                itp->category = std::string(CAT_DRV_MSR);
                itp->name = "MSR Sorgusu Başarısız (malformed response)";
                itp->score = CompatScore::MAYBE;
                itp->detail = std::format("Sürücüden gelen MSR yanıtı beklenen boyutta değil (bytes=%u)", bytesReturned);
                itp->recommendation = "Sürücünün ABI uyumluluğunu doğrulayın.";
                itp->critical = false;
            }
        }
    }
};


/* =================================================================
 * Standart Windows API Analizörleri (Mevcut kodunuzun çevrilmiş hali)
 * ================================================================= */

class CpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        int info[4]{};
        __cpuid(info, 0);

        union { int i[3]; char c[12]; } vendor_raw{};
        vendor_raw.i[0] = info[1];
        vendor_raw.i[1] = info[3];
        vendor_raw.i[2] = info[2];
        std::string vendor(vendor_raw.c, strnlen(vendor_raw.c, sizeof(vendor_raw.c)));

        char brand[49]{};
        __cpuid(info, 0x80000000);
        if (static_cast<unsigned>(info[0]) >= 0x80000004u) {
            __cpuid(info, 0x80000002); memcpy(brand,      info, 16);
            __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
            __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
        }

        std::string brand_str(brand[0] ? brand : "");
        {
            auto first = brand_str.find_first_not_of(' ');
            auto last  = brand_str.find_last_not_of(' ');
            if (first != std::string::npos)
                brand_str = brand_str.substr(first, last - first + 1);
            else
                brand_str.clear();
        }

        __cpuid(info, 1);
        const bool has_sse2 = (info[3] >> 26) & 1;
        const bool has_avx  = (info[2] >> 28) & 1;
        const bool has_vmx  = (info[2] >> 5) & 1;  

        __cpuid(info, 0x80000001);
        const bool has_svm = (info[2] >> 2) & 1;   

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const DWORD cores = si.dwNumberOfProcessors;

        const bool is_intel = vendor.find("GenuineIntel") != std::string::npos;
        const bool is_amd   = vendor.find("AuthenticAMD") != std::string::npos;

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category    = std::string(CAT_CPU);
        it.name        = !brand_str.empty() ? brand_str : vendor;
        it.critical    = true;

        if (is_intel || is_amd) {
            it.score = CompatScore::FULL;
            it.detail = std::format("{} {} | {} logical cores | SSE2:{}  AVX:{}  VT-x/AMD-V:{}",
                                    is_intel ? "Intel" : "AMD",
                                    !brand_str.empty() ? brand_str : "",
                                    cores,
                                    has_sse2 ? "Yes" : "No",
                                    has_avx  ? "Yes" : "No",
                                    (is_intel ? has_vmx : has_svm) ? "Yes" : "No");
            it.recommendation = "Excellent Linux support. Any mainstream distro should work well.";
        } else {
            it.score  = CompatScore::MAYBE;
            it.detail = std::format("Non-x86 CPU detected: Vendor='{}', {} logical cores", vendor, cores);
            it.recommendation = "ARM Linux support is improving, but some x86-only software may not run. Try Ubuntu ARM or Fedora ARM.";
        }
    }
};

class RamAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);

        const unsigned long long total_mb = ms.ullTotalPhys / (1024ULL * 1024);
        const unsigned long long total_gb = total_mb / 1024;

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category    = std::string(CAT_RAM);
        it.name        = std::format("Sistem Belleği: {} MB ({} GB)", total_mb, total_gb);
        it.critical    = true;

        if (total_mb < 2048) {
            it.score          = CompatScore::NONE;
            it.detail         = std::format("Yalnızca {} MB RAM algılandı — Linux masaüstü sürümleri için genelde en az 1-2 GB gerekir.", total_mb);
            it.recommendation = "En az 4 GB RAM önerilir. Lubuntu, Xubuntu veya Alpine Linux gibi çok hafif dağıtımları deneyin.";
        } else if (total_mb < 4096) {
            it.score          = CompatScore::MINOR;
            it.detail         = std::format("{} MB RAM var — temel masaüstü kullanımı için yeterli.", total_mb);
            it.recommendation = "Xfce, LXQt veya Mate gibi hafif masaüstü ortamlarını kullanan dağıtımları tercih edin.";
        } else {
            it.score          = CompatScore::FULL;
            it.detail         = std::format("{} MB ({} GB) RAM — tüm masaüstü işlemleri için mükemmel.", total_mb, total_gb);
            it.recommendation = "Herhangi bir masaüstü ortamını (GNOME, KDE Plasma) ve sanal makineleri rahatça kullanabilirsiniz.";
        }
    }
};

class StorageAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        ULARGE_INTEGER free_bytes{}, total_bytes{};
        GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, nullptr);
        const unsigned long long total_gb = total_bytes.QuadPart / (1024ULL * 1024 * 1024);
        const unsigned long long free_gb  = free_bytes.QuadPart  / (1024ULL * 1024 * 1024);

        bool is_ssd  = false;
        bool is_nvme = false;

        /*
         * BUG FIX #4 — PhysicalDrive0 hardcode
         * ----------------------------------------
         * Always querying PhysicalDrive0 is wrong when the OS lives on
         * a different disk (e.g. NVMe on Drive1, SATA data on Drive0).
         *
         * Fix: open the C: volume, call IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
         * to learn which physical disk number backs it, then open that disk.
         */
        DWORD physDriveNumber = 0;   /* fallback */
        {
            HANDLE hVol = CreateFileA("\\\\.\\C:",
                                      0,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      nullptr, OPEN_EXISTING, 0, nullptr);
            if (hVol != INVALID_HANDLE_VALUE) {
                alignas(VOLUME_DISK_EXTENTS)
                char extBuf[sizeof(VOLUME_DISK_EXTENTS) + 3 * sizeof(DISK_EXTENT)]{};
                DWORD extBytes = 0;
                if (DeviceIoControl(hVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                    nullptr, 0,
                                    extBuf, sizeof(extBuf),
                                    &extBytes, nullptr))
                {
                    auto* vde = reinterpret_cast<VOLUME_DISK_EXTENTS*>(extBuf);
                    if (vde->NumberOfDiskExtents > 0)
                        physDriveNumber = vde->Extents[0].DiskNumber;
                }
                CloseHandle(hVol);
            }
        }

        char drivePath[32]{};
        snprintf(drivePath, sizeof(drivePath), "\\\\.\\PhysicalDrive%lu", physDriveNumber);

        HANDLE hDisk = CreateFileA(drivePath, 0,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDisk != INVALID_HANDLE_VALUE) {
            DWORD bytes_returned = 0;
            STORAGE_PROPERTY_QUERY        spq_seek{};
            DEVICE_SEEK_PENALTY_DESCRIPTOR dsp{};
            spq_seek.PropertyId = StorageDeviceSeekPenaltyProperty;
            spq_seek.QueryType  = PropertyStandardQuery;
            if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq_seek, sizeof(spq_seek), &dsp, sizeof(dsp), &bytes_returned, nullptr))
                is_ssd = !dsp.IncursSeekPenalty;

            STORAGE_PROPERTY_QUERY spq_desc{};
            spq_desc.PropertyId = StorageDeviceProperty;
            spq_desc.QueryType  = PropertyStandardQuery;
            char desc_buf[2048]{};
            if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq_desc, sizeof(spq_desc), desc_buf, sizeof(desc_buf), &bytes_returned, nullptr)) {
                auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(desc_buf);
                is_nvme = (desc->BusType == BusTypeNvme);
            }
            CloseHandle(hDisk);
        }

        const char* drive_type = is_nvme ? "NVMe SSD" : is_ssd ? "SATA SSD" : "Mekanik Disk (HDD)";

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category    = std::string(CAT_DISK);
        it.name        = std::format("Depolama: {} GB Toplam / {} GB Boş  [{}]", total_gb, free_gb, drive_type);
        it.critical    = true;

        if (free_gb < 20) {
            it.score          = CompatScore::NONE;
            it.detail         = std::format("Boş alan: {} GB — Linux kurulumu için genellikle en az 20 GB gereklidir.", free_gb);
            it.recommendation = "C sürücünüzde yer açın veya kurulum için farklı bir disk/bölüm kullanın.";
        } else if (free_gb < 50) {
            it.score          = CompatScore::MINOR;
            it.detail         = std::format("Boş alan: {} GB — Kurulum yapılabilir ancak depolama sınırda.", free_gb);
            it.recommendation = "İyi bir deneyim ve oyun/uygulama yükleyebilmek için 50+ GB ayrılması tavsiye edilir.";
        } else {
            it.score  = CompatScore::FULL;
            it.detail = std::format("Boş alan: {} GB — Linux ve verileriniz için geniş bir alan var.", free_gb);
            if (is_nvme)
                it.recommendation = "NVMe SSD ile Linux son derece hızlı çalışacaktır. Dosya sistemi olarak Ext4 veya Btrfs kullanabilirsiniz.";
            else if (is_ssd)
                it.recommendation = "SSD diskiniz sayesinde sisteminiz hızlı açılır. Ext4 dosya sistemini tercih edebilirsiniz.";
            else
                it.recommendation = "Mekanik diskte Linux biraz yavaş çalışabilir. Bol miktarda Swap alanı (Takas alanı) ayarlamayı unutmayın.";
        }
    }
};

class GpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_DISPLAY, [&](std::string_view name, std::string_view hw_id) {
            auto has = [&](std::string_view s) { return name.find(s) != std::string_view::npos; };

            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category    = std::string(CAT_GPU);
            it.name        = std::string(name);
            it.critical    = true;

            const bool is_nvidia  = has("NVIDIA") || has("GeForce") || has("Quadro") || has("RTX") || has("GTX");
            const bool is_amd_gpu = has("AMD")    || has("Radeon")  || has("RX ");
            const bool is_intel_g = has("Intel")  || has("UHD")     || has("Iris") || has("Arc");
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

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_GPU);
            itp->name           = "Display adapter not found in device tree";
            itp->critical       = true;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "The display adapter list could not be opened (SetupAPI error).";
            itp->recommendation = "Try running the application as Administrator.";
        }
    }
};

class NetworkAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_NET, [&](std::string_view name, std::string_view hw_id) {
            auto has = [&](std::string_view s) { return name.find(s) != std::string_view::npos; };

            if (has("Microsoft") || has("WAN Miniport") || has("Bluetooth") || has("Loopback")) return;

            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
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

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_NET);
            itp->name           = "Network adapters could not be enumerated";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "SetupAPI could not open device records.";
            itp->recommendation = "Try running the application as Administrator.";
        }
    }
};

class AudioAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_MEDIA, [&](std::string_view name, std::string_view hw_id) {
            auto has = [&](std::string_view s) { return name.find(s) != std::string_view::npos; };

            if (has("Virtual") || has("Microsoft")) return;

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

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_AUDIO);
            itp->name           = "Audio device tree could not be read";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "Unable to retrieve the media device list.";
            itp->recommendation = "Try running the application as Administrator.";
        }
    }
};

class FirmwareAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        const auto pe_fw   = Registry::read_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control", "PEFirmwareType");
        const bool is_uefi = (pe_fw.value_or(0) == 2);

        const auto sb_val  = Registry::read_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled");
        const bool secure_boot = (sb_val.value_or(0) != 0);

        bool has_tpm = false;
        HDEVINFO tpmDev = SetupDiGetClassDevsA(nullptr, "ROOT\\TPM", nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (tpmDev != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA td{}; td.cbSize = sizeof(td);
            has_tpm = SetupDiEnumDeviceInfo(tpmDev, 0, &td);
            SetupDiDestroyDeviceInfoList(tpmDev);
        }

        const std::string bios_ver    = Registry::read_string(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion").value_or("");
        const std::string bios_vendor = Registry::read_string(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor").value_or("");

        /* UEFI / BIOS */
        {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category    = std::string(CAT_FW);
            it.name        = std::format("Boot type: {}  |  BIOS: {} {}", is_uefi ? "UEFI" : "Legacy BIOS", bios_vendor, bios_ver);
            it.critical    = true;

            if (is_uefi) {
                it.score          = CompatScore::FULL;
                it.detail         = "Modern UEFI system detected. GRUB2 and systemd-boot installers should work fine.";
                it.recommendation = "Install Linux in UEFI mode and ensure the EFI System Partition is selected.";
            } else {
                it.score          = CompatScore::MINOR;
                it.detail         = "Legacy BIOS system detected. Linux can be installed, but GPT or Secure Boot may not be available.";
                it.recommendation = "Use MBR partitioning during installation if your system does not support UEFI.";
            }
        }

        /* Güvenli Önyükleme (Secure Boot) */
        {
            CompatItem* itp2 = new_item(report);
            if (!itp2) return;
            CompatItem& it = *itp2;
            it.category    = std::string(CAT_SB);
            it.name        = std::format("Secure Boot: {}", secure_boot ? "ENABLED" : "DISABLED");
            it.critical    = false;

            if (secure_boot) {
                it.score          = CompatScore::MINOR;
                it.detail         = "Secure Boot is currently ENABLED. Many distros like Ubuntu and Fedora support it, but some may still have issues.";
                it.recommendation = "If installing Arch, Gentoo, or Manjaro, you may need to disable Secure Boot in BIOS.";
            } else {
                it.score          = CompatScore::FULL;
                it.detail         = "Secure Boot is disabled. Most Linux distributions should boot without restrictions.";
                it.recommendation = "No action is required.";
            }
        }

        /* TPM */
        {
            CompatItem* itp3 = new_item(report);
            if (!itp3) return;
            CompatItem& it    = *itp3;
            it.category       = std::string(CAT_TPM);
            it.name           = std::format("Trusted Platform Module (TPM): {}", has_tpm ? "Present" : "Not detected");
            it.critical       = false;
            it.score          = CompatScore::FULL;
            it.detail         = has_tpm ? "TPM is present — manageable with tpm2-tools on Linux." : "No TPM hardware detected.";
            it.recommendation = "TPM can be used for LUKS encryption keys or secure boot workflows if desired.";
        }
    }
};

class PowerAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        SYSTEM_POWER_STATUS sps{};
        GetSystemPowerStatus(&sps);

        if (sps.BatteryFlag == 128 || sps.BatteryFlag == 255) return; // Masaüstü ise atla

        const int  pct   = (sps.BatteryLifePercent == 255) ? 0 : sps.BatteryLifePercent;
        const bool on_ac = (sps.ACLineStatus == 1);

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
        int info[4]{};
        __cpuid(info, 1);
        if (!((info[2] >> 31) & 1)) return; // Sanal ortam değil

        union { int i[3]; char c[12]; } hv_raw{};
        __cpuid(info, 0x40000000);
        hv_raw.i[0] = info[1];
        hv_raw.i[1] = info[2];
        hv_raw.i[2] = info[3];
        const std::string hv_name(hv_raw.c, strnlen(hv_raw.c, sizeof(hv_raw.c)));

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it    = *itp;
        it.category       = std::string(CAT_VIRT);
        it.name           = std::format("Virtual machine detected: {}", hv_name);
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = std::format("Hypervisor: {} — this compatibility scan is running inside a VM.", hv_name);
        it.recommendation = "Results may not reflect physical hardware compatibility. Run on bare metal for the most accurate assessment.";
    }
};

class OnlineAnalyzer : public Analyzer {
public:
    explicit OnlineAnalyzer(bool online) : m_online(online) {}

    void analyze(CompatReport& report) override {
        if (!m_online) return;

        HINTERNET hSession = WinHttpOpen(L"LinuxCompatChecker/2.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;

        HINTERNET hConnect = WinHttpConnect(hSession, L"www.kernel.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        HINTERNET hRequest = hConnect ? WinHttpOpenRequest(hConnect, L"GET", L"/finger_banner",
                                                           nullptr, WINHTTP_NO_REFERER,
                                                           WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;

        std::string raw_body;
        if (hRequest && WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
                     && WinHttpReceiveResponse(hRequest, nullptr)) {
            char   chunk[512]{};
            DWORD  bytes_read = 0;
            while (WinHttpReadData(hRequest, chunk, sizeof(chunk) - 1, &bytes_read) && bytes_read > 0) {
                chunk[bytes_read] = '\0';
                raw_body += chunk;
            }
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        std::string kernel_ver;
        {
            const std::string marker = "stable";
            auto pos = raw_body.find(marker);
            if (pos != std::string::npos) {
                pos = raw_body.find(": ", pos);
                if (pos != std::string::npos) {
                    pos += 2;
                    auto end = raw_body.find_first_of(" \t\r\n", pos);
                    kernel_ver = raw_body.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
                }
            }
        }

        if (kernel_ver.empty()) return;

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it    = *itp;
        it.category       = std::string(CAT_ONLINE);
        it.name           = std::format("Latest stable kernel: {}  (source: kernel.org)", kernel_ver);
        it.critical       = false;
        it.score          = CompatScore::FULL;
        it.detail         = std::format("Kernel {} is currently the latest stable release. This analysis checks compatibility with modern Linux kernel drivers.", kernel_ver);
        it.recommendation = "Pick a distro with an up-to-date kernel, such as Fedora or Ubuntu LTS, for the best hardware support.";
    }

private:
    bool m_online;
};


/* =================================================================
 * ReportPrinter — Çıktı formatlama
 * ================================================================= */
class ReportPrinter {
public:
    explicit ReportPrinter(bool online) : m_online(online) {}

    void print(CompatReport& report) {
        report.compute();

        printf("\n%s%s════════════════════════════════════════════════════════════════\n%s", CYAN, BOLD, RESET);
        printf("%s%s  📋 DETAILED HARDWARE COMPATIBILITY REPORT\n%s", BOLD, WHITE, RESET);
        printf("%s%s════════════════════════════════════════════════════════════════\n\n%s", CYAN, BOLD, RESET);

        constexpr std::array categories{
            CAT_CPU, CAT_RAM, CAT_DISK, CAT_GPU, CAT_NET,
            CAT_AUDIO, CAT_FW, CAT_SB, CAT_TPM, CAT_POWER, CAT_VIRT, 
            CAT_DRV_PCI, CAT_DRV_ACP, CAT_DRV_MSR, CAT_ONLINE
        };

        for (const auto& cat : categories) {
            bool header_printed = false;

            for (const auto& it : report.items) {
                if (it.category != cat) continue;

                if (!header_printed) {
                    printf("%s%s  ┌─ %.*s\n%s", BLUE, BOLD, static_cast<int>(cat.size()), cat.data(), RESET);
                    header_printed = true;
                }

                printf("  │  %s  %s  %s\n", Console::score_icon(it.score), Console::score_label(it.score), it.name.c_str());
                printf("  │     %s→ %s\n%s", DIM, it.detail.c_str(), RESET);
                printf("  │     %s✦ %s\n%s", CYAN, it.recommendation.c_str(), RESET);
                printf("  │\n");
            }
        }

        printf("\n%s%s════════════════════════════════════════════════════════════════\n%s", CYAN, BOLD, RESET);
        printf("%s%s  📊 ÖZET İSTATİSTİKLER\n%s", BOLD, WHITE, RESET);
        printf("%s%s════════════════════════════════════════════════════════════════\n\n%s", CYAN, BOLD, RESET);

        printf("  %s●%s  Fully compatible         : %d items\n",  GREEN,  RESET, report.score_counts[0]);
        printf("  %s◑%s  Compatible (minor)      : %d items\n",  YELLOW, RESET, report.score_counts[1]);
        printf("  %s◔%s  Maybe incompatible      : %d items\n",  ORANGE, RESET, report.score_counts[2]);
        printf("  %s○%s  Incompatible            : %d items\n",  RED,    RESET, report.score_counts[3]);
        printf("\n  Total compatibility score:\n  ");
        Console::print_percent_bar(report.overall_percent, 40);
        printf("\n\n");

        printf("%s%s  🧭 OVERALL ASSESSMENT AND RESULT\n\n%s", BOLD, WHITE, RESET);
        if (report.overall_percent >= 85.0) {
            printf("%s%s  ✅ Your system is READY for Linux!\n%s", GREEN, BOLD, RESET);
            printf("     You can use Ubuntu, Fedora, Mint, or most mainstream distros without much hassle.\n");
        } else if (report.overall_percent >= 65.0) {
            printf("%s%s  ⚠️  Your system is LARGELY compatible with Linux.\n%s", YELLOW, BOLD, RESET);
            printf("     Some devices may require manual driver setup after installation.\n");
            printf("     Ubuntu LTS or Linux Mint are usually easiest for this setup.\n");
        } else if (report.overall_percent >= 40.0) {
            printf("%s%s  🔶 Compatibility is MODERATE.\n%s", ORANGE, BOLD, RESET);
            printf("     Several components may not work out of the box. Test from a live USB before installing.\n");
        } else {
            printf("%s%s  ❌ Your system has serious compatibility issues.\n%s", RED, BOLD, RESET);
            printf("     Installing Linux on this machine may not be suitable for daily use.\n");
        }

        printf("\n%s%s  🐧 DISTRIBUTION RECOMMENDATIONS\n\n%s", BOLD, WHITE, RESET);
        printf("     1. Ubuntu 24.04 LTS  — widest driver support and easy installation.\n");
        printf("     2. Linux Mint 22     — familiar layout for Windows users and beginner friendly.\n");
        printf("     3. Fedora 40         — bleeding-edge kernel and good hardware support.\n");
        printf("     4. Pop!_OS 24.04     — good default driver support for NVIDIA systems.\n");
        printf("     5. EndeavourOS       — Arch-based choice for advanced users who want full control.\n");

        printf("\n%s  🌐 Internet status: %s%s\n%s", DIM,
               m_online ? GREEN : YELLOW,
               m_online ? "Online — kernel.org data fetched." : "Offline — local analysis only.", RESET);

        printf("\n%s%s════════════════════════════════════════════════════════════════\n%s", CYAN, BOLD, RESET);
        printf("%s  Linux Compatibility Checker v2.1  |  linux-hardware.org\n%s", DIM, RESET);
        printf("%s%s════════════════════════════════════════════════════════════════\n\n%s", CYAN, BOLD, RESET);
    }

private:
    bool m_online;
};


/* =================================================================
 * Tarama adımları tanımlamaları (Adımlar ve Yükleme Barları)
 * ================================================================= */
struct StepMeta {
    const char* label       = nullptr;
    int         steps       = 0;
    int         delay_ms    = 0;
    bool        online_only = false;
};

inline constexpr std::array<StepMeta, 13> PIPELINE_STEPS{{
    { "Step 2/14: CPU analysis in progress          ",  8, 30, false },
    { "Step 3/14: Memory (RAM) analysis            ",  6, 25, false },
    { "Step 4/14: Disk and storage analysis        ",  7, 35, false },
    { "Step 5/14: Graphics (GPU) scan              ",  9, 40, false },
    { "Step 6/14: Networking inspection            ",  8, 35, false },
    { "Step 7/14: Audio device inspection          ",  6, 30, false },
    { "Step 8/14: Firmware / UEFI check            ",  7, 25, false },
    { "Step 9/14: Power and battery status         ",  4, 20, false },
    { "Step 10/14: Virtualization environment      ",  4, 20, false },
    { "Step 11/14: DRIVER: Ring-0 PCI scan         ",  8, 30, false },  /* kernel driver only */
    { "Step 12/14: DRIVER: Ring-0 ACPI read         ",  8, 30, false },
    { "Step 13/14: DRIVER: MSR processor query      ",  5, 20, false },
    { "Step 14/14: kernel.org online lookup        ", 12, 60, true  },
}};


/* =================================================================
 * ANA UYGULAMA (ENTRY POINT)
 * ================================================================= */
int main(int argc, char* argv[]) {
    std::string save_path;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--save" && i + 1 < argc) {
            save_path = argv[++i];
        }
    }
    
    Console::enable_ansi();
    Console::print_header();

    const std::string os_name = Registry::read_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName").value_or("Windows");

    char  computer_name[256]{};
    DWORD comp_size = sizeof(computer_name);
    GetComputerNameA(computer_name, &comp_size);

    SYSTEMTIME st{};
    GetLocalTime(&st);

    printf("%s  Computer name  : %s\n%s", DIM, computer_name, RESET);
    printf("%s  OS version     : %s\n%s", DIM, os_name.c_str(), RESET);
    printf("%s  Date / time    : %02d/%02d/%04d  %02d:%02d\n\n%s", DIM, st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, RESET);

    /* STEP 1: Internet */
    printf("%s  Step 1/14: %sTesting internet connectivity...\n", CYAN, RESET);
    const bool g_online = Internet::check_connection();
    printf("              %s%s%s\n\n", g_online ? GREEN : YELLOW, g_online ? "✓ Online" : "✗ Offline", RESET);

    /* ÇEKİRDEK SÜRÜCÜ (DRIVER) BAĞLANTISI VE HABERLEŞME TESTİ */
    printf("%s  [SYSTEM]  : %sLooking for kernel-mode driver (LccDriver)...\n", BLUE, RESET);
    HANDLE hDriver = CreateFileA(LCC_USERMODE_PATH, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDriver != INVALID_HANDLE_VALUE) {
        LCC_VERSION_RESULT ver{};
        DWORD retBytes = 0;
        if (DeviceIoControl(hDriver, IOCTL_LCC_GET_VERSION, nullptr, 0, &ver, sizeof(ver), &retBytes, nullptr)) {
            if (retBytes == sizeof(ver)) {
                printf("              %s✓ Driver found and connected. (Version: v%u.%u)%s\n\n", GREEN, ver.driver_version >> 8, ver.driver_version & 0xFF, RESET);
            } else {
                printf("              %s✗ Unexpected driver response size (bytes=%u).\n\n", YELLOW, retBytes);
            }
        } else {
            printf("              %s✗ Connected to driver but DeviceIoControl failed.%s\n\n", YELLOW, RESET);
        }
    } else {
        printf("              %s✗ Driver not found. (LccDriver not installed) Kernel-level checks will be skipped.%s\n\n", RED, RESET);
    }

    /* Analizörleri Sırala */
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
    
    /* YENİ SÜRÜCÜ ANALİZÖRLERİNİ EKLİYORUZ (Driver Handle vererek) */
    analyzers.push_back(std::make_unique<DriverPciAnalyzer>(hDriver));
    analyzers.push_back(std::make_unique<DriverAcpiAnalyzer>(hDriver));
    analyzers.push_back(std::make_unique<DriverMsrAnalyzer>(hDriver));
    
    analyzers.push_back(std::make_unique<OnlineAnalyzer>(g_online));

    static_assert(PIPELINE_STEPS.size() == 13, "PIPELINE_STEPS sayısı analizör sayısı ile eşleşmeli (Internet adımı hariç 13)");

    CompatReport report;

    /* Taramaları Yürüt */
    for (std::size_t i = 0; i < analyzers.size(); ++i) {
        const StepMeta& meta = PIPELINE_STEPS[i];

        if (meta.online_only && !g_online) {
            printf("%s  %s — Skipped (offline).\n%s", DIM, meta.label, RESET);
            continue;
        }

        /* If the driver is missing, skip the driver-specific steps */
        if (hDriver == INVALID_HANDLE_VALUE && (i == 9 || i == 10 || i == 11)) {
            printf("%s  %s — Skipped (driver unavailable).\n%s", DIM, meta.label, RESET);
            continue; 
        }

        if (meta.label)
            Console::loading_bar(meta.label, meta.steps, meta.delay_ms);

        analyzers[i]->analyze(report);
    }

    printf("\n");
    ReportPrinter printer(g_online);
    printer.print(report);

    if (!save_path.empty()) {
        FILE* f = fopen(save_path.c_str(), "w");
        if (f) {
            fprintf(f, "Linux Compatibility Checker v2.1 — Report\n");
            fprintf(f, "Computer name : %s\n", computer_name);
            fprintf(f, "OS version    : %s\n", os_name.c_str());
            fprintf(f, "Date          : %02d/%02d/%04d  %02d:%02d\n\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);

            constexpr const char* score_text[] = {
                "[0] FULLY COMPATIBLE",
                "[1] COMPATIBLE (minor)",
                "[2] MAYBE INCOMPATIBLE",
                "[3] INCOMPATIBLE"
            };
            for (const auto& item : report.items) {
                const int s = static_cast<int>(item.score);
                fprintf(f, "%-26s  %-30s  %s\n", item.category.c_str(), score_text[s], item.name.c_str());
                fprintf(f, "  → %s\n", item.detail.c_str());
                fprintf(f, "  ✦ %s\n\n", item.recommendation.c_str());
            }
            fprintf(f, "Overall compatibility score: %%%.1f\n", report.overall_percent);
            fprintf(f, "Fully compatible: %d | Compatible (minor): %d | Maybe incompatible: %d | Incompatible: %d\n",
                    report.score_counts[0], report.score_counts[1], report.score_counts[2], report.score_counts[3]);
            fclose(f);
            printf("%s  ✓ Report saved to file: %s\n%s", GREEN, save_path.c_str(), RESET);
        } else {
            printf("%s  ✗ Failed to save report to file: %s\n%s", RED, save_path.c_str(), RESET);
        }
    }

    /* Uygulama biterken çekirdek sürücüsünün bağlantısını kapatmayı unutmuyoruz */
    if (hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(hDriver);
    }

    printf("  Çıkmak için Enter'a basın...\n");
    getchar();
    return 0;
}
