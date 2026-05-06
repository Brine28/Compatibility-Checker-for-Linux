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

#define _WIN32_WINNT 0x0A00   /* Windows 10+ */
#define UNICODE
#define _UNICODE

#include <windows.h>
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
inline constexpr std::string_view CAT_CPU    = "İşlemci (CPU)";
inline constexpr std::string_view CAT_RAM    = "Bellek (RAM)";
inline constexpr std::string_view CAT_DISK   = "Depolama (Disk)";
inline constexpr std::string_view CAT_GPU    = "Ekran Kartı (GPU)";
inline constexpr std::string_view CAT_NET    = "Ağ Kartı";
inline constexpr std::string_view CAT_AUDIO  = "Ses Kartı";
inline constexpr std::string_view CAT_FW     = "Aygıt Yazılımı (Firmware)";
inline constexpr std::string_view CAT_SB     = "Güvenli Önyükleme";
inline constexpr std::string_view CAT_TPM    = "TPM";
inline constexpr std::string_view CAT_POWER  = "Güç/Batarya";
inline constexpr std::string_view CAT_VIRT   = "Sanallaştırma";
inline constexpr std::string_view CAT_ONLINE = "Çevrimiçi Veri";
inline constexpr std::string_view CAT_DRV_PCI= "PCI Taraması (Sürücü)";
inline constexpr std::string_view CAT_DRV_ACP= "ACPI Okuması (Sürücü)";
inline constexpr std::string_view CAT_DRV_MSR= "MSR Sorgusu (Sürücü)";

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
        DWORD type = REG_SZ;
        DWORD sz   = sizeof(buf);
        bool  ok   = (RegQueryValueExA(hk, value, nullptr, &type,
                                       reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS);
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
        printf("%s%s║%s%s%s     🐧  Linux Çekirdeği Uyumluluk Denetleyicisi v2.1      %s%s║\n%s", CYAN, BOLD, RESET, BLUE, BOLD, CYAN, BOLD, RESET);
        printf("%s%s║%s%s     Windows 11 → Linux Geçişine Uygunluk Raporu           %s%s║\n%s", CYAN, BOLD, RESET, DIM, CYAN, BOLD, RESET);
        printf("%s%s╚══════════════════════════════════════════════════════════════╝\n%s", CYAN, BOLD, RESET);
        printf("\n");
    }

    [[nodiscard]] inline const char* score_label(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return "\033[92m\033[1m[0] TAM UYUMLU           \033[0m";
            case CompatScore::MINOR: return "\033[93m\033[1m[1] UYUMLU (küçük pürüz) \033[0m";
            case CompatScore::MAYBE: return "\033[38;5;208m\033[1m[2] OLASI UYUMSUZLUK     \033[0m";
            case CompatScore::NONE:  return "\033[91m\033[1m[3] UYUMSUZ              \033[0m";
        }
        return "\033[97m[?] BİLİNMİYOR\033[0m";
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
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category = std::string(CAT_DRV_PCI);
            itp->name = std::format("Donanım Taraması: {} PCI aygıtı bulundu", res->count);
            itp->score = CompatScore::FULL;
            itp->detail = "Çekirdek modu sürücüsü (Ring-0) üzerinden ham PCI konfigürasyon alanı başarıyla okundu.";
            itp->recommendation = "Donanıma doğrudan erişim sağlanabiliyor. Sürücü haberleşmesi kusursuz.";
            itp->critical = false;
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
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category = std::string(CAT_DRV_ACP);
            itp->name = std::format("ACPI Tabloları: {} adet bulundu", res->count);
            itp->score = res->xsdt_present ? CompatScore::FULL : CompatScore::MINOR;
            itp->detail = std::format("ACPI Sürümü: {}, XSDT: {}, RSDP: {}", 
                                      res->acpi_revision, res->xsdt_present ? "Var" : "Yok", res->has_rsdp ? "Var" : "Yok");
            itp->recommendation = res->xsdt_present 
                ? "Modern XSDT yönlendirmesi mevcut. Linux güç ve donanım yönetimi mükemmel çalışacaktır." 
                : "Yalnızca eski RSDT yönlendirmesi bulundu. Modern güç yönetimi kısıtlı olabilir.";
            itp->critical = false;
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
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category = std::string(CAT_DRV_MSR);

            if (res.valid) {
                bool isLocked = (res.value & 1) != 0;
                bool vmxEnabled = (res.value & 4) != 0;

                itp->name = std::format("MSR 0x3A (Feature Control): 0x{:X}", res.value);

                if (isLocked && !vmxEnabled) {
                    itp->score = CompatScore::MINOR;
                    itp->detail = "Donanımsal Sanallaştırma (VT-x/VMX) BIOS üzerinden kapatılmış veya kilitli.";
                    itp->recommendation = "Linux'ta sanal makine (KVM/QEMU) çalıştırmak için bilgisayarı yeniden başlatıp BIOS'tan sanallaştırmayı (Virtualization) etkinleştirin.";
                } else {
                    itp->score = CompatScore::FULL;
                    itp->detail = "Donanımsal Sanallaştırma (VT-x/VMX) etkin ve erişilebilir durumda.";
                    itp->recommendation = "KVM / QEMU sanallaştırma araçları Linux üzerinde tam performansla çalışmaya hazırdır.";
                }
            } else {
                itp->score = CompatScore::MINOR;
                itp->name = "MSR 0x3A (Feature Control): Desteklenmiyor / Okunamadı";
                itp->detail = "İşlemci bu adresi desteklemiyor ya da hipervizör (VM) tarafından erişim engellendi.";
                itp->recommendation = "AMD işlemcilerde veya VirtualBox/VMware gibi ortamlarda MSR okunamaması normaldir.";
            }
            itp->critical = false;
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

        const bool is_intel = vendor.contains("GenuineIntel"); 
        const bool is_amd   = vendor.contains("AuthenticAMD");

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category    = std::string(CAT_CPU);
        it.name        = !brand_str.empty() ? brand_str : vendor;
        it.critical    = true;

        if (is_intel || is_amd) {
            it.score = CompatScore::FULL;
            it.detail = std::format("{} {} | {} mantıksal çekirdek | SSE2:{}  AVX:{}  VT-x/AMD-V:{}",
                                    is_intel ? "Intel" : "AMD",
                                    !brand_str.empty() ? brand_str : "",
                                    cores,
                                    has_sse2 ? "Evet" : "Hayır",
                                    has_avx  ? "Evet" : "Hayır",
                                    (is_intel ? has_vmx : has_svm) ? "Evet" : "Hayır");
            it.recommendation = "Mükemmel Linux desteği. Herhangi bir dağıtım sorunsuz çalışacaktır.";
        } else {
            it.score  = CompatScore::MAYBE;
            it.detail = std::format("X86 dışı işlemci algılandı: Üretici='{}', {} mantıksal çekirdek", vendor, cores);
            it.recommendation = "ARM tabanlı Linux desteği gelişiyor ancak bazı x86 özel programlar çalışmayabilir. Ubuntu ARM veya Fedora ARM deneyin.";
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
            auto has = [&](std::string_view s) { return name.contains(s); };

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
                it.detail         = std::format("NVIDIA Ekran Kartı: {}", name);
                it.recommendation = "NVIDIA Sahipli (Proprietary) sürücüsünü kurmanız gerekir. Açık kaynaklı Nouveau sürücüsü kısıtlıdır. Ubuntu, Linux Mint veya Pop!_OS bu kurulumu sizin için otomatik yapar.";
            } else if (is_amd_gpu) {
                it.score          = CompatScore::FULL;
                it.detail         = std::format("AMD Ekran Kartı: {}", name);
                it.recommendation = "Çekirdeğe gömülü AMDGPU sürücüsü ile MÜKEMMEL uyumluluk. Hiçbir ekstra sürücü kurmanıza gerek kalmadan tak-çalıştır oyun performansı alırsınız.";
            } else if (is_intel_g) {
                it.score          = CompatScore::FULL;
                it.detail         = std::format("Intel Grafik Birimi: {}", name);
                it.recommendation = "Intel i915/xe çekirdek sürücüsü harika çalışır. Hem Wayland hem X11 görüntü sunucularıyla tam uyumludur.";
            } else if (is_virtual) {
                it.score          = CompatScore::MINOR;
                it.detail         = std::format("Sanal/Emüle Ekran Kartı: {}", name);
                it.recommendation = "Şu anda sanal bir ortam algılandı. Gerçek ekran kartınızın uyumluluğunu görmek için aracı fiziksel bilgisayarınızda çalıştırın.";
            } else {
                it.score          = CompatScore::MAYBE;
                it.detail         = std::format("Bilinmeyen Ekran Kartı: {}", name);
                it.recommendation = "Lütfen internetten 'Linux + [Kart Modeli] sürücüsü' araması yapıp desteğini doğrulayın.";
            }
        });

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_GPU);
            itp->name           = "Ekran kartı donanım ağacında bulunamadı";
            itp->critical       = true;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "Görüntü bağdaştırıcıları listesi açılamadı (SetupAPI Hatası).";
            itp->recommendation = "Uygulamayı Yönetici Olarak (Run as Administrator) çalıştırmayı deneyin.";
        }
    }
};

class NetworkAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_NET, [&](std::string_view name, std::string_view hw_id) {
            auto has = [&](std::string_view s) { return name.contains(s); };

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
                it.detail = std::format("{} bağdaştırıcı: {}", is_wifi ? "Intel Wi-Fi" : "Intel Ethernet", name);
                it.recommendation = is_wifi ? "Intel Wi-Fi (iwlwifi) çekirdek üzerinde kusursuz bir Linux desteğine sahiptir." : "Intel Ethernet çekirdekte gömülü olarak tam desteklenir.";
            } else if (is_realtek) {
                it.score  = CompatScore::MINOR;
                it.detail = std::format("Realtek {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = is_wifi ? "Realtek Wi-Fi yongaları bazen harici bir sürücü paketi kurmanızı gerektirebilir (dkms ile)." : "Realtek Ethernet (r8169) genelde sorunsuz çalışır.";
            } else if (is_broadcom) {
                it.score  = CompatScore::MAYBE;
                it.detail = std::format("Broadcom {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = "Broadcom adaptörler Linux'ta sıkıntılı olabilir. Kurulum esnasında internete bağlanmak için kablo takmanız (ethernet) gerekebilir.";
            } else if (is_atheros) {
                it.score  = CompatScore::FULL;
                it.detail = std::format("Atheros/Killer {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = "Atheros veya Killer kartlar genelde ath10k/ath11k sürücüleriyle tam uyumlu şekilde otomatik çalışır.";
            } else if (is_mediatek) {
                it.score  = CompatScore::MINOR;
                it.detail = std::format("MediaTek/Ralink {}: {}", is_wifi ? "Wi-Fi" : "Ethernet", name);
                it.recommendation = "MediaTek (mt76) sürücüsü çekirdekte mevcuttur ancak çok yeni yongalar ekstra Firmware gerektirebilir.";
            } else {
                it.score  = CompatScore::MAYBE;
                it.detail = std::format("{}: {}  [HWID: {}]", is_wifi ? "Wi-Fi" : "Ağ Kartı", name, hw_id.substr(0, std::min(hw_id.size(), std::size_t{80})));
                it.recommendation = "Üreticinin kendi sitesinden veya linux-hardware.org'dan donanım kimliğini kontrol etmeniz tavsiye edilir.";
            }
        });

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_NET);
            itp->name           = "Ağ bağdaştırıcıları listelenemedi";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "SetupAPI cihaz kayıtlarını açamadı.";
            itp->recommendation = "Uygulamayı Yönetici Olarak (Run as Administrator) çalıştırmayı deneyin.";
        }
    }
};

class AudioAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = enumerate_devices(&GUID_DEVCLASS_MEDIA, [&](std::string_view name, std::string_view hw_id) {
            auto has = [&](std::string_view s) { return name.contains(s); };

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
                it.detail         = std::format("HDA uyumlu Ses Yongası: {}", name);
                it.recommendation = "ALSA, PulseAudio veya modern PipeWire ses sunucusu ile hiçbir ayar gerektirmeden çalışacaktır.";
            } else if (is_focusrite) {
                it.score          = CompatScore::MINOR;
                it.detail         = std::format("USB Ses Arayüzü (Interface): {}", name);
                it.recommendation = "Focusrite ürünleri genelde sorunsuz çalışır (Scarlett serisi vb.). Profesyonel ses miksajı için JACK veya PipeWire kullanın.";
            } else if (is_creative) {
                it.score          = CompatScore::MAYBE;
                it.detail         = std::format("Creative Ses Kartı: {}", name);
                it.recommendation = "Sound Blaster serisi kartların bazı gelişmiş DSP ve yazılımsal Ekolayzer özellikleri Linux üzerinde desteklenmeyebilir.";
            } else {
                it.score          = CompatScore::MINOR;
                it.detail         = std::format("Ses Aygıtı: {}", name);
                it.recommendation = "Çoğu standart USB veya Bluetooth ses aygıtı Linux'a bağlandığı anda otomatik tanınır.";
            }
        });

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_AUDIO);
            itp->name           = "Ses kartı donanım ağacında okunamadı";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "Medya aygıtları listesi çekilemedi.";
            itp->recommendation = "Uygulamayı Yönetici Olarak (Run as Administrator) çalıştırmayı deneyin.";
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
            it.name        = std::format("Önyükleme (Boot) Tipi: {}  |  BIOS: {} {}", is_uefi ? "UEFI" : "Eski (Legacy) BIOS", bios_vendor, bios_ver);
            it.critical    = true;

            if (is_uefi) {
                it.score          = CompatScore::FULL;
                it.detail         = "Modern UEFI sistemi algılandı. GRUB2 ve systemd-boot gibi modern Linux önyükleyicileri sorunsuz kurulur.";
                it.recommendation = "Linux'u mutlaka UEFI modunda yükleyin. Kurulum sırasında EFI Sistem Bölümü (ESP) seçildiğinden emin olun.";
            } else {
                it.score          = CompatScore::MINOR;
                it.detail         = "Eski (Legacy) BIOS sistemi algılandı. Linux kurulabilir ancak GPT disk veya Secure Boot özellikleri kullanılamaz.";
                it.recommendation = "Diskinizde kurulum esnasında MBR tablo tipini kullanmalısınız.";
            }
        }

        /* Güvenli Önyükleme (Secure Boot) */
        {
            CompatItem* itp2 = new_item(report);
            if (!itp2) return;
            CompatItem& it = *itp2;
            it.category    = std::string(CAT_SB);
            it.name        = std::format("Güvenli Önyükleme: {}", secure_boot ? "AÇIK" : "KAPALI");
            it.critical    = false;

            if (secure_boot) {
                it.score          = CompatScore::MINOR;
                it.detail         = "Güvenli Önyükleme (Secure Boot) şu anda AÇIK. Birçok dağıtım (Ubuntu, Fedora) bunu desteklese de bazı dağıtımlarda hata alabilirsiniz.";
                it.recommendation = "Eğer Arch Linux, Gentoo veya Manjaro kuracaksanız BIOS menüsünden Secure Boot'u kapatmanız gerekir.";
            } else {
                it.score          = CompatScore::FULL;
                it.detail         = "Güvenli Önyükleme kapalı. Herhangi bir Linux dağıtımı engellemeye takılmadan başlatılabilir.";
                it.recommendation = "Hiçbir işlem yapmanıza gerek yok.";
            }
        }

        /* TPM */
        {
            CompatItem* itp3 = new_item(report);
            if (!itp3) return;
            CompatItem& it    = *itp3;
            it.category       = std::string(CAT_TPM);
            it.name           = std::format("Güvenilir Platform Modülü (TPM): {}", has_tpm ? "Mevcut" : "Algılanmadı");
            it.critical       = false;
            it.score          = CompatScore::FULL;
            it.detail         = has_tpm ? "TPM yongası var — Linux üzerinde tpm2-tools paketiyle yönetilebilir." : "Sistemde TPM donanımı yok.";
            it.recommendation = "TPM, dilerseniz LUKS (Tam Disk Şifreleme) anahtarınızı saklamak ve parolasız otomatik Linux boot işlemi için kullanılabilir.";
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
        it.name           = std::format("Batarya: %{}  |  Güç Kaynağı: {}", pct, on_ac ? "Adaptöre Bağlı" : "Bataryada Çalışıyor");
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = "Dizüstü bilgisayar algılandı. Linux üzerindeki güç yönetimi varsayılan olarak Windows'tan farklı çalışabilir.";
        it.recommendation = "Pil ömrünü iyileştirmek için kurulumdan sonra 'TLP' paketini veya 'power-profiles-daemon' servisini kurmanız önerilir.";
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
        it.name           = std::format("Sanal Makine Algılandı: {}", hv_name);
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = std::format("Hipervizör: {} — Bu uyumluluk taraması sanal bir makinenin içinde yapılıyor.", hv_name);
        it.recommendation = "Elde edilen sonuçlar doğrudan fiziksel bilgisayarınızın uyumluluğunu tam yansıtmayabilir. En doğru sonuç için aracı ana makinenizde (bare metal) çalıştırın.";
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
        it.name           = std::format("Güncel Kararlı Çekirdek (Kernel): {}  (Kaynak: kernel.org)", kernel_ver);
        it.critical       = false;
        it.score          = CompatScore::FULL;
        it.detail         = std::format("Kernel {} şu an piyasadaki en kararlı sürümdür. Analiz, donanımlarınızın genel olarak güncel Linux çekirdek sürücülerine olan uygunluğunu test etti.", kernel_ver);
        it.recommendation = "Donanımlarınızdan tam verim almak için güncel çekirdek sürümlerine sahip (Fedora, Ubuntu LTS gibi) dağıtımları seçmeye özen gösterin.";
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
        printf("%s%s  📋 DETAYLI DONANIM UYUMLULUK RAPORU\n%s", BOLD, WHITE, RESET);
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

        printf("  %s●%s  Tam Uyumlu              : %d bileşen\n",  GREEN,  RESET, report.score_counts[0]);
        printf("  %s◑%s  Uyumlu (Küçük Pürüz)    : %d bileşen\n",  YELLOW, RESET, report.score_counts[1]);
        printf("  %s◔%s  Olası Uyumsuzluk        : %d bileşen\n",  ORANGE, RESET, report.score_counts[2]);
        printf("  %s○%s  Uyumsuz                 : %d bileşen\n",  RED,    RESET, report.score_counts[3]);
        printf("\n  Toplam İncelenen Bileşen : %d\n", static_cast<int>(report.items.size()));

        printf("\n  Genel Uyumluluk Puanı:\n  ");
        Console::print_percent_bar(report.overall_percent, 40);
        printf("\n\n");

        printf("%s%s  🧭 GENEL DEĞERLENDİRME VE SONUÇ\n\n%s", BOLD, WHITE, RESET);
        if (report.overall_percent >= 85.0) {
            printf("%s%s  ✅ Sisteminiz Linux kullanmaya KESİNLİKLE HAZIR!\n%s", GREEN, BOLD, RESET);
            printf("     Ubuntu, Fedora, Mint veya herhangi popüler bir dağıtımı sorunsuz bir şekilde kullanabilirsiniz.\n");
        } else if (report.overall_percent >= 65.0) {
            printf("%s%s  ⚠️  Sisteminiz BÜYÜK ÖLÇÜDE Linux ile uyumlu.\n%s", YELLOW, BOLD, RESET);
            printf("     Kurulum sonrası bazı cihazlar için (Örn: Ağ veya Ekran Kartı) manuel sürücü kurmanız gerekebilir.\n");
            printf("     İşinizi kolaylaştırmak adına kapalı kaynak sürücüleri kendi halleden Ubuntu LTS veya Linux Mint önerilir.\n");
        } else if (report.overall_percent >= 40.0) {
            printf("%s%s  🔶 Uyumluluk durumu ORTA SEVİYEDE.\n%s", ORANGE, BOLD, RESET);
            printf("     Pek çok bileşen çalışmayabilir. İşletim sistemini bilgisayara tam kurmadan önce, USB belleğe yazdırarak 'Canlı (Live) Test' yapmanız şiddetle önerilir.\n");
        } else {
            printf("%s%s  ❌ Sisteminizde çok ciddi uyumsuzluk sorunları mevcut.\n%s", RED, BOLD, RESET);
            printf("     Gündelik kullanım veya iş amaçlı bu cihazı Linux ortamına göç ettirmeniz pek sağlıklı olmayacaktır.\n");
        }

        printf("\n%s%s  🐧 SİZE ÖZEL DAĞITIM (DİSTRO) TAVSİYELERİ\n\n%s", BOLD, WHITE, RESET);
        printf("     1. Ubuntu 24.04 LTS  — En geniş sürücü havuzu ve çok kolay kurulum.\n");
        printf("     2. Linux Mint 22     — Windows arayüzüne çok benzer, Linux'a yeni geçenler için ideal.\n");
        printf("     3. Fedora 40         — Geliştiriciler için son teknoloji Kernel ve iyi NVIDIA desteği.\n");
        printf("     4. Pop!_OS 24.04     — NVIDIA kullananlar ve oyuncular için öncelikli tercih.\n");
        printf("     5. EndeavourOS       — Arch tabanlı, sistemi üzerinde tam kontrol isteyen ileri düzey kullanıcılar için.\n");

        printf("\n%s  🌐 İnternet Durumu: %s%s\n%s", DIM,
               m_online ? GREEN : YELLOW,
               m_online ? "Bağlı — kernel.org verileri canlı olarak çekildi." : "Çevrimdışı — Sadece yerel analiz yapıldı.", RESET);

        printf("\n%s%s════════════════════════════════════════════════════════════════\n%s", CYAN, BOLD, RESET);
        printf("%s  Linux Çekirdeği Uyumluluk Denetleyicisi v2.1  |  linux-hardware.org\n%s", DIM, RESET);
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

inline constexpr std::array<StepMeta, 14> PIPELINE_STEPS{{
    { "Adım  2/14: İşlemci Analiz Ediliyor        ",  8, 30, false },
    { "Adım  3/14: Bellek (RAM) Analiz Ediliyor   ",  6, 25, false },
    { "Adım  4/14: Disk ve Depolama Analizi       ",  7, 35, false },
    { "Adım  5/14: Ekran Kartı (GPU) Taraması     ",  9, 40, false },
    { "Adım  6/14: Ağ Kartı Kontrol Ediliyor      ",  8, 35, false },
    { "Adım  7/14: Ses Kartı Kontrol Ediliyor     ",  6, 30, false },
    { "Adım  8/14: Firmware/UEFI Bios Kontrolü    ",  7, 25, false },
    { "Adım  9/14: Güç ve Batarya Durumu Okunuyor ",  4, 20, false },
    { "Adım 10/14: Sanal Makine / Ortam Kontrolü  ",  4, 20, false },
    { "Adım 11/14: SÜRÜCÜ: Ring-0 PCI Taraması    ",  8, 30, false },  /* Çekirdek sürücüsü kullanılıyor */
    { "Adım 12/14: SÜRÜCÜ: Ring-0 ACPI Verisi     ",  8, 30, false },  /* Çekirdek sürücüsü kullanılıyor */
    { "Adım 13/14: SÜRÜCÜ: MSR İşlemci Register'ı ",  5, 20, false },  /* Çekirdek sürücüsü kullanılıyor */
    { "Adım 14/14: kernel.org Bulut Verisi Akışı  ", 12, 60, true  },
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

    printf("%s  Bilgisayar Adı : %s\n%s", DIM, computer_name, RESET);
    printf("%s  İşletim Sis.   : %s\n%s", DIM, os_name.c_str(), RESET);
    printf("%s  Tarih / Saat   : %02d/%02d/%04d  %02d:%02d\n\n%s", DIM, st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, RESET);

    /* BAĞLANTI ADIMI 1: İnternet */
    printf("%s  Adım  1/14: %sİnternet bağlantısı test ediliyor...\n", CYAN, RESET);
    const bool g_online = Internet::check_connection();
    printf("              %s%s%s\n\n", g_online ? GREEN : YELLOW, g_online ? "✓ Bağlandı" : "✗ Çevrimdışı", RESET);

    /* ÇEKİRDEK SÜRÜCÜ (DRIVER) BAĞLANTISI VE HABERLEŞME TESTİ */
    printf("%s  [SİSTEM]  : %sÖzel Kernel Modu Sürücüsü (LccDriver) Aranıyor...\n", BLUE, RESET);
    HANDLE hDriver = CreateFileA(LCC_USERMODE_PATH, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDriver != INVALID_HANDLE_VALUE) {
        LCC_VERSION_RESULT ver{};
        DWORD retBytes = 0;
        if (DeviceIoControl(hDriver, IOCTL_LCC_GET_VERSION, nullptr, 0, &ver, sizeof(ver), &retBytes, nullptr)) {
            printf("              %s✓ Sürücü Bulundu ve Bağlanıldı. (Versiyon: v%u.%u)%s\n\n", GREEN, ver.driver_version >> 8, ver.driver_version & 0xFF, RESET);
        } else {
            printf("              %s✓ Sürücü dosyası açıldı ancak versiyon doğrulanamadı.%s\n\n", YELLOW, RESET);
        }
    } else {
        printf("              %s✗ Sürücü Bulunamadı. (LccDriver Yüklü Değil) Çekirdek derin analizleri atlanacak.%s\n\n", RED, RESET);
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
            printf("%s  %s — İptal Edildi (Çevrimdışı).\n%s", DIM, meta.label, RESET);
            continue;
        }

        /* Eğer sürücü yoksa Driver (Sürücü) adımlarını simüle edip atlıyoruz */
        if (hDriver == INVALID_HANDLE_VALUE && (i == 9 || i == 10 || i == 11)) {
            printf("%s  %s — İptal Edildi (Sürücü Yok).\n%s", DIM, meta.label, RESET);
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
            fprintf(f, "Linux Çekirdeği Uyumluluk Denetleyicisi v2.1 — Rapor\n");
            fprintf(f, "Bilgisayar Adı : %s\n", computer_name);
            fprintf(f, "İşletim Sist.  : %s\n", os_name.c_str());
            fprintf(f, "Tarih          : %02d/%02d/%04d  %02d:%02d\n\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);

            constexpr const char* score_text[] = {
                "[0] TAM UYUMLU",
                "[1] UYUMLU (küçük pürüz)",
                "[2] OLASI UYUMSUZLUK",
                "[3] UYUMSUZ"
            };
            for (const auto& item : report.items) {
                const int s = static_cast<int>(item.score);
                fprintf(f, "%-26s  %-30s  %s\n", item.category.c_str(), score_text[s], item.name.c_str());
                fprintf(f, "  → %s\n", item.detail.c_str());
                fprintf(f, "  ✦ %s\n\n", item.recommendation.c_str());
            }
            fprintf(f, "Genel Uyumluluk Puanı: %%%.1f\n", report.overall_percent);
            fprintf(f, "Tam Uyumlu: %d | Küçük Pürüzler: %d | Olası Sorun: %d | Uyumsuz: %d\n",
                    report.score_counts[0], report.score_counts[1], report.score_counts[2], report.score_counts[3]);
            fclose(f);
            printf("%s  ✓ Rapor şu dosyaya kaydedildi: %s\n%s", GREEN, save_path.c_str(), RESET);
        } else {
            printf("%s  ✗ Raporu dosyaya kaydetme başarısız: %s\n%s", RED, save_path.c_str(), RESET);
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
