/*
 * Linux Compatibility Checker v2.2  --  SAF SYSCALL sürümü (x64, Windows 10/11)
 * ============================================================================
 *  - ntdll.dll'e IMPORT YOK, ntdll'den hiçbir fonksiyon ÇAĞRILMAZ.
 *  - C runtime / libc / kernel32 YOK. Giriş noktası kendi mainCRTStartup'ımız.
 *  - Çekirdeğe giriş: tek bir elle yazılmış `syscall` trampolini (do_syscall).
 *
 * Syscall numaraları (SSN) Windows build'ine göre değişir. Bu yüzden numaralar
 * sabit yazılmaz; süreç belleğindeki ntdll imajının EXPORT TABLOSU okunur
 * (sadece veri okuma: PEB -> Ldr -> ntdll PE başlığı). Stub'ın `mov eax,SSN`
 * baytları okunur. Güvenilir syscall stub'ı bulunamazsa yanlış SSN tahmin edilmez;
 * program güvenli biçimde durur.
 *
 * Çıktı: PEB->ProcessParameters->StandardOutput üzerine NtWriteFile.
 *   Varsayılan: düz ASCII, renksiz (konsol kod sayfası/VT modunu ayarlamanın
 *   syscall karşılığı yok; conhost özel protokol kullanır).
 *   --ansi : renk kodları    --utf8 : Unicode çizgi/ok karakterleri
 *   (--utf8 için önce terminalde `chcp 65001` yapın)
 *
 * Yönetici yetkisi: manifest/UAC bu modda kullanılamaz (yeni konsol, kernel32
 * olmadan std handle'ları alamaz). YÖNETİCİ olarak açılmış bir terminalden
 * çalıştırın.
 *
 * Kullanım:  linux_compat_checker_syscall.exe [--save rapor.txt] [--ansi] [--utf8] [--pnp]
 *   --pnp : NtPlugPlayControl (belgesiz) ile "takılı olmayan cihaz" filtresi
 *
 * Derleme (MinGW-w64, yalnızca x64):
 *   x86_64-w64-mingw32-gcc -O2 -std=gnu11 -Wall -Wextra -ffreestanding -fno-builtin \
 *     -fno-stack-protector -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns \
 *     -nostdlib -nostartfiles -Wl,-e,mainCRTStartup -Wl,--subsystem,console -Wl,--gc-sections \
 *     linux_compat_checker_syscall.c -o linux_compat_checker_syscall.exe
 *
 * NOT: ARM64 Windows'ta x64 emülasyonu altında ham syscall çalışmaz; yerel x64 gerekir.
 */

#include <stdarg.h>
#include <stddef.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        i8;
typedef int                i32;
typedef long long          i64;
typedef u16                wch;
typedef void*              HANDLE;
typedef i32                NTSTATUS;

#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#define STATUS_PENDING  ((NTSTATUS)0x00000103)
#define STATUS_BUFFER_OVERFLOW  ((NTSTATUS)0x80000005)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define STATUS_NO_SUCH_DEVICE   ((NTSTATUS)0xC000000E)
#define Q(x) ((u64)(size_t)(x))
#define CUR_PROCESS ((HANDLE)(size_t)-1)

/* =====================================================================
 * Minimal libc (derleyici bazen memcpy/memset çağrısı üretir)
 * ===================================================================== */
void* memcpy(void* d, const void* s, size_t n) {
    void* r = d;
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) : : "memory");
    return r;
}
void* memset(void* d, int c, size_t n) {
    void* r = d;
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory");
    return r;
}
void* memmove(void* d, const void* s, size_t n) {
    u8* dd = (u8*)d; const u8* ss = (const u8*)s;
    if (dd == ss || n == 0) return d;
    if ((size_t)dd < (size_t)ss) { for (size_t i = 0; i < n; i++) dd[i] = ss[i]; }
    else                         { for (size_t i = n; i > 0; i--) dd[i - 1] = ss[i - 1]; }
    return d;
}
int memcmp(const void* a, const void* b, size_t n) {
    const u8* x = a; const u8* y = b;
    for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}

static size_t slen(const char* s) { size_t n = 0; while (s[n]) n++; return n; }
static int    seq(const char* a, const char* b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
static char   lc(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

/* 'ci' != 0 ise büyük/küçük harf duyarsız alt dize arama */
static int has(const char* hay, const char* needle, int ci) {
    size_t nl = slen(needle);
    if (nl == 0) return 1;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nl && hay[i] && (ci ? lc(hay[i]) == lc(needle[i]) : hay[i] == needle[i])) i++;
        if (i == nl) return 1;
    }
    return 0;
}
static void scopy(char* d, size_t cap, const char* s) {
    size_t i = 0;
    if (!cap) return;
    while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; }
    d[i] = 0;
}
static void lower_inplace(char* s) { for (; *s; s++) *s = lc(*s); }

static size_t wlen(const wch* s) { size_t n = 0; while (s[n]) n++; return n; }
static void wapp(wch* d, size_t cap, const wch* s) {
    size_t n = wlen(d), i = 0;
    while (s[i] && n + 1 < cap) d[n++] = s[i++];
    d[n] = 0;
}
static void wset(wch* d, size_t cap, const wch* s) { if (cap) d[0] = 0; wapp(d, cap, s); }

/* ---- biçimlendirme: %s %c %d %u %x %% , bayraklar: - 0, genişlik, .kesinlik, l/ll ---- */
static size_t vfmt(char* dst, size_t cap, const char* f, va_list ap) {
    size_t n = 0;
#define PUT(ch) do { if (n + 1 < cap) dst[n] = (ch); n++; } while (0)
    for (; *f; f++) {
        if (*f != '%') { PUT(*f); continue; }
        f++;
        int left = 0, zero = 0, width = 0, prec = -1, lng = 0;
        for (;; f++) { if (*f == '-') left = 1; else if (*f == '0') zero = 1; else break; }
        while (*f >= '0' && *f <= '9') width = width * 10 + (*f++ - '0');
        if (*f == '.') { f++; prec = 0; while (*f >= '0' && *f <= '9') prec = prec * 10 + (*f++ - '0'); }
        while (*f == 'l') { lng++; f++; }
        char tmp[24]; const char* s = tmp; int len = 0;
        switch (*f) {
        case 's': s = va_arg(ap, const char*); if (!s) s = "(null)";
                  while (s[len] && (prec < 0 || len < prec)) { len++; }
                  zero = 0; break;
        case 'c': tmp[0] = (char)va_arg(ap, int); len = 1; zero = 0; break;
        case '%': tmp[0] = '%'; len = 1; zero = 0; break;
        case 'd': case 'u': case 'x': {
            u64 u; int neg = 0;
            if (*f == 'd') {
                i64 v = lng ? va_arg(ap, i64) : (i64)va_arg(ap, int);
                neg = v < 0;
                /* Avoid signed overflow when v == INT64_MIN. */
                u = neg ? (u64)(-(v + 1)) + 1u : (u64)v;
            }
            else           { u = lng ? va_arg(ap, u64) : (u64)va_arg(ap, u32); }
            char rev[24]; int rl = 0; u64 base = (*f == 'x') ? 16 : 10;
            do { int dg = (int)(u % base); rev[rl++] = (char)(dg < 10 ? '0' + dg : 'a' + dg - 10); u /= base; } while (u);
            if (neg) tmp[len++] = '-';
            while (rl) tmp[len++] = rev[--rl];
            break; }
        default: PUT('%'); if (!*f) goto done; PUT(*f); continue;
        }
        int pad = width > len ? width - len : 0;
        if (!left && !zero) while (pad-- > 0) PUT(' ');
        if (!left && zero) {
            int i = 0;
            if (s[0] == '-') { PUT('-'); i = 1; }
            while (pad-- > 0) PUT('0');
            for (; i < len; i++) PUT(s[i]);
        } else {
            for (int i = 0; i < len; i++) PUT(s[i]);
            if (left) while (pad-- > 0) PUT(' ');
        }
    }
done:
    if (cap) dst[n < cap ? n : cap - 1] = 0;
#undef PUT
    return n;
}
static void sfmt(char* dst, size_t cap, const char* f, ...) {
    va_list ap; va_start(ap, f); vfmt(dst, cap, f, ap); va_end(ap);
}

/* =====================================================================
 * NT yapıları
 * ===================================================================== */
typedef struct { u16 Length, MaximumLength; wch* Buffer; } UNICODE_STRING;
typedef struct { u32 Length; HANDLE Root; UNICODE_STRING* Name; u32 Attributes; void* Sd; void* Sqos; } OBJECT_ATTRIBUTES;
typedef struct { union { NTSTATUS Status; void* Ptr; }; u64 Info; } IO_STATUS_BLOCK;
typedef struct { u32 TitleIndex, Type, DataLength; u8 Data[1]; } KVPI;           /* KEY_VALUE_PARTIAL_INFORMATION */
typedef struct { i64 LastWrite; u32 TitleIndex, NameLength; wch Name[1]; } KBI;  /* KEY_BASIC_INFORMATION */
typedef struct { u16 Arch, Level, Revision, MaxProcs; u32 FeatureBits; } SYS_PROC_INFO;
typedef struct { u32 Reserved, TimerRes, PageSize, NumPhys, LowPage, HighPage, AllocGran; u64 MinUser, MaxUser, Affinity; i8 NumProcs; } SYS_BASIC_INFO;
typedef struct { u8 BootId[16]; u32 FirmwareType; u32 pad; u64 BootFlags; } SYS_BOOT_ENV;
typedef struct { u8 Enabled, Capable; } SYS_SECBOOT;
typedef struct { u8 AcOnLine, BatteryPresent, Charging, Discharging, Spare[3], Tag; u32 Max, Remaining, Rate, EstTime, Alert1, Alert2; } SYS_BATTERY;
typedef struct { i64 Total, CallerAvail, ActualAvail; u32 SecPerUnit, BytesPerSec; } FS_FULL_SIZE;
typedef struct { UNICODE_STRING Instance; u32 Operation, Status, Problem; } PNP_STATUS;
typedef struct { u32 Count; u32 pad; struct { u32 Disk; u32 pad; i64 Start, Len; } Ext[4]; } VOL_EXTENTS;
typedef struct { u32 PropertyId, QueryType; u8 Extra[4]; } STOR_QUERY;
typedef struct { u32 Count; struct { u32 LuidLo; i32 LuidHi; u32 Attr; } P[1]; } TOKEN_PRIV1;

/* =====================================================================
 * SAF SYSCALL ALTYAPISI
 * ===================================================================== */
extern NTSTATUS do_syscall(u32 ssn, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,
                           u64 a7, u64 a8, u64 a9, u64 a10, u64 a11);

__asm__(
    ".text\n"
    ".globl do_syscall\n"
    "do_syscall:\n"
    ".intel_syntax noprefix\n"
    "    mov  eax, ecx\n"                 /* SSN */
    "    mov  r10, rdx\n"                 /* arg1 */
    "    mov  rdx, r8\n"                  /* arg2 */
    "    mov  r8,  r9\n"                  /* arg3 */
    "    mov  r9,  [rsp+0x28]\n"          /* arg4 */
    "    sub  rsp, 0x68\n"                /* yeni çerçeve: arg5..arg11 -> [rsp+0x28..0x58] */
    "    mov  r11, [rsp+0x98]\n    mov [rsp+0x28], r11\n"
    "    mov  r11, [rsp+0xA0]\n    mov [rsp+0x30], r11\n"
    "    mov  r11, [rsp+0xA8]\n    mov [rsp+0x38], r11\n"
    "    mov  r11, [rsp+0xB0]\n    mov [rsp+0x40], r11\n"
    "    mov  r11, [rsp+0xB8]\n    mov [rsp+0x48], r11\n"
    "    mov  r11, [rsp+0xC0]\n    mov [rsp+0x50], r11\n"
    "    mov  r11, [rsp+0xC8]\n    mov [rsp+0x58], r11\n"
#ifndef FORCE_SYSCALL_INSN               /* -DFORCE_SYSCALL_INSN: SystemCall bayt kontrolünü atla (yalnız Wine testi için) */
    "    mov  r11d, 0x7FFE0308\n"         /* KUSER_SHARED_DATA.SystemCall (ntdll stub'larıyla aynı kontrol) */
    "    test byte ptr [r11], 1\n"
    "    jne  1f\n"
#endif
    "    syscall\n"
    "    add  rsp, 0x68\n"
    "    ret\n"
    "1:  int  0x2e\n"
    "    add  rsp, 0x68\n"
    "    ret\n"
    ".att_syntax prefix\n"
    /* libgcc'nin ___chkstk_ms eşdeğeri: büyük yığın çerçevelerinde sayfa sayfa dokunur */
    ".globl ___chkstk_ms\n"
    "___chkstk_ms:\n"
    ".intel_syntax noprefix\n"
    "    push rcx\n"
    "    push rax\n"
    "    cmp  rax, 0x1000\n"
    "    lea  rcx, [rsp+24]\n"
    "    jb   3f\n"
    "2:  sub  rcx, 0x1000\n"
    "    test [rcx], rcx\n"
    "    sub  rax, 0x1000\n"
    "    cmp  rax, 0x1000\n"
    "    ja   2b\n"
    "3:  sub  rcx, rax\n"
    "    test [rcx], rcx\n"
    "    pop  rax\n"
    "    pop  rcx\n"
    "    ret\n"
    ".att_syntax prefix\n"
);

enum { SC_Close, SC_OpenKey, SC_QueryValueKey, SC_EnumerateKey, SC_CreateFile, SC_ReadFile, SC_WriteFile,
       SC_DeviceIoControlFile, SC_QueryVolumeInformationFile, SC_QuerySystemInformation, SC_DelayExecution,
       SC_PowerInformation, SC_OpenProcessToken, SC_QueryInformationToken, SC_WaitForSingleObject,
       SC_PlugPlayControl, SC_TerminateProcess, SC_AdjustPrivilegesToken, SC_COUNT };

static const char* const g_sc_names[SC_COUNT] = {
    "NtClose", "NtOpenKey", "NtQueryValueKey", "NtEnumerateKey", "NtCreateFile", "NtReadFile", "NtWriteFile",
    "NtDeviceIoControlFile", "NtQueryVolumeInformationFile", "NtQuerySystemInformation", "NtDelayExecution",
    "NtPowerInformation", "NtOpenProcessToken", "NtQueryInformationToken", "NtWaitForSingleObject",
    "NtPlugPlayControl", "NtTerminateProcess", "NtAdjustPrivilegesToken" };
static u32 g_ssn[SC_COUNT];

static NTSTATUS sys_impl(int id, int nargs, const u64* args) {
    u64 a[11] = {0};
    if (id < 0 || id >= SC_COUNT || nargs < 0 || nargs > 11 || (!args && nargs != 0))
        return (NTSTATUS)0xC000000D; /* STATUS_INVALID_PARAMETER */
    for (int i = 0; i < nargs; i++) a[i] = args[i];
    return do_syscall(g_ssn[id], a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]);
}
/* Each variadic argument is converted to u64 before it is read; this avoids
   va_arg type mismatches for integer literals and 32-bit ULONG arguments. */
#define sys(id, nargs, ...) sys_impl((id), (nargs), (const u64[]){ __VA_ARGS__ })

static u8* get_peb(void) { u8* p; __asm__("mov %%gs:0x60, %0" : "=r"(p)); return p; }

/* ---- ntdll imajı: yalnızca export tablosu OKUNUR ---- */
static const u8* g_nt_base;
static u32 g_exp_rva, g_exp_size, g_n_names;
static const u32 *g_funcs, *g_names; static const u16* g_ords;

static int find_ntdll(void) {
    u8* peb = get_peb();
    u8* ldr = *(u8**)(peb + 0x18);
    u8* head = ldr + 0x20;                              /* InMemoryOrderModuleList */
    for (u8* l = *(u8**)head; l && l != head; l = *(u8**)l) {
        u8* e = l - 0x10;                               /* LDR_DATA_TABLE_ENTRY */
        UNICODE_STRING* nm = (UNICODE_STRING*)(e + 0x58);   /* BaseDllName */
        static const char want[] = "ntdll.dll";
        if (nm->Length == 9 * 2) {
            int ok = 1;
            for (int i = 0; i < 9; i++) { wch c = nm->Buffer[i]; if (c >= 'A' && c <= 'Z') c = (wch)(c + 32); if (c != (wch)want[i]) { ok = 0; break; } }
            if (ok) { g_nt_base = *(const u8**)(e + 0x30); break; }
        }
    }
    if (!g_nt_base) return 0;
    const u8* nt = g_nt_base + *(const u32*)(g_nt_base + 0x3C);
    if (*(const u16*)(nt + 24) != 0x20B) return 0;      /* PE32+ */
    g_exp_rva  = *(const u32*)(nt + 24 + 0x70);
    g_exp_size = *(const u32*)(nt + 24 + 0x74);
    if (!g_exp_rva) return 0;
    const u8* ex = g_nt_base + g_exp_rva;
    g_n_names = *(const u32*)(ex + 0x18);
    g_funcs = (const u32*)(g_nt_base + *(const u32*)(ex + 0x1C));
    g_names = (const u32*)(g_nt_base + *(const u32*)(ex + 0x20));
    g_ords  = (const u16*)(g_nt_base + *(const u32*)(ex + 0x24));
    return 1;
}

static int find_export(const char* name, u32* rva_out) {
    for (u32 i = 0; i < g_n_names; i++) {
        if (seq((const char*)(g_nt_base + g_names[i]), name)) {
            u32 rva = g_funcs[g_ords[i]];
            if (rva >= g_exp_rva && rva < g_exp_rva + g_exp_size) return 0;   /* forwarder */
            *rva_out = rva; return 1;
        }
    }
    return 0;
}

static long ssn_from_stub(u32 rva) {
    const u8* p = g_nt_base + rva;
    /* Canonical x64 NT syscall stub: mov r10,rcx ; mov eax,SSN. */
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        u32 ssn = *(const u32*)(p + 4);
        if (ssn < 0x2000) return (long)ssn;
    }
    return -1;
}

static long resolve_ssn(const char* nt_name) {
    u32 rva;
    if (find_export(nt_name, &rva)) {
        long ssn = ssn_from_stub(rva);
        if (ssn >= 0) return ssn;
    }
    /* Try the Zw alias only if it independently contains a canonical stub.
       Export-address ranking is not reliable on every Windows build; guessing
       an SSN could invoke an unrelated kernel service with the wrong arguments. */
    char zn[64]; zn[0] = 'Z'; zn[1] = 'w'; scopy(zn + 2, sizeof zn - 2, nt_name + 2);
    if (find_export(zn, &rva)) return ssn_from_stub(rva);
    return -1;
}

/* ---- tipli sarmalayıcılar ---- */
static NTSTATUS NtClose_(HANDLE h) { return sys(SC_Close, 1, Q(h)); }
static void     terminate(u32 code) { sys(SC_TerminateProcess, 2, Q(CUR_PROCESS), (u64)code); for (;;) {} }

/* =====================================================================
 * Süreç parametreleri / KUSER_SHARED_DATA
 * ===================================================================== */
static u8* g_params;
static HANDLE std_in(void)  { return *(HANDLE*)(g_params + 0x20); }
static HANDLE std_out(void) { return *(HANDLE*)(g_params + 0x28); }
static const volatile u8* kuser(void) { return (const volatile u8*)(size_t)0x7FFE0000; }
static int proc_feature(unsigned id) { return id < 64 && kuser()[0x274 + id] != 0; }

static i64 read_ksystem_time(unsigned off) {
    const volatile u8* b = kuser() + off;
    for (;;) {
        i32 hi = *(const volatile i32*)(b + 4);
        u32 lo = *(const volatile u32*)(b);
        if (*(const volatile i32*)(b + 8) == hi)
            return (i64)(((u64)(u32)hi << 32) | (u64)lo);
    }
}

static int handle_ok(HANDLE h) { return h && h != (HANDLE)(size_t)-1; }

/* =====================================================================
 * Çıktı / girdi (NtWriteFile / NtReadFile)
 * ===================================================================== */
static char   g_out[65536]; static size_t g_outn;
static int    g_out_ok = 1;                  /* stdout çalışmıyorsa 0 */
static char   g_rep[65536]; static size_t g_repn;

static int write_all(HANDLE h, const char* d, size_t n) {
    while (n) {
        size_t c = n > 32768 ? 32768 : n;
        while (c < n && c > 1 && ((u8)d[c] & 0xC0) == 0x80) c--;     /* UTF-8 ortasından kesme */
        IO_STATUS_BLOCK io; memset(&io, 0, sizeof io);
        NTSTATUS st = sys(SC_WriteFile, 9, Q(h), 0, 0, 0, Q(&io), Q(d), (u64)c, 0, 0);
        if (st == STATUS_PENDING) { sys(SC_WaitForSingleObject, 3, Q(h), 0, 0); st = io.Status; }
        if (!NT_SUCCESS(st)) return 0;
        size_t w = (size_t)io.Info;
        if (w == 0 || w > c) return 0;
        d += w; n -= w;
    }
    return 1;
}
static void out_flush(void) {
    if (!g_outn) return;
    if (g_out_ok) {
        HANDLE h = std_out();
        if (!handle_ok(h) || !write_all(h, g_out, g_outn)) g_out_ok = 0;
    }
    g_outn = 0;
}
static void outf(const char* f, ...) {
    static char tmp[4096];
    va_list ap; va_start(ap, f);
    size_t n = vfmt(tmp, sizeof tmp, f, ap);
    va_end(ap);
    if (n >= sizeof tmp) n = sizeof tmp - 1;
    if (g_outn + n > sizeof g_out) out_flush();
    memcpy(g_out + g_outn, tmp, n); g_outn += n;
    if (g_outn > 16384) out_flush();
}
static void repf(const char* f, ...) {
    static char tmp[4096];
    va_list ap; va_start(ap, f);
    size_t n = vfmt(tmp, sizeof tmp, f, ap);
    va_end(ap);
    if (n >= sizeof tmp) n = sizeof tmp - 1;
    if (g_repn + n >= sizeof g_rep) return;
    memcpy(g_rep + g_repn, tmp, n); g_repn += n;
}
static void wait_enter(void) {
    out_flush();
    HANDLE h = std_in();
    if (!handle_ok(h) || !g_out_ok) return;
    char line[256]; IO_STATUS_BLOCK io; memset(&io, 0, sizeof io);
    NTSTATUS st = sys(SC_ReadFile, 9, Q(h), 0, 0, 0, Q(&io), Q(line), (u64)sizeof line, 0, 0);
    if (st == STATUS_PENDING) sys(SC_WaitForSingleObject, 3, Q(h), 0, 0);
}
static void sleep_ms(unsigned ms) { i64 iv = -(i64)ms * 10000; sys(SC_DelayExecution, 2, 0, Q(&iv)); }

/* ---- UTF-16 -> UTF-8 ---- */
static size_t u16_to_u8(const wch* s, size_t n, char* d, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00); i++;
        }
        char b[4]; int l;
        if (c < 0x80)        { b[0] = (char)c; l = 1; }
        else if (c < 0x800)  { b[0] = (char)(0xC0 | (c >> 6)); b[1] = (char)(0x80 | (c & 63)); l = 2; }
        else if (c < 0x10000){ b[0] = (char)(0xE0 | (c >> 12)); b[1] = (char)(0x80 | ((c >> 6) & 63)); b[2] = (char)(0x80 | (c & 63)); l = 3; }
        else                 { b[0] = (char)(0xF0 | (c >> 18)); b[1] = (char)(0x80 | ((c >> 12) & 63)); b[2] = (char)(0x80 | ((c >> 6) & 63)); b[3] = (char)(0x80 | (c & 63)); l = 4; }
        if (o + (size_t)l + 1 > cap) break;
        for (int k = 0; k < l; k++) d[o++] = b[k];
    }
    if (cap) d[o] = 0;
    return o;
}

/* =====================================================================
 * Registry (NtOpenKey / NtQueryValueKey / NtEnumerateKey)
 * ===================================================================== */
static void us_init(UNICODE_STRING* u, const wch* s, size_t n) {
    u->Length = (u16)(n * 2); u->MaximumLength = u->Length; u->Buffer = (wch*)s;
}
static HANDLE reg_open(const wch* path) {
    UNICODE_STRING us; us_init(&us, path, wlen(path));
    OBJECT_ATTRIBUTES oa = { sizeof oa, 0, &us, 0x40, 0, 0 };
    HANDLE h = 0;
    NTSTATUS st = sys(SC_OpenKey, 3, Q(&h), 0x20119 /* KEY_READ | KEY_WOW64_64KEY */, Q(&oa));
    return NT_SUCCESS(st) ? h : 0;
}
static u8 g_vbuf[8192];
static int reg_value(HANDLE k, const wch* name, u32* type, const u8** data, u32* len) {
    UNICODE_STRING n; us_init(&n, name, wlen(name));
    u32 ret = 0;
    NTSTATUS st = sys(SC_QueryValueKey, 6, Q(k), Q(&n), 2, Q(g_vbuf), (u64)sizeof g_vbuf, Q(&ret));
    if (!NT_SUCCESS(st) || ret < 12) return 0;
    const KVPI* p = (const KVPI*)g_vbuf;
    if (p->DataLength > ret - 12) return 0;
    *type = p->Type; *data = g_vbuf + 12; *len = p->DataLength;
    return 1;
}
static int reg_str(HANDLE k, const wch* name, char* out, size_t cap) {
    u32 type, len; const u8* d;
    if (cap) out[0] = 0;
    if (!reg_value(k, name, &type, &d, &len)) return 0;
    if (type != 1 && type != 2 && type != 7) return 0;
    const wch* w = (const wch*)d; size_t n = 0, max = len / 2;
    while (n < max && w[n]) n++;
    u16_to_u8(w, n, out, cap);
    return 1;
}
static int reg_dword(HANDLE k, const wch* name, u32* v) {
    u32 type, len; const u8* d;
    if (!reg_value(k, name, &type, &d, &len) || type != 4 || len != 4) return 0;
    memcpy(v, d, 4); return 1;
}
static int reg_enum(HANDLE k, u32 idx, wch* out, size_t cap) {
    static u8 buf[1024];
    u32 ret = 0;
    NTSTATUS st = sys(SC_EnumerateKey, 6, Q(k), idx, 0, Q(buf), (u64)sizeof buf, Q(&ret));
    if (!NT_SUCCESS(st) || ret < 16) return 0;
    const KBI* ki = (const KBI*)buf;
    size_t n = ki->NameLength / 2;
    if (ki->NameLength > ret - 16 || n + 1 > cap) return 0;
    memcpy(out, buf + 16, n * 2); out[n] = 0;
    return 1;
}
/* yol + değer adı ile tek seferlik okuma */
static int reg_path_str(const wch* path, const wch* val, char* out, size_t cap) {
    HANDLE k = reg_open(path); if (!k) { if (cap) out[0] = 0; return 0; }
    int ok = reg_str(k, val, out, cap); NtClose_(k); return ok;
}
static int reg_path_dword(const wch* path, const wch* val, u32* v) {
    HANDLE k = reg_open(path); if (!k) return 0;
    int ok = reg_dword(k, val, v); NtClose_(k); return ok;
}

/* =====================================================================
 * Dosya / aygıt yardımcıları
 * ===================================================================== */
static HANDLE open_nt(const wch* path, u32 access, u32 share, u32 options, u32 disposition) {
    UNICODE_STRING us; us_init(&us, path, wlen(path));
    OBJECT_ATTRIBUTES oa = { sizeof oa, 0, &us, 0x40, 0, 0 };
    IO_STATUS_BLOCK io; memset(&io, 0, sizeof io);
    HANDLE h = 0;
    NTSTATUS st = sys(SC_CreateFile, 11, Q(&h), access, Q(&oa), Q(&io), 0, 0x80, share, disposition, options, 0, 0);
    return NT_SUCCESS(st) ? h : 0;
}
static int ioctl_(HANDLE h, u32 code, void* in, u32 inl, void* out, u32 outl) {
    IO_STATUS_BLOCK io; memset(&io, 0, sizeof io);
    NTSTATUS st = sys(SC_DeviceIoControlFile, 10, Q(h), 0, 0, 0, Q(&io), code, Q(in), inl, Q(out), outl);
    if (st == STATUS_PENDING) { sys(SC_WaitForSingleObject, 3, Q(h), 0, 0); st = io.Status; }
    return NT_SUCCESS(st);
}
static NTSTATUS query_sysinfo(u32 cls, void* buf, u32 len) {
    u32 ret = 0; return sys(SC_QuerySystemInformation, 4, cls, Q(buf), len, Q(&ret));
}

/* =====================================================================
 * Arayüz bayrakları / renkler / glifler
 * ===================================================================== */
static int g_ansi, g_utf8, g_pnp;
static const char *cR = "", *cB = "", *cD = "", *cRed = "", *cGrn = "", *cYel = "", *cBlu = "", *cCyn = "", *cWht = "", *cOrg = "";
static const char *G_HR = "=", *G_BAR_ON = "#", *G_BAR_OFF = "-", *G_V = "|", *G_ARROW = "->", *G_STAR = "*", *G_TOP = "+-";

static void ui_init(void) {
    if (g_ansi) {
        cR = "\033[0m"; cB = "\033[1m"; cD = "\033[2m"; cRed = "\033[91m"; cGrn = "\033[92m"; cYel = "\033[93m";
        cBlu = "\033[94m"; cCyn = "\033[96m"; cWht = "\033[97m"; cOrg = "\033[38;5;208m";
    }
    if (g_utf8) {
        G_HR = "\xE2\x95\x90"; G_BAR_ON = "\xE2\x96\x88"; G_BAR_OFF = "\xE2\x96\x91";
        G_V = "\xE2\x94\x82"; G_ARROW = "\xE2\x86\x92"; G_STAR = "\xE2\x9C\xA6"; G_TOP = "\xE2\x94\x8C\xE2\x94\x80";
    }
}
static void out_hr(void) { for (int i = 0; i < 64; i++) outf("%s", G_HR); outf("\n"); }

/* =====================================================================
 * Rapor veri modeli
 * ===================================================================== */
enum { C_CPU, C_RAM, C_DISK, C_GPU, C_NET, C_AUDIO, C_FW, C_SB, C_TPM, C_POWER, C_VIRT, C_COUNT };
static const char* const CAT[C_COUNT] = { "CPU", "Memory (RAM)", "Storage (Disk)", "Graphics (GPU)", "Networking",
                                          "Audio", "Firmware", "Secure Boot", "TPM", "Power / Battery", "Virtualization" };
enum { S_FULL = 0, S_MINOR = 1, S_MAYBE = 2, S_NONE = 3 };

typedef struct { u8 cat, score, critical; char name[200]; char detail[480]; char rec[360]; } Item;
#define MAX_ITEMS 128
static Item g_items[MAX_ITEMS]; static int g_nitems;
static int g_counts[4]; static u32 g_pct10;

static Item* new_item(int cat, int score, int critical) {
    if (g_nitems >= MAX_ITEMS) return 0;
    Item* it = &g_items[g_nitems++];
    memset(it, 0, sizeof *it);
    it->cat = (u8)cat; it->score = (u8)score; it->critical = (u8)critical;
    return it;
}

static void compute(void) {
    u64 num = 0, den = 0;
    for (int i = 0; i < 4; i++) g_counts[i] = 0;
    for (int i = 0; i < g_nitems; i++) {
        int s = g_items[i].score; if (s < 0 || s > 3) continue;
        g_counts[s]++;
        u64 w = g_items[i].critical ? 2 : 1;
        num += (u64)(3 - s) * w; den += 3 * w;
    }
    g_pct10 = den ? (u32)(num * 1000 / den) : 0;           /* yüzde x 10 */
}

/* =====================================================================
 * Cihaz listesi: HKLM\SYSTEM\CurrentControlSet\Enum ağacı
 * ===================================================================== */
#define CLS_DISPLAY "{4d36e968-e325-11ce-bfc1-08002be10318}"
#define CLS_NET     "{4d36e972-e325-11ce-bfc1-08002be10318}"
#define CLS_MEDIA   "{4d36e96c-e325-11ce-bfc1-08002be10318}"
typedef struct { char cls[48]; char name[140]; char hw[100]; } Device;
#define MAX_DEV 160
static Device g_dev[MAX_DEV]; static int g_ndev; static int g_dev_ok = -1; static int g_has_tpm;

static int pnp_present(const wch* rel) {
    if (!g_pnp) return 1;
    PNP_STATUS d; memset(&d, 0, sizeof d);
    us_init(&d.Instance, rel, wlen(rel));
    NTSTATUS st = sys(SC_PlugPlayControl, 3, 14 /* PlugPlayControlDeviceStatus */, Q(&d), (u64)sizeof d);
    if (st == STATUS_NO_SUCH_DEVICE) return 0;
    if (NT_SUCCESS(st) && d.Problem == 45) return 0;       /* CM_PROB_PHANTOM */
    return 1;
}
static void enable_tcb_privilege(void) {
    HANDLE tok = 0;
    if (!NT_SUCCESS(sys(SC_OpenProcessToken, 3, Q(CUR_PROCESS), 0x28 /* ADJUST|QUERY */, Q(&tok)))) return;
    TOKEN_PRIV1 tp; tp.Count = 1; tp.P[0].LuidLo = 7; tp.P[0].LuidHi = 0; tp.P[0].Attr = 2; /* SeTcbPrivilege */
    sys(SC_AdjustPrivilegesToken, 6, Q(tok), 0, Q(&tp), (u64)sizeof tp, 0, 0);
    NtClose_(tok);
}
static void resolve_desc(char* d) {                          /* "@oem.inf,%x%;Gerçek Ad" -> "Gerçek Ad" */
    if (d[0] != '@') return;
    char* semi = 0; for (char* p = d; *p; p++) if (*p == ';') semi = p;
    if (semi) { size_t n = slen(semi + 1); memmove(d, semi + 1, n + 1); }
}
static void scan_devices(void) {
    if (g_dev_ok != -1) return;
    g_dev_ok = 0;
    static const wch ROOT[] = u"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum";
    HANDLE kroot = reg_open(ROOT);
    if (!kroot) return;
    if (g_pnp) enable_tcb_privilege();
    static wch bus[260], dev[260], inst[260], p1[800], p2[800], p3[800], rel[800];
    for (u32 bi = 0; reg_enum(kroot, bi, bus, 260); bi++) {
        wset(p1, 800, ROOT); wapp(p1, 800, u"\\"); wapp(p1, 800, bus);
        HANDLE kb = reg_open(p1); if (!kb) continue;
        for (u32 di = 0; reg_enum(kb, di, dev, 260); di++) {
            wset(p2, 800, p1); wapp(p2, 800, u"\\"); wapp(p2, 800, dev);
            HANDLE kd = reg_open(p2); if (!kd) continue;
            for (u32 ii = 0; reg_enum(kd, ii, inst, 260); ii++) {
                wset(p3, 800, p2); wapp(p3, 800, u"\\"); wapp(p3, 800, inst);
                HANDLE ki = reg_open(p3); if (!ki) continue;

                char desc[200], cls[64], hw[140];
                if (reg_str(ki, u"DeviceDesc", desc, sizeof desc)) {
                    wset(rel, 800, bus); wapp(rel, 800, u"\\"); wapp(rel, 800, dev); wapp(rel, 800, u"\\"); wapp(rel, 800, inst);
                    reg_str(ki, u"ClassGUID", cls, sizeof cls); lower_inplace(cls);
                    reg_str(ki, u"HardwareID", hw, sizeof hw);
                    resolve_desc(desc);
                    int interesting = seq(cls, CLS_DISPLAY) || seq(cls, CLS_NET) || seq(cls, CLS_MEDIA);
                    int tpm = has(hw, "MSFT0101", 1) || has(hw, "MSFT0200", 1) ||
                              has(desc, "Trusted Platform Module", 1) || has(desc, "TPM", 0);
                    if ((interesting || tpm) && pnp_present(rel)) {
                        if (tpm) g_has_tpm = 1;
                        if (interesting && g_ndev < MAX_DEV) {
                            Device* d = &g_dev[g_ndev++];
                            scopy(d->cls, sizeof d->cls, cls); scopy(d->name, sizeof d->name, desc); scopy(d->hw, sizeof d->hw, hw);
                        }
                    }
                }
                NtClose_(ki);
            }
            NtClose_(kd);
        }
        NtClose_(kb);
    }
    NtClose_(kroot);
    g_dev_ok = 1;
}

/* =====================================================================
 * Analizörler
 * ===================================================================== */
static const char* arch_name(u16 a) {
    switch (a) { case 0: return "x86"; case 9: return "x86-64"; case 5: return "ARM32"; case 12: return "ARM64"; case 6: return "IA-64"; default: return "Unknown"; }
}

static void analyze_cpu(void) {
    static const wch CPU0[] = u"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    char pname[128], vendor[64], ident[128];
    reg_path_str(CPU0, u"ProcessorNameString", pname, sizeof pname);
    reg_path_str(CPU0, u"VendorIdentifier", vendor, sizeof vendor);
    reg_path_str(CPU0, u"Identifier", ident, sizeof ident);

    SYS_PROC_INFO spi; memset(&spi, 0, sizeof spi);
    int have_arch = NT_SUCCESS(query_sysinfo(1, &spi, sizeof spi));
    u16 arch = have_arch ? spi.Arch : 0xFFFF;

    u32 cores = *(const volatile u32*)(kuser() + 0x3C0);                 /* ActiveProcessorCount */
    if (cores == 0) { SYS_BASIC_INFO sb; memset(&sb, 0, sizeof sb); if (NT_SUCCESS(query_sysinfo(0, &sb, sizeof sb)) && sb.NumProcs > 0) cores = (u32)sb.NumProcs; }

    Item* it = new_item(C_CPU, S_FULL, 1); if (!it) return;
    scopy(it->name, sizeof it->name, pname[0] ? pname : (vendor[0] ? vendor : arch_name(arch)));

    if (arch == 0 || arch == 9) {
        sfmt(it->detail, sizeof it->detail, "%s | Vendor: %s | %u logical cores | SSE2:%s  AVX:%s  AVX2:%s  HW virtualization:%s%s%s",
             pname[0] ? pname : "x86 CPU", vendor[0] ? vendor : "unknown", cores,
             proc_feature(10) ? "Yes" : "No", proc_feature(39) ? "Yes" : "No", proc_feature(40) ? "Yes" : "No",
             proc_feature(21) ? "Available" : "Not reported", ident[0] ? " | Identifier: " : "", ident);
        scopy(it->rec, sizeof it->rec, "Excellent Linux support. Any mainstream x86-64 distribution should work well.");
    } else if (arch == 5 || arch == 12) {
        sfmt(it->detail, sizeof it->detail, "%s | Vendor: %s | %u logical cores | ARMv8:%s  Crypto:%s  CRC32:%s  SVE:%s",
             pname[0] ? pname : "ARM CPU", vendor[0] ? vendor : "unknown", cores,
             proc_feature(29) ? "Yes" : "No", proc_feature(30) ? "Yes" : "No", proc_feature(31) ? "Yes" : "No", proc_feature(46) ? "Yes" : "No");
        scopy(it->rec, sizeof it->rec, "ARM Linux is supported, but package and driver availability depends on the exact SoC/device.");
    } else {
        it->score = S_MAYBE;
        sfmt(it->detail, sizeof it->detail, "Architecture: %s | Vendor: %s | %u logical cores", arch_name(arch), vendor[0] ? vendor : "unknown", cores);
        scopy(it->rec, sizeof it->rec, "This CPU architecture is not specifically covered. Verify Linux kernel and distribution support.");
    }
}

static void analyze_ram(void) {
    SYS_BASIC_INFO sb; memset(&sb, 0, sizeof sb);
    NTSTATUS st = query_sysinfo(0, &sb, sizeof sb);
    Item* it = new_item(C_RAM, S_FULL, 1); if (!it) return;
    if (!NT_SUCCESS(st) || sb.PageSize == 0 || sb.NumPhys == 0) {
        it->score = S_MAYBE;
        scopy(it->name, sizeof it->name, "System memory: unknown");
        scopy(it->detail, sizeof it->detail, "Physical memory could not be queried through NtQuerySystemInformation.");
        scopy(it->rec, sizeof it->rec, "Verify the system information query and check the installed RAM in Windows System Information.");
        return;
    }
    u64 mb = (u64)sb.NumPhys * sb.PageSize / (1024ULL * 1024);
    u64 gb = mb / 1024;
    sfmt(it->name, sizeof it->name, "System memory: %llu MB (%llu GB)", mb, gb);
    if (mb < 2048) {
        it->score = S_NONE;
        sfmt(it->detail, sizeof it->detail, "Only %llu MB of RAM detected; Linux desktops generally need at least 1-2 GB.", mb);
        scopy(it->rec, sizeof it->rec, "At least 4 GB is recommended. Try very light distributions such as Lubuntu, Xubuntu or Alpine Linux.");
    } else if (mb < 4096) {
        it->score = S_MINOR;
        sfmt(it->detail, sizeof it->detail, "%llu MB of RAM; enough for basic desktop use.", mb);
        scopy(it->rec, sizeof it->rec, "Prefer distributions with light desktops such as Xfce, LXQt or MATE.");
    } else {
        sfmt(it->detail, sizeof it->detail, "%llu MB (%llu GB) of RAM; excellent for desktop workloads.", mb, gb);
        scopy(it->rec, sizeof it->rec, "You should be able to run desktop environments such as GNOME or KDE Plasma and use virtual machines comfortably.");
    }
}

static void analyze_storage(void) {
    wch letter = (wch)'C';
    { const volatile wch* root = (const volatile wch*)(kuser() + 0x30);    /* NtSystemRoot: "C:\WINDOWS" */
      wch c = root[0]; if (root[1] == ':' && ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) letter = c; }

    u64 total = 0, freeb = 0; int space_ok = 0;
    wch path[40] = u"\\??\\X:\\"; path[4] = letter;
    HANDLE h = open_nt(path, 0x80 | 0x100000, 7, 0x01 | 0x20, 1);        /* kök dizin */
    if (h) {
        IO_STATUS_BLOCK io; memset(&io, 0, sizeof io); FS_FULL_SIZE fs; memset(&fs, 0, sizeof fs);
        if (NT_SUCCESS(sys(SC_QueryVolumeInformationFile, 5, Q(h), Q(&io), Q(&fs), (u64)sizeof fs, 7 /* FileFsFullSizeInformation */))) {
            u64 unit = (u64)fs.SecPerUnit * fs.BytesPerSec;
            total = (u64)fs.Total * unit; freeb = (u64)fs.CallerAvail * unit; space_ok = 1;
        }
        NtClose_(h);
    }
    u64 total_gb = total >> 30, free_gb = freeb >> 30;

    int is_ssd = 0, is_nvme = 0, class_known = 0, phys_known = 0; u32 phys = 0;
    wch vol[40] = u"\\??\\X:"; vol[4] = letter;
    HANDLE hv = open_nt(vol, 0x80 | 0x100000, 7, 0x20, 1);
    if (hv) {
        VOL_EXTENTS ve; memset(&ve, 0, sizeof ve);
        if (ioctl_(hv, 0x00560000 /* IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS */, 0, 0, &ve, sizeof ve) && ve.Count > 0) { phys = ve.Ext[0].Disk; phys_known = 1; }
        NtClose_(hv);
    }
    if (phys_known) {
        wch dp[48] = u"\\??\\PhysicalDrive"; size_t n = wlen(dp);
        char num[12]; sfmt(num, sizeof num, "%u", phys);
        for (int i = 0; num[i]; i++) dp[n++] = (wch)num[i];
        dp[n] = 0;
        HANDLE hd = open_nt(dp, 0x80 | 0x100000, 7, 0x20, 1);
        if (hd) {
            STOR_QUERY q; memset(&q, 0, sizeof q); u8 seek[16]; memset(seek, 0, sizeof seek);
            q.PropertyId = 7; q.QueryType = 0;                           /* SeekPenalty / StandardQuery */
            if (ioctl_(hd, 0x002D1400, &q, sizeof q, seek, sizeof seek)) { is_ssd = (seek[8] == 0); class_known = 1; }
            static u8 desc[1024]; memset(desc, 0, sizeof desc); memset(&q, 0, sizeof q);
            if (ioctl_(hd, 0x002D1400, &q, sizeof q, desc, sizeof desc)) is_nvme = (*(u32*)(desc + 28) == 0x11);
            NtClose_(hd);
        }
    }
    const char* dt = is_nvme ? "NVMe SSD" : is_ssd ? "SSD" : class_known ? "HDD" : "storage type unknown";

    Item* it = new_item(C_DISK, S_FULL, 1); if (!it) return;
    sfmt(it->name, sizeof it->name, "System drive: %llu GB total / %llu GB free [%s]", total_gb, free_gb, dt);
    if (!space_ok) {
        it->score = S_MAYBE;
        scopy(it->detail, sizeof it->detail, "Free space on the system drive could not be read via NtQueryVolumeInformationFile.");
        scopy(it->rec, sizeof it->rec, "Make sure the Windows system drive is accessible and run the tool as Administrator.");
    } else if (free_gb < 20) {
        it->score = S_NONE;
        sfmt(it->detail, sizeof it->detail, "%llu GB free; a Linux installation generally needs at least 20 GB.", free_gb);
        scopy(it->rec, sizeof it->rec, "Free up space on the system drive or use a different disk/partition for the installation.");
    } else if (free_gb < 50) {
        it->score = S_MINOR;
        sfmt(it->detail, sizeof it->detail, "%llu GB free; installation is possible but storage is tight.", free_gb);
        scopy(it->rec, sizeof it->rec, "Reserve 50+ GB for a comfortable experience with games and applications.");
    } else {
        sfmt(it->detail, sizeof it->detail, "%llu GB free; there is ample space for Linux and your data.", free_gb);
        scopy(it->rec, sizeof it->rec, is_nvme ? "An NVMe SSD makes Linux very fast. Ext4 or Btrfs are good filesystem choices."
                                      : is_ssd ? "An SSD should provide fast startup. Ext4 is a suitable filesystem choice."
                                               : "Linux may feel slower on a mechanical disk. Configure a generous swap area.");
    }
}

static void analyze_gpu(void) {
    scan_devices();
    int n = 0;
    for (int i = 0; i < g_ndev; i++) {
        if (!seq(g_dev[i].cls, CLS_DISPLAY)) continue;
        const char* nm = g_dev[i].name;
        Item* it = new_item(C_GPU, S_MAYBE, 1); if (!it) return; n++;
        scopy(it->name, sizeof it->name, nm);
        int nv = has(nm, "NVIDIA", 1) || has(nm, "GeForce", 1) || has(nm, "Quadro", 1) || has(nm, "RTX", 0) || has(nm, "GTX", 0);
        int amd = has(nm, "AMD", 0) || has(nm, "Radeon", 1) || has(nm, "RX ", 0);
        int intel = has(nm, "Intel", 1) || has(nm, "UHD", 0) || has(nm, "Iris", 1) || has(nm, "Arc", 0);
        int virt = has(nm, "VMware", 1) || has(nm, "VirtualBox", 1) || has(nm, "Microsoft Basic Render", 1) || has(nm, "SVGA", 0);
        if (nv) { it->score = S_MINOR; sfmt(it->detail, sizeof it->detail, "NVIDIA graphics card: %s", nm);
                  scopy(it->rec, sizeof it->rec, "Install NVIDIA proprietary drivers. Nouveau support is limited. Ubuntu, Linux Mint, or Pop!_OS can simplify this setup."); }
        else if (amd) { it->score = S_FULL; sfmt(it->detail, sizeof it->detail, "AMD graphics card: %s", nm);
                  scopy(it->rec, sizeof it->rec, "AMDGPU is well supported by the kernel. Expect good out-of-the-box performance."); }
        else if (intel) { it->score = S_FULL; sfmt(it->detail, sizeof it->detail, "Intel graphics device: %s", nm);
                  scopy(it->rec, sizeof it->rec, "Intel i915/xe kernel driver works well with both Wayland and X11."); }
        else if (virt) { it->score = S_MINOR; sfmt(it->detail, sizeof it->detail, "Virtual/emulated display adapter: %s", nm);
                  scopy(it->rec, sizeof it->rec, "A virtual environment is detected. Run on physical hardware to verify your GPU compatibility."); }
        else { sfmt(it->detail, sizeof it->detail, "Unknown graphics card: %s", nm);
               scopy(it->rec, sizeof it->rec, "Search online for 'Linux + [GPU model] driver' to verify support."); }
    }
    if (!n) {
        Item* it = new_item(C_GPU, S_MAYBE, 1); if (!it) return;
        scopy(it->name, sizeof it->name, g_dev_ok ? "No display adapter found" : "Display adapter not found in device tree");
        scopy(it->detail, sizeof it->detail, g_dev_ok ? "No display adapter was found in the device enumeration tree." : "The device enumeration tree (Enum registry key) could not be opened.");
        scopy(it->rec, sizeof it->rec, "Try running the application as Administrator.");
    }
}

static void analyze_net(void) {
    scan_devices();
    int n = 0;
    for (int i = 0; i < g_ndev; i++) {
        if (!seq(g_dev[i].cls, CLS_NET)) continue;
        const char* nm = g_dev[i].name;
        if (has(nm, "Microsoft", 1) || has(nm, "WAN Miniport", 1) || has(nm, "Bluetooth", 1) || has(nm, "Loopback", 1) || has(nm, "Virtual", 1)) continue;
        Item* it = new_item(C_NET, S_MAYBE, 0); if (!it) return; n++;
        scopy(it->name, sizeof it->name, nm);
        int wifi = has(nm, "Wi-Fi", 1) || has(nm, "Wireless", 1) || has(nm, "WLAN", 1);
        const char* kind = wifi ? "Wi-Fi" : "Ethernet";
        if (has(nm, "Intel", 1)) { it->score = S_FULL; sfmt(it->detail, sizeof it->detail, "Intel %s adapter: %s", kind, nm);
            scopy(it->rec, sizeof it->rec, wifi ? "Intel Wi-Fi (iwlwifi) has excellent Linux kernel support." : "Intel Ethernet is fully supported in the kernel."); }
        else if (has(nm, "Realtek", 1)) { it->score = S_MINOR; sfmt(it->detail, sizeof it->detail, "Realtek %s: %s", kind, nm);
            scopy(it->rec, sizeof it->rec, wifi ? "Realtek Wi-Fi may require an external DKMS driver package." : "Realtek Ethernet (r8169) usually works reliably."); }
        else if (has(nm, "Broadcom", 1)) { it->score = S_MAYBE; sfmt(it->detail, sizeof it->detail, "Broadcom %s: %s", kind, nm);
            scopy(it->rec, sizeof it->rec, "Broadcom adapters can be problematic on Linux. Use a wired connection during install."); }
        else if (has(nm, "Atheros", 1) || has(nm, "Killer", 1)) { it->score = S_FULL; sfmt(it->detail, sizeof it->detail, "Atheros/Killer %s: %s", kind, nm);
            scopy(it->rec, sizeof it->rec, "Atheros and Killer adapters typically work well with ath10k/ath11k drivers."); }
        else if (has(nm, "MediaTek", 1) || has(nm, "Ralink", 1)) { it->score = S_MINOR; sfmt(it->detail, sizeof it->detail, "MediaTek/Ralink %s: %s", kind, nm);
            scopy(it->rec, sizeof it->rec, "MediaTek (mt76) support is in the kernel, but very new chips may need extra firmware."); }
        else { sfmt(it->detail, sizeof it->detail, "%s: %s  [HWID: %.80s]", wifi ? "Wi-Fi" : "Network adapter", nm, g_dev[i].hw);
            scopy(it->rec, sizeof it->rec, "Check the hardware ID on the vendor website or linux-hardware.org for compatibility."); }
    }
    if (!n) {
        Item* it = new_item(C_NET, S_MAYBE, 0); if (!it) return;
        scopy(it->name, sizeof it->name, g_dev_ok ? "No suitable network adapter found" : "Network adapters could not be enumerated");
        scopy(it->detail, sizeof it->detail, g_dev_ok ? "No non-virtual network adapter remained after filtering." : "The device enumeration tree (Enum registry key) could not be opened.");
        scopy(it->rec, sizeof it->rec, "Check whether a physical network adapter is enabled and detected by Windows, and run as Administrator.");
    }
}

static void analyze_audio(void) {
    scan_devices();
    int n = 0;
    for (int i = 0; i < g_ndev; i++) {
        if (!seq(g_dev[i].cls, CLS_MEDIA)) continue;
        const char* nm = g_dev[i].name;
        if (has(nm, "Virtual", 1) || has(nm, "Microsoft", 1)) continue;
        Item* it = new_item(C_AUDIO, S_MINOR, 0); if (!it) return; n++;
        scopy(it->name, sizeof it->name, nm);
        if (has(nm, "Realtek", 1) || has(nm, "Intel", 1) || has(nm, "AMD", 0) || has(nm, "Nvidia", 1)) {
            it->score = S_FULL; sfmt(it->detail, sizeof it->detail, "HDA-compatible audio codec: %s", nm);
            scopy(it->rec, sizeof it->rec, "Should work with ALSA, PulseAudio, or PipeWire without extra configuration."); }
        else if (has(nm, "Focusrite", 1) || has(nm, "Scarlett", 1)) {
            sfmt(it->detail, sizeof it->detail, "USB audio interface: %s", nm);
            scopy(it->rec, sizeof it->rec, "Focusrite devices usually work well. Use JACK or PipeWire for professional audio."); }
        else if (has(nm, "Creative", 1) || has(nm, "Sound Blaster", 1)) {
            it->score = S_MAYBE; sfmt(it->detail, sizeof it->detail, "Creative sound card: %s", nm);
            scopy(it->rec, sizeof it->rec, "Some Sound Blaster DSP or equalizer features may not be supported on Linux."); }
        else { sfmt(it->detail, sizeof it->detail, "Audio device: %s", nm);
            scopy(it->rec, sizeof it->rec, "Most standard USB or Bluetooth audio devices are recognized automatically on Linux."); }
    }
    if (!n) {
        Item* it = new_item(C_AUDIO, S_MAYBE, 0); if (!it) return;
        scopy(it->name, sizeof it->name, g_dev_ok ? "No suitable audio device found" : "Audio device tree could not be read");
        scopy(it->detail, sizeof it->detail, g_dev_ok ? "No non-virtual audio device remained after filtering." : "Unable to retrieve the media device list.");
        scopy(it->rec, sizeof it->rec, "Check whether an audio device is enabled and detected by Windows, and run as Administrator.");
    }
}

static void analyze_firmware(void) {
    scan_devices();
    int fw = 0;           /* 0 = bilinmiyor, 1 = BIOS, 2 = UEFI */
    { SYS_BOOT_ENV be; memset(&be, 0, sizeof be);
      if (NT_SUCCESS(query_sysinfo(90, &be, sizeof be)) && (be.FirmwareType == 1 || be.FirmwareType == 2)) fw = (int)be.FirmwareType;
      else { u32 v; if (reg_path_dword(u"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control", u"PEFirmwareType", &v) && (v == 1 || v == 2)) fw = (int)v; } }
    int sb = -1;          /* -1 = bilinmiyor */
    { SYS_SECBOOT ss; memset(&ss, 0, sizeof ss);
      if (NT_SUCCESS(query_sysinfo(145, &ss, sizeof ss))) sb = ss.Enabled ? 1 : 0;
      else { u32 v; if (reg_path_dword(u"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", u"UEFISecureBootEnabled", &v)) sb = v ? 1 : 0; } }

    static const wch BIOS[] = u"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS";
    char bver[120], bven[120];
    reg_path_str(BIOS, u"BIOSVersion", bver, sizeof bver);
    reg_path_str(BIOS, u"BIOSVendor", bven, sizeof bven);

    Item* it = new_item(C_FW, fw == 2 ? S_FULL : fw == 1 ? S_MINOR : S_MAYBE, 1);
    if (it) {
        sfmt(it->name, sizeof it->name, "Boot type: %s  |  BIOS: %s %s", fw == 2 ? "UEFI" : fw == 1 ? "Legacy BIOS" : "unknown", bven, bver);
        if (fw == 2) { scopy(it->detail, sizeof it->detail, "Modern UEFI system detected. GRUB2 and systemd-boot installers should work fine.");
                       scopy(it->rec, sizeof it->rec, "Install Linux in UEFI mode and ensure the EFI System Partition is selected."); }
        else if (fw == 1) { scopy(it->detail, sizeof it->detail, "Legacy BIOS system detected. Linux can be installed, but GPT or Secure Boot may not be available.");
                       scopy(it->rec, sizeof it->rec, "Use MBR partitioning during installation if your system does not support UEFI."); }
        else { scopy(it->detail, sizeof it->detail, "The firmware type could not be determined from the system.");
               scopy(it->rec, sizeof it->rec, "Check the firmware type in msinfo32 (BIOS Mode) and verify it manually."); }
    }
    it = new_item(C_SB, sb == 1 ? S_MINOR : sb == 0 ? S_FULL : S_MAYBE, 0);
    if (it) {
        sfmt(it->name, sizeof it->name, "Secure Boot: %s", sb == 1 ? "ENABLED" : sb == 0 ? "DISABLED" : "unknown");
        if (sb == 1) { scopy(it->detail, sizeof it->detail, "Secure Boot is currently ENABLED. Many distros like Ubuntu and Fedora support it, but some may still have issues.");
                       scopy(it->rec, sizeof it->rec, "If installing Arch, Gentoo, or Manjaro, you may need to disable Secure Boot in BIOS."); }
        else if (sb == 0) { scopy(it->detail, sizeof it->detail, "Secure Boot is disabled. Most Linux distributions should boot without restrictions.");
                       scopy(it->rec, sizeof it->rec, "No action is required."); }
        else { scopy(it->detail, sizeof it->detail, "The Secure Boot state could not be determined from the system.");
               scopy(it->rec, sizeof it->rec, "Check the Secure Boot State in msinfo32 and verify it manually."); }
    }
    it = new_item(C_TPM, S_FULL, 0);
    if (it) {
        sfmt(it->name, sizeof it->name, "Trusted Platform Module (TPM): %s", g_has_tpm ? "Present" : "Not detected");
        scopy(it->detail, sizeof it->detail, g_has_tpm ? "TPM is present; manageable with tpm2-tools on Linux." : "No TPM hardware detected.");
        scopy(it->rec, sizeof it->rec, "TPM can be used for LUKS encryption keys or secure boot workflows if desired.");
    }
}

static void analyze_power(void) {
    SYS_BATTERY b; memset(&b, 0, sizeof b);
    if (!NT_SUCCESS(sys(SC_PowerInformation, 5, 5 /* SystemBatteryState */, 0, 0, Q(&b), (u64)sizeof b))) return;
    if (!b.BatteryPresent) return;
    u32 pct = b.Max ? (u32)((u64)b.Remaining * 100 / b.Max) : 0;
    Item* it = new_item(C_POWER, S_MINOR, 0); if (!it) return;
    sfmt(it->name, sizeof it->name, "Battery: %%%u  |  Power source: %s", pct, b.AcOnLine ? "AC adapter" : "Running on battery");
    scopy(it->detail, sizeof it->detail, "A laptop battery was detected. Power management behaves differently on Linux than on Windows.");
    scopy(it->rec, sizeof it->rec, "Install TLP or power-profiles-daemon after setup to improve battery life.");
}

static void analyze_virt(void) {
    if (!proc_feature(21)) return;
    Item* it = new_item(C_VIRT, S_FULL, 0); if (!it) return;
    scopy(it->name, sizeof it->name, "Hardware virtualization available");
    scopy(it->detail, sizeof it->detail, "Windows reports that hardware virtualization is enabled and available to the operating system.");
    scopy(it->rec, sizeof it->rec, "Linux KVM/QEMU and other virtualization features can use the available hardware virtualization support.");
}

typedef struct { const char* label; int steps, delay; void (*fn)(void); } Step;
static const Step STEPS[9] = {
    { "Step 1/9: CPU analysis in progress          ", 8, 30, analyze_cpu },
    { "Step 2/9: Memory (RAM) analysis            ", 6, 25, analyze_ram },
    { "Step 3/9: Disk and storage analysis        ", 7, 35, analyze_storage },
    { "Step 4/9: Graphics (GPU) scan              ", 9, 40, analyze_gpu },
    { "Step 5/9: Networking inspection            ", 8, 35, analyze_net },
    { "Step 6/9: Audio device inspection          ", 6, 30, analyze_audio },
    { "Step 7/9: Firmware / UEFI check            ", 7, 25, analyze_firmware },
    { "Step 8/9: Power and battery status         ", 4, 20, analyze_power },
    { "Step 9/9: Virtualization environment       ", 4, 20, analyze_virt },
};

/* =====================================================================
 * Rapor yazdırma
 * ===================================================================== */
static void out_score(int s) {
    static const char* const lab[4] = { "[0] FULLY COMPATIBLE", "[1] COMPATIBLE (minor)", "[2] MAYBE INCOMPATIBLE", "[3] INCOMPATIBLE" };
    const char* col[4] = { cGrn, cYel, cOrg, cRed };
    outf("%s%s%-22s%s", col[s], cB, lab[s], cR);
}

static void print_report(void) {
    compute();
    outf("\n%s%s", cCyn, cB); out_hr(); outf("%s", cR);
    outf("%s%s  DETAILED HARDWARE COMPATIBILITY REPORT\n%s", cB, cWht, cR);
    outf("%s%s", cCyn, cB); out_hr(); outf("%s\n", cR);

    for (int c = 0; c < C_COUNT; c++) {
        int printed = 0;
        for (int i = 0; i < g_nitems; i++) {
            const Item* it = &g_items[i];
            if (it->cat != c) continue;
            if (!printed) { outf("%s%s  %s %s\n%s", cBlu, cB, G_TOP, CAT[c], cR); printed = 1; }
            outf("  %s  ", G_V); out_score(it->score); outf("  %s\n", it->name);
            outf("  %s     %s%s %s\n%s", G_V, cD, G_ARROW, it->detail, cR);
            outf("  %s     %s%s %s\n%s", G_V, cCyn, G_STAR, it->rec, cR);
            outf("  %s\n", G_V);
        }
    }

    outf("\n%s%s", cCyn, cB); out_hr(); outf("%s", cR);
    outf("%s%s  SUMMARY STATISTICS\n%s", cB, cWht, cR);
    outf("%s%s", cCyn, cB); out_hr(); outf("%s\n", cR);
    outf("  %s*%s  Fully compatible         : %d items\n", cGrn, cR, g_counts[0]);
    outf("  %s*%s  Compatible (minor)       : %d items\n", cYel, cR, g_counts[1]);
    outf("  %s*%s  Maybe incompatible       : %d items\n", cOrg, cR, g_counts[2]);
    outf("  %s*%s  Incompatible             : %d items\n", cRed, cR, g_counts[3]);

    outf("\n  Total compatibility score:\n  ");
    { u32 p = g_pct10; const char* col = p >= 750 ? cGrn : p >= 500 ? cYel : cRed; int w = 40, filled = (int)(p * (u32)w / 1000);
      outf("%s%s[", col, cB); for (int i = 0; i < w; i++) outf("%s", i < filled ? G_BAR_ON : G_BAR_OFF);
      outf("] %%%u.%u%s", p / 10, p % 10, cR); }
    outf("\n\n%s%s  OVERALL ASSESSMENT AND RESULT\n\n%s", cB, cWht, cR);
    u32 p = g_pct10;
    if (p >= 850) { outf("%s%s  [OK] Your system is READY for Linux!\n%s", cGrn, cB, cR);
        outf("     You can use Ubuntu, Fedora, Mint, or most mainstream distros without much hassle.\n"); }
    else if (p >= 650) { outf("%s%s  [!] Your system is LARGELY compatible with Linux.\n%s", cYel, cB, cR);
        outf("     Some devices may require manual driver setup after installation.\n     Ubuntu LTS or Linux Mint are usually easiest for this setup.\n"); }
    else if (p >= 400) { outf("%s%s  [~] Compatibility is MODERATE.\n%s", cOrg, cB, cR);
        outf("     Several components may not work out of the box. Test from a live USB before installing.\n"); }
    else { outf("%s%s  [X] Your system has serious compatibility issues.\n%s", cRed, cB, cR);
        outf("     Installing Linux on this machine may not be suitable for daily use.\n"); }

    outf("\n%s%s  DISTRIBUTION RECOMMENDATIONS\n\n%s", cB, cWht, cR);
    outf("     1. Ubuntu LTS         - wide driver support and easy installation.\n");
    outf("     2. Linux Mint         - familiar layout for Windows users and beginner friendly.\n");
    outf("     3. Fedora             - current kernel and strong hardware support.\n");
    outf("     4. Pop!_OS            - convenient NVIDIA setup when supported by the current release.\n");
    outf("     5. EndeavourOS        - Arch-based choice for advanced users who want full control.\n");
    outf("\n%s%s", cCyn, cB); out_hr(); outf("%s", cR);
    outf("%s  Linux Compatibility Checker v2.2 (raw syscalls)  |  linux-hardware.org\n%s", cD, cR);
    outf("%s%s", cCyn, cB); out_hr(); outf("%s\n", cR);
}

/* =====================================================================
 * Zaman, komut satırı, dosyaya kaydetme
 * ===================================================================== */
typedef struct { int y, mo, d, h, mi; } LocalTime;
static LocalTime local_now(void) {
    i64 ticks = read_ksystem_time(0x14) - read_ksystem_time(0x20);     /* SystemTime - TimeZoneBias = yerel */
    i64 days1601 = ticks / 864000000000LL;
    i64 secs = (ticks % 864000000000LL) / 10000000LL;
    i64 z = days1601 - 134774 + 719468;                                /* 1970 -> 0000-03-01 */
    i64 era = (z >= 0 ? z : z - 146096) / 146097;
    i64 doe = z - era * 146097;
    i64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    i64 y = yoe + era * 400;
    i64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    i64 mp = (5 * doy + 2) / 153;
    i64 d = doy - (153 * mp + 2) / 5 + 1;
    i64 m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    LocalTime t = { (int)y, (int)m, (int)d, (int)(secs / 3600), (int)((secs / 60) % 60) };
    return t;
}

static int wequals_ascii(const wch* w, const char* a) { size_t i = 0; for (; a[i]; i++) if (w[i] != (wch)(u8)a[i]) return 0; return w[i] == 0; }

/* Komut satırını boşluklara/tırnaklara göre böler (sade CommandLineToArgv) */
#define MAX_ARGS 16
static wch g_argbuf[MAX_ARGS][520]; static int g_argc;
static void parse_cmdline(void) {
    const UNICODE_STRING* cl = (const UNICODE_STRING*)(g_params + 0x70);
    if (!cl->Buffer) return;
    size_t n = cl->Length / 2, len = 0; int inq = 0, intok = 0;
    for (size_t i = 0; i <= n; i++) {
        wch c = i < n ? cl->Buffer[i] : 0;
        int sep = (c == 0) || ((c == ' ' || c == '\t') && !inq);
        if (sep) {
            if (intok && g_argc < MAX_ARGS) { g_argbuf[g_argc][len] = 0; g_argc++; }
            len = 0; intok = 0; continue;
        }
        if (c == '"') { inq = !inq; intok = 1; continue; }
        if (g_argc < MAX_ARGS && len < 519) g_argbuf[g_argc][len++] = c;
        intok = 1;
    }
}

/* DOS yolunu NT yoluna çevirir: C:\x -> \??\C:\x ; \\srv\sh -> \??\UNC\srv\sh ; göreli -> cwd + yol */
static int to_nt_path(const wch* dos, wch* out, size_t cap) {
    size_t n = wlen(dos);
    if (n >= 4 && dos[0] == '\\' && dos[1] == '?' && dos[2] == '?' && dos[3] == '\\') { wset(out, cap, dos); return 1; }
    if (n >= 4 && dos[0] == '\\' && dos[1] == '\\' && dos[2] == '?' && dos[3] == '\\') { wset(out, cap, u"\\??\\"); wapp(out, cap, dos + 4); return 1; }
    if (n >= 3 && dos[1] == ':' && (dos[2] == '\\' || dos[2] == '/')) { wset(out, cap, u"\\??\\"); wapp(out, cap, dos); return 1; }
    if (n >= 2 && dos[0] == '\\' && dos[1] == '\\') { wset(out, cap, u"\\??\\UNC\\"); wapp(out, cap, dos + 2); return 1; }
    const UNICODE_STRING* cwd = (const UNICODE_STRING*)(g_params + 0x38);      /* CurrentDirectory.DosPath */
    if (!cwd->Buffer) return 0;
    wset(out, cap, u"\\??\\");
    size_t o = wlen(out), cn = cwd->Length / 2;
    for (size_t i = 0; i < cn && o + 2 < cap; i++) out[o++] = cwd->Buffer[i];
    if (o > 0 && out[o - 1] != '\\' && o + 2 < cap) out[o++] = '\\';
    out[o] = 0;
    wapp(out, cap, dos);
    return 1;
}

static int save_report(const wch* dos_path) {
    static wch nt[1100];
    if (!to_nt_path(dos_path, nt, 1100)) return 0;
    HANDLE h = open_nt(nt, 0x120116 | 0x100000, 1, 0x40 | 0x20, 5 /* FILE_OVERWRITE_IF */);
    if (!h) return 0;
    int ok = write_all(h, g_rep, g_repn);
    NtClose_(h);
    return ok;
}

static void build_text_report(const char* os, const char* comp, LocalTime t) {
    static const char* const st[4] = { "[0] FULLY COMPATIBLE", "[1] COMPATIBLE (minor)", "[2] MAYBE INCOMPATIBLE", "[3] INCOMPATIBLE" };
    repf("Linux Compatibility Checker v2.2 (raw syscalls) - Report\n");
    repf("Computer name : %s\nOS version    : %s\n", comp, os);
    repf("Date          : %02d/%02d/%04d  %02d:%02d\n\n", t.d, t.mo, t.y, t.h, t.mi);
    for (int i = 0; i < g_nitems; i++) {
        const Item* it = &g_items[i];
        repf("%-26s  %-30s  %s\n  -> %s\n  * %s\n\n", CAT[it->cat], st[it->score], it->name, it->detail, it->rec);
    }
    repf("Overall compatibility score: %%%u.%u\n", g_pct10 / 10, g_pct10 % 10);
    repf("Fully compatible: %d | Compatible (minor): %d | Maybe incompatible: %d | Incompatible: %d\n",
         g_counts[0], g_counts[1], g_counts[2], g_counts[3]);
}

static int is_elevated(void) {
    HANDLE tok = 0;
    if (!NT_SUCCESS(sys(SC_OpenProcessToken, 3, Q(CUR_PROCESS), 0x8, Q(&tok)))) return 0;
    u32 el = 0, ret = 0;
    NTSTATUS st = sys(SC_QueryInformationToken, 5, Q(tok), 20 /* TokenElevation */, Q(&el), 4, Q(&ret));
    NtClose_(tok);
    return NT_SUCCESS(st) && ret == 4 && el != 0;
}

static void loading_bar(const char* msg, int steps, int delay) {
    outf("%s  > %s%s ", cCyn, cR, msg); out_flush();
    for (int i = 0; i < steps; i++) { outf("%s", G_BAR_ON); out_flush(); sleep_ms((unsigned)delay); }
    outf(" %s%sOK\n%s", cGrn, cB, cR); out_flush();
}

/* =====================================================================
 * GİRİŞ NOKTASI
 * ===================================================================== */
__attribute__((force_align_arg_pointer))
void mainCRTStartup(void) {
    g_params = *(u8**)(get_peb() + 0x20);                       /* PEB->ProcessParameters */

    if (!find_ntdll()) terminate(10);
    for (int i = 0; i < SC_COUNT; i++) {
        long s = resolve_ssn(g_sc_names[i]);
        if (s < 0) {
            char m[96]; sfmt(m, sizeof m, "syscall resolve failed: %s\n", g_sc_names[i]);
            g_ssn[SC_WriteFile] = 0;                             /* henüz çözülmemiş olabilir; dene */
            long w = resolve_ssn("NtWriteFile"); if (w >= 0) { g_ssn[SC_WriteFile] = (u32)w; if (handle_ok(std_out())) write_all(std_out(), m, slen(m)); }
            terminate(11);
        }
        g_ssn[i] = (u32)s;
    }

    parse_cmdline();
    static wch save_path[520]; save_path[0] = 0;
    for (int i = 1; i < g_argc; i++) {
        if (wequals_ascii(g_argbuf[i], "--ansi")) g_ansi = 1;
        else if (wequals_ascii(g_argbuf[i], "--utf8")) g_utf8 = 1;
        else if (wequals_ascii(g_argbuf[i], "--pnp")) g_pnp = 1;
        else if (wequals_ascii(g_argbuf[i], "--save") && i + 1 < g_argc) wset(save_path, 520, g_argbuf[++i]);
    }
    ui_init();

    if (!is_elevated()) {
        outf("This tool requires Administrator privileges.\nRun it from an elevated terminal (Run as administrator).\nPress Enter to exit...\n");
        wait_enter(); terminate(1);
    }

    outf("\n%s%s", cCyn, cB); out_hr(); outf("%s", cR);
    outf("%s%s        Linux Compatibility Checker v2.2 (raw syscalls)\n%s", cBlu, cB, cR);
    outf("%s        Windows 11 -> Linux migration readiness report\n%s", cD, cR);
    outf("%s%s", cCyn, cB); out_hr(); outf("%s\n", cR);

    static const wch CV[] = u"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    char os[128], bld[16], comp[80];
    if (!reg_path_str(CV, u"ProductName", os, sizeof os)) scopy(os, sizeof os, "Windows");
    if (reg_path_str(CV, u"CurrentBuildNumber", bld, sizeof bld)) {
        int b = 0; for (int i = 0; bld[i] >= '0' && bld[i] <= '9'; i++) b = b * 10 + (bld[i] - '0');
        if (b >= 22000 && os[0] == 'W' && has(os, "Windows 10", 0) && os[8] == '1' && os[9] == '0') { os[8] = '1'; os[9] = '1'; }   /* Win11 kayıt defterinde "Windows 10" yazar */
    }
    if (!reg_path_str(u"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", u"ComputerName", comp, sizeof comp))
        scopy(comp, sizeof comp, "?");
    LocalTime t = local_now();
    outf("%s  Computer name  : %s\n  OS version     : %s\n  Date / time    : %02d/%02d/%04d  %02d:%02d\n\n%s", cD, comp, os, t.d, t.mo, t.y, t.h, t.mi, cR);

    for (int i = 0; i < 9; i++) { loading_bar(STEPS[i].label, STEPS[i].steps, STEPS[i].delay); STEPS[i].fn(); }
    outf("\n");
    print_report();

    compute();
    build_text_report(os, comp, t);
    out_flush();
    if (!g_out_ok && !save_path[0]) wset(save_path, 520, u"linux_compat_report.txt");   /* konsol çıktısı yoksa dosyaya yaz */
    if (save_path[0]) {
        if (save_report(save_path)) outf("%s  Report saved to file.\n%s", cGrn, cR);
        else                        outf("%s  Failed to save report to file.\n%s", cRed, cR);
    }
    outf("  Press Enter to exit...\n");
    wait_enter();
    terminate(0);
}
