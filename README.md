# 🐧 Linux Kernel Uyumluluk Analiz Aracı v2.0

Windows 11 kullanan kullanıcılar için Linux'a geçmeden önce
sistemin ne kadar uyumlu olduğunu analiz eden terminal aracı.

---

## Uyumluluk Skorları

| Skor | Anlam              | Renk   |
|------|--------------------|--------|
| [0]  | Tam Uyumlu         | Yeşil  |
| [1]  | Uyumlu (Aksaklık olabilir) | Sarı |
| [2]  | Belki Uyumsuz      | Turuncu|
| [3]  | Uyumsuz            | Kırmızı|

---

## Analiz Edilen Bileşenler

- ✅ CPU (Intel/AMD/ARM tespiti, SSE2, AVX, VT-x)
- ✅ RAM (boyut ve yeterlilik)
- ✅ Disk (alan kontrolü, SSD/HDD/NVMe tespiti)
- ✅ GPU (NVIDIA/AMD/Intel, açık kaynak sürücü analizi)
- ✅ Ağ Kartı / WiFi (Intel, Realtek, Broadcom, Atheros...)
- ✅ Ses Kartı (HDA, Focusrite, Creative...)
- ✅ Firmware (UEFI / Legacy BIOS)
- ✅ Secure Boot durumu
- ✅ TPM varlığı
- ✅ Batarya / Güç yönetimi (dizüstü)
- ✅ Sanallaştırma tespiti (VMware, Hyper-V, VirtualBox...)
- ✅ kernel.org → En güncel kararlı kernel sürümü (çevrimiçi)

---

## Derleme Talimatları

### MSVC (Visual Studio — Tavsiye Edilen)

```bat
cl linux_compat_checker.c ^
   /Fe:linux_compat_checker.exe ^
   /link advapi32.lib setupapi.lib winhttp.lib
```

### MinGW / GCC

```bash
gcc linux_compat_checker.c \
    -o linux_compat_checker.exe \
    -ladvapi32 -lsetupapi -lwinhttp \
    -masm=intel
```

### CMake ile

```cmake
cmake_minimum_required(VERSION 3.16)
project(LinuxCompatChecker C)

add_executable(linux_compat_checker linux_compat_checker.c)
target_link_libraries(linux_compat_checker advapi32 setupapi winhttp)
```

---

## Çalıştırma

```
linux_compat_checker.exe
```

Yönetici (Administrator) modunda çalıştırılması önerilir.
(Disk ve aygıt tespiti için gereklidir.)

---

## Gereksinimler

- Windows 10 / 11
- Visual Studio 2019+ veya MinGW-w64
- İnternet bağlantısı (kernel.org sorgusu için, opsiyonel)

---

## Notlar

- Program herhangi bir veriyi internete göndermez.
- kernel.org'dan yalnızca en güncel kernel sürüm numarası okunur.
- Tüm analiz yerel ve salt-okunur işlemlerle yapılır.
