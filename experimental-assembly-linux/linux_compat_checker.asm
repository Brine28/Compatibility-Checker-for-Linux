; =============================================================================
; Linux Kernel Compatibility Checker v2.1 — x86-64 NASM
; =============================================================================
; Reads /proc and /sys interfaces to evaluate hardware compatibility for Linux.
;
; Scores: 0 = Fully Compatible
;         1 = Compatible (minor issues)
;         2 = Possibly Incompatible
;         3 = Incompatible
;
; Assemble and link:
;   nasm -f elf64 linux_compat_checker.asm -o linux_compat_checker.o
;   ld linux_compat_checker.o -o linux_compat_checker
;
; CachyOS / Arch: nasm is in 'extra' repo, ld is in 'binutils'.
; =============================================================================

BITS 64
DEFAULT REL

; ── Linux syscall numbers ────────────────────────────────────────────────────
SYS_READ        equ 0
SYS_WRITE       equ 1
SYS_OPEN        equ 2
SYS_CLOSE       equ 3
SYS_STAT        equ 4
SYS_FSTAT       equ 5
SYS_LSEEK       equ 8
SYS_STATFS      equ 137
SYS_GETDENTS64  equ 217
SYS_EXIT        equ 60
SYS_NANOSLEEP   equ 35
SYS_SOCKET      equ 41
SYS_CONNECT     equ 42

; ── open() flags ────────────────────────────────────────────────────────────
O_RDONLY        equ 0
O_DIRECTORY     equ 0x10000

; ── Score constants ──────────────────────────────────────────────────────────
SCORE_FULL      equ 0
SCORE_MINOR     equ 1
SCORE_MAYBE     equ 2
SCORE_NONE      equ 3

; ── Buffer sizes ────────────────────────────────────────────────────────────
BUFSIZE         equ 65536
LINEBUF_SIZE    equ 512
NUMBUF_SIZE     equ 32
DIRBUF_SIZE     equ 8192
PATHBUF_SIZE    equ 256
STRBUF_SIZE     equ 512

; =============================================================================
; SECTION .data — read-only string constants
; =============================================================================
SECTION .data

; ── ANSI color codes ─────────────────────────────────────────────────────────
S_RESET         db 27,"[0m",0
S_BOLD          db 27,"[1m",0
S_DIM           db 27,"[2m",0
S_RED           db 27,"[91m",0
S_GREEN         db 27,"[92m",0
S_YELLOW        db 27,"[93m",0
S_BLUE          db 27,"[94m",0
S_CYAN          db 27,"[96m",0
S_WHITE         db 27,"[97m",0
S_ORANGE        db 27,"[38;5;208m",0

; ── Score label strings (include color) ──────────────────────────────────────
label_full      db 27,"[92m",27,"[1m[0] FULLY COMPATIBLE     ",27,"[0m",0
label_minor     db 27,"[93m",27,"[1m[1] COMPATIBLE (minor)   ",27,"[0m",0
label_maybe     db 27,"[38;5;208m",27,"[1m[2] POSSIBLY INCOMPATIBLE",27,"[0m",0
label_none      db 27,"[91m",27,"[1m[3] INCOMPATIBLE         ",27,"[0m",0

; ── Score icons ──────────────────────────────────────────────────────────────
icon_full       db 27,"[92m",0xE2,0x97,0x8F,27,"[0m",0      ; ● green
icon_minor      db 27,"[93m",0xE2,0x97,0x91,27,"[0m",0      ; ◑ yellow
icon_maybe      db 27,"[38;5;208m",0xE2,0x97,0x94,27,"[0m",0 ; ◔ orange
icon_none       db 27,"[91m",0xE2,0x97,0x8B,27,"[0m",0      ; ○ red

; ── Header ───────────────────────────────────────────────────────────────────
hdr_top         db 27,"[96m",27,"[1m",0xE2,0x95,0x94
                times 62 db 0xE2,0x95,0x90
                db 0xE2,0x95,0x97,10,27,"[0m",0

hdr_mid1        db 27,"[96m",27,"[1m",0xE2,0x95,0x91,27,"[0m"
                db 27,"[94m",27,"[1m"
                db "     ",0xF0,0x9F,0x90,0xA7,"  Linux Kernel Compatibility Checker v2.1           "
                db 27,"[96m",27,"[1m",0xE2,0x95,0x91,10,27,"[0m",0

hdr_mid2        db 27,"[96m",27,"[1m",0xE2,0x95,0x91,27,"[0m"
                db 27,"[2m"
                db "     Linux Hardware Readiness Report                      "
                db 27,"[96m",27,"[1m",0xE2,0x95,0x91,10,27,"[0m",0

hdr_bot         db 27,"[96m",27,"[1m",0xE2,0x95,0x9A
                times 62 db 0xE2,0x95,0x90
                db 27,"[0m",10,0

; ── Section divider ──────────────────────────────────────────────────────────
divider         db 27,"[96m",27,"[1m"
                times 64 db 0xE2,0x95,0x90
                db 27,"[0m",10,0

; ── Category labels ──────────────────────────────────────────────────────────
str_nl          db 10,0
str_bar_open    db 27,"[94m",27,"[1m  ",0xE2,0x94,0x8C,0xE2,0x94,0x80," ",27,"[0m",0
str_bar_item    db "  ",0xE2,0x94,0x82,"  ",0
str_bar_detail  db "  ",0xE2,0x94,0x82,"     ",27,"[2m",0xE2,0x86,0x92," ",0
str_bar_rec     db "  ",0xE2,0x94,0x82,"     ",27,"[96m",0xE2,0x9C,0xA6," ",0
str_bar_sep     db "  ",0xE2,0x94,0x82,10,0

; ── Category header strings ───────────────────────────────────────────────────
cat_cpu         db "CPU",0
cat_ram         db "RAM",0
cat_disk        db "Disk",0
cat_gpu         db "GPU",0
cat_net         db "Network Card",0
cat_audio       db "Audio",0
cat_firmware    db "Firmware / UEFI",0
cat_secboot     db "Secure Boot",0
cat_tpm         db "TPM",0
cat_virt        db "Virtualization",0
cat_online      db "Online",0

; ── Generic labels ───────────────────────────────────────────────────────────
str_colon_sp    db ": ",0
str_space       db " ",0
str_pipe        db "  |  ",0
str_mb          db " MB",0
str_gb          db " GB",0
str_mhz         db " MHz",0
str_kb          db " kB",0
str_yes         db "Yes",0
str_no          db "No",0
str_unknown     db "Unknown",0
str_na          db "N/A",0
str_pct         db "%",0
str_enter       db 10,"  Press Enter to exit...",10,0

; ── Summary strings ──────────────────────────────────────────────────────────
sum_hdr         db 27,"[1m",27,"[97m  ",0xF0,0x9F,0x93,0x8A," SUMMARY STATISTICS",10,27,"[0m",0
sum_full        db "  ",27,"[92m",0xE2,0x97,0x8F,27,"[0m","  Fully Compatible          : ",0
sum_minor       db "  ",27,"[93m",0xE2,0x97,0x91,27,"[0m","  Compatible (minor issues) : ",0
sum_maybe       db "  ",27,"[38;5;208m",0xE2,0x97,0x94,27,"[0m","  Possibly Incompatible     : ",0
sum_none        db "  ",27,"[91m",0xE2,0x97,0x8B,27,"[0m","  Incompatible              : ",0
sum_total       db 10,"  Total components analyzed : ",0
sum_score       db 10,"  Overall Compatibility Score:",10,"  ",0
str_comp        db " component(s)",10,0

assess_hdr      db 10,27,"[1m",27,"[97m  ",0xF0,0x9F,0xA7,0xAD," GENERAL ASSESSMENT",10,10,27,"[0m",0
assess_ready    db 27,"[92m",27,"[1m  ",0xE2,0x9C,0x85," Your system is READY for Linux!",27,"[0m",10
                db "     Ubuntu, Fedora, Mint, or any major distribution will work seamlessly.",10,0
assess_mostly   db 27,"[93m",27,"[1m  ",0xE2,0x9A,0xA0,0xEF,0xB8,0x8F,"  Your system is MOSTLY compatible with Linux.",27,"[0m",10
                db "     A few components may need additional drivers or configuration.",10,
                db "     Ubuntu LTS or Linux Mint is recommended for the best out-of-box experience.",10,0
assess_moderate db 27,"[38;5;208m",27,"[1m  ",0xF0,0x9F,0x94,0xB6," Compatibility is MODERATE.",27,"[0m",10
                db "     Several components may cause issues. Test with a live USB before committing.",10,0
assess_bad      db 27,"[91m",27,"[1m  ",0xE2,0x9D,0x8C," Your system has serious compatibility issues.",27,"[0m",10
                db "     Consider hardware upgrades before migrating to Linux.",10,0

distro_hdr      db 10,27,"[1m",27,"[97m  ",0xF0,0x9F,0x90,0xA7," RECOMMENDED DISTRIBUTIONS",10,10,27,"[0m",0
distro_list     db "     1. Ubuntu 24.04 LTS  — Widest driver support, easiest installation",10
                db "     2. Linux Mint 22     — Windows-like interface, great for beginners",10
                db "     3. Fedora 41         — Latest kernel, excellent hardware support",10
                db "     4. Pop!_OS 24.04     — Optimised for gamers and NVIDIA users",10
                db "     5. EndeavourOS       — Arch-based, full control over the system",10,0

footer          db 27,"[96m",27,"[1m"
                times 64 db 0xE2,0x95,0x90
                db 27,"[0m",10
                db 27,"[2m  Linux Kernel Compatibility Checker v2.1  |  linux-hardware.org",10,27,"[0m"
                db 27,"[96m",27,"[1m"
                times 64 db 0xE2,0x95,0x90
                db 27,"[0m",10,10,0

; ── /proc / /sys paths ───────────────────────────────────────────────────────
path_cpuinfo    db "/proc/cpuinfo",0
path_meminfo    db "/proc/meminfo",0
path_drm        db "/sys/class/drm",0
path_vendor     db "/sys/class/drm/card0/device/vendor",0
path_device_id  db "/sys/class/drm/card0/device/device",0
path_asound     db "/proc/asound/cards",0
path_efi        db "/sys/firmware/efi",0
path_sb_policy  db "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",0
path_tpm        db "/sys/class/tpm",0
path_net        db "/sys/class/net",0
path_route      db "/proc/net/route",0
path_wireless   db "/wireless",0
path_dmi_vendor db "/sys/class/dmi/id/sys_vendor",0
path_dmi_prod   db "/sys/class/dmi/id/product_name",0
path_sb_state   db "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",0

; ── Search keys ──────────────────────────────────────────────────────────────
key_vendor_id   db "vendor_id",0
key_model_name  db "model name",0
key_cpu_mhz     db "cpu MHz",0
key_hypervisor  db "hypervisor",0
key_memtotal    db "MemTotal",0
key_00000000    db "00000000",0      ; default route marker in /proc/net/route
key_intel_vi    db "GenuineIntel",0
key_amd_vi      db "AuthenticAMD",0

; ── GPU vendor IDs ───────────────────────────────────────────────────────────
gpu_intel_id    db "0x8086",0
gpu_amd_id      db "0x1002",0
gpu_nvidia_id   db "0x10de",0

; ── Audio keywords ───────────────────────────────────────────────────────────
audio_realtek   db "Realtek",0
audio_intel     db "Intel",0
audio_amd_a     db "AMD",0
audio_nvidia_a  db "Nvidia",0
audio_focusrite db "Focusrite",0
audio_scarlett  db "Scarlett",0
audio_creative  db "Creative",0
audio_soundb    db "Sound Blaster",0

; ── DMI hypervisor names ──────────────────────────────────────────────────────
virt_vmware     db "VMware",0
virt_vbox       db "VirtualBox",0
virt_kvm        db "KVM",0
virt_qemu       db "QEMU",0
virt_hyperv     db "Microsoft",0
virt_xen        db "Xen",0
virt_parallels  db "Parallels",0

; ── Recommendation strings ────────────────────────────────────────────────────
rec_cpu_ok      db "Excellent Linux support. Any distribution will work seamlessly.",0
rec_cpu_arm     db "ARM Linux support is improving; some x86-only software may not run.",0
rec_ram_bad     db "Under 2 GB — try ultra-lightweight distros such as Lubuntu or Alpine.",0
rec_ram_minor   db "Use lightweight desktop environments such as Xfce or LXQt.",0
rec_ram_ok      db "All desktop environments and virtualisation will run comfortably.",0
rec_disk_bad    db "Free space < 20 GB — free up space or install Linux on a separate drive.",0
rec_disk_minor  db "Minimum viable space. 50+ GB recommended for comfortable use.",0
rec_disk_nvme   db "NVMe + ample space = blazing fast Linux. Use Ext4 or Btrfs.",0
rec_disk_ssd    db "SATA SSD + ample space = fast Linux. Use Ext4 or Btrfs.",0
rec_disk_hdd    db "HDD may feel slow. Prefer Ext4 and add a swap partition.",0
rec_gpu_nvidia  db "Install the proprietary NVIDIA driver (nvidia-open or nvidia package).",0
rec_gpu_amd     db "AMD GPU: fully supported by the amdgpu in-kernel driver — no extra steps.",0
rec_gpu_intel   db "Intel GPU: fully supported by i915 in-kernel driver.",0
rec_gpu_unk     db "Check linux-hardware.org for driver availability.",0
rec_net_intel   db "Intel Ethernet/Wi-Fi: excellent in-kernel support (e1000e / iwlwifi).",0
rec_net_realtek db "Realtek: Ethernet usually works (r8169). Wi-Fi may need an out-of-tree driver.",0
rec_net_broadco db "Broadcom: may need broadcom-sta or b43 firmware — obtain before install.",0
rec_net_atheros db "Atheros/Killer: fully in-kernel via ath9k / ath10k / ath11k.",0
rec_net_mediatek db "MediaTek mt76 driver is in-kernel; older chips may need a firmware pkg.",0
rec_net_wifi    db "Wi-Fi detected. Check linux-hardware.org for this adapter.",0
rec_net_eth     db "Ethernet adapter detected. Most are well supported in-kernel.",0
rec_audio_hda   db "HDA-compatible device — fully supported by snd_hda_intel in ALSA/PipeWire.",0
rec_audio_focus db "Focusrite generally works. Use JACK or PipeWire for pro-audio workflows.",0
rec_audio_crea  db "Creative Sound Blaster has limited Linux support; some DSP features absent.",0
rec_audio_usb   db "USB/Bluetooth audio devices generally work out-of-the-box on Linux.",0
rec_fw_uefi     db "Install Linux in UEFI mode; an EFI System Partition (ESP) will be created.",0
rec_fw_bios     db "Use an MBR partition scheme during installation.",0
rec_sb_on       db "Ubuntu, Fedora, openSUSE support Secure Boot. Disable it for Arch/Gentoo.",0
rec_sb_off      db "No action needed — all distributions can be installed.",0
rec_tpm_ok      db "TPM accessible on Linux via tpm2-tools; use with LUKS full-disk encryption.",0
rec_tpm_none    db "No TPM detected — LUKS encryption still works without hardware TPM.",0
rec_virt_on     db "Results reflect virtual hardware. Re-run on bare metal for accuracy.",0
rec_virt_none   db "Running on bare metal — analysis reflects physical hardware.",0
rec_online_ok   db "Connected — check linux-hardware.org for detailed driver status.",0
rec_online_no   db "Offline — connect to the internet for kernel.org version check.",0

; ── Detail format fragments ───────────────────────────────────────────────────
det_cpu_intel   db "Intel CPU | ",0
det_cpu_amd     db "AMD CPU | ",0
det_cpu_other   db "Non-x86 CPU | ",0
det_cpu_cores   db " logical cores | SSE2: ",0
det_cpu_avx     db " | AVX: ",0
det_cpu_vmx     db " | VT-x/AMD-V: ",0
det_ram_total   db " MB RAM total — ",0
det_ram_bad_d   db "under 2 GB, Linux requires at least 1 GB to boot.",0
det_ram_minor_d db "sufficient for basic desktop use.",0
det_ram_ok_d    db "excellent for any desktop workload.",0
det_disk_free   db " GB free / ",0
det_disk_total  db " GB total",0
det_disk_type   db "  [",0
det_disk_close  db "]",0
det_disk_nvme_s db "NVMe SSD",0
det_disk_ssd_s  db "SATA SSD",0
det_disk_hdd_s  db "HDD",0
det_disk_bad_d  db " — Linux installation requires at least 20 GB.",0
det_disk_min_d  db " — installation possible but headroom is limited.",0
det_disk_ok_d   db " — ample room for installation and data.",0
det_gpu_intel_d db "Intel integrated GPU — i915 in-kernel driver.",0
det_gpu_amd_d   db "AMD Radeon GPU — amdgpu in-kernel driver.",0
det_gpu_nvidia_d db "NVIDIA GPU — proprietary driver required for full performance.",0
det_gpu_unk_d   db "GPU vendor unknown — check /sys/class/drm/card0/device/vendor",0
det_fw_uefi_d   db "UEFI firmware — modern bootloaders (GRUB2, systemd-boot) work.",0
det_fw_bios_d   db "Legacy BIOS — UEFI features (GPT, Secure Boot) unavailable.",0
det_sb_on_d     db "Secure Boot enabled — may block some kernels and modules.",0
det_sb_off_d    db "Secure Boot disabled — all distributions will boot without issues.",0
det_tpm_ok_d    db "TPM chip present and accessible.",0
det_tpm_none_d  db "No TPM chip detected.",0
det_virt_d      db "Virtual machine detected — hypervisor: ",0
det_virt_bare_d db "Bare metal system.",0
det_online_ok_d db "Default gateway present — internet likely available.",0
det_online_no_d db "No default gateway in routing table.",0
det_audio_hda_d db "HDA-compatible audio device.",0
det_audio_foc_d db "USB audio interface.",0
det_audio_cre_d db "Creative audio device.",0
det_audio_gen_d db "Audio device detected.",0
det_audio_non_d db "No audio devices found in /proc/asound/cards.",0
det_net_none_d  db "No network interfaces found in /sys/class/net.",0

; ── GPU name strings (for display) ───────────────────────────────────────────
gpu_name_intel  db "Intel Integrated Graphics",0
gpu_name_amd    db "AMD Radeon GPU",0
gpu_name_nvidia db "NVIDIA GPU",0
gpu_name_unk    db "Unknown GPU",0

; ── Misc ─────────────────────────────────────────────────────────────────────
str_nvme_ssd    db "NVMe SSD",0
str_sata_ssd    db "SATA SSD",0
str_hdd         db "HDD",0

; For bar chart
bar_filled      db 0xE2,0x96,0x88,0     ; █
bar_empty       db 0xE2,0x96,0x91,0     ; ░

; =============================================================================
; SECTION .bss — uninitialised buffers
; =============================================================================
SECTION .bss

; Main I/O buffer (shared across reads — one analyzer at a time)
g_buf           resb BUFSIZE

; Per-call line / value buffer
g_linebuf       resb LINEBUF_SIZE

; Number conversion buffer
g_numbuf        resb NUMBUF_SIZE

; Directory scan buffer
g_dirbuf        resb DIRBUF_SIZE

; Path construction buffer
g_pathbuf       resb PATHBUF_SIZE

; Generic string-build buffer (for composing output lines)
g_strbuf        resb STRBUF_SIZE

; statfs struct (Linux x86-64: 6 * 8 = 120 bytes we use first 3 fields)
g_statfs        resb 128

; Summary counters
g_item_count    resq 1
g_score_sum     resq 1
g_cnt_full      resq 1
g_cnt_minor     resq 1
g_cnt_maybe     resq 1
g_cnt_none      resq 1
g_pct           resq 1

; Disk type flags  (0 = HDD, 1 = SATA SSD, 2 = NVMe)
g_disk_type     resq 1

; CPU info
g_cpu_cores     resq 1
g_cpu_mhz       resq 1

; =============================================================================
; SECTION .text
; =============================================================================
SECTION .text
GLOBAL _start

; =============================================================================
; _start
; =============================================================================
_start:
    ; zero summary counters
    mov qword [g_item_count], 0
    mov qword [g_score_sum],  0
    mov qword [g_cnt_full],   0
    mov qword [g_cnt_minor],  0
    mov qword [g_cnt_maybe],  0
    mov qword [g_cnt_none],   0
    mov qword [g_pct],        0

    ; print banner
    mov rdi, hdr_top
    call print_str
    mov rdi, hdr_mid1
    call print_str
    mov rdi, hdr_mid2
    call print_str
    mov rdi, hdr_bot
    call print_str

    ; run analyzers
    call analyze_cpu
    call analyze_ram
    call analyze_disk
    call analyze_gpu
    call analyze_network
    call analyze_audio
    call analyze_firmware
    call analyze_tpm
    call analyze_virtualization
    call analyze_online

    ; compute and print report
    call compute_summary
    call print_report

    ; print footer
    mov rdi, footer
    call print_str

    ; wait for Enter
    mov rdi, str_enter
    call print_str
    ; read 1 char from stdin
    mov rax, SYS_READ
    mov rdi, 0
    lea rsi, [g_numbuf]
    mov rdx, 1
    syscall

    ; exit(0)
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall

; =============================================================================
; ── UTILITY FUNCTIONS ────────────────────────────────────────────────────────
; =============================================================================

; ----------------------------------------------------------------------------
; print_str — write NUL-terminated string to stdout
;   rdi = string pointer
; clobbers: rax, rsi, rdx, rcx (via strlen)
; ----------------------------------------------------------------------------
print_str:
    push rdi
    call str_len            ; rax = length
    pop rsi                 ; rsi = string pointer (was rdi)
    test rax, rax
    jz .done
    mov rdx, rax
    mov rax, SYS_WRITE
    mov rdi, 1
    syscall
.done:
    ret

; ----------------------------------------------------------------------------
; str_len — length of NUL-terminated string
;   rdi = string pointer
;   returns rax = length
; clobbers: rax, rcx
; ----------------------------------------------------------------------------
str_len:
    xor rax, rax
.loop:
    cmp byte [rdi + rax], 0
    je  .done
    inc rax
    jmp .loop
.done:
    ret

; ----------------------------------------------------------------------------
; print_u64 — print unsigned 64-bit integer in decimal to stdout
;   rdi = value
; uses g_numbuf
; clobbers: rax, rbx, rcx, rdx, rsi
; ----------------------------------------------------------------------------
print_u64:
    lea rsi, [g_numbuf]
    call u64_to_str
    mov rdi, g_numbuf
    call print_str
    ret

; ----------------------------------------------------------------------------
; u64_to_str — convert u64 to decimal ASCII in g_numbuf (NUL-terminated)
;   rdi = value
;   fills g_numbuf
; clobbers: rax, rbx, rcx, rdx, rsi, r8
; ----------------------------------------------------------------------------
u64_to_str:
    lea r8, [g_numbuf]
    mov rax, rdi
    test rax, rax
    jnz .nonzero
    mov byte [r8], '0'
    mov byte [r8+1], 0
    ret
.nonzero:
    ; write digits in reverse to g_numbuf
    xor rcx, rcx           ; digit count
    mov rbx, 10
.digit_loop:
    xor rdx, rdx
    div rbx                ; rax = quotient, rdx = remainder
    add dl, '0'
    mov [r8 + rcx], dl
    inc rcx
    test rax, rax
    jnz .digit_loop
    ; reverse in place
    mov rdx, rcx           ; rdx = total digits
    dec rcx                 ; rcx = last index
    xor rbx, rbx           ; rbx = first index
.rev_loop:
    cmp rbx, rcx
    jge .rev_done
    mov al, [r8 + rbx]
    mov sil, [r8 + rcx]
    mov [r8 + rbx], sil
    mov [r8 + rcx], al
    inc rbx
    dec rcx
    jmp .rev_loop
.rev_done:
    mov byte [r8 + rdx], 0
    ret

; ----------------------------------------------------------------------------
; read_file — open file at rdi path, read into g_buf
;   rdi = NUL-terminated path
;   returns rax = bytes read (0 on failure)
; ----------------------------------------------------------------------------
read_file:
    push rbp
    mov rbp, rsp
    push r12

    mov rax, SYS_OPEN
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall
    test rax, rax
    js .fail
    mov r12, rax            ; save fd

    ; read
    mov rax, SYS_READ
    mov rdi, r12
    lea rsi, [g_buf]
    mov rdx, BUFSIZE - 1
    syscall
    push rax               ; save bytes_read

    ; close fd
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

    pop rax
    test rax, rax
    js .fail_zero
    ; NUL-terminate
    lea r12, [g_buf]
    mov byte [r12 + rax], 0

    pop r12
    pop rbp
    ret

.fail:
    xor rax, rax
    pop r12
    pop rbp
    ret
.fail_zero:
    xor rax, rax
    pop r12
    pop rbp
    ret

; ----------------------------------------------------------------------------
; path_exists — test whether path exists (stat syscall)
;   rdi = path
;   returns rax = 1 if exists, 0 if not
; ----------------------------------------------------------------------------
path_exists:
    push r12
    lea r12, [g_statfs]     ; reuse statfs buf as stat buf (large enough)
    mov rax, SYS_STAT
    mov rsi, r12
    syscall
    test rax, rax
    js .no
    mov rax, 1
    pop r12
    ret
.no:
    xor rax, rax
    pop r12
    ret

; ----------------------------------------------------------------------------
; find_key_value — search NUL-terminated buffer for "key : value\n"
;   rdi = buffer start
;   rsi = bytes in buffer
;   rdx = key string (NUL-terminated)
;   r8  = output buffer
;   r9  = output buffer max length
;   returns rax = 1 if found, 0 if not
;   output: value copied (NUL-terminated) into [r8]
;
; This performs a case-sensitive search for the key string, then skips
; optional whitespace and ':', then copies until end-of-line.
; ----------------------------------------------------------------------------
find_key_value:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; get key length
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    mov rdi, rdx
    call str_len
    mov r12, rax            ; r12 = key_len
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi

    ; r13 = buf, r14 = buflen
    mov r13, rdi
    mov r14, rsi

    xor r15, r15            ; r15 = scan position
.outer:
    ; check if enough bytes remain
    mov rax, r14
    sub rax, r12
    cmp r15, rax
    ja .not_found

    ; compare key at position r15
    xor rbx, rbx
.cmp_loop:
    cmp rbx, r12
    je .match_key
    mov al, [r13 + r15 + rbx]
    mov cl, [rdx + rbx]
    cmp al, cl
    jne .next_pos
    inc rbx
    jmp .cmp_loop

.next_pos:
    inc r15
    jmp .outer

.match_key:
    ; skip to ':' or end of line
    mov rax, r15
    add rax, r12
.skip_to_colon:
    cmp rax, r14
    jae .not_found
    mov cl, [r13 + rax]
    cmp cl, ':'
    je .found_colon
    cmp cl, 10
    je .not_found
    inc rax
    jmp .skip_to_colon

.found_colon:
    inc rax                 ; skip ':'
.skip_spaces:
    cmp rax, r14
    jae .not_found
    mov cl, [r13 + rax]
    cmp cl, ' '
    je .next_sp
    cmp cl, 9
    je .next_sp
    jmp .copy_val
.next_sp:
    inc rax
    jmp .skip_spaces

.copy_val:
    xor rbx, rbx
.copy_loop:
    cmp rax, r14
    jae .copy_done
    cmp rbx, r9
    jae .copy_done
    mov cl, [r13 + rax]
    cmp cl, 10
    je .copy_done
    cmp cl, 13
    je .copy_done
    mov [r8 + rbx], cl
    inc rbx
    inc rax
    jmp .copy_loop
.copy_done:
    ; trim trailing spaces
.trim:
    test rbx, rbx
    jz .copy_empty
    dec rbx
    mov cl, [r8 + rbx]
    cmp cl, ' '
    je .trim
    cmp cl, 9
    je .trim
    inc rbx
.copy_empty:
    mov byte [r8 + rbx], 0
    cmp rbx, 0
    je .not_found
    mov rax, 1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.not_found:
    xor rax, rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; str_contains_ci — case-insensitive substring search
;   rdi = haystack (NUL-terminated)
;   rsi = needle   (NUL-terminated)
;   returns rax = 1 if found, 0 if not
; ----------------------------------------------------------------------------
str_contains_ci:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; haystack
    mov r13, rsi            ; needle

    ; get lengths
    call str_len
    mov r14, rax            ; r14 = haystack length
    mov rdi, r13
    call str_len
    mov r15, rax            ; r15 = needle length

    test r15, r15
    jz .not_found

    xor rbx, rbx            ; rbx = position in haystack
.outer_ci:
    mov rax, r14
    sub rax, r15
    cmp rbx, rax
    ja .not_found

    xor rdi, rdi            ; rdi = position in needle
.inner_ci:
    cmp rdi, r15
    je .found_ci
    movzx rax, byte [r12 + rbx + rdi]
    call to_lower_al
    mov r8b, al
    movzx rax, byte [r13 + rdi]
    call to_lower_al
    cmp r8b, al
    jne .next_ci
    inc rdi
    jmp .inner_ci

.next_ci:
    inc rbx
    jmp .outer_ci

.found_ci:
    mov rax, 1
    jmp .done_ci
.not_found:
    xor rax, rax
.done_ci:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; str_contains — case-sensitive substring search
;   rdi = haystack (NUL-terminated)
;   rsi = needle   (NUL-terminated)
;   returns rax = 1 if found, 0 if not
; ----------------------------------------------------------------------------
str_contains:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi

    call str_len
    mov r14, rax
    mov rdi, r13
    call str_len
    mov r15, rax

    test r15, r15
    jz .not_found_cs

    xor rbx, rbx
.outer_cs:
    mov rax, r14
    sub rax, r15
    cmp rbx, rax
    ja .not_found_cs

    xor rdi, rdi
.inner_cs:
    cmp rdi, r15
    je .found_cs
    mov al, [r12 + rbx + rdi]
    cmp al, [r13 + rdi]
    jne .next_cs
    inc rdi
    jmp .inner_cs
.next_cs:
    inc rbx
    jmp .outer_cs
.found_cs:
    mov rax, 1
    jmp .done_cs
.not_found_cs:
    xor rax, rax
.done_cs:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; to_lower_al — convert ASCII character in al to lowercase
; ----------------------------------------------------------------------------
to_lower_al:
    cmp al, 'A'
    jb .done_lw
    cmp al, 'Z'
    ja .done_lw
    add al, 32
.done_lw:
    ret

; ----------------------------------------------------------------------------
; parse_u64_str — parse decimal ASCII digits from NUL-terminated string
;   rdi = string pointer
;   returns rax = parsed value (stops at first non-digit)
; ----------------------------------------------------------------------------
parse_u64_str:
    xor rax, rax
    xor rcx, rcx
.skip_spaces_p:
    mov cl, [rdi]
    cmp cl, ' '
    je .skip_sp
    cmp cl, 9
    jne .parse_digits
.skip_sp:
    inc rdi
    jmp .skip_spaces_p
.parse_digits:
    mov cl, [rdi]
    cmp cl, '0'
    jb .done_p
    cmp cl, '9'
    ja .done_p
    imul rax, rax, 10
    sub cl, '0'
    add rax, rcx
    inc rdi
    jmp .parse_digits
.done_p:
    ret

; ----------------------------------------------------------------------------
; append_str — append NUL-terminated string at end of g_strbuf
;   rdi = source string (NUL-terminated)
;   rsi = g_strbuf pointer (NUL-terminated, NUL marks current end)
; ----------------------------------------------------------------------------
; We use a fixed pattern: caller passes ptr to g_strbuf, finds end, appends.
; Simpler: a dedicated append_to_strbuf using g_strbuf.

; append_str: appends rdi to g_strbuf (finds NUL, copies there)
append_str:
    push rbx
    push r12
    push r13
    mov r12, rdi            ; source
    lea r13, [g_strbuf]
    ; find end of g_strbuf
    xor rbx, rbx
.find_end:
    cmp byte [r13 + rbx], 0
    je .found_end
    inc rbx
    jmp .find_end
.found_end:
    ; copy source starting at [r13+rbx]
.copy_ap:
    mov al, [r12]
    mov [r13 + rbx], al
    test al, al
    jz .done_ap
    inc r12
    inc rbx
    jmp .copy_ap
.done_ap:
    pop r13
    pop r12
    pop rbx
    ret

; clear_strbuf — zero the first byte of g_strbuf
clear_strbuf:
    mov byte [g_strbuf], 0
    ret

; print_strbuf — print g_strbuf then reset it
print_strbuf:
    mov rdi, g_strbuf
    call print_str
    mov byte [g_strbuf], 0
    ret

; ----------------------------------------------------------------------------
; update_score — add score byte to totals, increment counters
;   al = score (SCORE_FULL/MINOR/MAYBE/NONE)
; ----------------------------------------------------------------------------
update_score:
    movzx rax, al
    add  [g_score_sum], rax
    inc  qword [g_item_count]
    cmp  al, SCORE_FULL
    je   .us_full
    cmp  al, SCORE_MINOR
    je   .us_minor
    cmp  al, SCORE_MAYBE
    je   .us_maybe
    inc  qword [g_cnt_none]
    ret
.us_full:
    inc  qword [g_cnt_full]
    ret
.us_minor:
    inc  qword [g_cnt_minor]
    ret
.us_maybe:
    inc  qword [g_cnt_maybe]
    ret

; ----------------------------------------------------------------------------
; print_item — print one compatibility item
;   rdi = category string
;   rsi = name string
;   rdx = detail string
;   rcx = recommendation string
;   r8b = score byte
; ----------------------------------------------------------------------------
print_item:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov r12, rdi            ; category
    mov r13, rsi            ; name
    mov r14, rdx            ; detail
    mov r15, rcx            ; recommendation
    movzx rbx, r8b          ; score

    ; ── category header line ─────────────────────────────────────────────
    mov rdi, str_bar_open
    call print_str
    mov rdi, r12
    call print_str
    mov rdi, str_nl
    call print_str

    ; ── name line: │  ICON  LABEL  name ─────────────────────────────────
    mov rdi, str_bar_item
    call print_str

    ; icon
    cmp rbx, SCORE_FULL
    je .pi_full
    cmp rbx, SCORE_MINOR
    je .pi_minor
    cmp rbx, SCORE_MAYBE
    je .pi_maybe
    mov rdi, icon_none
    jmp .pi_icon_done
.pi_full:
    mov rdi, icon_full
    jmp .pi_icon_done
.pi_minor:
    mov rdi, icon_minor
    jmp .pi_icon_done
.pi_maybe:
    mov rdi, icon_maybe
.pi_icon_done:
    call print_str
    mov rdi, str_space
    call print_str

    ; label
    cmp rbx, SCORE_FULL
    je .pi_lbl_full
    cmp rbx, SCORE_MINOR
    je .pi_lbl_minor
    cmp rbx, SCORE_MAYBE
    je .pi_lbl_maybe
    mov rdi, label_none
    jmp .pi_lbl_done
.pi_lbl_full:
    mov rdi, label_full
    jmp .pi_lbl_done
.pi_lbl_minor:
    mov rdi, label_minor
    jmp .pi_lbl_done
.pi_lbl_maybe:
    mov rdi, label_maybe
.pi_lbl_done:
    call print_str
    mov rdi, str_space
    call print_str

    ; name
    mov rdi, r13
    call print_str
    mov rdi, str_nl
    call print_str

    ; ── detail line ──────────────────────────────────────────────────────
    mov rdi, str_bar_detail
    call print_str
    mov rdi, r14
    call print_str
    mov rdi, S_RESET
    call print_str
    mov rdi, str_nl
    call print_str

    ; ── recommendation line ───────────────────────────────────────────────
    mov rdi, str_bar_rec
    call print_str
    mov rdi, r15
    call print_str
    mov rdi, S_RESET
    call print_str
    mov rdi, str_nl
    call print_str

    ; ── separator ─────────────────────────────────────────────────────────
    mov rdi, str_bar_sep
    call print_str

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; ── ANALYZERS ────────────────────────────────────────────────────────────────
; =============================================================================

; =============================================================================
; analyze_cpu
; =============================================================================
analyze_cpu:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; read /proc/cpuinfo
    mov rdi, path_cpuinfo
    call read_file
    mov r12, rax            ; bytes read

    ; ── vendor_id ─────────────────────────────────────────────────────────
    mov rdi, g_buf
    mov rsi, r12
    mov rdx, key_vendor_id
    lea r8, [g_linebuf]
    mov r9, LINEBUF_SIZE - 1
    call find_key_value
    ; g_linebuf now has e.g. "GenuineIntel"
    ; check Intel
    lea rdi, [g_linebuf]
    mov rsi, key_intel_vi
    call str_contains
    mov r13, rax            ; r13 = 1 if Intel
    ; check AMD
    lea rdi, [g_linebuf]
    mov rsi, key_amd_vi
    call str_contains
    mov r14, rax            ; r14 = 1 if AMD

    ; ── model name ────────────────────────────────────────────────────────
    ; reuse g_strbuf for the name
    call clear_strbuf
    mov rdi, g_buf
    mov rsi, r12
    mov rdx, key_model_name
    lea r8, [g_linebuf]
    mov r9, LINEBUF_SIZE - 1
    call find_key_value
    test rax, rax
    jz .cpu_no_model
    ; copy to strbuf
    lea rdi, [g_linebuf]
    call append_str
    jmp .cpu_name_done
.cpu_no_model:
    ; fall back to vendor string
    lea rdi, [g_linebuf]   ; still has vendor_id from above
    call append_str
.cpu_name_done:

    ; ── cpu MHz ───────────────────────────────────────────────────────────
    mov rdi, g_buf
    mov rsi, r12
    mov rdx, key_cpu_mhz
    lea r8, [g_linebuf]
    mov r9, LINEBUF_SIZE - 1
    call find_key_value
    xor r15, r15
    test rax, rax
    jz .cpu_no_mhz
    lea rdi, [g_linebuf]
    call parse_u64_str
    mov r15, rax            ; r15 = MHz (integer part)
.cpu_no_mhz:

    ; ── count logical cores (count "processor" lines) ─────────────────────
    ; simple approach: count occurrences of "processor" as key
    mov qword [g_cpu_cores], 0
    lea rdi, [g_buf]
    xor rbx, rbx
.cnt_loop:
    cmp rbx, r12
    jae .cnt_done
    ; look for "processor" at start of line
    cmp byte [rdi + rbx], 'p'
    jne .cnt_next
    ; quick 9-char match "processor"
    lea rsi, [rdi + rbx]
    cmp byte [rsi+0], 'p'
    jne .cnt_next
    cmp byte [rsi+1], 'r'
    jne .cnt_next
    cmp byte [rsi+2], 'o'
    jne .cnt_next
    cmp byte [rsi+3], 'c'
    jne .cnt_next
    cmp byte [rsi+4], 'e'
    jne .cnt_next
    cmp byte [rsi+5], 's'
    jne .cnt_next
    cmp byte [rsi+6], 's'
    jne .cnt_next
    cmp byte [rsi+7], 'o'
    jne .cnt_next
    cmp byte [rsi+8], 'r'
    jne .cnt_next
    inc qword [g_cpu_cores]
.cnt_next:
    inc rbx
    jmp .cnt_loop
.cnt_done:
    mov rax, [g_cpu_cores]
    test rax, rax
    jnz .cores_ok
    mov qword [g_cpu_cores], 1
.cores_ok:

    ; ── build detail string ───────────────────────────────────────────────
    ; build in g_strbuf (but name is already there, so we need separate buf)
    ; We'll print name from strbuf, then build detail separately.
    ; Save name: it's in g_strbuf. We'll print the item at the end.

    ; Determine score
    cmp r13, 1
    je .cpu_x86
    cmp r14, 1
    je .cpu_x86
    ; non-x86
    mov al, SCORE_MAYBE
    jmp .cpu_emit
.cpu_x86:
    mov al, SCORE_FULL

.cpu_emit:
    push rax                ; save score

    ; -- build detail -------------------------------------------------
    ; detail lives in g_linebuf (we'll overwrite it now that we're done)
    mov byte [g_linebuf], 0

    ; "Intel CPU | " or "AMD CPU | " or "Non-x86 CPU | "
    cmp r13, 1
    je .det_intel
    cmp r14, 1
    je .det_amd
    lea rdi, [det_cpu_other]
    call .ap_linebuf
    jmp .det_cores
.det_intel:
    lea rdi, [det_cpu_intel]
    call .ap_linebuf
    jmp .det_cores
.det_amd:
    lea rdi, [det_cpu_amd]
    call .ap_linebuf

.det_cores:
    ; append core count
    mov rdi, [g_cpu_cores]
    call u64_to_str
    lea rdi, [g_numbuf]
    call .ap_linebuf
    lea rdi, [det_cpu_cores]
    call .ap_linebuf
    ; MHz
    cmp r15, 0
    je .det_no_mhz
    mov rdi, r15
    call u64_to_str
    lea rdi, [g_numbuf]
    call .ap_linebuf
    lea rdi, [str_mhz]
    call .ap_linebuf
.det_no_mhz:

    pop rax                 ; restore score

    ; emit item
    lea rdi, [cat_cpu]
    lea rsi, [g_strbuf]     ; name (built above)
    lea rdx, [g_linebuf]    ; detail
    cmp r13, 1
    je .cpu_rec_intel
    cmp r14, 1
    jne .cpu_rec_arm
.cpu_rec_intel:
    lea rcx, [rec_cpu_ok]
    jmp .cpu_print
.cpu_rec_arm:
    lea rcx, [rec_cpu_arm]
.cpu_print:
    mov r8b, al
    call print_item
    call update_score

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; local helper: append rdi (NUL-terminated) to g_linebuf
.ap_linebuf:
    push rbx
    push r12
    mov r12, rdi
    lea rdi, [g_linebuf]
    call str_len
    mov rbx, rax            ; rbx = current end
.apl_loop:
    mov al, [r12]
    mov [g_linebuf + rbx], al
    test al, al
    jz .apl_done
    inc r12
    inc rbx
    jmp .apl_loop
.apl_done:
    pop r12
    pop rbx
    ret

; =============================================================================
; analyze_ram
; =============================================================================
analyze_ram:
    push rbx
    push r12

    mov rdi, path_meminfo
    call read_file
    mov r12, rax

    xor rbx, rbx            ; rbx = MB
    test r12, r12
    jz .ram_fail

    mov rdi, g_buf
    mov rsi, r12
    mov rdx, key_memtotal
    lea r8, [g_linebuf]
    mov r9, LINEBUF_SIZE - 1
    call find_key_value
    test rax, rax
    jz .ram_fail

    ; value is in kB (Linux MemTotal is in kB)
    lea rdi, [g_linebuf]
    call parse_u64_str
    ; rax = kB, divide by 1024 → MB
    xor rdx, rdx
    mov rbx, 1024
    div rbx
    mov rbx, rax            ; rbx = MB

.ram_classify:
    ; build name: "System Memory: X MB (Y GB)"
    call clear_strbuf
    lea rdi, [str_mb + 1]   ; hack: use "System Memory: " prefix via direct prints
    ; We'll build in g_strbuf via append_str
    ; strbuf = "X MB (Y GB)"
    mov rdi, rbx
    call u64_to_str
    lea rdi, [g_numbuf]
    call append_str
    lea rdi, [str_mb]
    call append_str
    lea rdi, [str_space]
    call append_str
    ; GB
    mov rax, rbx
    xor rdx, rdx
    mov rcx, 1024
    div rcx
    mov rdi, rax
    call u64_to_str
    lea rdi, [g_numbuf]
    call append_str
    lea rdi, [str_gb]
    call append_str

    ; detail and score
    cmp rbx, 2048
    jl .ram_bad
    cmp rbx, 4096
    jl .ram_minor
    ; full
    mov al, SCORE_FULL
    push rax
    lea rdx, [det_ram_ok_d]
    lea rcx, [rec_ram_ok]
    jmp .ram_emit
.ram_minor:
    mov al, SCORE_MINOR
    push rax
    lea rdx, [det_ram_minor_d]
    lea rcx, [rec_ram_minor]
    jmp .ram_emit
.ram_bad:
    mov al, SCORE_NONE
    push rax
    lea rdx, [det_ram_bad_d]
    lea rcx, [rec_ram_bad]
.ram_emit:
    lea rdi, [cat_ram]
    lea rsi, [g_strbuf]
    mov r8b, [rsp]
    call print_item
    pop rax
    call update_score
    pop r12
    pop rbx
    ret

.ram_fail:
    call clear_strbuf
    lea rdi, [str_unknown]
    call append_str
    mov al, SCORE_MAYBE
    lea rdi, [cat_ram]
    lea rsi, [g_strbuf]
    lea rdx, [str_unknown]
    lea rcx, [str_na]
    mov r8b, al
    call print_item
    call update_score
    pop r12
    pop rbx
    ret

; =============================================================================
; analyze_disk
; =============================================================================
analyze_disk:
    push rbx
    push r12
    push r13

    ; statfs("/")
    mov rax, SYS_STATFS
    lea rdi, [slash_path]
    lea rsi, [g_statfs]
    syscall
    test rax, rax
    js .disk_fail

    ; struct statfs (Linux x86-64):
    ;   +0:  f_type   (8 bytes)
    ;   +8:  f_bsize  (8 bytes) — block size
    ;   +16: f_blocks (8 bytes) — total blocks
    ;   +24: f_bfree  (8 bytes) — free blocks (root)
    ;   +32: f_bavail (8 bytes) — free blocks (non-root)

    mov r12, [g_statfs + 8]     ; block size
    mov r13, [g_statfs + 32]    ; bavail (available blocks)
    mov rbx, [g_statfs + 16]    ; total blocks

    ; total_bytes = f_blocks * f_bsize
    mov rax, rbx
    mul r12                 ; rax = total bytes
    ; → GB
    mov rcx, 1024*1024*1024
    xor rdx, rdx
    div rcx
    mov rbx, rax            ; rbx = total GB

    ; free_bytes = f_bavail * f_bsize
    mov rax, r13
    mul r12
    xor rdx, rdx
    div rcx
    mov r13, rax            ; r13 = free GB

    ; detect disk type via /sys/block
    ; NVMe: check /sys/block/nvme0n1
    ; SSD: check rotational flag /sys/block/sda/queue/rotational
    ; Simplified detection: try to open /sys/block/nvme0n1 first
    mov qword [g_disk_type], 0  ; 0=HDD default
    mov rdi, path_nvme_blk
    call path_exists
    test rax, rax
    jz .try_ssd
    mov qword [g_disk_type], 2  ; NVMe
    jmp .disk_type_done
.try_ssd:
    mov rdi, path_rotational
    call read_file
    test rax, rax
    jz .disk_type_done
    ; if rotational == 0, it's SSD
    mov al, [g_buf]
    cmp al, '0'
    jne .disk_type_done
    mov qword [g_disk_type], 1  ; SATA SSD
.disk_type_done:

    ; build name
    call clear_strbuf
    ; "X GB free / Y GB total [type]"
    mov rdi, r13
    call u64_to_str
    lea rdi, [g_numbuf]
    call append_str
    lea rdi, [str_gb]
    call append_str
    lea rdi, [det_disk_free]
    call append_str
    mov rdi, rbx
    call u64_to_str
    lea rdi, [g_numbuf]
    call append_str
    lea rdi, [str_gb]
    call append_str
    lea rdi, [str_space]
    call append_str
    lea rdi, [det_disk_type]
    call append_str
    mov rax, [g_disk_type]
    cmp rax, 2
    je .dn_nvme
    cmp rax, 1
    je .dn_ssd
    lea rdi, [str_hdd]
    jmp .dn_done
.dn_nvme:
    lea rdi, [str_nvme_ssd]
    jmp .dn_done
.dn_ssd:
    lea rdi, [str_sata_ssd]
.dn_done:
    call append_str
    lea rdi, [det_disk_close]
    call append_str

    ; score and recommendation
    cmp r13, 20
    jl .disk_bad
    cmp r13, 50
    jl .disk_minor
    ; full
    mov al, SCORE_FULL
    push rax
    ; recommendation depends on disk type
    mov rax, [g_disk_type]
    cmp rax, 2
    je .dk_rec_nvme
    cmp rax, 1
    je .dk_rec_ssd
    lea rcx, [rec_disk_hdd]
    lea rdx, [det_disk_ok_d]
    jmp .disk_emit
.dk_rec_nvme:
    lea rcx, [rec_disk_nvme]
    lea rdx, [det_disk_ok_d]
    jmp .disk_emit
.dk_rec_ssd:
    lea rcx, [rec_disk_ssd]
    lea rdx, [det_disk_ok_d]
    jmp .disk_emit
.disk_minor:
    mov al, SCORE_MINOR
    push rax
    lea rdx, [det_disk_min_d]
    lea rcx, [rec_disk_minor]
    jmp .disk_emit
.disk_bad:
    mov al, SCORE_NONE
    push rax
    lea rdx, [det_disk_bad_d]
    lea rcx, [rec_disk_bad]
.disk_emit:
    lea rdi, [cat_disk]
    lea rsi, [g_strbuf]
    mov r8b, [rsp]
    call print_item
    pop rax
    call update_score
    pop r13
    pop r12
    pop rbx
    ret

.disk_fail:
    call clear_strbuf
    lea rdi, [str_unknown]
    call append_str
    mov al, SCORE_MAYBE
    lea rdi, [cat_disk]
    lea rsi, [g_strbuf]
    lea rdx, [str_unknown]
    lea rcx, [str_na]
    mov r8b, al
    call print_item
    call update_score
    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; analyze_gpu
; =============================================================================
analyze_gpu:
    push r12
    push r13

    ; read vendor id
    mov rdi, path_vendor
    call read_file
    mov r12, rax
    test r12, r12
    jz .gpu_unknown

    ; g_buf has e.g. "0x8086\n"
    ; strip newline
    lea rdi, [g_buf]
    call str_len
    test rax, rax
    jz .gpu_unknown
    dec rax
    cmp byte [g_buf + rax], 10
    jne .gpu_vendor_ok
    mov byte [g_buf + rax], 0
.gpu_vendor_ok:

    ; check vendor
    lea rdi, [g_buf]
    lea rsi, [gpu_intel_id]
    call str_contains_ci
    cmp rax, 1
    je .gpu_intel
    lea rdi, [g_buf]
    lea rsi, [gpu_amd_id]
    call str_contains_ci
    cmp rax, 1
    je .gpu_amd
    lea rdi, [g_buf]
    lea rsi, [gpu_nvidia_id]
    call str_contains_ci
    cmp rax, 1
    je .gpu_nvidia

.gpu_unknown:
    lea rdi, [cat_gpu]
    lea rsi, [gpu_name_unk]
    lea rdx, [det_gpu_unk_d]
    lea rcx, [rec_gpu_unk]
    mov r8b, SCORE_MAYBE
    call print_item
    mov al, SCORE_MAYBE
    call update_score
    pop r13
    pop r12
    ret

.gpu_intel:
    lea rdi, [cat_gpu]
    lea rsi, [gpu_name_intel]
    lea rdx, [det_gpu_intel_d]
    lea rcx, [rec_gpu_intel]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    pop r13
    pop r12
    ret

.gpu_amd:
    lea rdi, [cat_gpu]
    lea rsi, [gpu_name_amd]
    lea rdx, [det_gpu_amd_d]
    lea rcx, [rec_gpu_amd]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    pop r13
    pop r12
    ret

.gpu_nvidia:
    lea rdi, [cat_gpu]
    lea rsi, [gpu_name_nvidia]
    lea rdx, [det_gpu_nvidia_d]
    lea rcx, [rec_gpu_nvidia]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score
    pop r13
    pop r12
    ret

; =============================================================================
; analyze_network
; =============================================================================
; Strategy: open /sys/class/net, use getdents64 to enumerate interfaces,
; for each check /sys/class/net/<iface>/wireless to detect Wi-Fi.
; We count wired and wireless; report based on presence.
; =============================================================================
analyze_network:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    ; open directory
    mov rax, SYS_OPEN
    lea rdi, [path_net]
    mov rsi, O_RDONLY | O_DIRECTORY
    xor rdx, rdx
    syscall
    test rax, rax
    js .net_fail
    mov r12, rax            ; r12 = dir fd

    mov r13, 0              ; wired count
    mov r14, 0              ; wifi count

.getdents_loop:
    mov rax, SYS_GETDENTS64
    mov rdi, r12
    lea rsi, [g_dirbuf]
    mov rdx, DIRBUF_SIZE
    syscall
    test rax, rax
    jle .net_getdents_done
    mov r15, rax            ; bytes returned
    xor rbx, rbx           ; offset

.parse_entry:
    cmp rbx, r15
    jae .getdents_loop

    ; struct linux_dirent64:
    ;   +0:  d_ino   (8 bytes)
    ;   +8:  d_off   (8 bytes)
    ;   +16: d_reclen (2 bytes)
    ;   +18: d_type  (1 byte)
    ;   +19: d_name  (variable)
    lea rsi, [g_dirbuf + rbx]
    movzx rdx, word [rsi + 16]  ; d_reclen
    test rdx, rdx
    jz .net_getdents_done

    ; skip . and ..
    lea rdi, [rsi + 19]     ; d_name
    mov al, [rdi]
    cmp al, '.'
    je .next_entry_net
    cmp al, 0
    je .next_entry_net

    ; skip "lo" (loopback)
    cmp byte [rdi], 'l'
    jne .net_check_iface
    cmp byte [rdi+1], 'o'
    jne .net_check_iface
    cmp byte [rdi+2], 0
    jne .net_check_iface
    jmp .next_entry_net

.net_check_iface:
    ; build path: /sys/class/net/<iface>/wireless
    lea rdi, [g_pathbuf]
    ; copy path_net
    mov rsi, path_net
    call .strcpy_local
    ; append /
    call .append_slash
    ; append iface name
    lea rsi, [g_dirbuf + rbx + 19]
    call .strcpy_local
    ; append /wireless
    mov rsi, path_wireless
    call .strcpy_local

    ; check if wireless path exists
    lea rdi, [g_pathbuf]
    call path_exists
    test rax, rax
    jz .net_wired
    inc r14                 ; wifi found
    jmp .next_entry_net
.net_wired:
    inc r13                 ; wired

.next_entry_net:
    add rbx, rdx
    jmp .parse_entry

.net_getdents_done:
    ; close dir
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

    ; decide result
    mov rax, r13
    add rax, r14
    test rax, rax
    jz .net_none

    ; build name
    call clear_strbuf
    ; "Wired: X  Wi-Fi: Y"
    mov rdi, r13
    call u64_to_str
    lea rdi, [g_numbuf]
    call append_str
    lea rdi, [net_wired_str]
    call append_str
    mov rdi, r14
    call u64_to_str
    lea rdi, [g_numbuf]
    call append_str
    lea rdi, [net_wifi_str]
    call append_str

    ; score: if any wifi, minor (drivers vary); if only wired, full
    cmp r14, 0
    jg .net_has_wifi
    ; wired only
    lea rdi, [cat_net]
    lea rsi, [g_strbuf]
    lea rdx, [rec_net_eth]
    lea rcx, [rec_net_intel]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    jmp .net_done

.net_has_wifi:
    lea rdi, [cat_net]
    lea rsi, [g_strbuf]
    lea rdx, [rec_net_wifi]
    lea rcx, [rec_net_wifi]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score
    jmp .net_done

.net_none:
    lea rdi, [cat_net]
    lea rsi, [det_net_none_d]
    lea rdx, [det_net_none_d]
    lea rcx, [str_na]
    mov r8b, SCORE_MAYBE
    call print_item
    mov al, SCORE_MAYBE
    call update_score

.net_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.net_fail:
    lea rdi, [cat_net]
    lea rsi, [str_unknown]
    lea rdx, [str_unknown]
    lea rcx, [str_na]
    mov r8b, SCORE_MAYBE
    call print_item
    mov al, SCORE_MAYBE
    call update_score
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; local helpers for analyze_network
.strcpy_local:
    ; append rsi (NUL-terminated) to [rdi] (finds NUL in rdi then copies)
    ; rdi = dest buffer (find its end first)
    push rbx
    push r8
    mov r8, rdi
    ; find end of dest
    xor rbx, rbx
.scl_find_end:
    cmp byte [r8 + rbx], 0
    je .scl_end_found
    inc rbx
    jmp .scl_find_end
.scl_end_found:
.scl_copy:
    mov al, [rsi]
    mov [r8 + rbx], al
    test al, al
    jz .scl_done
    inc rsi
    inc rbx
    jmp .scl_copy
.scl_done:
    pop r8
    pop rbx
    ret

.append_slash:
    ; append '/' to g_pathbuf
    push rdi
    push rbx
    mov rbx, rdi
    xor rdi, rdi
.as_find:
    cmp byte [rbx + rdi], 0
    je .as_found
    inc rdi
    jmp .as_find
.as_found:
    mov byte [rbx + rdi], '/'
    mov byte [rbx + rdi + 1], 0
    pop rbx
    pop rdi
    ret

; =============================================================================
; analyze_audio
; =============================================================================
analyze_audio:
    push r12

    ; read /proc/asound/cards
    mov rdi, path_asound
    call read_file
    mov r12, rax
    test r12, r12
    jz .audio_none

    ; g_buf has card listing like: " 0 [PCH            ]: HDA-Intel ..."
    ; Check for known keywords
    lea rdi, [g_buf]
    lea rsi, [audio_realtek]
    call str_contains_ci
    test rax, rax
    jnz .audio_hda

    lea rdi, [g_buf]
    lea rsi, [audio_intel]
    call str_contains_ci
    test rax, rax
    jnz .audio_hda

    lea rdi, [g_buf]
    lea rsi, [audio_amd_a]
    call str_contains_ci
    test rax, rax
    jnz .audio_hda

    lea rdi, [g_buf]
    lea rsi, [audio_nvidia_a]
    call str_contains_ci
    test rax, rax
    jnz .audio_hda

    lea rdi, [g_buf]
    lea rsi, [audio_focusrite]
    call str_contains_ci
    test rax, rax
    jnz .audio_focusrite

    lea rdi, [g_buf]
    lea rsi, [audio_scarlett]
    call str_contains_ci
    test rax, rax
    jnz .audio_focusrite

    lea rdi, [g_buf]
    lea rsi, [audio_creative]
    call str_contains_ci
    test rax, rax
    jnz .audio_creative

    ; generic device found
    lea rdi, [cat_audio]
    lea rsi, [det_audio_gen_d]
    lea rdx, [det_audio_gen_d]
    lea rcx, [rec_audio_usb]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score
    pop r12
    ret

.audio_hda:
    lea rdi, [cat_audio]
    lea rsi, [det_audio_hda_d]
    lea rdx, [det_audio_hda_d]
    lea rcx, [rec_audio_hda]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    pop r12
    ret

.audio_focusrite:
    lea rdi, [cat_audio]
    lea rsi, [det_audio_foc_d]
    lea rdx, [det_audio_foc_d]
    lea rcx, [rec_audio_focus]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score
    pop r12
    ret

.audio_creative:
    lea rdi, [cat_audio]
    lea rsi, [det_audio_cre_d]
    lea rdx, [det_audio_cre_d]
    lea rcx, [rec_audio_crea]
    mov r8b, SCORE_MAYBE
    call print_item
    mov al, SCORE_MAYBE
    call update_score
    pop r12
    ret

.audio_none:
    lea rdi, [cat_audio]
    lea rsi, [det_audio_non_d]
    lea rdx, [det_audio_non_d]
    lea rcx, [str_na]
    mov r8b, SCORE_MAYBE
    call print_item
    mov al, SCORE_MAYBE
    call update_score
    pop r12
    ret

; =============================================================================
; analyze_firmware — UEFI / Secure Boot
; =============================================================================
analyze_firmware:
    ; ── UEFI check ────────────────────────────────────────────────────────
    mov rdi, path_efi
    call path_exists
    mov r8, rax             ; r8 = 1 if UEFI

    ; ── Secure Boot check ─────────────────────────────────────────────────
    ; Read the SecureBoot EFI variable (first 4 bytes are attr, byte 4 is value)
    xor r9, r9              ; r9 = secure_boot flag
    test r8, r8
    jz .fw_emit
    mov rdi, path_sb_state
    call read_file
    test rax, rax
    jz .fw_emit
    ; byte at offset 4 is the SecureBoot value (1 = enabled)
    cmp rax, 5
    jl .fw_emit
    cmp byte [g_buf + 4], 1
    jne .fw_emit
    mov r9, 1

.fw_emit:
    ; ── Firmware item ─────────────────────────────────────────────────────
    test r8, r8
    jz .fw_legacy
    lea rdi, [cat_firmware]
    lea rsi, [fw_uefi_name]
    lea rdx, [det_fw_uefi_d]
    lea rcx, [rec_fw_uefi]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    jmp .fw_sb

.fw_legacy:
    lea rdi, [cat_firmware]
    lea rsi, [fw_bios_name]
    lea rdx, [det_fw_bios_d]
    lea rcx, [rec_fw_bios]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score

.fw_sb:
    ; ── Secure Boot item ──────────────────────────────────────────────────
    test r9, r9
    jnz .sb_enabled
    lea rdi, [cat_secboot]
    lea rsi, [sb_off_name]
    lea rdx, [det_sb_off_d]
    lea rcx, [rec_sb_off]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    ret

.sb_enabled:
    lea rdi, [cat_secboot]
    lea rsi, [sb_on_name]
    lea rdx, [det_sb_on_d]
    lea rcx, [rec_sb_on]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score
    ret

; =============================================================================
; analyze_tpm
; =============================================================================
analyze_tpm:
    mov rdi, path_tpm
    call path_exists
    test rax, rax
    jz .tpm_none

    lea rdi, [cat_tpm]
    lea rsi, [tpm_ok_name]
    lea rdx, [det_tpm_ok_d]
    lea rcx, [rec_tpm_ok]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    ret

.tpm_none:
    lea rdi, [cat_tpm]
    lea rsi, [tpm_none_name]
    lea rdx, [det_tpm_none_d]
    lea rcx, [rec_tpm_none]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    ret

; =============================================================================
; analyze_virtualization
; =============================================================================
; Checks: /proc/cpuinfo "hypervisor" flag, then DMI product_name for brand.
; =============================================================================
analyze_virtualization:
    push r12

    ; read cpuinfo
    mov rdi, path_cpuinfo
    call read_file
    mov r12, rax

    ; search "hypervisor" in flags
    lea rdi, [g_buf]
    lea rsi, [key_hypervisor]
    call str_contains_ci
    test rax, rax
    jz .virt_check_dmi

    ; hypervisor present — try to get name from DMI
    call .get_hv_name       ; returns rdi = name string
    jmp .virt_emit

.virt_check_dmi:
    ; also check dmi product_name for VM strings
    mov rdi, path_dmi_prod
    call read_file
    test rax, rax
    jz .virt_none

    lea rdi, [g_buf]
    lea rsi, [virt_vmware]
    call str_contains_ci
    test rax, rax
    jnz .virt_emit_vmware
    lea rdi, [g_buf]
    lea rsi, [virt_vbox]
    call str_contains_ci
    test rax, rax
    jnz .virt_emit_vbox
    lea rdi, [g_buf]
    lea rsi, [virt_kvm]
    call str_contains_ci
    test rax, rax
    jnz .virt_emit_kvm
    lea rdi, [g_buf]
    lea rsi, [virt_qemu]
    call str_contains_ci
    test rax, rax
    jnz .virt_emit_kvm

    jmp .virt_none

.virt_emit_vmware:
    lea rdi, [virt_vmware]
    jmp .virt_emit
.virt_emit_vbox:
    lea rdi, [virt_vbox]
    jmp .virt_emit
.virt_emit_kvm:
    lea rdi, [virt_kvm]
    jmp .virt_emit

.virt_emit:
    ; rdi = hypervisor name string
    push rdi
    ; build name: "Virtual Machine: <name>"
    call clear_strbuf
    lea rsi, [det_virt_d]
    push rsi
    lea rdi, [det_virt_d]
    call append_str
    pop rsi
    pop rdi
    call append_str         ; append hv name

    lea rdi, [cat_virt]
    lea rsi, [g_strbuf]
    lea rdx, [det_virt_bare_d] ; overridden below
    ; actually use det_virt_d as detail (already in strbuf, we reuse)
    lea rdx, [g_strbuf]
    lea rcx, [rec_virt_on]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score
    pop r12
    ret

.virt_none:
    lea rdi, [cat_virt]
    lea rsi, [virt_bare_name]
    lea rdx, [det_virt_bare_d]
    lea rcx, [rec_virt_none]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    pop r12
    ret

.get_hv_name:
    ; try dmi sys_vendor for hv name
    push rax
    push rdi
    mov rdi, path_dmi_vendor
    call read_file
    pop rdi
    test rax, rax
    jz .ghvn_unknown
    ; strip newline
    lea rdi, [g_buf]
    call str_len
    test rax, rax
    jz .ghvn_unknown
    dec rax
    cmp byte [g_buf + rax], 10
    jne .ghvn_ret
    mov byte [g_buf + rax], 0
.ghvn_ret:
    lea rdi, [g_buf]
    pop rax
    ret
.ghvn_unknown:
    lea rdi, [str_unknown]
    pop rax
    ret

; =============================================================================
; analyze_online
; =============================================================================
; Check /proc/net/route for a default gateway (destination 00000000).
; =============================================================================
analyze_online:
    mov rdi, path_route
    call read_file
    test rax, rax
    jz .online_no

    ; search for "00000000" in buf (default route destination field)
    lea rdi, [g_buf]
    lea rsi, [key_00000000]
    call str_contains
    test rax, rax
    jz .online_no

.online_ok:
    lea rdi, [cat_online]
    lea rsi, [online_ok_name]
    lea rdx, [det_online_ok_d]
    lea rcx, [rec_online_ok]
    mov r8b, SCORE_FULL
    call print_item
    mov al, SCORE_FULL
    call update_score
    ret

.online_no:
    lea rdi, [cat_online]
    lea rsi, [online_no_name]
    lea rdx, [det_online_no_d]
    lea rcx, [rec_online_no]
    mov r8b, SCORE_MINOR
    call print_item
    mov al, SCORE_MINOR
    call update_score
    ret

; =============================================================================
; compute_summary — calculate g_pct
; Formula: pct = (item_count*3 - score_sum) / (item_count*3) * 100
; =============================================================================
compute_summary:
    mov rax, [g_item_count]
    test rax, rax
    jz .cs_zero
    mov rbx, [g_score_sum]
    mov rcx, rax
    imul rcx, rcx, 3        ; max possible = count*3
    sub rcx, rbx            ; weighted compat points
    imul rcx, rcx, 100
    ; divide by max possible
    mov rax, rcx
    cqo
    mov rbx, [g_item_count]
    imul rbx, rbx, 3
    idiv rbx
    mov [g_pct], rax
    ret
.cs_zero:
    mov qword [g_pct], 0
    ret

; =============================================================================
; print_report — print detailed report and summary
; =============================================================================
print_report:
    ; ── Detailed report header ────────────────────────────────────────────
    mov rdi, divider
    call print_str
    mov rdi, S_BOLD
    call print_str
    mov rdi, S_WHITE
    call print_str
    lea rdi, [rep_hdr]
    call print_str
    mov rdi, S_RESET
    call print_str
    mov rdi, divider
    call print_str
    mov rdi, str_nl
    call print_str

    ; ── Summary statistics ────────────────────────────────────────────────
    mov rdi, sum_hdr
    call print_str

    mov rdi, sum_full
    call print_str
    mov rdi, [g_cnt_full]
    call print_u64
    mov rdi, str_comp
    call print_str

    mov rdi, sum_minor
    call print_str
    mov rdi, [g_cnt_minor]
    call print_u64
    mov rdi, str_comp
    call print_str

    mov rdi, sum_maybe
    call print_str
    mov rdi, [g_cnt_maybe]
    call print_u64
    mov rdi, str_comp
    call print_str

    mov rdi, sum_none
    call print_str
    mov rdi, [g_cnt_none]
    call print_u64
    mov rdi, str_comp
    call print_str

    mov rdi, sum_total
    call print_str
    mov rdi, [g_item_count]
    call print_u64
    mov rdi, str_nl
    call print_str

    ; ── Percent bar ───────────────────────────────────────────────────────
    mov rdi, sum_score
    call print_str
    mov rdi, [g_pct]
    call print_percent_bar
    mov rdi, str_nl
    call print_str

    ; ── Assessment ────────────────────────────────────────────────────────
    mov rdi, assess_hdr
    call print_str
    mov rax, [g_pct]
    cmp rax, 85
    jae .pr_ready
    cmp rax, 65
    jae .pr_mostly
    cmp rax, 40
    jae .pr_moderate
    mov rdi, assess_bad
    call print_str
    jmp .pr_distros
.pr_ready:
    mov rdi, assess_ready
    call print_str
    jmp .pr_distros
.pr_mostly:
    mov rdi, assess_mostly
    call print_str
    jmp .pr_distros
.pr_moderate:
    mov rdi, assess_moderate
    call print_str

.pr_distros:
    mov rdi, distro_hdr
    call print_str
    mov rdi, distro_list
    call print_str
    ret

; =============================================================================
; print_percent_bar — colored ASCII progress bar
;   rdi = percentage (0–100)
; =============================================================================
print_percent_bar:
    push rbx
    push r12
    push r13

    mov r12, rdi            ; r12 = pct
    mov r13, 40             ; bar width

    ; pick color
    cmp r12, 75
    jae .bar_green
    cmp r12, 50
    jae .bar_yellow
    mov rdi, S_RED
    jmp .bar_color_done
.bar_green:
    mov rdi, S_GREEN
    jmp .bar_color_done
.bar_yellow:
    mov rdi, S_YELLOW
.bar_color_done:
    call print_str
    mov rdi, S_BOLD
    call print_str

    ; opening bracket
    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [bracket_open]
    mov rdx, 1
    syscall

    ; filled = pct * width / 100
    mov rax, r12
    imul rax, r13
    xor rdx, rdx
    mov rbx, 100
    div rbx
    mov rbx, rax            ; rbx = filled cells

    xor rcx, rcx
.bar_loop:
    cmp rcx, r13
    jge .bar_done
    cmp rcx, rbx
    jl .bar_fill
    ; empty
    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [bar_empty]
    mov rdx, 3              ; 3 UTF-8 bytes for ░
    syscall
    jmp .bar_next
.bar_fill:
    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [bar_filled]
    mov rdx, 3              ; 3 UTF-8 bytes for █
    syscall
.bar_next:
    inc rcx
    jmp .bar_loop

.bar_done:
    ; closing bracket
    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [bracket_close]
    mov rdx, 1
    syscall

    mov rdi, S_RESET
    call print_str
    mov rdi, str_space
    call print_str
    mov rdi, r12
    call print_u64
    lea rdi, [str_pct]
    call print_str

    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; Additional .data items referenced above
; =============================================================================
SECTION .data

; Bracket characters for progress bar
bracket_open    db "["
bracket_close   db "]"

; Disk paths for type detection
path_nvme_blk   db "/sys/block/nvme0n1",0
path_rotational db "/sys/block/sda/queue/rotational",0
slash_path      db "/",0

; Network name strings
net_wired_str   db " wired / ",0
net_wifi_str    db " Wi-Fi",0

; Firmware item names
fw_uefi_name    db "UEFI Firmware",0
fw_bios_name    db "Legacy BIOS",0
sb_on_name      db "Secure Boot: Enabled",0
sb_off_name     db "Secure Boot: Disabled",0

; TPM item names
tpm_ok_name     db "TPM: Present",0
tpm_none_name   db "TPM: Not detected",0

; Virtualization item names
virt_bare_name  db "Bare metal — no hypervisor detected",0

; Online item names
online_ok_name  db "Internet: Connected",0
online_no_name  db "Internet: Offline / No default gateway",0

; Report header
rep_hdr         db 10,"  ",0xF0,0x9F,0x93,0x8B," COMPATIBILITY REPORT",10,0
