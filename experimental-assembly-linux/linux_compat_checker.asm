; Linux-compatible NASM version of a hardware compatibility checker.
; This program inspects /proc and /sys, evaluates compatibility, and
; prints a summary with scores for CPU, RAM, disk, GPU, network, audio,
; firmware, TPM, virtualization, and online connectivity.
;
; Assemble and link:
;   nasm -f elf64 linux_compat_checker.asm -o linux_compat_checker.o
;   ld linux_compat_checker.o -o linux_compat_checker

BITS 64
DEFAULT REL

SECTION .data
header1         db "Linux Kernel Compatibility Checker", 10, 0
header2         db "Local Linux hardware readiness report", 10, 0
separator       db "============================================", 10, 0
cpu_label       db "CPU: ", 0
ram_label       db "RAM: ", 0
disk_label      db "Disk /: ", 0
gpu_label       db "GPU: ", 0
net_label       db "Network: ", 0
audio_label     db "Audio: ", 0
fw_label        db "Firmware: ", 0
tpm_label       db "TPM: ", 0
virt_label      db "Virtualization: ", 0
online_label    db "Internet: ", 0
ok_text         db "OK", 0
minor_text      db "Minor issues", 0
maybe_text      db "Possibly incompatible", 0
none_text       db "Incompatible", 0
unknown_text    db "Unknown", 0
ready_text      db "Ready for Linux.", 10, 0
mostly_text     db "Mostly compatible. Some drivers may need configuration.", 10, 0
moderate_text   db "Moderate compatibility. Test with live media before installing.", 10, 0
bad_text        db "Serious compatibility issues detected.", 10, 0
summary_title   db "Summary compatibility: ", 0
percent_suffix  db "%%", 10, 0
cpuinfo_path    db "/proc/cpuinfo", 0
meminfo_path    db "/proc/meminfo", 0
vendor_path     db "/sys/class/drm/card0/device/vendor", 0
device_path     db "/sys/class/drm/card0/device/device", 0
asound_path     db "/proc/asound/cards", 0
efi_path        db "/sys/firmware/efi", 0
tpm_path        db "/sys/class/tpm", 0
net_dir_path    db "/sys/class/net", 0
route_path      db "/proc/net/route", 0
route_marker    db "00000000", 0
debug_virt      db "DBG-VIRT", 10, 0
debug_virt_read db "DBG-VIRT-READ", 10, 0
debug_virt_search db "DBG-VIRT-SEARCH", 10, 0
debug_online    db "DBG-ONLINE", 10, 0
product_name    db "/sys/class/dmi/id/product_name", 0
wireless_suf    db "/wireless", 0
hypervisor_key  db "hypervisor", 0
vendor_id_key   db "vendor_id", 0
model_key       db "model name", 0
memtotal_key    db "MemTotal", 0
intel_tag       db "intel", 0
amd_tag         db "amd", 0
nvidia_tag      db "NVIDIA", 0
radeon_tag      db "AMD", 0
intel_gpu_tag   db "8086", 0
amd_gpu_tag     db "1002", 0
nvidia_gpu_tag  db "10de", 0
vmware_tag      db "vmware", 0
vbox_tag        db "virtualbox", 0
kvm_tag         db "kvm", 0
hyperv_tag      db "microsoft", 0
newline         db 10
zero_char       db '0', 0
slash_char      db '/', 0

SECTION .bss
buf             resb 32768
linebuf         resb 256
numbuf          resb 32
tmpbuf          resb 128
dirbuf          resb 4096
statfs_buf      resb 96
pathbuf         resb 128
item_count      resq 1
score_sum       resq 1
summary_pct     resq 1

SECTION .text
GLOBAL _start

_start:
    mov qword [item_count], 0
    mov qword [score_sum], 0

    mov rdi, header1
    call print_str
    mov rdi, header2
    call print_str
    mov rdi, separator
    call print_str

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

    call compute_summary
    call print_summary

    mov rax, 60
    xor rdi, rdi
    syscall

; ---------------------------------------------------------------------------
; Helper routines
; ---------------------------------------------------------------------------
print_str:
    mov rsi, rdi
    call strlen
    mov rdx, rax
    mov rax, 1
    mov rdi, 1
    syscall
    ret

print_char:
    mov rax, 1
    mov rdi, 1
    mov rsi, rdi
    mov rdx, 1
    syscall
    ret

strlen:
    xor rax, rax
.len_loop:
    cmp byte [rdi + rax], 0
    je .len_done
    inc rax
    jmp .len_loop
.len_done:
    ret

print_number:
    mov rax, rsi
    mov r10, rdi
    mov rcx, 0
    test rax, rax
    jnz .num_loop
    mov byte [r10], '0'
    mov byte [r10+1], 0
    ret
.num_loop:
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    mov [tmpbuf + rcx], dl
    inc rcx
    test rax, rax
    jnz .num_loop
    mov r11, rcx
    mov r12, rcx
    xor rcx, rcx
.rev_loop:
    dec r11
    mov al, [tmpbuf + r11]
    mov [r10 + rcx], al
    inc rcx
    cmp rcx, r12
    jne .rev_loop
    mov byte [r10 + rcx], 0
    ret

read_file:
    mov rax, 2
    mov rsi, 0
    mov rdx, 0
    syscall
    cmp rax, 0
    js .read_fail
    mov r12, rax
    mov rdi, r12
    mov rsi, buf
    mov rdx, 32768
    mov rax, 0
    syscall
    mov r13, rax
    mov rdi, r12
    mov rax, 3
    syscall
    mov rax, r13
    ret
.read_fail:
    xor rax, rax
    ret

file_exists:
    mov rax, 2
    mov rsi, 0
    mov rdx, 0
    syscall
    cmp rax, 0
    js .exists_no
    mov rdi, rax
    mov rax, 3
    syscall
    mov rax, 1
    ret
.exists_no:
    xor rax, rax
    ret

extract_key_value:
    ; rdi = buffer, rsi = len, rdx = key, rcx = key_len, r8 = dest, r9 = maxlen
    push rbx
    push r12
    call find_substring
    cmp rax, -1
    je .fail
    mov r12, rax
    add r12, rcx
.skip_colon:
    cmp r12, rsi
    jae .fail
    mov al, [rdi + r12]
    cmp al, ':'
    je .after_colon
    inc r12
    jmp .skip_colon
.after_colon:
    inc r12
.skip_spaces:
    cmp r12, rsi
    jae .fail
    mov al, [rdi + r12]
    cmp al, ' '
    je .next_char
    cmp al, 9
    je .next_char
    jmp .copy_value
.next_char:
    inc r12
    jmp .skip_spaces
.copy_value:
    xor rbx, rbx
.copy_loop:
    cmp r12, rsi
    jae .done
    mov al, [rdi + r12]
    cmp al, 10
    je .done
    cmp al, 13
    je .done
    cmp rbx, r9
    jae .done
    mov [r8 + rbx], al
    inc rbx
    inc r12
    jmp .copy_loop
.done:
    mov byte [r8 + rbx], 0
    cmp rbx, 0
    je .fail
    mov rax, 1
    pop r12
    pop rbx
    ret
.fail:
    xor rax, rax
    pop r12
    pop rbx
    ret

find_substring:
    ; rdi = base, rsi = len, rdx = needle, rcx = needle_len
    cmp rcx, 0
    je .no_match
    mov r8, rsi
    sub r8, rcx
    jb .no_match
    xor rax, rax
.outer:
    cmp rax, r8
    ja .no_match
    xor rbx, rbx
.inner:
    lea r9, [rdi + rax]
    mov dl, [r9 + rbx]
    cmp dl, [rdx + rbx]
    jne .next_pos
    inc rbx
    cmp rbx, rcx
    jne .inner
    ret
.next_pos:
    inc rax
    jmp .outer
.no_match:
    mov rax, -1
    ret

str_contains:
    ; rdi = haystack, rsi = needle
    push rbx
    push r12
    mov r10, rdi
    mov r11, rsi
    call strlen
    mov r8, rax
    mov rdi, r11
    call strlen
    mov r9, rax
    cmp r9, 0
    je .not_found
    xor rax, rax
.search_outer:
    cmp rax, r8
    ja .not_found
    xor rbx, rbx
.search_inner:
    cmp rbx, r9
    je .found
    lea rdx, [r10 + rax]
    mov al, [rdx + rbx]
    call to_lower
    mov dl, al
    mov al, [r11 + rbx]
    call to_lower
    cmp dl, al
    jne .outer_next
    inc rbx
    jmp .search_inner
.outer_next:
    inc rax
    jmp .search_outer
.found:
    mov rax, 1
    jmp .cleanup
.not_found:
    xor rax, rax
.cleanup:
    pop r12
    pop rbx
    ret

to_lower:
    cmp al, 'A'
    jb .lower_end
    cmp al, 'Z'
    ja .lower_end
    add al, 32
.lower_end:
    ret

update_score:
    movzx rax, al
    add qword [score_sum], rax
    inc qword [item_count]
    ret

compute_summary:
    mov rax, [item_count]
    cmp rax, 0
    je .zero
    mov rbx, [score_sum]
    mov rcx, rax
    mov rdx, 3
    imul rcx, rdx
    sub rcx, rbx
    mov rax, rcx
    mov rbx, [item_count]
    imul rbx, 3
    mov rcx, 100
    imul rax, rcx
    cqo
    idiv rbx
    mov [summary_pct], rax
    ret
.zero:
    mov qword [summary_pct], 0
    ret

print_category:
    mov rax, rdi
    call print_str
    mov rdi, rsi
    call print_str
    mov rdi, newline
    call print_str
    ret

print_summary:
    mov rdi, separator
    call print_str
    mov rdi, summary_title
    call print_str
    mov rsi, [summary_pct]
    mov rdi, numbuf
    call print_number
    mov rdi, numbuf
    call print_str
    mov rdi, percent_suffix
    call print_str
    mov rdi, newline
    call print_str

    mov rax, [summary_pct]
    cmp rax, 85
    jae .ready
    cmp rax, 65
    jae .mostly
    cmp rax, 40
    jae .moderate
    jmp .bad
.ready:
    mov rdi, ready_text
    call print_str
    jmp .end
.mostly:
    mov rdi, mostly_text
    call print_str
    jmp .end
.moderate:
    mov rdi, moderate_text
    call print_str
    jmp .end
.bad:
    mov rdi, bad_text
    call print_str
.end:
    mov rdi, newline
    call print_str
    ret

; ---------------------------------------------------------------------------
; Analysis routines
; ---------------------------------------------------------------------------

analyze_cpu:
    mov rdi, cpuinfo_path
    call read_file
    cmp rax, 0
    je .cpu_failed
    mov rsi, rax
    mov rdi, buf
    mov rdx, vendor_id_key
    mov rcx, 9
    mov r8, linebuf
    mov r9, 128
    call extract_key_value
    cmp rax, 0
    je .cpu_vendor_unknown
    mov rdi, cpu_label
    call print_str
    mov rdi, linebuf
    call print_str
    mov rdi, newline
    call print_str

    mov rdi, buf
    mov rsi, rax
    mov rdx, model_key
    mov rcx, 10
    mov r8, tmpbuf
    mov r9, 128
    call extract_key_value
    cmp rax, 0
    jne .print_model
.cpu_vendor_unknown:
    mov rdi, unknown_text
    call print_str
    mov rdi, newline
    call print_str
    jmp .cpu_score
.print_model:
    mov rdi, tmpbuf
    call print_str
    mov rdi, newline
    call print_str
.cpu_score:
    mov al, 0
    call update_score
    ret
.cpu_failed:
    mov rdi, cpu_label
    call print_str
    mov rdi, unknown_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 2
    call update_score
    ret

analyze_ram:
    mov rdi, meminfo_path
    call read_file
    cmp rax, 0
    je .ram_failed
    mov rsi, rax
    mov rdi, buf
    mov rdx, memtotal_key
    mov rcx, 8
    mov r8, linebuf
    mov r9, 128
    call extract_key_value
    cmp rax, 0
    je .ram_failed
    mov rdi, linebuf
    call parse_decimal_buf
    mov rbx, rax
    mov rdi, ram_label
    call print_str
    mov rsi, rax
    mov rdi, numbuf
    call print_number
    mov rdi, numbuf
    call print_str
    mov rdi, newline
    call print_str

    mov rax, rbx
    mov rcx, 1024
    xor rdx, rdx
    div rcx
    cmp rax, 2048
    jl .ram_bad
    cmp rax, 4096
    jl .ram_minor
    mov al, 0
    jmp .ram_score
.ram_minor:
    mov al, 1
    jmp .ram_score
.ram_bad:
    mov al, 3
.ram_score:
    call update_score
    ret
.ram_failed:
    mov rdi, ram_label
    call print_str
    mov rdi, unknown_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 2
    call update_score
    ret

parse_decimal_buf:
    mov rdi, linebuf
    xor rax, rax
.next_digit:
    mov bl, [rdi]
    cmp bl, '0'
    jb .done_parse
    cmp bl, '9'
    ja .done_parse
    imul rax, rax, 10
    sub bl, '0'
    add rax, rbx
    inc rdi
    jmp .next_digit
.done_parse:
    ret

analyze_disk:
    mov rax, 137
    mov rdi, slash_char
    lea rsi, [rel statfs_buf]
    syscall
    cmp rax, 0
    js .disk_failed
    mov rax, [statfs_buf + 8]
    mov rbx, [statfs_buf + 16]
    mul rbx
    mov rdi, disk_label
    call print_str
    mov rsi, rax
    mov rdi, numbuf
    call print_number
    mov rdi, numbuf
    call print_str
    mov rdi, newline
    call print_str

    mov rbx, 1024*1024*1024
    xor rdx, rdx
    div rbx
    cmp rax, 20
    jl .disk_bad
    cmp rax, 50
    jl .disk_minor
    mov al, 0
    jmp .disk_score
.disk_minor:
    mov al, 1
    jmp .disk_score
.disk_bad:
    mov al, 3
.disk_score:
    call update_score
    ret
.disk_failed:
    mov rdi, disk_label
    call print_str
    mov rdi, unknown_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 2
    call update_score
    ret

analyze_gpu:
    mov rdi, vendor_path
    call read_file
    cmp rax, 0
    je .gpu_unknown
    mov rdi, gpu_label
    call print_str
    mov rdi, buf
    call print_str
    mov rdi, newline
    call print_str
    mov al, 1
    call update_score
    ret
.gpu_unknown:
    mov rdi, gpu_label
    call print_str
    mov rdi, unknown_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 2
    call update_score
    ret

analyze_network:
    mov rax, 2
    mov rdi, net_dir_path
    mov rsi, 0
    mov rdx, 0
    syscall
    cmp rax, 0
    js .net_failed
    mov r12, rax
    mov rax, 217
    mov rdi, r12
    mov rsi, dirbuf
    mov rdx, 4096
    syscall
    mov rcx, rax
    mov r13, 0
    mov r14, 0

    mov rbx, dirbuf
.next_entry:
    lea rdx, [dirbuf + rcx]
    cmp rbx, rdx
    jae .net_done
    mov rdx, [rbx + 0]
    test rdx, rdx
    je .net_done
    movzx r15, word [rbx + 16]
    cmp r15, 0
    je .net_done
    lea rsi, [rbx + 19]
    movzx eax, byte [rsi]
    cmp al, '.'
    je .skip_net
    cmp al, 0
    je .net_done
    inc r13
    mov rdi, pathbuf
    mov rsi, net_dir_path
    call copy_string
    mov rdi, pathbuf
    lea rsi, [rbx + 19]
    call copy_string
    mov rdi, pathbuf
    mov rsi, wireless_suf
    call copy_string
    mov rdi, pathbuf
    call file_exists
    test rax, rax
    jnz .wifi_found
.skip_net:
    add rbx, r15
    jmp .next_entry
.wifi_found:
    mov r14, 1
    add rbx, r15
    jmp .next_entry
.net_done:
    mov rax, r13
    cmp rax, 0
    je .net_none
    mov rdi, net_label
    call print_str
    cmp r14, 1
    je .net_wifi
    mov rdi, ok_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 0
    call update_score
    jmp .net_close
.net_wifi:
    mov rdi, minor_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 1
    call update_score
.net_close:
    mov rdi, r12
    mov rax, 3
    syscall
    ret
.net_none:
    mov rdi, net_label
    call print_str
    mov rdi, unknown_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 2
    call update_score
    mov rdi, r12
    mov rax, 3
    syscall
    ret
.net_failed:
    mov rdi, net_label
    call print_str
    mov rdi, unknown_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 2
    call update_score
    ret

analyze_audio:
    mov rdi, asound_path
    call file_exists
    mov rdi, audio_label
    call print_str
    test rax, rax
    jnz .audio_ok
    mov rdi, unknown_text
    call print_str
    mov al, 2
    jmp .audio_score
.audio_ok:
    mov rdi, ok_text
    call print_str
    mov al, 0
.audio_score:
    mov rdi, newline
    call print_str
    call update_score
    ret

analyze_firmware:
    mov rdi, efi_path
    call file_exists
    mov rdi, fw_label
    call print_str
    test rax, rax
    jnz .fw_ok
    mov rdi, minor_text
    call print_str
    mov al, 1
    jmp .fw_score
.fw_ok:
    mov rdi, ok_text
    call print_str
    mov al, 0
.fw_score:
    mov rdi, newline
    call print_str
    call update_score
    ret

analyze_tpm:
    mov rdi, tpm_path
    call file_exists
    mov rdi, tpm_label
    call print_str
    test rax, rax
    jnz .tpm_ok
    mov rdi, unknown_text
    call print_str
    mov al, 2
    jmp .tpm_score
.tpm_ok:
    mov rdi, ok_text
    call print_str
    mov al, 0
.tpm_score:
    mov rdi, newline
    call print_str
    call update_score
    ret

analyze_virtualization:
    mov rdi, debug_virt
    call print_str
    mov rdi, cpuinfo_path
    call read_file
    mov rdi, debug_virt_read
    call print_str
    mov rdi, buf
    mov rsi, hypervisor_key
    call str_contains
    mov rdi, debug_virt_search
    call print_str
    cmp rax, 0
    je .virt_none
    mov rdi, buf
    mov rsi, hypervisor_key
    call str_contains
    test rax, rax
    jz .virt_none
    mov rdi, virt_label
    call print_str
    mov rdi, minor_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 1
    call update_score
    ret
.virt_none:
    mov rdi, virt_label
    call print_str
    mov rdi, ok_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 0
    call update_score
    ret

analyze_online:
    mov rdi, debug_online
    call print_str
    mov rdi, route_path
    call read_file
    cmp rax, 0
    je .online_minor
    mov rsi, rax
    mov rdi, buf
    mov rdx, route_marker
    mov rcx, 8
    call find_substring
    cmp rax, -1
    jne .online_ok
.online_minor:
    mov rdi, online_label
    call print_str
    mov rdi, minor_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 1
    call update_score
    ret
.online_ok:
    mov rdi, online_label
    call print_str
    mov rdi, ok_text
    call print_str
    mov rdi, newline
    call print_str
    mov al, 0
    call update_score
    ret

copy_string:
    mov rcx, 0
.copy_loop2:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    cmp al, 0
    je .copy_done
    inc rcx
    jmp .copy_loop2
.copy_done:
    ret

SECTION .data
sockaddr:
    dw 2
    dw 0x5000
    dd 0x01010101
    dq 0
