/* LT-Stream-v1: modern single-port virtio-console, opaque inherited socket.
 * The two bounded split queues carry bytes only. No catalog/protocol policy. */
network_read:
    lea rdi, [rip+network_state]
    cmp eax, 0
    je virtio_magic
    cmp eax, 4
    je modern_version
    cmp eax, 8
    je network_id
    cmp eax, 12
    je virtio_vendor
    cmp eax, 0x10
    je network_features
    cmp eax, 0x34
    je network_max
    cmp eax, 0x44
    je network_ready
    cmp eax, 0x60
    je network_interrupt
    cmp eax, 0x70
    je network_status
    jmp virtio_zero
network_id:
    xor eax, eax
    cmp qword ptr [rip+network_fd], 0
    jl 1f
    mov eax, 3
1:  ret
network_features:
    xor eax, eax
    cmp dword ptr [rdi], 1
    sete al
    ret
network_max:
    cmp dword ptr [rdi+16], 1
    ja virtio_zero
    mov eax, 8
    ret
network_ready:
    call network_selected
    mov eax, [rdi+4]
    ret
network_interrupt:
    mov eax, [rdi+32]
    ret
network_status:
    mov eax, [rdi+28]
    ret
network_selected:
    mov eax, [rdi+16]
    and eax, 1
    shl eax, 6
    lea rdi, [rdi+rax+64]
    ret
network_write:
    lea rdi, [rip+network_state]
    cmp eax, 0x14
    je network_feature_sel
    cmp eax, 0x24
    je network_driver_sel
    cmp eax, 0x20
    je network_driver_features
    cmp eax, 0x30
    je network_queue_sel
    cmp eax, 0x64
    je network_ack
    cmp eax, 0x70
    je network_set_status
    cmp eax, 0x50
    je network_notify
    cmp dword ptr [rdi+16], 1
    ja network_fail
    mov r8d, eax
    call network_selected
    cmp r8d, 0x38
    je network_num
    cmp r8d, 0x44
    je network_set_ready
    cmp dword ptr [rdi+4], 0
    jne network_fail
    cmp r8d, 0x80
    je network_desc
    cmp r8d, 0x90
    je network_avail
    cmp r8d, 0xa0
    je network_used
    cmp r8d, 0x84
    je network_desc_high
    cmp r8d, 0x94
    je network_avail_high
    cmp r8d, 0xa4
    je network_used_high
    ret
network_feature_sel: mov [rdi], edx
    ret
network_driver_sel: mov [rdi+8], edx
    ret
network_driver_features:
    cmp dword ptr [rdi+8], 0
    jne 1f
    mov [rdi+4], edx
    ret
1:  cmp dword ptr [rdi+8], 1
    jne network_fail
    mov [rdi+12], edx
    ret
network_queue_sel: mov [rdi+16], edx
    ret
network_ack: not edx
    and [rdi+32], edx
    ret
network_set_status:
    test edx, edx
    jz network_reset
    test edx, 8
    jz 1f
    cmp dword ptr [rdi+4], 0
    jne network_fail
    cmp dword ptr [rdi+12], 1
    jne network_fail
1:  mov [rdi+28], edx
    ret
network_reset:
    xor eax, eax
    mov ecx, 24
    rep stosq
    ret
network_num:
    cmp dword ptr [rdi+4], 0
    jne network_fail
    cmp edx, 8
    jne network_fail
    mov [rdi], edx
    ret
network_set_ready:
    cmp edx, 1
    ja network_fail
    mov [rdi+4], edx
    ret
network_desc: mov [rdi+16], edx
    ret
network_avail: mov [rdi+24], edx
    ret
network_used: mov [rdi+32], edx
    ret
network_desc_high: mov [rdi+20], edx
    ret
network_avail_high: mov [rdi+28], edx
    ret
network_used_high: mov [rdi+36], edx
    ret
network_fail:
    or dword ptr [rip+network_state+28], 128
    ret
network_notify:
    cmp edx, 1
    ja network_fail
    mov [rip+network_direction], edx
    mov eax, [rdi+28]
    and eax, 143
    cmp eax, 15
    jne network_fail
    mov eax, edx
    shl eax, 6
    lea rdi, [rdi+rax+64]
    mov [rip+network_current], rdi
    cmp dword ptr [rdi], 8
    jne network_fail
    cmp dword ptr [rdi+4], 1
    jne network_fail
    mov rax, [rdi+16]
    test eax, 15
    jnz network_fail
    mov ecx, 128
    call dma_pointer
    jc network_fail
    mov [rip+network_desc_host], rax
    mov rdi, [rip+network_current]
    mov rax, [rdi+24]
    test eax, 1
    jnz network_fail
    mov ecx, 22
    call dma_pointer
    jc network_fail
    mov [rip+network_avail_host], rax
    mov rdi, [rip+network_current]
    movzx eax, word ptr [rax+2]
    sub ax, [rdi+8]
    test ax, ax
    jz network_done
    cmp ax, 8
    ja network_fail
    movzx eax, word ptr [rdi+8]
    and eax, 7
    mov rsi, [rip+network_avail_host]
    movzx eax, word ptr [rsi+4+rax*2]
    cmp eax, 8
    jae network_fail
    mov [rip+network_head], eax
    shl eax, 4
    add rax, [rip+network_desc_host]
    movzx ecx, word ptr [rax+12]
    cmp dword ptr [rip+network_direction], 0
    jne 1f
    cmp ecx, 2
    jne network_fail
    jmp 2f
1:  test ecx, ecx
    jnz network_fail
2:  mov ecx, [rax+8]
    test ecx, ecx
    jz network_fail
    cmp ecx, 1024
    ja network_fail
    mov [rip+network_length], ecx
    mov rax, [rax]
    call dma_pointer
    jc network_fail
    mov rsi, rax
    mov rdi, [rip+network_current]
    mov eax, [rdi+12]
    cmp eax, [rip+network_length]
    jae network_fail
    add rsi, rax
    mov edx, [rip+network_length]
    sub edx, eax
    mov rdi, [rip+network_fd]
    cmp dword ptr [rip+network_direction], 0
    jne network_send
    mov eax, 45 /* recvfrom MSG_DONTWAIT */
    mov r10d, 64
    xor r8d, r8d
    xor r9d, r9d
    syscall
    jmp network_io_result
network_send:
    mov eax, 44 /* sendto MSG_DONTWAIT|MSG_NOSIGNAL */
    mov r10d, 16448
    xor r8d, r8d
    xor r9d, r9d
    syscall
network_io_result:
    cmp rax, -11
    je network_done
    cmp rax, -4
    je network_done
    test rax, rax
    jle network_fail
    mov rdi, [rip+network_current]
    add [rdi+12], eax
    cmp dword ptr [rip+network_direction], 0
    je network_complete
    mov eax, [rdi+12]
    cmp eax, [rip+network_length]
    jb network_done
network_complete:
    mov eax, [rdi+12]
    mov [rip+network_actual], eax
    mov rax, [rdi+32]
    test eax, 3
    jnz network_fail
    mov ecx, 68
    call dma_pointer
    jc network_fail
    mov rsi, rax
    mov rdi, [rip+network_current]
    movzx ecx, word ptr [rdi+8]
    and ecx, 7
    mov eax, [rip+network_head]
    mov [rsi+4+rcx*8], eax
    mov eax, [rip+network_actual]
    mov [rsi+8+rcx*8], eax
    inc word ptr [rdi+8]
    mov ax, [rdi+8]
    mov word ptr [rsi+2], ax
    mov dword ptr [rdi+12], 0
    or dword ptr [rip+network_state+32], 1
network_done:
    ret
.section .bss
.balign 16
network_state: .skip 192
network_fd: .skip 8
network_current: .skip 8
network_desc_host: .skip 8
network_avail_host: .skip 8
network_direction: .skip 4
network_head: .skip 4
network_length: .skip 4
network_actual: .skip 4
.section .rodata
network_arg: .asciz "--network-fd"
.section .text
