/* LT-PCM-v1: modern single-port virtio-console, opaque inherited socket.
 * The two bounded split queues carry bytes only. No catalog/protocol policy. */
pcm_read:
    lea rdi, [rip+pcm_state]
    cmp eax, 0
    je virtio_magic
    cmp eax, 4
    je modern_version
    cmp eax, 8
    je pcm_id
    cmp eax, 12
    je virtio_vendor
    cmp eax, 0x10
    je pcm_features
    cmp eax, 0x34
    je pcm_max
    cmp eax, 0x44
    je pcm_ready
    cmp eax, 0x60
    je pcm_interrupt
    cmp eax, 0x70
    je pcm_status
    jmp virtio_zero
pcm_id:
    xor eax, eax
    cmp qword ptr [rip+pcm_fd], 0
    jl 1f
    mov eax, 3
1:  ret
pcm_features:
    xor eax, eax
    cmp dword ptr [rdi], 1
    sete al
    ret
pcm_max:
    cmp dword ptr [rdi+16], 1
    ja virtio_zero
    mov eax, 8
    ret
pcm_ready:
    call pcm_selected
    mov eax, [rdi+4]
    ret
pcm_interrupt:
    mov eax, [rdi+32]
    ret
pcm_status:
    mov eax, [rdi+28]
    ret
pcm_selected:
    mov eax, [rdi+16]
    and eax, 1
    shl eax, 6
    lea rdi, [rdi+rax+64]
    ret
pcm_write:
    lea rdi, [rip+pcm_state]
    cmp eax, 0x14
    je pcm_feature_sel
    cmp eax, 0x24
    je pcm_driver_sel
    cmp eax, 0x20
    je pcm_driver_features
    cmp eax, 0x30
    je pcm_queue_sel
    cmp eax, 0x64
    je pcm_ack
    cmp eax, 0x70
    je pcm_set_status
    cmp eax, 0x50
    je pcm_notify
    cmp dword ptr [rdi+16], 1
    ja pcm_fail
    mov r8d, eax
    call pcm_selected
    cmp r8d, 0x38
    je pcm_num
    cmp r8d, 0x44
    je pcm_set_ready
    cmp dword ptr [rdi+4], 0
    jne pcm_fail
    cmp r8d, 0x80
    je pcm_desc
    cmp r8d, 0x90
    je pcm_avail
    cmp r8d, 0xa0
    je pcm_used
    cmp r8d, 0x84
    je pcm_desc_high
    cmp r8d, 0x94
    je pcm_avail_high
    cmp r8d, 0xa4
    je pcm_used_high
    ret
pcm_feature_sel: mov [rdi], edx
    ret
pcm_driver_sel: mov [rdi+8], edx
    ret
pcm_driver_features:
    cmp dword ptr [rdi+8], 0
    jne 1f
    mov [rdi+4], edx
    ret
1:  cmp dword ptr [rdi+8], 1
    jne pcm_fail
    mov [rdi+12], edx
    ret
pcm_queue_sel: mov [rdi+16], edx
    ret
pcm_ack: not edx
    and [rdi+32], edx
    ret
pcm_set_status:
    test edx, edx
    jz pcm_reset
    test edx, 8
    jz 1f
    cmp dword ptr [rdi+4], 0
    jne pcm_fail
    cmp dword ptr [rdi+12], 1
    jne pcm_fail
1:  mov [rdi+28], edx
    ret
pcm_reset:
    xor eax, eax
    mov ecx, 24
    rep stosq
    ret
pcm_num:
    cmp dword ptr [rdi+4], 0
    jne pcm_fail
    cmp edx, 8
    jne pcm_fail
    mov [rdi], edx
    ret
pcm_set_ready:
    cmp edx, 1
    ja pcm_fail
    mov [rdi+4], edx
    ret
pcm_desc: mov [rdi+16], edx
    ret
pcm_avail: mov [rdi+24], edx
    ret
pcm_used: mov [rdi+32], edx
    ret
pcm_desc_high: mov [rdi+20], edx
    ret
pcm_avail_high: mov [rdi+28], edx
    ret
pcm_used_high: mov [rdi+36], edx
    ret
pcm_fail:
    or dword ptr [rip+pcm_state+28], 128
    ret
pcm_notify:
    cmp edx, 1
    ja pcm_fail
    mov [rip+pcm_direction], edx
    mov eax, [rdi+28]
    and eax, 143
    cmp eax, 15
    jne pcm_fail
    mov eax, edx
    shl eax, 6
    lea rdi, [rdi+rax+64]
    mov [rip+pcm_current], rdi
    cmp dword ptr [rdi], 8
    jne pcm_fail
    cmp dword ptr [rdi+4], 1
    jne pcm_fail
    mov rax, [rdi+16]
    test eax, 15
    jnz pcm_fail
    mov ecx, 128
    call dma_pointer
    jc pcm_fail
    mov [rip+pcm_desc_host], rax
    mov rdi, [rip+pcm_current]
    mov rax, [rdi+24]
    test eax, 1
    jnz pcm_fail
    mov ecx, 22
    call dma_pointer
    jc pcm_fail
    mov [rip+pcm_avail_host], rax
    mov rdi, [rip+pcm_current]
    movzx eax, word ptr [rax+2]
    sub ax, [rdi+8]
    test ax, ax
    jz pcm_done
    cmp ax, 8
    ja pcm_fail
    movzx eax, word ptr [rdi+8]
    and eax, 7
    mov rsi, [rip+pcm_avail_host]
    movzx eax, word ptr [rsi+4+rax*2]
    cmp eax, 8
    jae pcm_fail
    mov [rip+pcm_head], eax
    shl eax, 4
    add rax, [rip+pcm_desc_host]
    movzx ecx, word ptr [rax+12]
    cmp dword ptr [rip+pcm_direction], 0
    jne 1f
    cmp ecx, 2
    jne pcm_fail
    jmp 2f
1:  test ecx, ecx
    jnz pcm_fail
2:  mov ecx, [rax+8]
    test ecx, ecx
    jz pcm_fail
    cmp ecx, 1024
    ja pcm_fail
    mov [rip+pcm_length], ecx
    mov rax, [rax]
    call dma_pointer
    jc pcm_fail
    mov rsi, rax
    mov rdi, [rip+pcm_current]
    mov eax, [rdi+12]
    cmp eax, [rip+pcm_length]
    jae pcm_fail
    add rsi, rax
    mov edx, [rip+pcm_length]
    sub edx, eax
    mov rdi, [rip+pcm_fd]
    cmp dword ptr [rip+pcm_direction], 0
    jne pcm_send
    mov eax, 45 /* recvfrom MSG_DONTWAIT */
    mov r10d, 64
    xor r8d, r8d
    xor r9d, r9d
    syscall
    jmp pcm_io_result
pcm_send:
    mov eax, 44 /* sendto MSG_DONTWAIT|MSG_NOSIGNAL */
    mov r10d, 16448
    xor r8d, r8d
    xor r9d, r9d
    syscall
pcm_io_result:
    cmp rax, -11
    je pcm_done
    cmp rax, -4
    je pcm_done
    test rax, rax
    jle pcm_fail
    mov rdi, [rip+pcm_current]
    add [rdi+12], eax
    cmp dword ptr [rip+pcm_direction], 0
    je pcm_complete
    mov eax, [rdi+12]
    cmp eax, [rip+pcm_length]
    jb pcm_done
pcm_complete:
    mov eax, [rdi+12]
    mov [rip+pcm_actual], eax
    mov rax, [rdi+32]
    test eax, 3
    jnz pcm_fail
    mov ecx, 68
    call dma_pointer
    jc pcm_fail
    mov rsi, rax
    mov rdi, [rip+pcm_current]
    movzx ecx, word ptr [rdi+8]
    and ecx, 7
    mov eax, [rip+pcm_head]
    mov [rsi+4+rcx*8], eax
    mov eax, [rip+pcm_actual]
    mov [rsi+8+rcx*8], eax
    inc word ptr [rdi+8]
    mov ax, [rdi+8]
    mov word ptr [rsi+2], ax
    mov dword ptr [rdi+12], 0
    or dword ptr [rip+pcm_state+32], 1
pcm_done:
    ret
.section .bss
.balign 16
pcm_state: .skip 192
pcm_fd: .skip 8
pcm_current: .skip 8
pcm_desc_host: .skip 8
pcm_avail_host: .skip 8
pcm_direction: .skip 4
pcm_head: .skip 4
pcm_length: .skip 4
pcm_actual: .skip 4
.section .rodata
pcm_arg: .asciz "--pcm-fd"
.section .text
