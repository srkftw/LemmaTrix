/* PCM2: fixed non-console port1, bounded control queues and raw samples.
 * Legacy PCM1 q0/q1 remains available when MULTIPORT is not negotiated. */
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
    cmp eax, 0x104
    je pcm_ports
    jmp virtio_zero
pcm_id:
    xor eax, eax
    cmp qword ptr [rip+pcm_fd], 0
    jl 1f
    mov eax, 3
1:  ret
pcm_features:
    mov eax, 2
    cmp dword ptr [rdi], 0
    je 1f
    xor eax, eax
    cmp dword ptr [rdi], 1
    sete al
1:  ret
pcm_ports:
    mov eax, 2
    ret
pcm_max:
    cmp dword ptr [rdi+16], 5
    ja virtio_zero
    mov eax, 8
    ret
pcm_ready:
    cmp dword ptr [rdi+16], 5
    ja virtio_zero
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
    cmp dword ptr [rdi+16], 5
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
    mov eax, [rdi+4]
    and eax, -3
    test eax, eax
    jnz pcm_fail
    cmp dword ptr [rdi+12], 1
    jne pcm_fail
1:  mov [rdi+28], edx
    ret
pcm_reset:
    xor eax, eax
    mov ecx, 56
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
    cmp edx, 5
    ja pcm_fail
    test dword ptr [rdi+4], 2
    jz pcm_legacy_notify
    cmp edx, 2
    je pcm_control_notify
    cmp edx, 3
    je pcm_queue_notify
    cmp edx, 5
    jne pcm_fail
    cmp dword ptr [rdi+40], 1
    jne pcm_fail
    jmp pcm_queue_notify
pcm_control_notify:
    mov eax, [rdi+36]
    cmp eax, 1
    je pcm_queue_notify
    cmp eax, 3
    je pcm_queue_notify
    cmp eax, 4
    je pcm_queue_notify
    ret
pcm_legacy_notify:
    cmp edx, 1
    ja pcm_fail
pcm_queue_notify:
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
    je 3f
    cmp dword ptr [rip+pcm_direction], 2
    jne 1f
3:
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
    cmp dword ptr [rip+pcm_direction], 2
    je pcm_control_receive
    cmp dword ptr [rip+pcm_direction], 3
    je pcm_control_send
    mov rdi, [rip+pcm_fd]
    cmp dword ptr [rip+pcm_direction], 0
    jne pcm_send
    mov eax, 45 /* recvfrom MSG_DONTWAIT */
    mov r10d, 64
    xor r8d, r8d
    xor r9d, r9d
    syscall
    jmp pcm_io_result
pcm_control_receive:
    cmp edx, 64
    jne pcm_fail
    mov eax, dword ptr [rip+pcm_state+36]
    cmp eax, 1
    jne 1f
    mov rax, 0x0001000100000001 /* port1 ADD */
    mov [rsi], rax
    mov dword ptr [rip+pcm_state+36], 2
    mov eax, 8
    jmp 3f
1:  cmp eax, 3
    jne 2f
    mov rax, 0x0001000700000001 /* port1 NAME */
    mov [rsi], rax
    mov rax, 0x00316d63702d746c /* lt-pcm1 NUL */
    mov [rsi+8], rax
    mov dword ptr [rip+pcm_state+36], 4
    mov eax, 16
    jmp 3f
2:  cmp eax, 4
    jne pcm_fail
    mov rax, 0x0001000600000001 /* host OPEN */
    mov [rsi], rax
    mov dword ptr [rip+pcm_state+36], 5
    mov eax, 8
3:  mov rdi, [rip+pcm_current]
    mov [rdi+12], eax
    jmp pcm_complete
pcm_control_send:
    cmp edx, 8
    jne pcm_fail
    mov rax, [rsi]
    mov rcx, 0x0001000000000000 /* DEVICE_READY */
    cmp rax, rcx
    jne 1f
    cmp dword ptr [rip+pcm_state+36], 0
    jne pcm_fail
    mov dword ptr [rip+pcm_state+36], 1
    jmp 3f
1:  mov rcx, 0x0001000300000001 /* port1 READY */
    cmp rax, rcx
    jne 2f
    cmp dword ptr [rip+pcm_state+36], 2
    jne pcm_fail
    mov dword ptr [rip+pcm_state+36], 3
    jmp 3f
2:  mov rcx, 0x0001000600000001 /* guest OPEN */
    cmp rax, rcx
    jne pcm_fail
    cmp dword ptr [rip+pcm_state+36], 5
    jne pcm_fail
    mov dword ptr [rip+pcm_state+40], 1
3:  mov rdi, [rip+pcm_current]
    mov dword ptr [rdi+12], 8
    jmp pcm_complete
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
pcm_state: .skip 448
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
