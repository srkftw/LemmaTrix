/* Stream2: fixed non-console port1, bounded control queues and raw samples.
 * Legacy Stream1 q0/q1 remains available when MULTIPORT is not negotiated. */
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
    cmp eax, 0x104
    je network_ports
    jmp virtio_zero
network_id:
    xor eax, eax
    cmp qword ptr [rip+network_fd], 0
    jl 1f
    mov eax, 3
1:  ret
network_features:
    mov eax, 2
    cmp dword ptr [rdi], 0
    je 1f
    xor eax, eax
    cmp dword ptr [rdi], 1
    sete al
1:  ret
network_ports:
    mov eax, 2
    ret
network_max:
    cmp dword ptr [rdi+16], 5
    ja virtio_zero
    mov eax, 8
    ret
network_ready:
    cmp dword ptr [rdi+16], 5
    ja virtio_zero
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
    cmp dword ptr [rdi+16], 5
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
    mov eax, [rdi+4]
    and eax, -3
    test eax, eax
    jnz network_fail
    cmp dword ptr [rdi+12], 1
    jne network_fail
1:  mov [rdi+28], edx
    ret
network_reset:
    xor eax, eax
    mov ecx, 56
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
    cmp edx, 5
    ja network_fail
    test dword ptr [rdi+4], 2
    jz network_legacy_notify
    cmp edx, 2
    je network_control_notify
    cmp edx, 3
    je network_queue_notify
    cmp edx, 4
    je network_data_notify
    cmp edx, 5
    jne network_fail
network_data_notify:
    cmp dword ptr [rdi+40], 1
    jne network_fail
    jmp network_queue_notify
network_control_notify:
    mov eax, [rdi+36]
    cmp eax, 1
    je network_queue_notify
    cmp eax, 3
    je network_queue_notify
    cmp eax, 4
    je network_queue_notify
    ret
network_legacy_notify:
    cmp edx, 1
    ja network_fail
network_queue_notify:
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
    je 3f
    cmp dword ptr [rip+network_direction], 2
    je 3f
    cmp dword ptr [rip+network_direction], 4
    jne 1f
3:
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
    cmp dword ptr [rip+network_direction], 2
    je network_control_receive
    cmp dword ptr [rip+network_direction], 3
    je network_control_send
    mov rdi, [rip+network_fd]
    cmp dword ptr [rip+network_direction], 0
    je network_receive
    cmp dword ptr [rip+network_direction], 4
    jne network_send
network_receive:
    mov eax, 45 /* recvfrom MSG_DONTWAIT */
    mov r10d, 64
    xor r8d, r8d
    xor r9d, r9d
    syscall
    jmp network_io_result
network_control_receive:
    cmp edx, 64
    jne network_fail
    mov eax, dword ptr [rip+network_state+36]
    cmp eax, 1
    jne 1f
    mov rax, 0x0001000100000001 /* port1 ADD */
    mov [rsi], rax
    mov dword ptr [rip+network_state+36], 2
    mov eax, 8
    jmp 3f
1:  cmp eax, 3
    jne 2f
    mov rax, 0x0001000700000001 /* port1 NAME */
    mov [rsi], rax
    mov rax, 0x003174656e2d746c /* lt-net1 NUL */
    mov [rsi+8], rax
    mov dword ptr [rip+network_state+36], 4
    mov eax, 16
    jmp 3f
2:  cmp eax, 4
    jne network_fail
    mov rax, 0x0001000600000001 /* host OPEN */
    mov [rsi], rax
    mov dword ptr [rip+network_state+36], 5
    mov eax, 8
3:  mov rdi, [rip+network_current]
    mov [rdi+12], eax
    jmp network_complete
network_control_send:
    cmp edx, 8
    jne network_fail
    mov rax, [rsi]
    mov rcx, 0x0001000000000000 /* DEVICE_READY */
    cmp rax, rcx
    jne 1f
    cmp dword ptr [rip+network_state+36], 0
    jne network_fail
    mov dword ptr [rip+network_state+36], 1
    jmp 3f
1:  mov rcx, 0x0001000300000001 /* port1 READY */
    cmp rax, rcx
    jne 2f
    cmp dword ptr [rip+network_state+36], 2
    jne network_fail
    mov dword ptr [rip+network_state+36], 3
    jmp 3f
2:  mov rcx, 0x0001000600000001 /* guest OPEN */
    cmp rax, rcx
    jne network_fail
    cmp dword ptr [rip+network_state+36], 5
    jne network_fail
    mov dword ptr [rip+network_state+40], 1
3:  mov rdi, [rip+network_current]
    mov dword ptr [rdi+12], 8
    jmp network_complete
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
    cmp dword ptr [rip+network_direction], 4
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
network_state: .skip 448
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
