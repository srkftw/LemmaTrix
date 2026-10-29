/* Modern virtio-mmio GPU 2D and evdev devices, LT-Dev graphics profile.
 * Raw BGRX presentation and raw little-endian evdev transport only; the host
 * adapter has no widgets, fonts, project, permission or application semantics.
 * MMIO slots 2,3,4 expose GPU, keyboard+pointer source, second input source.
 */
graphics_open_adapters:
    mov rdi, [rip+display_path]
    test rdi, rdi
    jz 1f
    mov esi, 0x242 /* RDWR|CREAT|TRUNC: explicit disposable pixel export */
    mov edx, 384
    mov eax, 2
    syscall
    test rax, rax
    js image_error
    mov [rip+display_fd], rax
1:  mov rdi, [rip+input_path]
    test rdi, rdi
    jz 2f
    mov esi, 0x800 /* RDONLY|NONBLOCK; no implicit input source */
    xor edx, edx
    mov eax, 2
    syscall
    test rax, rax
    js image_error
    mov [rip+input_fd], rax
2:  ret

/* State: featuresSel0,driverLow4,driverSel8,driverHigh12,queueSel16,
 * queueNum20,ready24,status28,interrupt32,consumed36,completed40,
 * desc48,avail56,used64. One bounded direct queue per device. */
modern_read:
    mov r9d, r8d
    sub r9d, 2
    shl r9d, 7
    lea rdi, [rip+graphics_states]
    add rdi, r9
    test eax, eax
    jz virtio_magic
    cmp eax, 4
    je modern_version
    cmp eax, 8
    je modern_id
    cmp eax, 12
    je virtio_vendor
    cmp eax, 0x10
    je modern_features
    cmp eax, 0x34
    je modern_max
    cmp eax, 0x44
    je modern_ready
    cmp eax, 0x60
    je modern_interrupt
    cmp eax, 0x70
    je modern_status
    cmp eax, 0x108
    jne virtio_zero
    cmp r8d, 2
    jne virtio_zero
    mov eax, 1 /* num_scanouts */
    ret
modern_version:
    mov eax, 2
    ret
modern_id:
    mov eax, 16
    cmp r8d, 2
    je 1f
    mov eax, 18
1:  ret
modern_features:
    xor eax, eax
    cmp dword ptr [rdi], 1
    sete al /* VERSION_1 only; no indirect, event-index, packed or 3D */
    ret
modern_max:
    cmp dword ptr [rdi+16], 0
    jne virtio_zero
    mov eax, 8
    ret
modern_ready:
    mov eax, [rdi+24]
    ret
modern_interrupt:
    mov eax, [rdi+32]
    ret
modern_status:
    mov eax, [rdi+28]
    ret
modern_write:
    mov [rip+graphics_number], r8d
    mov r9d, r8d
    sub r9d, 2
    shl r9d, 7
    lea rdi, [rip+graphics_states]
    add rdi, r9
    mov [rip+graphics_current], rdi
    cmp eax, 0x14
    je modern_feature_sel
    cmp eax, 0x24
    je modern_driver_sel
    cmp eax, 0x20
    je modern_driver_features
    cmp eax, 0x30
    je modern_queue_sel
    cmp eax, 0x38
    je modern_queue_num
    cmp eax, 0x44
    je modern_queue_ready
    cmp eax, 0x64
    je modern_ack
    cmp eax, 0x70
    je modern_set_status
    cmp eax, 0x50
    je modern_notify
    cmp eax, 0x80
    je modern_desc_low
    cmp eax, 0x84
    je modern_desc_high
    cmp eax, 0x90
    je modern_avail_low
    cmp eax, 0x94
    je modern_avail_high
    cmp eax, 0xa0
    je modern_used_low
    cmp eax, 0xa4
    je modern_used_high
    ret
modern_feature_sel:
    mov [rdi], edx
    ret
modern_driver_sel:
    mov [rdi+8], edx
    ret
modern_driver_features:
    cmp dword ptr [rdi+8], 0
    jne 1f
    mov [rdi+4], edx
    ret
1:  cmp dword ptr [rdi+8], 1
    jne modern_fail
    mov [rdi+12], edx
    ret
modern_queue_sel:
    mov [rdi+16], edx
    ret
modern_queue_num:
    cmp dword ptr [rdi+24], 0
    jne modern_fail
    cmp dword ptr [rdi+16], 0
    jne modern_fail
    cmp edx, 8
    jne modern_fail
    mov [rdi+20], edx
    ret
modern_queue_ready:
    cmp dword ptr [rdi+16], 0
    jne modern_fail
    cmp edx, 1
    ja modern_fail
    mov [rdi+24], edx
    ret
modern_ack:
    and edx, 3
    not edx
    and [rdi+32], edx
    ret
modern_set_status:
    test edx, edx
    jz modern_reset
    test edx, 8
    jz 1f
    cmp dword ptr [rdi+4], 0
    jne modern_fail
    cmp dword ptr [rdi+12], 1
    jne modern_fail
1:  mov [rdi+28], edx
    ret
modern_reset:
    cmp dword ptr [rip+graphics_number], 2
    jne 1f
    mov qword ptr [rip+graphics_backing], 0
    mov dword ptr [rip+graphics_resource], 0
    mov dword ptr [rip+graphics_scanout], 0
1:  xor eax, eax
    mov ecx, 16
    rep stosq
    ret
modern_desc_low:
    mov ecx, 48
    jmp modern_address_low
modern_avail_low:
    mov ecx, 56
    jmp modern_address_low
modern_used_low:
    mov ecx, 64
modern_address_low:
    cmp dword ptr [rdi+24], 0
    jne modern_fail
    mov [rdi+rcx], edx
    ret
modern_desc_high:
    mov ecx, 52
    jmp modern_address_low
modern_avail_high:
    mov ecx, 60
    jmp modern_address_low
modern_used_high:
    mov ecx, 68
    jmp modern_address_low
modern_fail:
    mov rdi, [rip+graphics_current]
    or dword ptr [rdi+28], 128
    ret
modern_notify:
    test edx, edx
    jnz modern_fail
    cmp dword ptr [rdi+20], 8
    jne modern_fail
    cmp dword ptr [rdi+24], 1
    jne modern_fail
    mov eax, [rdi+28]
    and eax, 143
    cmp eax, 15
    jne modern_fail
    mov rax, [rdi+48]
    test eax, 15
    jnz modern_fail
    mov ecx, 128
    call dma_pointer
    jc modern_fail
    mov [rip+graphics_desc], rax
    mov rdi, [rip+graphics_current]
    mov rax, [rdi+56]
    test eax, 1
    jnz modern_fail
    mov ecx, 22
    call dma_pointer
    jc modern_fail
    mov [rip+graphics_avail], rax
    mov rdi, [rip+graphics_current]
    mov rax, [rdi+64]
    test eax, 3
    jnz modern_fail
    mov ecx, 68
    call dma_pointer
    jc modern_fail
    mov [rip+graphics_used], rax
modern_consume:
    mov rdi, [rip+graphics_current]
    mov rsi, [rip+graphics_avail]
    movzx eax, word ptr [rsi+2]
    sub ax, [rdi+36]
    test ax, ax
    jz modern_done
    cmp ax, 8
    ja modern_fail
    movzx eax, word ptr [rdi+36]
    and eax, 7
    movzx eax, word ptr [rsi+4+rax*2]
    cmp eax, 8
    jae modern_fail
    mov [rip+graphics_head], eax
    shl eax, 4
    add rax, [rip+graphics_desc]
    mov [rip+graphics_request_desc], rax
    cmp dword ptr [rip+graphics_number], 2
    jne modern_input
    call graphics_gpu_request
    cmp eax, -1
    je modern_fail
    jmp modern_complete
modern_input:
    cmp dword ptr [rip+graphics_number], 3
    jne modern_done
    cmp word ptr [rax+12], 2
    jne modern_fail
    cmp dword ptr [rax+8], 8
    jne modern_fail
    mov rax, [rax]
    mov ecx, 8
    call dma_pointer
    jc modern_fail
    mov [rip+graphics_event_dest], rax
    mov rdi, [rip+input_fd]
    test rdi, rdi
    js modern_done
    mov edx, 8
    sub edx, [rip+graphics_input_count]
    lea rsi, [rip+graphics_input_event]
    mov eax, [rip+graphics_input_count]
    add rsi, rax
    xor eax, eax
    syscall
    test rax, rax
    jle modern_done
    add [rip+graphics_input_count], eax
    cmp dword ptr [rip+graphics_input_count], 8
    jne modern_done
    mov dword ptr [rip+graphics_input_count], 0
    mov rax, [rip+graphics_event_dest]
    mov rdx, [rip+graphics_input_event]
    mov [rax], rdx
    mov eax, 8
modern_complete:
    mov rdi, [rip+graphics_current]
    mov rsi, [rip+graphics_used]
    movzx ecx, word ptr [rdi+40]
    and ecx, 7
    lea rsi, [rsi+4+rcx*8]
    mov edx, [rip+graphics_head]
    mov [rsi], edx
    mov [rsi+4], eax
    inc word ptr [rdi+40]
    inc word ptr [rdi+36]
    mov ax, [rdi+40]
    mov rsi, [rip+graphics_used]
    mov [rsi+2], ax
    or dword ptr [rdi+32], 1
    jmp modern_consume
modern_done:
    ret

/* Consume one two-descriptor control request; 24-byte response or -1 malformed. */
graphics_gpu_request:
    mov rsi, [rip+graphics_request_desc]
    cmp word ptr [rsi+12], 1
    jne graphics_bad
    mov ecx, [rsi+8]
    cmp ecx, 24
    jb graphics_bad
    cmp ecx, 56
    ja graphics_bad
    mov [rip+graphics_request_length], ecx
    mov rax, [rsi]
    call dma_pointer
    jc graphics_bad
    mov [rip+graphics_request], rax
    mov rsi, [rip+graphics_request_desc]
    movzx eax, word ptr [rsi+14]
    cmp eax, 8
    jae graphics_bad
    cmp eax, [rip+graphics_head]
    je graphics_bad
    shl eax, 4
    add rax, [rip+graphics_desc]
    cmp word ptr [rax+12], 2
    jne graphics_bad
    cmp dword ptr [rax+8], 24
    jb graphics_bad
    mov ecx, 24
    mov rax, [rax]
    call dma_pointer
    jc graphics_bad
    mov [rip+graphics_response], rax
    xor edx, edx
    mov [rax], rdx
    mov [rax+8], rdx
    mov [rax+16], rdx
    mov dword ptr [rax], 0x1200
    mov rsi, [rip+graphics_request]
    cmp dword ptr [rsi+4], 0
    jne graphics_reply
    mov eax, [rsi]
    cmp eax, 0x101
    je graphics_create
    cmp eax, 0x106
    je graphics_attach
    cmp eax, 0x103
    je graphics_scan
    cmp eax, 0x105
    je graphics_transfer
    cmp eax, 0x104
    je graphics_flush
    cmp eax, 0x102
    je graphics_unref
    jmp graphics_reply
graphics_create:
    cmp dword ptr [rip+graphics_request_length], 40
    jne graphics_reply
    cmp dword ptr [rsi+24], 1
    jne graphics_reply
    cmp dword ptr [rsi+28], 2
    jne graphics_reply
    cmp dword ptr [rsi+32], 640
    jne graphics_reply
    cmp dword ptr [rsi+36], 400
    jne graphics_reply
    cmp dword ptr [rip+graphics_resource], 0
    jne graphics_reply
    mov dword ptr [rip+graphics_resource], 1
    jmp graphics_ok
graphics_attach:
    cmp dword ptr [rip+graphics_request_length], 48
    jne graphics_reply
    cmp dword ptr [rsi+24], 1
    jne graphics_reply
    cmp dword ptr [rsi+28], 1
    jne graphics_reply
    cmp dword ptr [rip+graphics_resource], 1
    jne graphics_reply
    cmp dword ptr [rsi+40], 1024000
    jne graphics_reply
    mov rax, [rsi+32]
    mov ecx, 1024000
    call dma_pointer
    jc graphics_reply
    mov [rip+graphics_backing], rax
    jmp graphics_ok
graphics_scan:
    cmp dword ptr [rip+graphics_request_length], 48
    jne graphics_reply
    cmp dword ptr [rsi+40], 0
    jne graphics_reply
    cmp dword ptr [rsi+44], 1
    jne graphics_reply
    cmp qword ptr [rsi+24], 0
    jne graphics_reply
    cmp dword ptr [rsi+32], 640
    jne graphics_reply
    cmp dword ptr [rsi+36], 400
    jne graphics_reply
    cmp qword ptr [rip+graphics_backing], 0
    je graphics_reply
    mov dword ptr [rip+graphics_scanout], 1
    jmp graphics_ok
graphics_rectangle:
    mov eax, [rsi+24]
    mov edx, [rsi+28]
    cmp eax, 640
    jae graphics_rect_bad
    cmp edx, 400
    jae graphics_rect_bad
    mov ecx, [rsi+32]
    test ecx, ecx
    jz graphics_rect_bad
    add rcx, rax
    cmp rcx, 640
    ja graphics_rect_bad
    mov ecx, [rsi+36]
    test ecx, ecx
    jz graphics_rect_bad
    add rcx, rdx
    cmp rcx, 400
    ja graphics_rect_bad
    imul edx, edx, 640
    add eax, edx
    shl eax, 2
    clc
    ret
graphics_rect_bad:
    stc
    ret
graphics_transfer:
    cmp dword ptr [rip+graphics_request_length], 56
    jne graphics_reply
    cmp dword ptr [rsi+48], 1
    jne graphics_reply
    cmp qword ptr [rip+graphics_backing], 0
    je graphics_reply
    call graphics_rectangle
    jc graphics_reply
    cmp rax, [rsi+40]
    jne graphics_reply
    mov r8d, [rsi+36]
    mov r9d, [rsi+32]
    shl r9d, 2
    lea rdi, [rip+graphics_pixels]
    add rdi, rax
    mov rsi, [rip+graphics_backing]
    add rsi, rax
1:  mov ecx, r9d
    rep movsb
    mov ecx, 2560
    sub ecx, r9d
    add rdi, rcx
    add rsi, rcx
    dec r8d
    jnz 1b
    jmp graphics_ok
graphics_flush:
    cmp dword ptr [rip+graphics_request_length], 48
    jne graphics_reply
    cmp dword ptr [rsi+40], 1
    jne graphics_reply
    cmp dword ptr [rip+graphics_scanout], 1
    jne graphics_reply
    call graphics_rectangle
    jc graphics_reply
    mov rdi, [rip+display_fd]
    test rdi, rdi
    js graphics_ok
    add qword ptr [rip+graphics_sequence], 2
    or qword ptr [rip+graphics_sequence], 1
    lea rsi, [rip+graphics_sequence]
    mov edx, 8
    mov r10d, 1024000
    mov eax, 18
    syscall
    cmp rax, 8
    jne graphics_reply
    mov rdi, [rip+display_fd]
    lea rsi, [rip+graphics_pixels]
    mov edx, 1024000
    xor r10d, r10d
    mov eax, 18
    syscall
    cmp rax, 1024000
    jne graphics_reply
    inc qword ptr [rip+graphics_sequence]
    mov rdi, [rip+display_fd]
    lea rsi, [rip+graphics_sequence]
    mov edx, 8
    mov r10d, 1024000
    mov eax, 18
    syscall
    cmp rax, 8
    jne graphics_reply
    jmp graphics_ok
graphics_unref:
    cmp dword ptr [rip+graphics_request_length], 32
    jne graphics_reply
    cmp dword ptr [rsi+24], 1
    jne graphics_reply
    mov dword ptr [rip+graphics_resource], 0
    mov dword ptr [rip+graphics_scanout], 0
    mov qword ptr [rip+graphics_backing], 0
graphics_ok:
    mov rax, [rip+graphics_response]
    mov dword ptr [rax], 0x1100
graphics_reply:
    mov eax, 24
    ret
graphics_bad:
    mov eax, -1
    ret
.section .rodata
display_arg: .asciz "--display-out"
input_arg: .asciz "--input-events"
.section .bss
.balign 16
graphics_states: .skip 384
graphics_current: .skip 8
graphics_number: .skip 4
graphics_head: .skip 4
graphics_request_length: .skip 4
graphics_resource: .skip 4
graphics_scanout: .skip 4
graphics_input_count: .skip 4
graphics_input_event: .skip 8
graphics_desc: .skip 8
graphics_avail: .skip 8
graphics_used: .skip 8
graphics_request_desc: .skip 8
graphics_request: .skip 8
graphics_response: .skip 8
graphics_backing: .skip 8
graphics_event_dest: .skip 8
graphics_sequence: .skip 8
display_path: .skip 8
display_fd: .skip 8
input_path: .skip 8
input_fd: .skip 8
.balign 16
graphics_pixels: .skip 1024000
.section .text
