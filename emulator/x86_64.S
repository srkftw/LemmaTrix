/* LT development machine: RV64IM interpreter, written in Linux x86-64 assembly.
 * Host syscalls only load a raw image, write UART bytes, and terminate.
 * Instruction execution, Sv39, privilege, traps, and devices are implemented here.
 */
.intel_syntax noprefix
.equ RAM_BASE, 0x80000000
.equ RAM_SIZE, 0x8000000
.equ SSTATUS_MASK, 0x80000003000de133
.equ CSR_SSTATUS, 0x100*8
.equ CSR_SIE, 0x104*8
.equ CSR_STVEC, 0x105*8
.equ CSR_SEPC, 0x141*8
.equ CSR_SCAUSE, 0x142*8
.equ CSR_STVAL, 0x143*8
.equ CSR_SIP, 0x144*8
.equ CSR_SATP, 0x180*8
.equ CSR_MSTATUS, 0x300*8
.equ CSR_MISA, 0x301*8
.equ CSR_MEDELEG, 0x302*8
.equ CSR_MIDELEG, 0x303*8
.equ CSR_MIE, 0x304*8
.equ CSR_MTVEC, 0x305*8
.equ CSR_MSCRATCH, 0x340*8
.equ CSR_MEPC, 0x341*8
.equ CSR_MCAUSE, 0x342*8
.equ CSR_MTVAL, 0x343*8
.equ CSR_MIP, 0x344*8
.section .text
.global _start
_start:
    cmp qword ptr [rsp], 2
    jb usage
    mov qword ptr [rip+server_fd], -1
    mov qword ptr [rip+network_fd], -1
    mov qword ptr [rip+vault_fd], -1
    mov qword ptr [rip+display_fd], -1
    mov qword ptr [rip+input_fd], -1
    mov r8, [rsp]
    mov r9, rsp
    mov ebx, 2
parse_arguments:
    cmp rbx, r8
    jae arguments_done
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+interactive_arg]
    call argument_equal
    test eax, eax
    jnz argument_interactive
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+readonly_arg]
    call argument_equal
    test eax, eax
    jnz argument_readonly
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+display_arg]
    call argument_equal
    test eax, eax
    jnz argument_display
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+input_arg]
    call argument_equal
    test eax, eax
    jnz argument_input
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+server_readonly_arg]
    call argument_equal
    test eax, eax
    jnz argument_server_readonly
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+server_arg]
    call argument_equal
    test eax, eax
    jnz argument_server
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+network_arg]
    call argument_equal
    test eax, eax
    jnz argument_network
    mov rdi, [r9+rbx*8+8]
    lea rsi, [rip+vault_arg]
    call argument_equal
    test eax, eax
    jz usage
    inc rbx
    cmp rbx, r8
    jae usage
    cmp qword ptr [rip+vault_path], 0
    jne usage
    mov rax, [r9+rbx*8+8]
    mov [rip+vault_path], rax
    inc rbx
    jmp parse_arguments
argument_network:
    inc rbx
    cmp rbx, r8
    jae usage
    mov rsi, [r9+rbx*8+8]
    xor eax, eax
1:  movzx edx, byte ptr [rsi]
    test dl, dl
    jz 2f
    sub edx, 48
    cmp edx, 9
    ja usage
    imul eax, eax, 10
    add eax, edx
    cmp eax, 1023
    ja usage
    inc rsi
    jmp 1b
2:  cmp eax, 3
    jb usage
    mov [rip+network_fd], rax
    inc rbx
    jmp parse_arguments
argument_readonly:
    mov byte ptr [rip+vault_readonly], 1
    inc rbx
    jmp parse_arguments
argument_interactive:
    mov byte ptr [rip+interactive], 1
    inc rbx
    jmp parse_arguments
argument_server_readonly:
    mov byte ptr [rip+server_readonly], 1
    inc rbx
    jmp parse_arguments
argument_server:
    lea rdx, [rip+server_path]
    jmp argument_adapter_path
argument_display:
    lea rdx, [rip+display_path]
    jmp argument_adapter_path
argument_input:
    lea rdx, [rip+input_path]
argument_adapter_path:
    inc rbx
    cmp rbx, r8
    jae usage
    cmp qword ptr [rdx], 0
    jne usage
    mov rax, [r9+rbx*8+8]
    mov [rdx], rax
    inc rbx
    jmp parse_arguments
arguments_done:
    mov rdi, [rsp+16]
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall
    test rax, rax
    js image_error
    mov rbx, rax
    xor edi, edi
    mov esi, RAM_SIZE
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    test rax, rax
    js image_error
    mov r13, rax
    xor ebp, ebp
load_image:
    mov rdi, rbx
    lea rsi, [r13+rbp]
    mov edx, RAM_SIZE
    sub rdx, rbp
    xor eax, eax
    syscall
    test rax, rax
    js image_error
    jz image_loaded
    add rbp, rax
    cmp rbp, RAM_SIZE
    jb load_image
    /* Check one extra byte so exact-capacity images do not get truncated. */
    mov rdi, rbx
    lea rsi, [rip+uart_byte]
    mov edx, 1
    xor eax, eax
    syscall
    test rax, rax
    jnz image_error
    jmp image_loaded
image_loaded:
    test rbp, rbp
    jz image_error
    mov rdi, rbx
    mov eax, 3
    syscall
    mov rdi, [rip+vault_path]
    test rdi, rdi
    jz vault_opened
    mov esi, 2 /* explicit existing backing file, no creation */
    cmp byte ptr [rip+vault_readonly], 0
    je vault_open_flags
    xor esi, esi
vault_open_flags:
    xor edx, edx
    mov eax, 2
    syscall
    test rax, rax
    js vault_error
    mov [rip+vault_fd], rax
    mov rdi, rax
    lea rsi, [rip+host_stat]
    mov eax, 5
    syscall
    test rax, rax
    js vault_error
    mov eax, [rip+host_stat+24]
    and eax, 0xf000
    cmp eax, 0x8000
    jne vault_error
    mov rax, [rip+host_stat+48]
    test rax, rax
    jz vault_error
    test eax, 511
    jnz vault_error
    shr rax, 9
    mov [rip+vault_sectors], rax
vault_opened:
    mov rdi, [rip+server_path]
    test rdi, rdi
    jz server_opened
    mov esi, 2
    cmp byte ptr [rip+server_readonly], 0
    je 1f
    xor esi, esi
1:
    xor edx, edx
    mov eax, 2
    syscall
    test rax, rax
    js vault_error
    mov [rip+server_fd], rax
    mov rdi, rax
    lea rsi, [rip+host_stat]
    mov eax, 5
    syscall
    test rax, rax
    js vault_error
    mov eax, [rip+host_stat+24]
    and eax, 0xf000
    cmp eax, 0x8000
    jne vault_error
    mov rax, [rip+host_stat+48]
    test rax, rax
    jz vault_error
    test eax, 511
    jnz vault_error
    shr rax, 9
    mov [rip+server_sectors], rax
server_opened:
    call graphics_open_adapters
    lea r12, [rip+regs]
    mov r14d, RAM_BASE
    mov qword ptr [rip+privilege], 3
    mov qword ptr [rip+timecmp], -1
    mov qword ptr [rip+csrs+CSR_MISA], 0 /* initialized below: RV64 I M S U */
    movabs rax, 0x8000000000141100
    mov [rip+csrs+CSR_MISA], rax
    movabs rax, 0xa00000000
    mov [rip+csrs+CSR_MSTATUS], rax
    mov [rip+host_rsp], rsp
    mov r15, 536870912
run:
    mov rsp, [rip+host_rsp]
    cmp byte ptr [rip+interactive], 0
    jne instruction_unbounded
    dec r15
    jz budget_error
instruction_unbounded:
    inc qword ptr [rip+ticks]
    mov rax, [rip+ticks]
    cmp rax, [rip+timecmp]
    jb timer_low
    or qword ptr [rip+csrs+CSR_MIP], 128
    jmp timer_check
timer_low:
    and qword ptr [rip+csrs+CSR_MIP], -129
timer_check:
    mov rax, [rip+csrs+CSR_MIP]
    and rax, [rip+csrs+CSR_MIE]
    test rax, rax
    jz fetch
    /* Choose machine timer then supervisor software/timer/external. */
    mov ecx, 3
    bt rax, rcx
    jc interrupt_pending
    mov ecx, 7
    bt rax, rcx
    jc interrupt_pending
    mov ecx, 9
    bt rax, rcx
    jc interrupt_pending
    mov ecx, 1
    bt rax, rcx
    jc interrupt_pending
    mov ecx, 5
    bt rax, rcx
    jnc fetch
interrupt_pending:
    mov rdx, [rip+csrs+CSR_MIDELEG]
    bt rdx, rcx
    jc delegated_interrupt
    cmp qword ptr [rip+privilege], 3
    jb take_interrupt
    test qword ptr [rip+csrs+CSR_MSTATUS], 8
    jz fetch
    jmp take_interrupt
delegated_interrupt:
    cmp qword ptr [rip+privilege], 3
    je fetch
    cmp qword ptr [rip+privilege], 1
    jb take_interrupt
    test qword ptr [rip+csrs+CSR_MSTATUS], 2
    jz fetch
take_interrupt:
    mov rax, rcx
    bts rax, 63
    xor edx, edx
    jmp trap
fetch:
    test r14b, 3
    jnz instruction_misaligned
    mov rdi, r14
    mov esi, 2
    call translate
    mov ecx, 4
    call phys_read
    mov r8d, eax
    mov [rip+instruction], eax
    lea rbp, [r14+4]
    mov ecx, r8d
    shr ecx, 15
    and ecx, 31
    mov r9, [r12+rcx*8]
    mov ecx, r8d
    shr ecx, 20
    and ecx, 31
    mov r10, [r12+rcx*8]
    mov ebx, r8d
    shr ebx, 12
    and ebx, 7
    mov eax, r8d
    and eax, 127
    cmp eax, 0x37
    je op_lui
    cmp eax, 0x17
    je op_auipc
    cmp eax, 0x6f
    je op_jal
    cmp eax, 0x67
    je op_jalr
    cmp eax, 0x63
    je op_branch
    cmp eax, 0x03
    je op_load
    cmp eax, 0x23
    je op_store
    cmp eax, 0x13
    je op_imm
    cmp eax, 0x1b
    je op_imm32
    cmp eax, 0x33
    je op_reg
    cmp eax, 0x3b
    je op_reg32
    cmp eax, 0x73
    je op_system
    cmp eax, 0x0f
    je op_fence
    jmp illegal
commit:
    mov eax, [rip+instruction]
    shr eax, 7
    and eax, 31
    jz advance
    mov [r12+rax*8], r11
advance:
    inc qword ptr [rip+retired]
    mov r14, rbp
    jmp run
op_lui:
    mov r11d, r8d
    and r11d, 0xfffff000
    movsxd r11, r11d
    jmp commit
op_auipc:
    mov r11d, r8d
    and r11d, 0xfffff000
    movsxd r11, r11d
    add r11, r14
    jmp commit
op_jal:
    mov eax, r8d
    sar eax, 31
    shl eax, 20
    mov ecx, r8d
    shr ecx, 21
    and ecx, 1023
    shl ecx, 1
    or eax, ecx
    mov ecx, r8d
    shr ecx, 20
    and ecx, 1
    shl ecx, 11
    or eax, ecx
    mov ecx, r8d
    and ecx, 0xff000
    or eax, ecx
    movsxd rax, eax
    mov r11, rbp
    lea rbp, [r14+rax]
    test bpl, 3
    jnz target_misaligned
    jmp commit
op_jalr:
    test ebx, ebx
    jnz illegal
    mov eax, r8d
    sar eax, 20
    cdqe
    mov r11, rbp
    lea rbp, [r9+rax]
    and rbp, -2
    test bpl, 3
    jnz target_misaligned
    jmp commit
op_branch:
    mov eax, r8d
    sar eax, 31
    shl eax, 12
    mov ecx, r8d
    shr ecx, 25
    and ecx, 63
    shl ecx, 5
    or eax, ecx
    mov ecx, r8d
    shr ecx, 8
    and ecx, 15
    shl ecx, 1
    or eax, ecx
    mov ecx, r8d
    shr ecx, 7
    and ecx, 1
    shl ecx, 11
    or eax, ecx
    cdqe
    cmp r9, r10
    je branch_equal
    cmp ebx, 1
    je branch_take
branch_other:
    cmp ebx, 4
    je branch_lt
    cmp ebx, 5
    je branch_ge
    cmp ebx, 6
    je branch_ltu
    cmp ebx, 7
    je branch_geu
    cmp ebx, 1
    jbe advance
    jmp illegal
branch_equal:
    test ebx, ebx
    jz branch_take
    jmp branch_other
branch_lt:
    cmp r9, r10
    jl branch_take
    jmp advance
branch_ge:
    cmp r9, r10
    jge branch_take
    jmp advance
branch_ltu:
    cmp r9, r10
    jb branch_take
    jmp advance
branch_geu:
    cmp r9, r10
    jae branch_take
    jmp advance
branch_take:
    lea rbp, [r14+rax]
    test bpl, 3
    jnz target_misaligned
    jmp advance
op_load:
    cmp ebx, 7
    je illegal
    mov eax, r8d
    sar eax, 20
    cdqe
    lea rdi, [r9+rax]
    mov [rip+fault_address], rdi
    mov ecx, ebx
    and ecx, 3
    mov eax, 1
    shl eax, cl
    mov [rip+memory_size], eax
    dec eax
    test rdi, rax
    jnz load_misaligned
    xor esi, esi
    call translate
    mov ecx, [rip+memory_size]
    call phys_read
    mov r11, rax
    mov ebx, [rip+instruction]
    shr ebx, 12
    and ebx, 7
    cmp ebx, 0
    jne load_h
    movsx r11, al
load_h:
    cmp ebx, 1
    jne load_w
    movsx r11, ax
load_w:
    cmp ebx, 2
    jne commit
    movsxd r11, eax
    jmp commit
op_store:
    cmp ebx, 3
    ja illegal
    mov eax, r8d
    sar eax, 25
    shl eax, 5
    mov ecx, r8d
    shr ecx, 7
    and ecx, 31
    or eax, ecx
    cdqe
    lea rdi, [r9+rax]
    mov [rip+fault_address], rdi
    mov [rip+store_value], r10
    mov ecx, ebx
    mov eax, 1
    shl eax, cl
    mov [rip+memory_size], eax
    dec eax
    test rdi, rax
    jnz store_misaligned
    mov esi, 1
    call translate
    mov ecx, [rip+memory_size]
    mov rdx, [rip+store_value]
    call phys_write
    jmp advance
op_imm:
    mov eax, r8d
    sar eax, 20
    cdqe
    mov r11, r9
    cmp ebx, 0
    je imm_add
    cmp ebx, 2
    je imm_slt
    cmp ebx, 3
    je imm_sltu
    cmp ebx, 4
    je imm_xor
    cmp ebx, 6
    je imm_or
    cmp ebx, 7
    je imm_and
    mov ecx, r8d
    shr ecx, 20
    and ecx, 63
    mov eax, r8d
    shr eax, 26
    cmp ebx, 1
    je imm_sll
    cmp ebx, 5
    jne illegal
    cmp eax, 0
    je imm_srl
    cmp eax, 16
    jne illegal
    sar r11, cl
    jmp commit
imm_srl:
    shr r11, cl
    jmp commit
imm_sll:
    test eax, eax
    jnz illegal
    shl r11, cl
    jmp commit
imm_add:
    add r11, rax
    jmp commit
imm_slt:
    xor r11d, r11d
    cmp r9, rax
    setl r11b
    jmp commit
imm_sltu:
    xor r11d, r11d
    cmp r9, rax
    setb r11b
    jmp commit
imm_xor:
    xor r11, rax
    jmp commit
imm_or:
    or r11, rax
    jmp commit
imm_and:
    and r11, rax
    jmp commit
op_imm32:
    mov r11d, r9d
    mov eax, r8d
    sar eax, 20
    cmp ebx, 0
    je imm32_add
    mov ecx, r8d
    shr ecx, 20
    and ecx, 31
    mov eax, r8d
    shr eax, 25
    cmp ebx, 1
    je imm32_sll
    cmp ebx, 5
    jne illegal
    cmp eax, 0
    je imm32_srl
    cmp eax, 32
    jne illegal
    sar r11d, cl
    jmp word_commit
imm32_srl:
    shr r11d, cl
    jmp word_commit
imm32_sll:
    test eax, eax
    jnz illegal
    shl r11d, cl
    jmp word_commit
imm32_add:
    add r11d, eax
word_commit:
    movsxd r11, r11d
    jmp commit
op_reg:
    mov eax, r8d
    shr eax, 25
    cmp eax, 1
    je op_muldiv
    mov r11, r9
    mov ecx, r10d
    test eax, eax
    jz reg_normal
    cmp eax, 32
    jne illegal
    cmp ebx, 0
    je reg_sub
    cmp ebx, 5
    jne illegal
    sar r11, cl
    jmp commit
reg_normal:
    cmp ebx, 0
    je reg_add
    cmp ebx, 1
    je reg_sll
    cmp ebx, 2
    je reg_slt
    cmp ebx, 3
    je reg_sltu
    cmp ebx, 4
    je reg_xor
    cmp ebx, 5
    je reg_srl
    cmp ebx, 6
    je reg_or
    and r11, r10
    jmp commit
reg_add:
    add r11, r10
    jmp commit
reg_sub:
    sub r11, r10
    jmp commit
reg_sll:
    shl r11, cl
    jmp commit
reg_slt:
    xor r11d, r11d
    cmp r9, r10
    setl r11b
    jmp commit
reg_sltu:
    xor r11d, r11d
    cmp r9, r10
    setb r11b
    jmp commit
reg_xor:
    xor r11, r10
    jmp commit
reg_srl:
    shr r11, cl
    jmp commit
reg_or:
    or r11, r10
    jmp commit
op_reg32:
    mov eax, r8d
    shr eax, 25
    cmp eax, 1
    je op_muldiv32
    mov r11d, r9d
    mov ecx, r10d
    test eax, eax
    jz reg32_normal
    cmp eax, 32
    jne illegal
    cmp ebx, 0
    je reg32_sub
    cmp ebx, 5
    jne illegal
    sar r11d, cl
    jmp word_commit
reg32_normal:
    cmp ebx, 0
    je reg32_add
    cmp ebx, 1
    je reg32_sll
    cmp ebx, 5
    jne illegal
    shr r11d, cl
    jmp word_commit
reg32_add:
    add r11d, r10d
    jmp word_commit
reg32_sub:
    sub r11d, r10d
    jmp word_commit
reg32_sll:
    shl r11d, cl
    jmp word_commit
op_muldiv:
    mov rax, r9
    cmp ebx, 0
    je mul_low
    cmp ebx, 1
    je mul_high
    cmp ebx, 2
    je mul_highsu
    cmp ebx, 3
    je mul_highu
    cmp ebx, 5
    je div_u
    cmp ebx, 7
    je rem_u
    test r10, r10
    jz div_zero
    movabs rcx, 0x8000000000000000
    cmp rax, rcx
    jne div_signed
    cmp r10, -1
    je div_overflow
div_signed:
    cqo
    idiv r10
    cmp ebx, 4
    je quotient
    mov r11, rdx
    jmp commit
mul_low:
    imul rax, r10
quotient:
    mov r11, rax
    jmp commit
mul_high:
    imul r10
    mov r11, rdx
    jmp commit
mul_highsu:
    mul r10
    test r9, r9
    jns mul_highsu_done
    sub rdx, r10
mul_highsu_done:
    mov r11, rdx
    jmp commit
mul_highu:
    mul r10
    mov r11, rdx
    jmp commit
div_u:
    test r10, r10
    jz div_zero
    xor edx, edx
    div r10
    jmp quotient
rem_u:
    test r10, r10
    jz div_zero
    xor edx, edx
    div r10
    mov r11, rdx
    jmp commit
div_zero:
    mov r11, -1
    cmp ebx, 6
    jb commit
    mov r11, r9
    jmp commit
div_overflow:
    mov r11, rax
    cmp ebx, 4
    je commit
    xor r11d, r11d
    jmp commit
op_muldiv32:
    mov eax, r9d
    cmp ebx, 0
    je mul32_low
    cmp ebx, 4
    jb illegal
    test r10d, r10d
    jz div32_zero
    cmp ebx, 5
    je div32_u
    cmp ebx, 7
    je div32_u
    cmp eax, 0x80000000
    jne div32_signed
    cmp r10d, -1
    je div32_overflow
div32_signed:
    cdq
    idiv r10d
    cmp ebx, 4
    je quotient32
    mov r11d, edx
    jmp word_commit
mul32_low:
    imul eax, r10d
quotient32:
    mov r11d, eax
    jmp word_commit
div32_u:
    xor edx, edx
    div r10d
    cmp ebx, 5
    je quotient32
    mov r11d, edx
    jmp word_commit
div32_zero:
    mov r11d, -1
    cmp ebx, 6
    jb word_commit
    mov r11d, r9d
    jmp word_commit
div32_overflow:
    mov r11d, eax
    cmp ebx, 4
    je word_commit
    xor r11d, r11d
    jmp word_commit
op_fence:
    /* Fetches read coherent RAM directly, so FENCE.I needs no cache flush. */
    cmp r8d, 0x0000100f
    je advance
    test ebx, ebx
    jnz illegal
    jmp advance
op_system:
    test ebx, ebx
    jnz csr_operation
    cmp r8d, 0x00000073
    je system_ecall
    cmp r8d, 0x00100073
    je system_ebreak
    cmp r8d, 0x30200073
    je system_mret
    cmp r8d, 0x10200073
    je system_sret
    cmp r8d, 0x10500073
    je system_wfi
    mov eax, r8d
    and eax, 0xfe007fff
    cmp eax, 0x12000073
    jne illegal
    cmp qword ptr [rip+privilege], 1
    jb illegal
    cmp qword ptr [rip+privilege], 3
    je advance
    test qword ptr [rip+csrs+CSR_MSTATUS], 0x100000
    jnz illegal
    jmp advance
system_ecall:
    mov rax, [rip+privilege]
    add eax, 8
    xor edx, edx
    jmp trap
system_ebreak:
    mov eax, 3
    mov rdx, r14
    jmp trap
system_wfi:
    cmp qword ptr [rip+privilege], 1
    jb illegal
    cmp qword ptr [rip+privilege], 3
    je advance
    test qword ptr [rip+csrs+CSR_MSTATUS], 0x200000
    jnz illegal
    /* Deterministic CPU remains runnable until an interrupt becomes pending. */
    jmp advance
system_mret:
    cmp qword ptr [rip+privilege], 3
    jne illegal
    mov rax, [rip+csrs+CSR_MSTATUS]
    mov rcx, rax
    shr rcx, 11
    and ecx, 3
    cmp ecx, 2
    je illegal
    mov [rip+privilege], rcx
    mov rdx, rax
    shr rdx, 4
    and edx, 8
    and rax, -6153 /* clear MPP, MIE */
    or rax, rdx
    or rax, 128
    cmp ecx, 3
    je mret_keep_mprv
    btr rax, 17
mret_keep_mprv:
    mov [rip+csrs+CSR_MSTATUS], rax
    mov rbp, [rip+csrs+CSR_MEPC]
    jmp advance
system_sret:
    cmp qword ptr [rip+privilege], 1
    jb illegal
    cmp qword ptr [rip+privilege], 3
    je sret_allowed
    test qword ptr [rip+csrs+CSR_MSTATUS], 0x400000
    jnz illegal
sret_allowed:
    mov rax, [rip+csrs+CSR_MSTATUS]
    mov rcx, rax
    shr rcx, 8
    and ecx, 1
    mov [rip+privilege], rcx
    mov rdx, rax
    shr rdx, 4
    and edx, 2
    and rax, -259 /* clear SPP, SIE */
    btr rax, 17
    or rax, rdx
    or rax, 32
    mov [rip+csrs+CSR_MSTATUS], rax
    mov rbp, [rip+csrs+CSR_SEPC]
    jmp advance
csr_operation:
    cmp ebx, 4
    je illegal
    mov ecx, r8d
    shr ecx, 20
    mov [rip+csr_number], ecx
    mov eax, ecx
    shr eax, 8
    and eax, 3
    cmp rax, [rip+privilege]
    ja illegal
    /* satp is inaccessible from S-mode when TVM is set. */
    cmp ecx, 0x180
    jne csr_no_tvm
    cmp qword ptr [rip+privilege], 1
    jne csr_no_tvm
    test qword ptr [rip+csrs+CSR_MSTATUS], 0x100000
    jnz illegal
csr_no_tvm:
    /* Recognize the implemented architectural CSR set explicitly. */
    cmp ecx, 0x100
    je csr_read_sstatus
    cmp ecx, 0x104
    je csr_read_sie
    cmp ecx, 0x144
    je csr_read_sip
    cmp ecx, 0xc00
    je csr_read_counter
    cmp ecx, 0xc01
    je csr_read_counter
    cmp ecx, 0xc02
    je csr_read_counter
    cmp ecx, 0xb00
    je csr_read_counter
    cmp ecx, 0xb02
    je csr_read_counter
    cmp ecx, 0xf11
    je csr_read_zero
    cmp ecx, 0xf12
    je csr_read_zero
    cmp ecx, 0xf13
    je csr_read_zero
    cmp ecx, 0xf14
    je csr_read_zero
    cmp ecx, 0x105
    je csr_read_plain
    cmp ecx, 0x106
    je csr_read_plain
    cmp ecx, 0x140
    je csr_read_plain
    cmp ecx, 0x141
    je csr_read_plain
    cmp ecx, 0x142
    je csr_read_plain
    cmp ecx, 0x143
    je csr_read_plain
    cmp ecx, 0x180
    je csr_read_plain
    cmp ecx, 0x300
    je csr_read_plain
    cmp ecx, 0x301
    je csr_read_plain
    cmp ecx, 0x302
    je csr_read_plain
    cmp ecx, 0x303
    je csr_read_plain
    cmp ecx, 0x304
    je csr_read_plain
    cmp ecx, 0x305
    je csr_read_plain
    cmp ecx, 0x306
    je csr_read_plain
    cmp ecx, 0x340
    je csr_read_plain
    cmp ecx, 0x341
    je csr_read_plain
    cmp ecx, 0x342
    je csr_read_plain
    cmp ecx, 0x343
    je csr_read_plain
    cmp ecx, 0x344
    je csr_read_plain
    cmp ecx, 0x3a0
    je csr_read_plain
    cmp ecx, 0x3b0
    je csr_read_plain
    jmp illegal
csr_read_plain:
    lea rax, [rip+csrs]
    mov r11, [rax+rcx*8]
    jmp csr_read_done
csr_read_sstatus:
    mov r11, [rip+csrs+CSR_MSTATUS]
    movabs rax, SSTATUS_MASK
    and r11, rax
    jmp csr_read_done
csr_read_sie:
    mov r11, [rip+csrs+CSR_MIE]
    and r11, [rip+csrs+CSR_MIDELEG]
    jmp csr_read_done
csr_read_sip:
    mov r11, [rip+csrs+CSR_MIP]
    and r11, [rip+csrs+CSR_MIDELEG]
    jmp csr_read_done
csr_read_counter:
    /* Counter permission follows mcounteren/scounteren, including time. */
    cmp qword ptr [rip+privilege], 3
    je csr_counter_allowed
    mov edx, ecx
    and edx, 31
    mov rax, [rip+csrs+0x306*8]
    bt rax, rdx
    jnc illegal
    cmp qword ptr [rip+privilege], 1
    je csr_counter_allowed
    mov rax, [rip+csrs+0x106*8]
    bt rax, rdx
    jnc illegal
csr_counter_allowed:
    mov r11, [rip+ticks]
    cmp ecx, 0xc02
    je csr_read_retired
    cmp ecx, 0xb02
    jne csr_read_done
csr_read_retired:
    mov r11, [rip+retired]
    jmp csr_read_done
csr_read_zero:
    xor r11d, r11d
csr_read_done:
    mov rax, r9
    cmp ebx, 5
    jb csr_source_done
    mov eax, r8d
    shr eax, 15
    and eax, 31
csr_source_done:
    mov edx, ebx
    and edx, 3
    cmp edx, 1
    je csr_write_value
    test rax, rax
    jz commit
    cmp edx, 2
    je csr_set
    not rax
    and rax, r11
    jmp csr_write_value
csr_set:
    or rax, r11
csr_write_value:
    mov ecx, [rip+csr_number]
    mov edx, ecx
    shr edx, 10
    cmp edx, 3
    je illegal
    cmp ecx, 0x301
    je commit /* misa is read-only WARL in this implementation. */
    cmp ecx, 0xb00
    je illegal /* Counters have no writable implementation. */
    cmp ecx, 0xb02
    je illegal
    cmp ecx, 0x100
    je csr_write_sstatus
    cmp ecx, 0x104
    je csr_write_sie
    cmp ecx, 0x144
    je csr_write_sip
    cmp ecx, 0x344
    je csr_write_mip
    cmp ecx, 0x180
    jne csr_write_not_satp
    mov rdx, rax
    shr rdx, 60
    test rdx, rdx
    jz csr_write_not_satp
    cmp edx, 8
    jne commit /* unsupported modes leave WARL satp unchanged */
csr_write_not_satp:
    /* This profile implements the single all-access PMP bootstrap setting.
     * Other PMP policies require machine support and trap explicitly.
     */
    cmp ecx, 0x3a0
    jne csr_write_not_pmpcfg
    cmp rax, 15
    jne illegal
csr_write_not_pmpcfg:
    cmp ecx, 0x3b0
    jne csr_write_not_pmp
    cmp rax, -1
    jne illegal
csr_write_not_pmp:
    cmp ecx, 0x141
    je csr_write_epc
    cmp ecx, 0x341
    jne csr_write_plain
csr_write_epc:
    and rax, -4
csr_write_plain:
    cmp ecx, 0x300
    jne csr_write_plain_width_done
    movabs rdx, 0xfffffff0ffffffff
    and rax, rdx
    movabs rdx, 0xa00000000
    or rax, rdx
csr_write_plain_width_done:
    lea rdx, [rip+csrs]
    mov [rdx+rcx*8], rax
    jmp commit
csr_write_sstatus:
    movabs rdx, SSTATUS_MASK
    and rax, rdx
    not rdx
    and rdx, [rip+csrs+CSR_MSTATUS]
    or rax, rdx
    movabs rdx, 0xfffffff0ffffffff
    and rax, rdx
    movabs rdx, 0xa00000000
    or rax, rdx
    mov [rip+csrs+CSR_MSTATUS], rax
    jmp commit
csr_write_sie:
    mov rdx, [rip+csrs+CSR_MIDELEG]
    and rax, rdx
    not rdx
    and rdx, [rip+csrs+CSR_MIE]
    or rax, rdx
    mov [rip+csrs+CSR_MIE], rax
    jmp commit
csr_write_sip:
    /* SSIP is the software-writable delegated pending bit. */
    mov rdx, [rip+csrs+CSR_MIDELEG]
    and edx, 2
    and rax, rdx
    not rdx
    and [rip+csrs+CSR_MIP], rdx
    or [rip+csrs+CSR_MIP], rax
    jmp commit
csr_write_mip:
    and rax, 2
    and qword ptr [rip+csrs+CSR_MIP], -3
    or [rip+csrs+CSR_MIP], rax
    jmp commit
/* Trap entry: rax = cause (interrupt high bit), rdx = tval. */
trap:
    mov [rip+last_cause], rax
    mov [rip+last_tval], rdx
    mov ecx, eax
    and ecx, 63
    cmp qword ptr [rip+privilege], 3
    je trap_machine
    test rax, rax
    js trap_interrupt_delegation
    mov rbx, [rip+csrs+CSR_MEDELEG]
    jmp trap_delegation_test
trap_interrupt_delegation:
    mov rbx, [rip+csrs+CSR_MIDELEG]
trap_delegation_test:
    bt rbx, rcx
    jnc trap_machine
    mov [rip+csrs+CSR_SEPC], r14
    mov [rip+csrs+CSR_SCAUSE], rax
    mov [rip+csrs+CSR_STVAL], rdx
    mov rbx, [rip+csrs+CSR_MSTATUS]
    mov rdx, rbx
    and edx, 2
    shl edx, 4
    and rbx, -291 /* clear SIE, SPIE, SPP */
    or rbx, rdx
    mov rdx, [rip+privilege]
    shl rdx, 8
    or rbx, rdx
    mov [rip+csrs+CSR_MSTATUS], rbx
    mov qword ptr [rip+privilege], 1
    mov rbx, [rip+csrs+CSR_STVEC]
    jmp trap_vector
trap_machine:
    mov [rip+csrs+CSR_MEPC], r14
    mov [rip+csrs+CSR_MCAUSE], rax
    mov [rip+csrs+CSR_MTVAL], rdx
    mov rbx, [rip+csrs+CSR_MSTATUS]
    mov rdx, rbx
    and edx, 8
    shl edx, 4
    and rbx, -6281 /* clear MIE, MPIE, MPP */
    or rbx, rdx
    mov rdx, [rip+privilege]
    shl rdx, 11
    or rbx, rdx
    mov [rip+csrs+CSR_MSTATUS], rbx
    mov qword ptr [rip+privilege], 3
    mov rbx, [rip+csrs+CSR_MTVEC]
trap_vector:
    mov r14, rbx
    and r14, -4
    jz unhandled_error
    test rax, rax
    jns run
    and ebx, 3
    cmp ebx, 1
    jne run
    lea r14, [r14+rcx*4]
    jmp run
illegal:
    mov edx, [rip+instruction]
    mov eax, 2
    jmp trap
instruction_misaligned:
    mov rdx, r14
    xor eax, eax
    jmp trap
target_misaligned:
    mov rdx, rbp
    xor eax, eax
    jmp trap
load_misaligned:
    mov rdx, [rip+fault_address]
    mov eax, 4
    jmp trap
store_misaligned:
    mov rdx, [rip+fault_address]
    mov eax, 6
    jmp trap
/* Translate virtual rdi for access esi (read=0/write=1/execute=2).
 * Sv39 supports 4 KiB, 2 MiB and 1 GiB leaves; no TLB is cached.
 * Hardware updates A/D bits. Page-table reads must themselves reside in RAM.
 */
translate:
    mov [rip+fault_address], rdi
    mov [rip+access_type], esi
    mov r11, [rip+privilege]
    cmp r11d, 3
    jne translate_effective
    cmp esi, 2
    je translate_bare
    mov rax, [rip+csrs+CSR_MSTATUS]
    test eax, 0x20000
    jz translate_bare
    shr rax, 11
    and eax, 3
    mov r11d, eax
    cmp r11d, 3
    je translate_bare
translate_effective:
    mov r8, [rip+csrs+CSR_SATP]
    mov rax, r8
    shr rax, 60
    test eax, eax
    jz translate_bare
    cmp eax, 8
    jne page_fault
    mov rax, rdi
    shl rax, 25
    sar rax, 25
    cmp rax, rdi
    jne page_fault
    shl r8, 20
    shr r8, 8
    mov r9d, 2
translate_level:
    lea rax, [r9*8]
    add eax, r9d
    add eax, 12
    mov ecx, eax
    mov rax, rdi
    shr rax, cl
    and eax, 511
    lea rbx, [r8+rax*8]
    mov eax, RAM_BASE
    sub rbx, rax
    cmp rbx, RAM_SIZE-8
    ja page_access_fault
    mov r10, [r13+rbx]
    test r10b, 1
    jz page_fault
    mov rax, r10
    shr rax, 54
    jnz page_fault
    mov eax, r10d
    and eax, 6
    cmp eax, 4 /* W without R is reserved */
    je page_fault
    test r10b, 10
    jnz translate_leaf
    test r10b, 0xd0 /* non-leaf U/A/D bits are reserved; G is inherited */
    jnz page_fault
    test r9d, r9d
    jz page_fault
    mov r8, r10
    shr r8, 10
    shl r8, 12
    dec r9d
    jmp translate_level
translate_leaf:
    cmp esi, 2
    je translate_execute
    cmp esi, 1
    je translate_write
    test r10b, 2
    jnz translate_permission
    test r10b, 8
    jz page_fault
    test qword ptr [rip+csrs+CSR_MSTATUS], 0x80000
    jz page_fault
    jmp translate_permission
translate_execute:
    test r10b, 8
    jz page_fault
    jmp translate_permission
translate_write:
    test r10b, 4
    jz page_fault
translate_permission:
    test r11d, r11d
    jz translate_user
    test r10b, 16
    jz translate_pte_address
    cmp esi, 2
    je page_fault
    test qword ptr [rip+csrs+CSR_MSTATUS], 0x40000
    jz page_fault
    jmp translate_pte_address
translate_user:
    test r10b, 16
    jz page_fault
translate_pte_address:
    mov rax, r10
    shr rax, 10
    /* A superpage leaf's lower PPN fields must be zero. */
    mov ecx, r9d
    imul ecx, ecx, 9
    mov rdx, 1
    shl rdx, cl
    dec rdx
    test rax, rdx
    jnz page_fault
    or r10, 64
    cmp esi, 1
    jne translate_ad_done
    or r10, 128
translate_ad_done:
    mov [r13+rbx], r10
    shl rax, 12
    add ecx, 12
    mov rdx, 1
    shl rdx, cl
    dec rdx
    and rdx, rdi
    or rax, rdx
    ret
translate_bare:
    mov rax, rdi
    ret
page_fault:
    mov eax, [rip+access_type]
    cmp eax, 2
    je instruction_page_fault
    imul eax, eax, 2
    add eax, 13
    jmp memory_trap
instruction_page_fault:
    mov eax, 12
    jmp memory_trap
page_access_fault:
    mov eax, [rip+access_type]
    cmp eax, 2
    je instruction_access_fault
    imul eax, eax, 2
    add eax, 5
    jmp memory_trap
instruction_access_fault:
    mov eax, 1
memory_trap:
    mov rdx, [rip+fault_address]
    jmp trap
/* Physical memory adapter: PA rax, byte length ecx, return value rax. */
phys_read:
    mov edx, RAM_BASE
    mov rdx, rax
    mov ebx, RAM_BASE
    sub rdx, rbx
    mov ebx, RAM_SIZE
    sub ebx, ecx
    cmp rdx, rbx
    ja phys_read_device
    lea rdx, [r13+rdx]
    cmp ecx, 1
    je phys_read_byte
    cmp ecx, 2
    je phys_read_half
    cmp ecx, 4
    je phys_read_word
    mov rax, [rdx]
    ret
phys_read_byte:
    movzx eax, byte ptr [rdx]
    ret
phys_read_half:
    movzx eax, word ptr [rdx]
    ret
phys_read_word:
    mov eax, [rdx]
    ret
phys_read_device:
    cmp dword ptr [rip+access_type], 2
    je page_access_fault
    cmp rax, 0x10001000
    jb phys_read_uart
    cmp rax, 0x10008fff
    jbe virtio_read
phys_read_uart:
    cmp rax, 0x10000000
    jb phys_read_clint
    cmp rax, 0x10000007
    ja phys_read_clint
    cmp ecx, 1
    jne page_access_fault
    sub eax, 0x10000000
    cmp eax, 5
    je uart_lsr
    test eax, eax
    jz uart_receive
    cmp eax, 2
    je uart_no_interrupt
    lea rdx, [rip+uart]
    movzx eax, byte ptr [rdx+rax]
    ret
uart_lsr:
    call uart_poll
    movzx eax, byte ptr [rip+rx_valid]
    or eax, 0x60
    ret
uart_receive:
    test byte ptr [rip+uart+3], 128
    jnz uart_divisor
    call uart_poll
    xor eax, eax
    cmp byte ptr [rip+rx_valid], 0
    je uart_receive_done
    movzx eax, byte ptr [rip+rx_byte]
    mov byte ptr [rip+rx_valid], 0
uart_receive_done:
    ret
uart_divisor:
    movzx eax, byte ptr [rip+uart]
    ret
uart_no_interrupt:
    mov eax, 1
    ret
/* Host adapter: poll stdin without blocking the CPU or altering parent fd flags. */
uart_poll:
    cmp byte ptr [rip+rx_valid], 0
    jne uart_poll_done
    cmp byte ptr [rip+stdin_eof], 0
    jne uart_poll_done
    lea rdi, [rip+stdin_poll]
    mov esi, 1
    xor edx, edx
    mov eax, 7
    syscall
    cmp rax, 1
    jne uart_poll_done
    test word ptr [rip+stdin_poll+6], 1
    jz uart_poll_done
    xor edi, edi
    lea rsi, [rip+rx_byte]
    mov edx, 1
    xor eax, eax
    syscall
    cmp rax, 1
    je uart_poll_byte
    test rax, rax
    jne uart_poll_done
    mov byte ptr [rip+stdin_eof], 1
    ret
uart_poll_byte:
    mov byte ptr [rip+rx_valid], 1
uart_poll_done:
    ret
phys_read_clint:
    lea rdx, [rip+timecmp]
    cmp rax, 0x2004000
    je phys_read_timer
    cmp rax, 0x2004004
    je phys_read_timer_high
    lea rdx, [rip+ticks]
    cmp rax, 0x200bff8
    je phys_read_timer
    cmp rax, 0x200bffc
    je phys_read_timer_high
    cmp rax, 0x2000000
    je phys_read_msip
    jmp page_access_fault
phys_read_timer:
    cmp ecx, 8
    je phys_read_timer64
    cmp ecx, 4
    jne page_access_fault
    mov eax, [rdx]
    ret
phys_read_timer64:
    mov rax, [rdx]
    ret
phys_read_timer_high:
    cmp ecx, 4
    jne page_access_fault
    mov eax, [rdx+4]
    ret
phys_read_msip:
    cmp ecx, 4
    jne page_access_fault
    mov rax, [rip+csrs+CSR_MIP]
    shr eax, 3
    and eax, 1
    ret
/* PA rax, byte length ecx, stored value rdx. */
phys_write:
    mov r8, rax
    mov ebx, RAM_BASE
    sub r8, rbx
    mov ebx, RAM_SIZE
    sub ebx, ecx
    cmp r8, rbx
    ja phys_write_device
    lea r8, [r13+r8]
    cmp ecx, 1
    je phys_write_byte
    cmp ecx, 2
    je phys_write_half
    cmp ecx, 4
    je phys_write_word
    mov [r8], rdx
    ret
phys_write_byte:
    mov [r8], dl
    ret
phys_write_half:
    mov [r8], dx
    ret
phys_write_word:
    mov [r8], edx
    ret
phys_write_device:
    cmp rax, 0x10001000
    jb phys_write_not_virtio
    cmp rax, 0x10008fff
    jbe virtio_write
phys_write_not_virtio:
    cmp rax, 0x100000
    je finisher
    cmp rax, 0x10000000
    jb phys_write_clint
    cmp rax, 0x10000007
    ja phys_write_clint
    cmp ecx, 1
    jne page_access_fault
    sub eax, 0x10000000
    lea r8, [rip+uart]
    mov [r8+rax], dl
    test eax, eax
    jnz phys_write_done
    test byte ptr [r8+3], 128 /* divisor latch suppresses transmit */
    jnz phys_write_done
    mov byte ptr [rip+uart_byte], dl
    mov eax, 1
    mov edi, 1
    lea rsi, [rip+uart_byte]
    mov edx, 1
    syscall
    cmp rax, 1
    jne host_io_error
phys_write_done:
    ret
phys_write_clint:
    lea r8, [rip+timecmp]
    cmp rax, 0x2004000
    je phys_write_timer
    cmp rax, 0x2004004
    je phys_write_timer_high
    lea r8, [rip+ticks]
    cmp rax, 0x200bff8
    je phys_write_timer
    cmp rax, 0x200bffc
    je phys_write_timer_high
    cmp rax, 0x2000000
    je phys_write_msip
    jmp page_access_fault
phys_write_timer:
    cmp ecx, 8
    je phys_write_timer64
    cmp ecx, 4
    jne page_access_fault
    mov [r8], edx
    ret
phys_write_timer64:
    mov [r8], rdx
    ret
phys_write_timer_high:
    cmp ecx, 4
    jne page_access_fault
    mov [r8+4], edx
    ret
phys_write_msip:
    cmp ecx, 4
    jne page_access_fault
    and edx, 1
    shl edx, 3
    and qword ptr [rip+csrs+CSR_MIP], -9
    or [rip+csrs+CSR_MIP], rdx
    ret
finisher:
    cmp ecx, 4
    jne page_access_fault
    cmp dx, 0x5555
    je success
    cmp dx, 0x3333
    jne page_access_fault
    mov edi, 1
    jmp exit_host
success:
    xor edi, edi
exit_host:
    mov eax, 60
    syscall
/* Virtio MMIO legacy transport. Queues are bounded direct descriptors only.
 * This host adapter translates checked DMA to RAM and Linux pread/pwrite/fsync
 * or getrandom; all guest protocol and privilege execution stays in assembly.
 */
virtio_read:
    cmp ecx, 4
    jne page_access_fault
    sub eax, 0x10001000
    mov r8d, eax
    shr r8d, 12
    and eax, 4095
    cmp r8d, 5
    je network_read
    cmp r8d, 2
    jb 1f
    cmp r8d, 5
    jb modern_read
1:
    mov r9d, r8d
    shl r9d, 6
    lea rdi, [rip+virtio_states]
    add rdi, r9
    cmp eax, 0
    je virtio_magic
    cmp eax, 4
    je virtio_version
    cmp eax, 8
    je virtio_id
    cmp eax, 12
    je virtio_vendor
    cmp r8d, 6
    je 2f
    cmp r8d, 2
    jae virtio_zero
2:
    cmp eax, 0x10
    je virtio_features
    cmp eax, 0x34
    je virtio_queue_max
    cmp eax, 0x40
    je virtio_queue_pfn
    cmp eax, 0x60
    je virtio_interrupt
    cmp eax, 0x70
    je virtio_status
    cmp eax, 0x100
    je virtio_capacity_low
    cmp eax, 0x104
    je virtio_capacity_high
virtio_zero:
    xor eax, eax
    ret
virtio_magic:
    mov eax, 0x74726976
    ret
virtio_version:
    mov eax, 1
    ret
virtio_id:
    cmp r8d, 6
    je virtio_server_id
    cmp r8d, 1
    je virtio_rng_id
    test r8d, r8d
    jnz virtio_zero
    cmp qword ptr [rip+vault_fd], 0
    jl virtio_zero
    mov eax, 2
    ret
virtio_server_id:
    cmp qword ptr [rip+server_fd], 0
    jl virtio_zero
    mov eax, 2
    ret
virtio_rng_id:
    mov eax, 4
    ret
virtio_vendor:
    mov eax, 0x4c54
    ret
virtio_features:
    cmp dword ptr [rdi], 0
    jne virtio_zero
    cmp r8d, 6
    je virtio_server_features
    test r8d, r8d
    jnz virtio_zero
    mov eax, 0x200 /* VIRTIO_BLK_F_FLUSH */
    cmp byte ptr [rip+vault_readonly], 0
    je virtio_features_return
    or eax, 32
virtio_features_return:
    ret
virtio_server_features:
    mov eax, 0x200
    cmp byte ptr [rip+server_readonly], 0
    je 1f
    or eax, 32
1:  ret
virtio_queue_max:
    cmp dword ptr [rdi+16], 0
    jne virtio_zero
    mov eax, 8
    ret
virtio_queue_pfn:
    mov eax, [rdi+28]
    ret
virtio_interrupt:
    mov eax, [rdi+32]
    ret
virtio_status:
    mov eax, [rdi+36]
    ret
virtio_capacity_low:
    cmp r8d, 6
    jne 1f
    mov eax, [rip+server_sectors]
    ret
1:
    test r8d, r8d
    jnz virtio_zero
    mov eax, [rip+vault_sectors]
    ret
virtio_capacity_high:
    cmp r8d, 6
    jne 1f
    mov eax, [rip+server_sectors+4]
    ret
1:
    test r8d, r8d
    jnz virtio_zero
    mov eax, [rip+vault_sectors+4]
    ret
virtio_write:
    cmp ecx, 4
    jne page_access_fault
    sub eax, 0x10001000
    mov r8d, eax
    shr r8d, 12
    and eax, 4095
    cmp r8d, 5
    je network_write
    cmp r8d, 2
    jb 1f
    cmp r8d, 5
    jb modern_write
1:
    cmp r8d, 6
    je 2f
    cmp r8d, 2
    jae virtio_write_done
2:
    mov [rip+virtio_number], r8d
    mov r9d, r8d
    shl r9d, 6
    lea rdi, [rip+virtio_states]
    add rdi, r9
    mov [rip+virtio_current], rdi
    cmp eax, 0x14
    je virtio_write_feature_sel
    cmp eax, 0x20
    je virtio_write_features
    cmp eax, 0x24
    je virtio_write_guest_sel
    cmp eax, 0x28
    je virtio_write_page
    cmp eax, 0x30
    je virtio_write_queue_sel
    cmp eax, 0x38
    je virtio_write_queue_num
    cmp eax, 0x3c
    je virtio_write_align
    cmp eax, 0x40
    je virtio_write_pfn
    cmp eax, 0x50
    je virtio_notify
    cmp eax, 0x64
    je virtio_ack
    cmp eax, 0x70
    je virtio_write_status
virtio_write_done:
    ret
virtio_write_feature_sel:
    mov [rdi], edx
    ret
virtio_write_features:
    cmp dword ptr [rdi+8], 0
    jne virtio_features_high
    mov [rdi+4], edx
    ret
virtio_features_high:
    test edx, edx
    jnz virtio_fail
    ret
virtio_write_guest_sel:
    mov [rdi+8], edx
    ret
virtio_write_page:
    cmp edx, 4096
    jne virtio_fail
    mov [rdi+12], edx
    ret
virtio_write_queue_sel:
    mov [rdi+16], edx
    ret
virtio_write_queue_num:
    cmp dword ptr [rdi+16], 0
    jne virtio_fail
    cmp edx, 1
    jb virtio_fail
    cmp edx, 8
    ja virtio_fail
    lea eax, [rdx-1]
    test edx, eax
    jnz virtio_fail
    mov [rdi+20], edx
    ret
virtio_write_align:
    cmp edx, 4096
    jne virtio_fail
    mov [rdi+24], edx
    ret
virtio_write_pfn:
    mov [rdi+28], edx
    mov dword ptr [rdi+40], 0
    mov dword ptr [rdi+44], 0
    ret
virtio_ack:
    not edx
    and [rdi+32], edx
    ret
virtio_write_status:
    test edx, edx
    jz virtio_reset
    /* Reject negotiation of unimplemented features. */
    mov eax, [rdi+4]
    cmp dword ptr [rip+virtio_number], 6
    jne 1f
    mov ecx, 0x200
    cmp byte ptr [rip+server_readonly], 0
    je virtio_status_feature_mask
    or ecx, 32
    jmp virtio_status_feature_mask
1:  cmp dword ptr [rip+virtio_number], 0
    jne virtio_status_rng
    mov ecx, 0x200
    cmp byte ptr [rip+vault_readonly], 0
    je virtio_status_feature_mask
    or ecx, 32
virtio_status_feature_mask:
    not ecx
    and eax, ecx
virtio_status_rng:
    test eax, eax
    jnz virtio_fail
    mov [rdi+36], edx
    ret
virtio_reset:
    xor eax, eax
    mov ecx, 8
    rep stosq
    ret
virtio_fail:
    mov rdi, [rip+virtio_current]
    or dword ptr [rdi+36], 128
    ret
virtio_notify:
    test edx, edx
    jnz virtio_fail
    test dword ptr [rdi+36], 4
    jz virtio_fail
    test dword ptr [rdi+36], 128
    jnz virtio_write_done
    cmp dword ptr [rdi+12], 4096
    jne virtio_fail
    cmp dword ptr [rdi+24], 4096
    jne virtio_fail
    mov eax, [rdi+28]
    test eax, eax
    jz virtio_fail
    shl rax, 12
    mov [rip+queue_physical], rax
    mov ecx, 4096
    call dma_pointer
    jc virtio_fail
    mov [rip+queue_host], rax
    mov rdi, [rip+virtio_current]
    mov ecx, [rdi+20]
    test ecx, ecx
    jz virtio_fail
    cmp ecx, 8
    ja virtio_fail
    mov [rip+queue_size], ecx
    shl ecx, 4
    add rax, rcx
    mov [rip+avail_host], rax
    mov rax, [rip+queue_physical]
    add rax, 4096
    mov ecx, 4096
    call dma_pointer
    jc virtio_fail
    mov [rip+used_host], rax
    mov rsi, [rip+avail_host]
    movzx eax, word ptr [rsi+2]
    mov [rip+avail_target], eax
    sub ax, [rdi+40]
    movzx eax, ax
    cmp eax, [rip+queue_size]
    ja virtio_fail
virtio_consume:
    mov rdi, [rip+virtio_current]
    movzx eax, word ptr [rdi+40]
    cmp ax, [rip+avail_target]
    je virtio_write_done
    mov ecx, [rip+queue_size]
    dec ecx
    and eax, ecx
    mov rsi, [rip+avail_host]
    movzx eax, word ptr [rsi+4+rax*2]
    cmp eax, [rip+queue_size]
    jae virtio_fail
    mov [rip+request_head], eax
    shl eax, 4
    add rax, [rip+queue_host]
    mov [rip+request_descriptor], rax
    cmp dword ptr [rip+virtio_number], 1
    je virtio_entropy
    call virtio_block
    jmp virtio_complete
virtio_entropy:
    mov rsi, rax
    cmp word ptr [rsi+12], 2
    jne virtio_fail
    mov ecx, [rsi+8]
    test ecx, ecx
    jz virtio_fail
    cmp ecx, 256
    ja virtio_fail
    mov [rip+request_length], ecx
    mov rax, [rsi]
    call dma_pointer
    jc virtio_fail
    mov rdi, rax
    mov esi, [rip+request_length]
    mov edx, 1 /* GRND_NONBLOCK; unavailable entropy fails closed. */
    mov eax, 318
    syscall
    xor ecx, ecx
    cmp eax, [rip+request_length]
    cmove ecx, eax
    mov [rip+request_used], ecx
virtio_complete:
    mov rdi, [rip+virtio_current]
    movzx eax, word ptr [rdi+44]
    mov ecx, [rip+queue_size]
    dec ecx
    and eax, ecx
    mov rsi, [rip+used_host]
    lea rsi, [rsi+4+rax*8]
    mov eax, [rip+request_head]
    mov [rsi], eax
    mov eax, [rip+request_used]
    mov [rsi+4], eax
    inc word ptr [rdi+44]
    mov ax, [rdi+44]
    mov rsi, [rip+used_host]
    mov [rsi+2], ax
    inc word ptr [rdi+40]
    or dword ptr [rdi+32], 1
    jmp virtio_consume
/* Check an entire physical DMA span before constructing a host pointer. */
dma_pointer:
    cmp ecx, RAM_SIZE
    ja dma_invalid
    mov edx, RAM_BASE
    sub rax, rdx
    mov edx, RAM_SIZE
    sub edx, ecx
    cmp rax, rdx
    ja dma_invalid
    add rax, r13
    clc
    ret
dma_invalid:
    stc
    ret
/* Descriptor helper: current chain node rsi; return checked next node rsi. */
virtio_next:
    test word ptr [rsi+12], 1
    jz virtio_chain_bad
    test word ptr [rsi+12], 0xfffc
    jnz virtio_chain_bad
    movzx eax, word ptr [rsi+14]
    cmp eax, [rip+queue_size]
    jae virtio_chain_bad
    shl eax, 4
    add rax, [rip+queue_host]
    mov rsi, rax
    clc
    ret
virtio_chain_bad:
    stc
    ret
virtio_block:
    mov rax, [rip+vault_fd]
    mov rdx, [rip+vault_sectors]
    movzx ecx, byte ptr [rip+vault_readonly]
    cmp dword ptr [rip+virtio_number], 6
    jne 1f
    mov rax, [rip+server_fd]
    mov rdx, [rip+server_sectors]
    movzx ecx, byte ptr [rip+server_readonly]
1:  mov [rip+block_active_fd], rax
    mov [rip+block_active_sectors], rdx
    mov [rip+block_active_readonly], cl
    mov rsi, [rip+request_descriptor]
    cmp word ptr [rsi+12], 1
    jne virtio_block_fatal
    cmp dword ptr [rsi+8], 16
    jne virtio_block_fatal
    mov rax, [rsi]
    mov ecx, 16
    call dma_pointer
    jc virtio_block_fatal
    mov edx, [rax]
    mov [rip+request_type], edx
    mov rdx, [rax+8]
    mov [rip+request_sector], rdx
    call virtio_next
    jc virtio_block_fatal
    cmp dword ptr [rip+request_type], 4
    je virtio_block_status
    mov eax, [rsi+8]
    test eax, eax
    jz virtio_block_fatal
    cmp eax, 4096
    ja virtio_block_fatal
    cmp dword ptr [rip+request_type], 8
    je 1f
    test eax, 511
    jnz virtio_block_fatal
    jmp 2f
1:  cmp eax, 20
    jne virtio_block_fatal
2:  mov [rip+request_length], eax
    movzx eax, word ptr [rsi+12]
    mov [rip+request_flags], eax
    mov rax, [rsi]
    mov ecx, [rip+request_length]
    call dma_pointer
    jc virtio_block_fatal
    mov [rip+request_buffer], rax
    call virtio_next
    jc virtio_block_fatal
virtio_block_status:
    cmp word ptr [rsi+12], 2
    jne virtio_block_fatal
    cmp dword ptr [rsi+8], 1
    jb virtio_block_fatal
    mov rax, [rsi]
    mov ecx, 1
    call dma_pointer
    jc virtio_block_fatal
    mov [rip+request_status], rax
    mov dword ptr [rip+request_used], 1
    cmp qword ptr [rip+block_active_fd], 0
    jl virtio_block_error
    mov eax, [rip+request_type]
    cmp eax, 8
    je virtio_block_identity
    cmp eax, 4
    je virtio_block_flush
    cmp eax, 0
    je virtio_block_input
    cmp eax, 1
    jne virtio_block_unsupported
    cmp dword ptr [rip+request_flags], 1
    jne virtio_block_error
    cmp byte ptr [rip+block_active_readonly], 0
    jne virtio_block_error
    jmp virtio_block_bounds
virtio_block_input:
    cmp dword ptr [rip+request_flags], 3
    jne virtio_block_error
virtio_block_bounds:
    mov r10, [rip+request_sector]
    mov rax, [rip+block_active_sectors]
    cmp r10, rax
    jae virtio_block_error
    sub rax, r10
    mov edx, [rip+request_length]
    shr edx, 9
    cmp rdx, rax
    ja virtio_block_error
    shl r10, 9
    mov rdi, [rip+block_active_fd]
    mov rsi, [rip+request_buffer]
    mov edx, [rip+request_length]
    mov eax, 17 /* pread64 */
    cmp dword ptr [rip+request_type], 0
    je virtio_block_io
    mov eax, 18 /* pwrite64 */
virtio_block_io:
    syscall
    cmp eax, [rip+request_length]
    jne virtio_block_error
    cmp dword ptr [rip+request_type], 0
    jne virtio_block_ok
    inc eax
    mov [rip+request_used], eax
    jmp virtio_block_ok
virtio_block_identity:
    cmp dword ptr [rip+request_flags], 3
    jne virtio_block_error
    mov rdi, [rip+request_buffer]
    lea rsi, [rip+objects_serial]
    cmp dword ptr [rip+virtio_number], 6
    jne 1f
    lea rsi, [rip+server_serial]
1:  mov ecx, 20
    rep movsb
    mov dword ptr [rip+request_used], 21
    jmp virtio_block_ok
virtio_block_flush:
    mov rdi, [rip+block_active_fd]
    mov eax, 74
    syscall
    test rax, rax
    jne virtio_block_error
virtio_block_ok:
    mov rax, [rip+request_status]
    mov byte ptr [rax], 0
    ret
virtio_block_error:
    mov rax, [rip+request_status]
    mov byte ptr [rax], 1
    ret
virtio_block_unsupported:
    mov rax, [rip+request_status]
    mov byte ptr [rax], 2
    ret
virtio_block_fatal:
    pop rax /* discard virtio_block return before returning to guest store */
    jmp virtio_fail

#include "graphics_x86_64.inc"
#include "network_x86_64.inc"

argument_equal:
    mov al, [rdi]
    cmp al, [rsi]
    jne argument_different
    inc rdi
    inc rsi
    test al, al
    jnz argument_equal
    mov eax, 1
    ret
argument_different:
    xor eax, eax
    ret
vault_error:
    lea rsi, [rip+vault_message]
    mov edx, 88
    jmp error_message
usage:
    lea rsi, [rip+usage_message]
    mov edx, 87
    jmp error_message
image_error:
    lea rsi, [rip+image_message]
    mov edx, 65
    jmp error_message
budget_error:
    lea rsi, [rip+budget_message]
    mov edx, 49
    jmp state_error
unhandled_error:
    mov r14, [rip+csrs+CSR_MEPC]
    lea rsi, [rip+trap_message]
    mov edx, 39
    jmp state_error
host_io_error:
    lea rsi, [rip+io_message]
    mov edx, 37
error_message:
    mov eax, 1
    mov edi, 2
    syscall
    mov edi, 2
    jmp exit_host
state_error:
    mov eax, 1
    mov edi, 2
    syscall
    mov rax, r14
    call print_hex
    lea rsi, [rip+cause_message]
    mov edx, 9
    mov eax, 1
    mov edi, 2
    syscall
    mov rax, [rip+last_cause]
    call print_hex
    lea rsi, [rip+tval_message]
    mov edx, 8
    mov eax, 1
    mov edi, 2
    syscall
    mov rax, [rip+last_tval]
    call print_hex
    lea rsi, [rip+newline]
    mov edx, 1
    jmp error_message
print_hex:
    lea rsi, [rip+hex_buffer]
    lea r8, [rip+hex_digits]
    mov ecx, 16
hex_loop:
    rol rax, 4
    mov edx, eax
    and edx, 15
    mov dl, [r8+rdx]
    mov [rsi], dl
    inc rsi
    dec ecx
    jnz hex_loop
    lea rsi, [rip+hex_buffer]
    mov edx, 16
    mov eax, 1
    mov edi, 2
    syscall
    ret
.section .rodata
usage_message: .ascii "usage: ltemu-x86_64 guest.bin [--interactive] [--vault backing.img] [--vault-readonly] [--display-out frame.bgrx] [--input-events events.evdev]\n"
usage_end:
image_message: .ascii "ltemu-x86_64: cannot load nonempty guest image (maximum 128 MiB)\n"
image_end:
budget_message: .ascii "ltemu-x86_64: instruction budget exhausted; pc=0x"
budget_end:
trap_message: .ascii "ltemu-x86_64: trap has no vector; pc=0x"
trap_end:
io_message: .ascii "ltemu-x86_64: host UART write failed\n"
io_end:
cause_message: .ascii " cause=0x"
cause_end:
tval_message: .ascii " tval=0x"
tval_end:
interactive_arg: .asciz "--interactive"
vault_arg: .asciz "--vault"
readonly_arg: .asciz "--vault-readonly"
vault_message: .ascii "ltemu-x86_64: vault must be an explicit existing regular file of whole 512-byte sectors\n"
hex_digits: .ascii "0123456789abcdef"
newline: .ascii "\n"
.section .bss
.balign 16
regs: .skip 256
csrs: .skip 32768
privilege: .skip 8
host_rsp: .skip 8
ticks: .skip 8
retired: .skip 8
timecmp: .skip 8
last_cause: .skip 8
last_tval: .skip 8
fault_address: .skip 8
store_value: .skip 8
instruction: .skip 4
memory_size: .skip 4
access_type: .skip 4
csr_number: .skip 4
uart: .skip 8
uart_byte: .skip 1
interactive: .skip 1
vault_readonly: .skip 1
rx_valid: .skip 1
rx_byte: .skip 1
stdin_eof: .skip 1
.balign 8
vault_path: .skip 8
vault_fd: .skip 8
vault_sectors: .skip 8
host_stat: .skip 144
.balign 8
virtio_states: .skip 512
virtio_current: .skip 8
virtio_number: .skip 4
queue_size: .skip 4
queue_physical: .skip 8
queue_host: .skip 8
avail_host: .skip 8
used_host: .skip 8
avail_target: .skip 4
request_head: .skip 4
request_descriptor: .skip 8
request_buffer: .skip 8
request_status: .skip 8
request_sector: .skip 8
request_length: .skip 4
request_used: .skip 4
request_type: .skip 4
request_flags: .skip 4
hex_buffer: .skip 16
.section .data
.balign 8
stdin_poll: .long 0
    .short 1, 0
.section .note.GNU-stack,"",@progbits

.section .rodata
server_arg: .asciz "--server-store"
objects_serial: .ascii "lt-objects-v1\0\0\0\0\0\0\0"
server_serial: .ascii "lt-server-v1\0\0\0\0\0\0\0\0"
.section .bss
.balign 8
server_path: .skip 8
server_fd: .skip 8
server_sectors: .skip 8
block_active_fd: .skip 8
block_active_sectors: .skip 8
block_active_readonly: .skip 8

.section .rodata
server_readonly_arg: .asciz "--server-store-readonly"
.section .bss
server_readonly: .skip 1
