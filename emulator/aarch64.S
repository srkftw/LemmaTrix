/* Linux/AArch64 host interpreter for the development RV64IM/Sv39 machine.
 * All guest execution, address translation, traps and devices live here.
 * x19: state, x20: RAM, x21: PC, x22: privilege, x28: clock ticks, x29: retired instructions.
 */
.equ RAM_BASE, 0x80000000
.equ RAM_SIZE, 0xa000000
.equ CSR, 256
.equ MTIMECMP, 32760
.equ HOSTSP, 32752
.macro addr reg, symbol
 adrp \reg, \symbol
 add \reg, \reg, :lo12:\symbol
.endm
.macro getcsr reg, number
 ldr \reg, [x19, #(CSR + 8 * \number)]
.endm
.macro setcsr reg, number
 str \reg, [x19, #(CSR + 8 * \number)]
.endm
.section .text
.global _start
_start:
 mov x18, sp
 addr x19, state
 addr x20, ram
 mov x21, #RAM_BASE
 mov x22, #3
 mov x23, #0
 mov x28, #0
 mov x29, #0
 str x18, [x19, #HOSTSP]
 mov x0, #-1
 str x0, [x19, #MTIMECMP]
 mov x0, #0xa00000000
 setcsr x0, 0x300
 addr x1, server_fd
 mov x0, #-1
 str x0, [x1]
 addr x1, pcm_fd
 mov x0, #-1
 str x0, [x1]
 addr x1, network_fd
 mov x0, #-1
 str x0, [x1]
 addr x1, vault_fd
 mov x0, #-1
 str x0, [x1]
 addr x1, display_fd
 str x0, [x1]
 addr x1, input_fd
 str x0, [x1]
 ldr x24, [sp]
 cmp x24, #2
 b.lt usage
 mov x25, #2
parse_arguments:
 cmp x25, x24
 b.hs arguments_done
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, interactive_arg
 bl argument_equal
 cbnz x0, argument_interactive
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, readonly_arg
 bl argument_equal
 cbnz x0, argument_readonly
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, display_arg
 bl argument_equal
 cbnz x0, argument_display
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, input_arg
 bl argument_equal
 cbnz x0, argument_input
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, server_readonly_arg
 bl argument_equal
 cbnz x0, argument_server_readonly
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, server_arg
 bl argument_equal
 cbnz x0, argument_server
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, pcm_arg
 bl argument_equal
 cbnz x0, argument_pcm
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, network_arg
 bl argument_equal
 cbnz x0, argument_network
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 addr x1, vault_arg
 bl argument_equal
 cbz x0, usage
 add x25, x25, #1
 cmp x25, x24
 b.hs usage
 addr x3, vault_path
 ldr x0, [x3]
 cbnz x0, usage
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 str x0, [x3]
 add x25, x25, #1
 b parse_arguments
argument_network:
 add x25, x25, #1
 cmp x25, x24
 b.hs usage
 add x2, x25, #1
 ldr x1, [x18, x2, lsl #3]
 mov x0, #0
1: ldrb w2, [x1], #1
 cbz w2, 2f
 sub w2, w2, #48
 cmp w2, #9
 b.hi usage
 mov x3, #10
 madd x0, x0, x3, x2
 cmp x0, #1023
 b.hi usage
 b 1b
2: cmp x0, #3
 b.lo usage
 addr x1, network_fd
 str x0, [x1]
 add x25, x25, #1
 b parse_arguments
argument_pcm:
 add x25, x25, #1
 cmp x25, x24
 b.hs usage
 add x2, x25, #1
 ldr x1, [x18, x2, lsl #3]
 mov x0, #0
1: ldrb w2, [x1], #1
 cbz w2, 2f
 sub w2, w2, #48
 cmp w2, #9
 b.hi usage
 mov x3, #10
 madd x0, x0, x3, x2
 cmp x0, #1023
 b.hi usage
 b 1b
2: cmp x0, #3
 b.lo usage
 addr x1, pcm_fd
 str x0, [x1]
 add x25, x25, #1
 b parse_arguments
argument_readonly:
 addr x0, vault_readonly
 mov w1, #1
 strb w1, [x0]
 add x25, x25, #1
 b parse_arguments
argument_interactive:
 addr x0, interactive
 mov w1, #1
 strb w1, [x0]
 add x25, x25, #1
 b parse_arguments
argument_server_readonly:
 addr x0, server_readonly
 mov w1, #1
 strb w1, [x0]
 add x25, x25, #1
 b parse_arguments
argument_server:
 addr x3, server_path
 b argument_adapter_path
argument_display:
 addr x3, display_path
 b argument_adapter_path
argument_input:
 addr x3, input_path
argument_adapter_path:
 add x25, x25, #1
 cmp x25, x24
 b.hs usage
 ldr x0, [x3]
 cbnz x0, usage
 add x2, x25, #1
 ldr x0, [x18, x2, lsl #3]
 str x0, [x3]
 add x25, x25, #1
 b parse_arguments
arguments_done:
 mov x0, #-100
 ldr x1, [sp, #16]
 mov x2, #0
 mov x3, #0
 mov x8, #56
 svc #0
 cmp x0, #0
 b.lt io_error
 mov x17, x0
 mov x1, x20
 mov x16, #0
load_image:
 mov x0, x17
 mov x2, #RAM_SIZE
 sub x2, x2, x16
 mov x8, #63
 svc #0
 cmp x0, #0
 b.lt io_error
 cbz x0, image_loaded
 add x16, x16, x0
 add x1, x1, x0
 mov x3, #RAM_SIZE
 cmp x16, x3
 b.lo load_image
 /* Reject oversized input rather than silently truncate it. */
 mov x0, x17
 addr x1, bytebuf
 mov x2, #1
 mov x8, #63
 svc #0
 cbnz x0, io_error
image_loaded:
 cbz x16, io_error
 mov x0, x17
 mov x8, #57
 svc #0
 addr x1, vault_path
 ldr x1, [x1]
 cbz x1, vault_opened
 mov x0, #-100
 mov x2, #2
 addr x3, vault_readonly
 ldrb w3, [x3]
 cbz w3, vault_open_flags
 mov x2, #0
vault_open_flags:
 mov x3, #0
 mov x8, #56
 svc #0
 cmp x0, #0
 b.lt vault_error
 addr x1, vault_fd
 str x0, [x1]
 addr x1, host_stat
 mov x8, #80
 svc #0
 cbnz x0, vault_error
 addr x1, host_stat
 ldr w0, [x1, #16]
 and w0, w0, #0xf000
 cmp w0, #0x8000
 b.ne vault_error
 ldr x0, [x1, #48]
 cbz x0, vault_error
 tst x0, #511
 b.ne vault_error
 lsr x0, x0, #9
 addr x1, vault_sectors
 str x0, [x1]
vault_opened:
 addr x1, server_path
 ldr x1, [x1]
 cbz x1, server_opened
 mov x0, #-100
 mov x2, #2
 addr x3, server_readonly
 ldrb w3, [x3]
 cbz w3, 1f
 mov x2, #0
1:
 mov x3, #0
 mov x8, #56
 svc #0
 cmp x0, #0
 b.lt vault_error
 addr x1, server_fd
 str x0, [x1]
 addr x1, host_stat
 mov x8, #80
 svc #0
 cbnz x0, vault_error
 addr x1, host_stat
 ldr w0, [x1, #16]
 and w0, w0, #0xf000
 cmp w0, #0x8000
 b.ne vault_error
 ldr x0, [x1, #48]
 cbz x0, vault_error
 tst x0, #511
 b.ne vault_error
 lsr x0, x0, #9
 addr x1, server_sectors
 str x0, [x1]
server_opened:
 bl graphics_open_adapters
 b step
argument_equal:
 ldrb w2, [x0], #1
 ldrb w3, [x1], #1
 cmp w2, w3
 b.ne argument_different
 cbnz w2, argument_equal
 mov x0, #1
 ret
argument_different:
 mov x0, #0
 ret
vault_error:
 addr x1, vault_msg
 mov x2, #vault_len
 b error_write
usage:
 addr x1, usage_msg
 mov x2, #usage_len
 b error_write
io_error:
 addr x1, io_msg
 mov x2, #io_len
 b error_write
fatal:
 cbnz x21, 1f
 cmp x22, #1
 b.ne 2f
 getcsr x21, 0x141
 b 1f
2: getcsr x21, 0x341
1: addr x1, fault_msg
 mov x2, #fault_len
 mov x0, #2
 mov x8, #64
 svc #0
 mov x0, x21
 bl print_hex
 addr x1, instruction_msg
 mov x2, #instruction_len
 mov x0, #2
 mov x8, #64
 svc #0
 mov x0, x23
 bl print_hex
 mov x0, #1
 b host_exit
/* Fixed-size diagnostics avoid any host runtime dependency. */
print_hex:
 addr x1, hexbuf
 mov x3, #16
 mov x9, x0
1: lsr x4, x9, #60
 add x5, x4, #48
 add x6, x4, #87
 cmp x4, #10
 csel x5, x5, x6, lo
 strb w5, [x1], #1
 lsl x9, x9, #4
 subs x3, x3, #1
 b.ne 1b
 mov w3, #10
 strb w3, [x1]
 addr x1, hexbuf
 mov x0, #2
 mov x2, #17
 mov x8, #64
 svc #0
 ret
error_write:
 mov x0, #2
 mov x8, #64
 svc #0
 mov x0, #1
 b host_exit
host_exit:
 mov x8, #93
 svc #0

step:
 /* An execution bound prevents malformed guest code hanging the host forever. */
 addr x0, interactive
 ldrb w0, [x0]
 cbnz w0, instruction_unbounded
 mov x0, #0x2000
 lsl x0, x0, #16
 cmp x28, x0
 b.hs fatal
instruction_unbounded:
 /* CLINT mtime is deterministic, one tick per completed instruction. */
 getcsr x2, 0x344
 bic x2, x2, #0x80
 ldr x0, [x19, #MTIMECMP]
 cmp x28, x0
 b.lo 1f
 orr x2, x2, #0x80
1: setcsr x2, 0x344
 getcsr x3, 0x304
 and x3, x3, x2
 cbz x3, fetch
 /* Interrupt priority: MEI, MSI, MTI, SEI, SSI, STI. */
 mov x4, #11
 tbnz x3, #11, irq_found
 mov x4, #3
 tbnz x3, #3, irq_found
 mov x4, #7
 tbnz x3, #7, irq_found
 mov x4, #9
 tbnz x3, #9, irq_found
 mov x4, #1
 tbnz x3, #1, irq_found
 mov x4, #5
 tbz x3, #5, fetch
irq_found:
 getcsr x5, 0x303
 lsr x5, x5, x4
 tbz x5, #0, irq_machine
 cmp x22, #3
 b.eq fetch
 cmp x22, #1
 b.lo irq_take
 getcsr x5, 0x300
 tbz x5, #1, fetch
 b irq_take
irq_machine:
 cmp x22, #3
 b.lo irq_take
 getcsr x5, 0x300
 tbz x5, #3, fetch
irq_take:
 mov x0, #0x8000000000000000
 orr x0, x0, x4
 mov x1, #0
 b exception
fetch:
 tst x21, #3
 b.ne fetch_misaligned
 mov x0, x21
 mov x1, #0
 bl translate
 mov x1, #RAM_BASE
 sub x0, x0, x1
 mov x1, #RAM_SIZE
 sub x1, x1, #4
 cmp x0, x1
 b.hi fetch_access
 ldr w23, [x20, x0]
 add x27, x21, #4
 ubfx x26, x23, #7, #5
 ubfx x0, x23, #15, #5
 ldr x24, [x19, x0, lsl #3]
 ubfx x0, x23, #20, #5
 ldr x25, [x19, x0, lsl #3]
 ubfx x16, x23, #12, #3
 and x0, x23, #0x7f
 cmp x0, #0x37
 b.eq op_lui
 cmp x0, #0x17
 b.eq op_auipc
 cmp x0, #0x6f
 b.eq op_jal
 cmp x0, #0x67
 b.eq op_jalr
 cmp x0, #0x63
 b.eq op_branch
 cmp x0, #0x03
 b.eq op_load
 cmp x0, #0x23
 b.eq op_store
 cmp x0, #0x13
 b.eq op_imm
 cmp x0, #0x1b
 b.eq op_immw
 cmp x0, #0x33
 b.eq op_reg
 cmp x0, #0x3b
 b.eq op_regw
 cmp x0, #0x73
 b.eq op_system
 cmp x0, #0x0f
 b.eq op_fence
 b illegal
finish:
 cbz x26, finish_no_rd
 str x0, [x19, x26, lsl #3]
finish_no_rd:
 mov x21, x27
 add x29, x29, #1
 add x28, x28, #1
 b step
op_lui:
 and w0, w23, #0xfffff000
 sxtw x0, w0
 b finish
op_auipc:
 and w0, w23, #0xfffff000
 sxtw x0, w0
 add x0, x0, x21
 b finish
op_jal:
 ubfx x0, x23, #21, #10
 lsl x0, x0, #1
 ubfx x1, x23, #20, #1
 orr x0, x0, x1, lsl #11
 and x1, x23, #0xff000
 orr x0, x0, x1
 ubfx x1, x23, #31, #1
 orr x0, x0, x1, lsl #20
 sbfx x0, x0, #0, #21
 mov x1, x27
 add x27, x21, x0
 mov x0, x1
 b check_jump
op_jalr:
 cbnz x16, illegal
 sbfx x0, x23, #20, #12
 add x1, x24, x0
 mov x0, x27
 bic x27, x1, #1
check_jump:
 tst x27, #3
 b.ne jump_misaligned
 b finish
op_branch:
 ubfx x0, x23, #8, #4
 lsl x0, x0, #1
 ubfx x1, x23, #25, #6
 orr x0, x0, x1, lsl #5
 ubfx x1, x23, #7, #1
 orr x0, x0, x1, lsl #11
 ubfx x1, x23, #31, #1
 orr x0, x0, x1, lsl #12
 sbfx x0, x0, #0, #13
 cbz x16, branch_eq
 cmp x16, #1
 b.eq branch_ne
 cmp x16, #4
 b.eq branch_lt
 cmp x16, #5
 b.eq branch_ge
 cmp x16, #6
 b.eq branch_ltu
 cmp x16, #7
 b.ne illegal
 cmp x24, x25
 cset x1, hs
 b branch_condition
branch_eq:
 cmp x24, x25
 cset x1, eq
 b branch_condition
branch_ne:
 cmp x24, x25
 cset x1, ne
 b branch_condition
branch_lt:
 cmp x24, x25
 cset x1, lt
 b branch_condition
branch_ge:
 cmp x24, x25
 cset x1, ge
 b branch_condition
branch_ltu:
 cmp x24, x25
 cset x1, lo
branch_condition:
 cbz x1, finish_no_rd
 add x27, x21, x0
 tst x27, #3
 b.ne jump_misaligned
 b finish_no_rd
op_load:
 cmp x16, #7
 b.eq illegal
 sbfx x0, x23, #20, #12
 add x0, x24, x0
 and x2, x16, #3
 mov x3, #1
 lsl x2, x3, x2
 bl load_memory
 cmp x16, #0
 b.eq load_s8
 cmp x16, #1
 b.eq load_s16
 cmp x16, #2
 b.eq load_s32
 b finish
load_s8: sxtb x0, w0
 b finish
load_s16: sxth x0, w0
 b finish
load_s32: sxtw x0, w0
 b finish
op_store:
 cmp x16, #3
 b.hi illegal
 ubfx x0, x23, #7, #5
 sbfx x1, x23, #25, #7
 orr x0, x0, x1, lsl #5
 add x0, x24, x0
 mov x1, x25
 mov x2, #1
 lsl x2, x2, x16
 bl store_memory
 b finish_no_rd
op_imm:
 sbfx x1, x23, #20, #12
 cbz x16, imm_add
 cmp x16, #2
 b.eq imm_slt
 cmp x16, #3
 b.eq imm_sltu
 cmp x16, #4
 b.eq imm_xor
 cmp x16, #6
 b.eq imm_or
 cmp x16, #7
 b.eq imm_and
 ubfx x1, x23, #20, #6
 lsr x2, x23, #26
 cmp x16, #1
 b.ne imm_right
 cbnz x2, illegal
 lsl x0, x24, x1
 b finish
imm_right:
 cbz x2, imm_srl
 cmp x2, #0x10
 b.ne illegal
 asr x0, x24, x1
 b finish
imm_srl: lsr x0, x24, x1
 b finish
imm_add: add x0, x24, x1
 b finish
imm_slt: cmp x24, x1
 cset x0, lt
 b finish
imm_sltu: cmp x24, x1
 cset x0, lo
 b finish
imm_xor: eor x0, x24, x1
 b finish
imm_or: orr x0, x24, x1
 b finish
imm_and: and x0, x24, x1
 b finish
op_immw:
 cbz x16, immw_add
 ubfx x1, x23, #20, #5
 lsr x2, x23, #25
 cmp x16, #1
 b.ne immw_right
 cbnz x2, illegal
 lsl w0, w24, w1
 b word_finish
immw_right:
 cmp x16, #5
 b.ne illegal
 cbz x2, immw_srl
 cmp x2, #0x20
 b.ne illegal
 asr w0, w24, w1
 b word_finish
immw_srl: lsr w0, w24, w1
 b word_finish
immw_add:
 sbfx x1, x23, #20, #12
 add w0, w24, w1
word_finish:
 sxtw x0, w0
 b finish
op_reg:
 lsr x2, x23, #25
 cmp x2, #1
 b.eq op_m
 cmp x2, #0x20
 b.eq op_sub_sra
 cbnz x2, illegal
 cbz x16, reg_add
 cmp x16, #1
 b.eq reg_sll
 cmp x16, #2
 b.eq reg_slt
 cmp x16, #3
 b.eq reg_sltu
 cmp x16, #4
 b.eq reg_xor
 cmp x16, #5
 b.eq reg_srl
 cmp x16, #6
 b.eq reg_or
 and x0, x24, x25
 b finish
reg_add: add x0, x24, x25
 b finish
reg_sll: lsl x0, x24, x25
 b finish
reg_slt: cmp x24, x25
 cset x0, lt
 b finish
reg_sltu: cmp x24, x25
 cset x0, lo
 b finish
reg_xor: eor x0, x24, x25
 b finish
reg_srl: lsr x0, x24, x25
 b finish
reg_or: orr x0, x24, x25
 b finish
op_sub_sra:
 cbz x16, reg_sub
 cmp x16, #5
 b.ne illegal
 asr x0, x24, x25
 b finish
reg_sub: sub x0, x24, x25
 b finish
op_m:
 cbz x16, m_mul
 cmp x16, #1
 b.eq m_mulh
 cmp x16, #2
 b.eq m_mulhsu
 cmp x16, #3
 b.eq m_mulhu
 cmp x16, #4
 b.eq m_div
 cmp x16, #5
 b.eq m_divu
 cmp x16, #6
 b.eq m_rem
 udiv x1, x24, x25
 msub x0, x1, x25, x24
 b finish
m_mul: mul x0, x24, x25
 b finish
m_mulh: smulh x0, x24, x25
 b finish
m_mulhsu:
 umulh x0, x24, x25
 asr x1, x24, #63
 and x1, x1, x25
 sub x0, x0, x1
 b finish
m_mulhu: umulh x0, x24, x25
 b finish
m_div:
 sdiv x0, x24, x25
 cbnz x25, finish
 mov x0, #-1
 b finish
m_divu:
 udiv x0, x24, x25
 cbnz x25, finish
 mov x0, #-1
 b finish
m_rem:
 sdiv x1, x24, x25
 msub x0, x1, x25, x24
 b finish
op_regw:
 lsr x2, x23, #25
 cmp x2, #1
 b.eq op_mw
 cmp x2, #0x20
 b.eq op_sub_sraw
 cbnz x2, illegal
 cbz x16, regw_add
 cmp x16, #1
 b.eq regw_sll
 cmp x16, #5
 b.ne illegal
 lsr w0, w24, w25
 b word_finish
regw_add: add w0, w24, w25
 b word_finish
regw_sll: lsl w0, w24, w25
 b word_finish
op_sub_sraw:
 cbz x16, regw_sub
 cmp x16, #5
 b.ne illegal
 asr w0, w24, w25
 b word_finish
regw_sub: sub w0, w24, w25
 b word_finish
op_mw:
 cbz x16, mw_mul
 cmp x16, #4
 b.eq mw_div
 cmp x16, #5
 b.eq mw_divu
 cmp x16, #6
 b.eq mw_rem
 cmp x16, #7
 b.ne illegal
 udiv w1, w24, w25
 msub w0, w1, w25, w24
 b word_finish
mw_mul: mul w0, w24, w25
 b word_finish
mw_div:
 sdiv w0, w24, w25
 cbnz w25, word_finish
 mov w0, #-1
 b word_finish
mw_divu:
 udiv w0, w24, w25
 cbnz w25, word_finish
 mov w0, #-1
 b word_finish
mw_rem:
 sdiv w1, w24, w25
 msub w0, w1, w25, w24
 b word_finish
op_fence:
 /* FENCE, FENCE.I: no speculative execution or instruction cache. */
 cmp x16, #1
 b.hi illegal
 b finish_no_rd
op_system:
 cbnz x16, op_csr
 mov x0, #0x73
 cmp x23, x0
 b.eq op_ecall
 mov x0, #0x73
 movk x0, #0x10, lsl #16
 cmp x23, x0
 b.eq op_ebreak
 mov x0, #0x73
 movk x0, #0x3020, lsl #16
 cmp x23, x0
 b.eq op_mret
 mov x0, #0x73
 movk x0, #0x1020, lsl #16
 cmp x23, x0
 b.eq op_sret
 mov x0, #0x73
 movk x0, #0x1050, lsl #16
 cmp x23, x0
 b.eq op_wfi
 /* SFENCE.VMA permits arbitrary rs1/rs2. */
 mov x0, #0x7fff
 movk x0, #0xfe00, lsl #16
 and x0, x23, x0
 mov x1, #0x73
 movk x1, #0x1200, lsl #16
 cmp x0, x1
 b.ne illegal
 cmp x22, #1
 b.lo illegal
 cmp x22, #3
 b.eq finish_no_rd
 getcsr x0, 0x300
 tbnz x0, #20, illegal
 b finish_no_rd
op_ecall:
 add x0, x22, #8
 mov x1, #0
 b exception
op_ebreak:
 mov x0, #3
 mov x1, x21
 b exception
op_wfi:
 cbz x22, illegal
 getcsr x0, 0x300
 cmp x22, #3
 b.eq finish_no_rd
 tbnz x0, #21, illegal
 b finish_no_rd
op_mret:
 cmp x22, #3
 b.ne illegal
 getcsr x0, 0x300
 ubfx x2, x0, #11, #2
 cmp x2, #2
 b.eq illegal
 mov x22, x2
 ubfx x1, x0, #7, #1
 bic x0, x0, #8
 orr x0, x0, x1, lsl #3
 orr x0, x0, #0x80
 bic x0, x0, #0x1800
 cmp x22, #3
 b.eq 1f
 bic x0, x0, #0x20000
1: setcsr x0, 0x300
 getcsr x27, 0x341
 b finish_no_rd
op_sret:
 cmp x22, #1
 b.lo illegal
 getcsr x0, 0x300
 cmp x22, #3
 b.eq 1f
 tbnz x0, #22, illegal
1: ubfx x22, x0, #8, #1
 ubfx x1, x0, #5, #1
 bic x0, x0, #2
 orr x0, x0, x1, lsl #1
 orr x0, x0, #0x20
 bic x0, x0, #0x100
 bic x0, x0, #0x20000
 setcsr x0, 0x300
 getcsr x27, 0x141
 b finish_no_rd
op_csr:
 cmp x16, #4
 b.eq illegal
 lsr x10, x23, #20
 ubfx x0, x10, #8, #2
 cmp x22, x0
 b.lo illegal
 cmp x10, #0x180
 b.ne 1f
 cmp x22, #1
 b.ne 1f
 getcsr x0, 0x300
 tbnz x0, #20, illegal
1:
 /* Validate the implemented CSR set before touching the register file. */
 mov x0, x10
 bl csr_supported
 cbz x0, illegal
 /* Read aliases and architectural counters. */
 mov x11, x10
 cmp x10, #0x100
 b.eq csr_sstatus
 cmp x10, #0x104
 b.eq csr_sie
 cmp x10, #0x144
 b.eq csr_sip
 cmp x10, #0xc00
 b.eq csr_counter
 cmp x10, #0xc01
 b.eq csr_counter
 cmp x10, #0xc02
 b.eq csr_counter
 cmp x10, #0xb00
 b.eq csr_counter_m
 cmp x10, #0xb02
 b.eq csr_counter_m
 cmp x10, #0x301
 b.eq csr_misa
 cmp x10, #0xf13
 b.eq csr_implid
 add x0, x19, #CSR
 ldr x12, [x0, x11, lsl #3]
 b csr_read_done
csr_implid: mov x12, #1
 b csr_read_done
csr_misa:
 mov x12, #0x1100
 movk x12, #0x14, lsl #16
 orr x12, x12, #0x8000000000000000
 b csr_read_done
csr_counter:
 cmp x22, #3
 b.eq csr_counter_m
 and x1, x10, #3
 getcsr x0, 0x306
 lsr x0, x0, x1
 tbz x0, #0, illegal
 cmp x22, #0
 b.ne csr_counter_m
 getcsr x0, 0x106
 lsr x0, x0, x1
 tbz x0, #0, illegal
csr_counter_m:
 mov x12, x28
 cmp x10, #0xc02
 b.eq csr_instret
 cmp x10, #0xb02
 b.ne csr_read_done
csr_instret:
 mov x12, x29
 b csr_read_done
csr_sstatus:
 mov x11, #0x300
 getcsr x12, 0x300
 mov x13, #0xe162
 movk x13, #0x000d, lsl #16
 movk x13, #0x0003, lsl #32
 movk x13, #0x8000, lsl #48
 and x12, x12, x13
 b csr_read_done
csr_sie:
 mov x11, #0x304
 getcsr x12, 0x304
 getcsr x13, 0x303
 and x12, x12, x13
 b csr_read_done
csr_sip:
 mov x11, #0x344
 getcsr x12, 0x344
 getcsr x13, 0x303
 and x12, x12, x13
csr_read_done:
 /* x12 old value; x14 proposed value; x15 whether a write occurs. */
 mov x1, x24
 tbz x16, #2, 1f
 ubfx x1, x23, #15, #5
1: and x2, x16, #3
 cmp x2, #1
 b.eq csr_swap
 cmp x2, #2
 b.eq csr_set
 cbnz x2, csr_clear
 b illegal
csr_swap:
 mov x14, x1
 mov x15, #1
 b csr_commit
csr_set:
 orr x14, x12, x1
 cmp x1, #0
 cset x15, ne
 b csr_commit
csr_clear:
 bic x14, x12, x1
 cmp x1, #0
 cset x15, ne
csr_commit:
 cbz x15, csr_done
 lsr x0, x10, #10
 cmp x0, #3
 b.eq illegal
 cmp x10, #0xb00
 b.eq illegal
 cmp x10, #0xb02
 b.eq illegal
 cmp x10, #0x301
 b.eq csr_done
 /* The development profile supports an open TOR entry only. Narrow PMP
  * policies must not appear to succeed without enforcing their bounds. */
 cmp x10, #0x3b0
 b.ne 3f
 cmn x14, #1
 b.ne illegal
3: cmp x10, #0x3a0
 b.ne 4f
 cmp x14, #15
 b.ne illegal
 getcsr x0, 0x3b0
 cmn x0, #1
 b.ne illegal
4: cmp x10, #0x180
 b.ne 1f
 lsr x0, x14, #60
 cbz x0, 1f
 cmp x0, #8
 b.ne illegal
1:
 cmp x10, #0x100
 b.eq csr_masked
 cmp x10, #0x104
 b.eq csr_masked
 cmp x10, #0x144
 b.eq csr_masked
 b csr_direct
csr_masked:
 add x0, x19, #CSR
 ldr x1, [x0, x11, lsl #3]
 bic x1, x1, x13
 and x14, x14, x13
 orr x14, x14, x1
csr_direct:
 cmp x10, #0x341
 b.eq csr_epc
 cmp x10, #0x141
 b.ne 1f
csr_epc: bic x14, x14, #3
1: cmp x11, #0x300
 b.ne 2f
 /* Both implemented lower privilege levels execute RV64. UXL/SXL are WARL. */
 bic x14, x14, #0xf00000000
 mov x0, #0xa00000000
 orr x14, x14, x0
2: add x0, x19, #CSR
 str x14, [x0, x11, lsl #3]
csr_done:
 mov x0, x12
 b finish
csr_supported:
 cmp x0, #0x100
 b.eq csr_yes
 cmp x0, #0x104
 b.eq csr_yes
 cmp x0, #0x105
 b.eq csr_yes
 cmp x0, #0x106
 b.eq csr_yes
 cmp x0, #0x10a
 b.eq csr_yes
 cmp x0, #0x140
 b.lo 1f
 cmp x0, #0x144
 b.ls csr_yes
1: cmp x0, #0x180
 b.eq csr_yes
 cmp x0, #0x300
 b.lo 1f
 cmp x0, #0x306
 b.ls csr_yes
1: cmp x0, #0x30a
 b.eq csr_yes
 cmp x0, #0x340
 b.lo 1f
 cmp x0, #0x344
 b.ls csr_yes
1: cmp x0, #0x3a0
 b.eq csr_yes
 cmp x0, #0x3b0
 b.eq csr_yes
 cmp x0, #0xb00
 b.eq csr_yes
 cmp x0, #0xb02
 b.eq csr_yes
 cmp x0, #0xc00
 b.lo 1f
 cmp x0, #0xc02
 b.ls csr_yes
1: cmp x0, #0xf11
 b.lo csr_no
 cmp x0, #0xf14
 b.ls csr_yes
csr_no: mov x0, #0
 ret
csr_yes: mov x0, #1
 ret

/* translate(virtual address x0, access x1: execute=0/read=1/write=2).
 * Sv39 enforces U/S/SUM/MXR, superpage alignment, canonicality and A/D.
 * There is no TLB, so SFENCE.VMA is inherently complete.
 */
translate:
 mov x3, x0
 mov x4, x22
 getcsr x5, 0x300
 cbz x1, 1f
 tbz x5, #17, 1f
 ubfx x4, x5, #11, #2
1: cmp x4, #3
 b.eq translate_done
 getcsr x6, 0x180
 lsr x7, x6, #60
 cbz x7, translate_done
 cmp x7, #8
 b.ne page_fault
 sbfx x7, x3, #0, #39
 cmp x7, x3
 b.ne page_fault
 ubfx x6, x6, #0, #44
 lsl x6, x6, #12
 mov x7, #2
page_walk:
 mov x8, #9
 madd x8, x7, x8, xzr
 add x8, x8, #12
 lsr x9, x3, x8
 and x9, x9, #0x1ff
 add x9, x6, x9, lsl #3
 mov x10, #RAM_BASE
 sub x10, x9, x10
 mov x11, #RAM_SIZE
 sub x11, x11, #8
 cmp x10, x11
 b.hi page_walk_access
 add x10, x20, x10
 ldr x11, [x10]
 tbz x11, #0, page_fault
 /* Reserved PTE high bits and W-without-R are invalid. */
 lsr x12, x11, #54
 cbnz x12, page_fault
 and x12, x11, #6
 cmp x12, #4
 b.eq page_fault
 mov x12, #0xa
 tst x11, x12
 b.ne page_leaf
 cbz x7, page_fault
 mov x12, #0xd0
 tst x11, x12
 b.ne page_fault
 ubfx x6, x11, #10, #44
 lsl x6, x6, #12
 sub x7, x7, #1
 b page_walk
page_leaf:
 cbnz x4, page_supervisor
 tbz x11, #4, page_fault
 b page_permission
page_supervisor:
 tbz x11, #4, page_permission
 cbz x1, page_fault
 tbz x5, #18, page_fault
page_permission:
 cbz x1, page_execute
 cmp x1, #2
 b.eq page_write
 tbnz x11, #1, page_allowed
 tbz x5, #19, page_fault
 tbz x11, #3, page_fault
 b page_allowed
page_execute:
 tbz x11, #3, page_fault
 b page_allowed
page_write:
 tbz x11, #2, page_fault
page_allowed:
 /* A leaf at level L must have its lower 9*L PPN bits clear. */
 ubfx x6, x11, #10, #44
 sub x9, x8, #12
 mov x12, #1
 lsl x12, x12, x9
 sub x12, x12, #1
 tst x6, x12
 b.ne page_fault
 orr x11, x11, #0x40
 cmp x1, #2
 b.ne 1f
 orr x11, x11, #0x80
1: str x11, [x10]
 mov x12, #1
 lsl x12, x12, x8
 sub x12, x12, #1
 and x12, x3, x12
 lsl x0, x6, #12
 orr x0, x0, x12
translate_done:
 ret
page_walk_access:
 mov x0, #1
 cbz x1, 1f
 mov x0, #5
 cmp x1, #2
 b.ne 1f
 mov x0, #7
1: mov x1, x3
 b exception
page_fault:
 mov x0, #12
 cbz x1, 1f
 mov x0, #13
 cmp x1, #2
 b.ne 1f
 mov x0, #15
1: mov x1, x3
 b exception

load_memory:
 sub x3, x2, #1
 tst x0, x3
 b.ne load_misaligned
 stp x0, x30, [sp, #-32]!
 str x2, [sp, #16]
 mov x1, #1
 bl translate
 ldr x2, [sp, #16]
 mov x3, #RAM_BASE
 sub x3, x0, x3
 mov x4, #RAM_SIZE
 sub x4, x4, x2
 cmp x3, x4
 b.hi load_device
 cmp x2, #1
 b.eq load_byte
 cmp x2, #2
 b.eq load_half
 cmp x2, #4
 b.eq load_word
 ldr x0, [x20, x3]
 b load_return
load_byte: ldrb w0, [x20, x3]
 b load_return
load_half: ldrh w0, [x20, x3]
 b load_return
load_word: ldr w0, [x20, x3]
load_return:
 ldr x30, [sp, #8]
 add sp, sp, #32
 ret
load_device:
 mov x3, #0x1000
 movk x3, #0x1000, lsl #16
 sub x4, x0, x3
 mov x3, #0x8000
 cmp x4, x3
 b.lo virtio_read
 mov x3, #0x10000000
 sub x4, x0, x3
 cmp x4, #7
 b.hi load_clint
 cmp x2, #1
 b.ne load_access
 cbz x4, uart_receive
 cmp x4, #5
 b.eq uart_lsr
 cmp x4, #2
 b.eq uart_no_interrupt
 addr x3, uart_regs
 ldrb w0, [x3, x4]
 b load_return
uart_lsr:
 bl uart_poll
 addr x1, rx_valid
 ldrb w0, [x1]
 orr x0, x0, #0x60
 b load_return
uart_receive:
 addr x3, uart_regs
 ldrb w0, [x3, #3]
 tbnz w0, #7, uart_divisor
 bl uart_poll
 addr x1, rx_valid
 ldrb w0, [x1]
 cbz w0, load_return
 strb wzr, [x1]
 addr x1, rx_byte
 ldrb w0, [x1]
 b load_return
uart_divisor:
 ldrb w0, [x3]
 b load_return
uart_no_interrupt:
 mov x0, #1
 b load_return
load_clint:
 mov x3, #0xbff8
 movk x3, #0x200, lsl #16
 sub x4, x0, x3
 cmp x4, #7
 b.ls load_time
 mov x3, #0x4000
 movk x3, #0x200, lsl #16
 sub x4, x0, x3
 cmp x4, #7
 b.ls load_timecmp
 mov x3, #0x2000000
 cmp x0, x3
 b.ne load_access
 getcsr x0, 0x344
 ubfx x0, x0, #3, #1
 b load_return
load_time: mov x0, x28
 b device_shift
load_timecmp: ldr x0, [x19, #MTIMECMP]
 b device_shift
device_zero: mov x0, #0
 b load_return
device_shift:
 lsl x4, x4, #3
 lsr x0, x0, x4
 cmp x2, #8
 b.eq load_return
 lsl x3, x2, #3
 mov x4, #-1
 lsl x4, x4, x3
 bic x0, x0, x4
 b load_return
store_memory:
 sub x3, x2, #1
 tst x0, x3
 b.ne store_misaligned
 stp x0, x30, [sp, #-32]!
 stp x1, x2, [sp, #16]
 mov x1, #2
 bl translate
 ldp x1, x2, [sp, #16]
 mov x3, #RAM_BASE
 sub x3, x0, x3
 mov x4, #RAM_SIZE
 sub x4, x4, x2
 cmp x3, x4
 b.hi store_device
 cmp x2, #1
 b.eq store_byte
 cmp x2, #2
 b.eq store_half
 cmp x2, #4
 b.eq store_word
 str x1, [x20, x3]
 b store_return
store_byte: strb w1, [x20, x3]
 b store_return
store_half: strh w1, [x20, x3]
 b store_return
store_word: str w1, [x20, x3]
store_return:
 ldr x30, [sp, #8]
 add sp, sp, #32
 ret
store_device:
 mov x3, #0x1000
 movk x3, #0x1000, lsl #16
 sub x4, x0, x3
 mov x3, #0x8000
 cmp x4, x3
 b.lo virtio_write
 mov x3, #0x10000000
 sub x4, x0, x3
 cmp x4, #7
 b.hi store_test
 cmp x2, #1
 b.ne store_access
 addr x3, uart_regs
 strb w1, [x3, x4]
 cbnz x4, store_return
 ldrb w0, [x3, #3]
 tbnz w0, #7, store_return
 addr x3, bytebuf
 strb w1, [x3]
 mov x0, #1
 mov x1, x3
 mov x2, #1
 mov x8, #64
 svc #0
 b store_return
store_test:
 mov x3, #0x100000
 cmp x0, x3
 b.ne store_clint
 and x1, x1, #0xffff
 mov x3, #0x5555
 cmp x1, x3
 b.eq test_pass
 mov x0, #1
 b host_exit
test_pass:
 mov x0, #0
 b host_exit
store_clint:
 mov x3, #0x4000
 movk x3, #0x200, lsl #16
 sub x4, x0, x3
 cmp x4, #7
 b.hi store_msip
 ldr x5, [x19, #MTIMECMP]
 lsl x4, x4, #3
 cmp x2, #8
 b.eq store_cmp64
 mov x3, #-1
 lsl x6, x2, #3
 lsl x3, x3, x6
 mvn x3, x3
 lsl x3, x3, x4
 bic x5, x5, x3
 lsl x1, x1, x4
 and x1, x1, x3
 orr x1, x1, x5
store_cmp64:
 str x1, [x19, #MTIMECMP]
 b store_return
store_msip:
 mov x3, #0x2000000
 cmp x0, x3
 b.ne store_access
 getcsr x3, 0x344
 bic x3, x3, #8
 and x1, x1, #1
 orr x3, x3, x1, lsl #3
 setcsr x3, 0x344
 b store_return

illegal:
 mov x0, #2
 mov x1, x23
 b exception
fetch_misaligned:
 mov x0, #0
 mov x1, x21
 b exception
jump_misaligned:
 mov x0, #0
 mov x1, x27
 b exception
fetch_access:
 mov x0, #1
 mov x1, x21
 b exception
load_misaligned:
 mov x1, x0
 mov x0, #4
 b exception
store_misaligned:
 mov x1, x0
 mov x0, #6
 b exception
load_access:
 ldr x1, [sp]
 mov x0, #5
 b exception
store_access:
 ldr x1, [sp]
 mov x0, #7
 b exception

/* exception(cause x0, tval x1): precise current PC, no leaked host stack. */
exception:
 ldr x2, [x19, #HOSTSP]
 mov sp, x2
 and x2, x0, #63
 cmp x22, #3
 b.eq trap_machine
 tbnz x0, #63, 1f
 getcsr x3, 0x302
 b 2f
1: getcsr x3, 0x303
2: lsr x3, x3, x2
 tbz x3, #0, trap_machine
 setcsr x0, 0x142
 setcsr x21, 0x141
 setcsr x1, 0x143
 getcsr x3, 0x300
 ubfx x4, x3, #1, #1
 bic x3, x3, #0x20
 orr x3, x3, x4, lsl #5
 bic x3, x3, #2
 bic x3, x3, #0x100
 and x4, x22, #1
 orr x3, x3, x4, lsl #8
 setcsr x3, 0x300
 mov x22, #1
 getcsr x21, 0x105
 b trap_vector
trap_machine:
 setcsr x0, 0x342
 setcsr x21, 0x341
 setcsr x1, 0x343
 getcsr x3, 0x300
 ubfx x4, x3, #3, #1
 bic x3, x3, #0x80
 orr x3, x3, x4, lsl #7
 bic x3, x3, #8
 bic x3, x3, #0x1800
 orr x3, x3, x22, lsl #11
 setcsr x3, 0x300
 mov x22, #3
 getcsr x21, 0x305
trap_vector:
 and x3, x21, #3
 bic x21, x21, #3
 cbz x21, fatal
 tbz x0, #63, 1f
 cmp x3, #1
 b.ne 1f
 add x21, x21, x2, lsl #2
1: add x28, x28, #1
 b step


/* Legacy virtio MMIO transport; device semantics are independently AArch64. */
.macro devget reg, symbol
 addr x18, \symbol
 ldr \reg, [x18]
.endm
.macro devset reg, symbol
 addr x18, \symbol
 str \reg, [x18]
.endm
virtio_read:
 cmp x2, #4
 b.ne load_access
 mov x3, #0x1000
 movk x3, #0x1000, lsl #16
 sub x5, x0, x3
 lsr x6, x5, #12
 and x5, x5, #4095
 cmp x6, #7
 b.eq pcm_read
 cmp x6, #5
 b.eq network_read
 cmp x6, #2
 b.lo 1f
 cmp x6, #5
 b.lo modern_read
1:
 addr x9, virtio_states
 add x9, x9, x6, lsl #6
 cbz x5, virtio_magic
 cmp x5, #4
 b.eq virtio_version
 cmp x5, #8
 b.eq virtio_id
 cmp x5, #12
 b.eq virtio_vendor
 cmp x6, #6
 b.eq 2f
 cmp x6, #2
 b.hs virtio_zero
2:
 cmp x5, #0x10
 b.eq virtio_features
 cmp x5, #0x34
 b.eq virtio_queue_max
 cmp x5, #0x40
 b.eq virtio_queue_pfn
 cmp x5, #0x60
 b.eq virtio_interrupt
 cmp x5, #0x70
 b.eq virtio_status
 cmp x5, #0x100
 b.eq virtio_capacity_low
 cmp x5, #0x104
 b.eq virtio_capacity_high
virtio_zero:
 mov x0, #0
 b load_return
virtio_magic:
 mov w0, #0x6976
 movk w0, #0x7472, lsl #16
 b load_return
virtio_version:
 mov x0, #1
 b load_return
virtio_id:
 cmp x6, #6
 b.eq virtio_server_id
 cmp x6, #1
 b.eq virtio_rng_id
 cbnz x6, virtio_zero
 devget x0, vault_fd
 cmp x0, #0
 b.lt virtio_zero
 mov x0, #2
 b load_return
virtio_server_id:
 devget x0, server_fd
 cmp x0, #0
 b.lt virtio_zero
 mov x0, #2
 b load_return
virtio_rng_id:
 mov x0, #4
 b load_return
virtio_vendor:
 mov x0, #0x4c54
 b load_return
virtio_features:
 ldr w0, [x9]
 cbnz w0, virtio_zero
 cmp x6, #6
 b.eq virtio_server_features
 cbnz x6, virtio_zero
 mov x0, #0x200
 addr x1, vault_readonly
 ldrb w1, [x1]
 cbz w1, virtio_features_return
 orr x0, x0, #32
virtio_features_return:
 b load_return
virtio_server_features:
 mov x0, #0x200
 addr x1, server_readonly
 ldrb w1, [x1]
 cbz w1, load_return
 orr x0, x0, #32
 b load_return
virtio_queue_max:
 ldr w0, [x9, #16]
 cbnz w0, virtio_zero
 mov x0, #8
 b load_return
virtio_queue_pfn:
 ldr w0, [x9, #28]
 b load_return
virtio_interrupt:
 ldr w0, [x9, #32]
 b load_return
virtio_status:
 ldr w0, [x9, #36]
 b load_return
virtio_capacity_low:
 cmp x6, #6
 b.ne 1f
 devget w0, server_sectors
 b load_return
1:
 cbnz x6, virtio_zero
 devget w0, vault_sectors
 b load_return
virtio_capacity_high:
 cmp x6, #6
 b.ne 1f
 devget x0, server_sectors
 lsr x0, x0, #32
 b load_return
1:
 cbnz x6, virtio_zero
 devget x0, vault_sectors
 lsr x0, x0, #32
 b load_return
virtio_write:
 cmp x2, #4
 b.ne store_access
 mov x3, #0x1000
 movk x3, #0x1000, lsl #16
 sub x5, x0, x3
 lsr x6, x5, #12
 and x5, x5, #4095
 cmp x6, #7
 b.eq pcm_write
 cmp x6, #5
 b.eq network_write
 cmp x6, #2
 b.lo 1f
 cmp x6, #5
 b.lo modern_write
1:
 cmp x6, #6
 b.eq 2f
 cmp x6, #2
 b.hs store_return
2:
 devset w6, virtio_number
 addr x9, virtio_states
 add x9, x9, x6, lsl #6
 devset x9, virtio_current
 cmp x5, #0x14
 b.eq virtio_write_feature_sel
 cmp x5, #0x20
 b.eq virtio_write_features
 cmp x5, #0x24
 b.eq virtio_write_guest_sel
 cmp x5, #0x28
 b.eq virtio_write_page
 cmp x5, #0x30
 b.eq virtio_write_queue_sel
 cmp x5, #0x38
 b.eq virtio_write_queue_num
 cmp x5, #0x3c
 b.eq virtio_write_align
 cmp x5, #0x40
 b.eq virtio_write_pfn
 cmp x5, #0x50
 b.eq virtio_notify
 cmp x5, #0x64
 b.eq virtio_ack
 cmp x5, #0x70
 b.eq virtio_write_status
 b store_return
virtio_write_feature_sel:
 str w1, [x9]
 b store_return
virtio_write_features:
 ldr w0, [x9, #8]
 cbnz w0, virtio_features_high
 str w1, [x9, #4]
 b store_return
virtio_features_high:
 cbnz w1, virtio_fail
 b store_return
virtio_write_guest_sel:
 str w1, [x9, #8]
 b store_return
virtio_write_page:
 cmp w1, #4096
 b.ne virtio_fail
 str w1, [x9, #12]
 b store_return
virtio_write_queue_sel:
 str w1, [x9, #16]
 b store_return
virtio_write_queue_num:
 ldr w0, [x9, #16]
 cbnz w0, virtio_fail
 cmp w1, #1
 b.lo virtio_fail
 cmp w1, #8
 b.hi virtio_fail
 sub w0, w1, #1
 tst w1, w0
 b.ne virtio_fail
 str w1, [x9, #20]
 b store_return
virtio_write_align:
 cmp w1, #4096
 b.ne virtio_fail
 str w1, [x9, #24]
 b store_return
virtio_write_pfn:
 str w1, [x9, #28]
 str wzr, [x9, #40]
 str wzr, [x9, #44]
 b store_return
virtio_ack:
 ldr w0, [x9, #32]
 bic w0, w0, w1
 str w0, [x9, #32]
 b store_return
virtio_write_status:
 cbz w1, virtio_reset
 ldr w0, [x9, #4]
 cmp x6, #6
 b.ne 1f
 mov w2, #0x200
 addr x3, server_readonly
 ldrb w3, [x3]
 cbz w3, virtio_status_feature_mask
 orr w2, w2, #32
 b virtio_status_feature_mask
1: cbnz x6, virtio_status_rng
 mov w2, #0x200
 addr x3, vault_readonly
 ldrb w3, [x3]
 cbz w3, virtio_status_feature_mask
 orr w2, w2, #32
virtio_status_feature_mask:
 bic w0, w0, w2
virtio_status_rng:
 cbnz w0, virtio_fail
 str w1, [x9, #36]
 b store_return
virtio_reset:
 stp xzr, xzr, [x9]
 stp xzr, xzr, [x9, #16]
 stp xzr, xzr, [x9, #32]
 stp xzr, xzr, [x9, #48]
 b store_return
virtio_fail:
 devget x9, virtio_current
 ldr w0, [x9, #36]
 orr w0, w0, #128
 str w0, [x9, #36]
 b store_return
virtio_notify:
 cbnz w1, virtio_fail
 ldr w0, [x9, #36]
 tbz w0, #2, virtio_fail
 tbnz w0, #7, store_return
 ldr w0, [x9, #12]
 cmp w0, #4096
 b.ne virtio_fail
 ldr w0, [x9, #24]
 cmp w0, #4096
 b.ne virtio_fail
 ldr w0, [x9, #28]
 cbz w0, virtio_fail
 lsl x0, x0, #12
 devset x0, queue_physical
 mov x2, #4096
 bl dma_pointer
 cbz x0, virtio_fail
 devset x0, queue_host
 ldr w2, [x9, #20]
 cbz w2, virtio_fail
 cmp w2, #8
 b.hi virtio_fail
 devset w2, queue_size
 add x0, x0, x2, lsl #4
 devset x0, avail_host
 devget x0, queue_physical
 add x0, x0, #4096
 mov x2, #4096
 bl dma_pointer
 cbz x0, virtio_fail
 devset x0, used_host
 devget x10, avail_host
 ldrh w0, [x10, #2]
 devset w0, avail_target
 ldrh w1, [x9, #40]
 sub w0, w0, w1
 and w0, w0, #65535
 devget w1, queue_size
 cmp w0, w1
 b.hi virtio_fail
virtio_consume:
 devget x9, virtio_current
 ldrh w0, [x9, #40]
 devget w1, avail_target
 cmp w0, w1
 b.eq store_return
 devget w1, queue_size
 sub w1, w1, #1
 and w0, w0, w1
 devget x10, avail_host
 add x10, x10, #4
 ldrh w0, [x10, x0, lsl #1]
 devget w1, queue_size
 cmp w0, w1
 b.hs virtio_fail
 devset w0, request_head
 devget x10, queue_host
 add x10, x10, x0, lsl #4
 devset x10, request_descriptor
 devget w0, virtio_number
 cmp w0, #1
 b.eq virtio_entropy
 bl virtio_block
 b virtio_complete
virtio_entropy:
 ldrh w0, [x10, #12]
 cmp w0, #2
 b.ne virtio_fail
 ldr w2, [x10, #8]
 cbz w2, virtio_fail
 cmp w2, #256
 b.hi virtio_fail
 devset w2, request_length
 ldr x0, [x10]
 bl dma_pointer
 cbz x0, virtio_fail
 devget w1, request_length
 mov x2, #1
 mov x8, #278
 svc #0
 devget w1, request_length
 cmp w0, w1
 csel w1, w0, wzr, eq
 devset w1, request_used
virtio_complete:
 devget x9, virtio_current
 ldrh w0, [x9, #44]
 devget w1, queue_size
 sub w1, w1, #1
 and w0, w0, w1
 devget x10, used_host
 add x10, x10, #4
 add x10, x10, x0, lsl #3
 devget w0, request_head
 devget w1, request_used
 stp w0, w1, [x10]
 ldrh w0, [x9, #44]
 add w0, w0, #1
 strh w0, [x9, #44]
 devget x10, used_host
 dmb ishst
 strh w0, [x10, #2]
 ldrh w0, [x9, #40]
 add w0, w0, #1
 strh w0, [x9, #40]
 ldr w0, [x9, #32]
 orr w0, w0, #1
 str w0, [x9, #32]
 b virtio_consume
/* Input x0 physical DMA address, x2 length; null means invalid. */
dma_pointer:
 mov x3, #RAM_BASE
 sub x0, x0, x3
 mov x3, #RAM_SIZE
 subs x3, x3, x2
 b.lo dma_invalid
 cmp x0, x3
 b.hi dma_invalid
 add x0, x20, x0
 ret
dma_invalid:
 mov x0, #0
 ret
/* x10 descriptor -> next descriptor, or null on malformed/indirect chain. */
virtio_next:
 ldrh w0, [x10, #12]
 tbz w0, #0, virtio_chain_bad
 tst w0, #0xfffc
 b.ne virtio_chain_bad
 ldrh w0, [x10, #14]
 devget w1, queue_size
 cmp w0, w1
 b.hs virtio_chain_bad
 devget x10, queue_host
 add x10, x10, x0, lsl #4
 ret
virtio_chain_bad:
 mov x10, #0
 ret
virtio_block:
 stp x30, xzr, [sp, #-16]!
 devget x0, vault_fd
 devget x1, vault_sectors
 addr x2, vault_readonly
 ldrb w2, [x2]
 devget w3, virtio_number
 cmp w3, #6
 b.ne 1f
 devget x0, server_fd
 devget x1, server_sectors
 addr x2, server_readonly
 ldrb w2, [x2]
1: devset x0, block_active_fd
 devset x1, block_active_sectors
 devset w2, block_active_readonly
 devget x10, request_descriptor
 ldrh w0, [x10, #12]
 cmp w0, #1
 b.ne virtio_block_fatal
 ldr w0, [x10, #8]
 cmp w0, #16
 b.ne virtio_block_fatal
 ldr x0, [x10]
 mov x2, #16
 bl dma_pointer
 cbz x0, virtio_block_fatal
 ldr w1, [x0]
 devset w1, request_type
 ldr x1, [x0, #8]
 devset x1, request_sector
 bl virtio_next
 cbz x10, virtio_block_fatal
 devget w0, request_type
 cmp w0, #4
 b.eq virtio_block_status
 ldr w2, [x10, #8]
 cbz w2, virtio_block_fatal
 cmp w2, #4096
 b.hi virtio_block_fatal
 devget w0, request_type
 cmp w0, #8
 b.eq 1f
 tst w2, #511
 b.ne virtio_block_fatal
 b 2f
1: cmp w2, #20
 b.ne virtio_block_fatal
2: devset w2, request_length
 ldrh w0, [x10, #12]
 devset w0, request_flags
 ldr x0, [x10]
 bl dma_pointer
 cbz x0, virtio_block_fatal
 devset x0, request_buffer
 bl virtio_next
 cbz x10, virtio_block_fatal
virtio_block_status:
 ldrh w0, [x10, #12]
 cmp w0, #2
 b.ne virtio_block_fatal
 ldr w0, [x10, #8]
 cmp w0, #1
 b.lo virtio_block_fatal
 ldr x0, [x10]
 mov x2, #1
 bl dma_pointer
 cbz x0, virtio_block_fatal
 devset x0, request_status
 mov w0, #1
 devset w0, request_used
 devget x0, block_active_fd
 cmp x0, #0
 b.lt virtio_block_error
 devget w0, request_type
 cmp w0, #8
 b.eq virtio_block_identity
 cmp w0, #4
 b.eq virtio_block_flush
 cbz w0, virtio_block_input
 cmp w0, #1
 b.ne virtio_block_unsupported
 devget w0, request_flags
 cmp w0, #1
 b.ne virtio_block_error
 addr x0, block_active_readonly
 ldrb w0, [x0]
 cbnz w0, virtio_block_error
 b virtio_block_bounds
virtio_block_input:
 devget w0, request_flags
 cmp w0, #3
 b.ne virtio_block_error
virtio_block_bounds:
 devget x3, request_sector
 devget x0, block_active_sectors
 cmp x3, x0
 b.hs virtio_block_error
 sub x0, x0, x3
 devget w2, request_length
 lsr x1, x2, #9
 cmp x1, x0
 b.hi virtio_block_error
 lsl x3, x3, #9
 devget x0, block_active_fd
 devget x1, request_buffer
 mov x8, #67
 devget w4, request_type
 cbz w4, virtio_block_io
 mov x8, #68
virtio_block_io:
 svc #0
 devget w1, request_length
 cmp w0, w1
 b.ne virtio_block_error
 devget w1, request_type
 cbnz w1, virtio_block_ok
 add w0, w0, #1
 devset w0, request_used
 b virtio_block_ok
virtio_block_identity:
 devget w0, request_flags
 cmp w0, #3
 b.ne virtio_block_error
 devget x0, request_buffer
 addr x1, objects_serial
 devget w2, virtio_number
 cmp w2, #6
 b.ne 1f
 addr x1, server_serial
1: mov x2, #20
2: ldrb w3, [x1], #1
 strb w3, [x0], #1
 subs x2, x2, #1
 b.ne 2b
 mov w0, #21
 devset w0, request_used
 b virtio_block_ok
virtio_block_flush:
 devget x0, block_active_fd
 mov x8, #82
 svc #0
 cbnz x0, virtio_block_error
virtio_block_ok:
 mov w1, #0
 b virtio_block_result
virtio_block_error:
 mov w1, #1
 b virtio_block_result
virtio_block_unsupported:
 mov w1, #2
virtio_block_result:
 devget x0, request_status
 strb w1, [x0]
 ldp x30, xzr, [sp], #16
 ret
virtio_block_fatal:
 ldp x30, xzr, [sp], #16
 b virtio_fail

/* stdin adapter: nonblocking pselect6 with a zero timeout, then one-byte read. */
uart_poll:
 addr x9, rx_valid
 ldrb w0, [x9]
 cbnz w0, uart_poll_done
 addr x9, stdin_eof
 ldrb w0, [x9]
 cbnz w0, uart_poll_done
 addr x1, stdin_poll
 mov x0, #1
 str x0, [x1]
 mov x0, #1
 mov x2, #0
 mov x3, #0
 addr x4, zero_timeout
 mov x5, #0
 mov x8, #72
 svc #0
 cmp x0, #1
 b.ne uart_poll_done
 mov x0, #0
 addr x1, rx_byte
 mov x2, #1
 mov x8, #63
 svc #0
 cmp x0, #1
 b.eq uart_poll_byte
 cbnz x0, uart_poll_done
 addr x1, stdin_eof
 mov w0, #1
 strb w0, [x1]
 ret
uart_poll_byte:
 addr x1, rx_valid
 mov w0, #1
 strb w0, [x1]
uart_poll_done:
 ret

#include "graphics_aarch64.inc"
#include "network_aarch64.inc"
#include "pcm_aarch64.inc"

.section .rodata
usage_msg: .ascii "usage: lemmatrix-arm64 guest.bin [--interactive] [--vault backing.img] [--vault-readonly] [--display-out frame.bgrx] [--input-events events.evdev]\n"
.equ usage_len, .-usage_msg
io_msg: .ascii "arm64 emulator: cannot load image (empty, inaccessible, or larger than 160 MiB)\n"
.equ io_len, .-io_msg
interactive_arg: .asciz "--interactive"
vault_arg: .asciz "--vault"
readonly_arg: .asciz "--vault-readonly"
vault_msg: .ascii "arm64 emulator: vault must be an explicit regular file of whole 512-byte sectors\n"
.equ vault_len, .-vault_msg
fault_msg: .ascii "arm64 emulator: unhandled guest trap or instruction budget exceeded; pc=0x"
.equ fault_len, .-fault_msg
instruction_msg: .ascii "last instruction=0x"
.equ instruction_len, .-instruction_msg
.section .bss
.balign 16
state: .skip 33040
bytebuf: .skip 16
hexbuf: .skip 32
uart_regs: .skip 8
interactive: .skip 1
vault_readonly: .skip 1
rx_valid: .skip 1
rx_byte: .skip 1
stdin_eof: .skip 1
.balign 8
vault_path: .skip 8
vault_fd: .skip 8
vault_sectors: .skip 8
host_stat: .skip 128
stdin_poll: .skip 8
zero_timeout: .skip 16
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
.balign 4096
ram: .skip RAM_SIZE
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
