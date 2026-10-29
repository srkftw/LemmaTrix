.option norvc
.section .text
.globl _start
_start:
 la t0,machine_trap
 csrw mtvec,t0
 li a0, 1234
 li a1, 17
 div a2,a0,a1
 li a3,72
 bne a2,a3,fail
 rem a2,a0,a1
 li a3,10
 bne a2,a3,fail
 li a0,-1234
 div a2,a0,a1
 li a3,-72
 bne a2,a3,fail
 rem a2,a0,a1
 li a3,-10
 bne a2,a3,fail
 li a0,0x8000000000000000
 li a1,-1
 div a2,a0,a1
 bne a2,a0,fail
 rem a2,a0,a1
 bnez a2,fail
 div a2,a0,zero
 bne a2,a1,fail
 rem a2,a0,zero
 bne a2,a0,fail
 li a0,0x87654321
 addiw a2,a0,0
 li a3,0xffffffff87654321
 bne a2,a3,fail
 li a0,-1
 li a1,2
 mulh a2,a0,a1
 li a3,-1
 bne a2,a3,fail
 mulhu a2,a0,a1
 li a3,1
 bne a2,a3,fail
 mulhsu a2,a0,a1
 li a3,-1
 bne a2,a3,fail
 /* Signed/unsigned branch and narrow memory edges. */
 li a0,-1
 li a1,1
 blt a0,a1,1f
 j fail
1: bge a1,a0,1f
 j fail
1: bltu a1,a0,1f
 j fail
1: bgeu a0,a1,1f
 j fail
1: la t0, scratch
 li t1,-128
 sb t1,0(t0)
 lb t2,0(t0)
 bne t1,t2,fail
 lbu t2,0(t0)
 li t3,128
 bne t2,t3,fail
 li t1,-32768
 sh t1,2(t0)
 lh t2,2(t0)
 bne t1,t2,fail
 lhu t2,2(t0)
 li t3,32768
 bne t2,t3,fail
 li t1,-2147483648
 sw t1,4(t0)
 lw t2,4(t0)
 bne t1,t2,fail
 lwu t2,4(t0)
 li t3,2147483648
 bne t2,t3,fail
 /* Deterministic emulators and QEMU both deliver real machine timer traps. */
 li t0,0x200bff8
 ld t1,0(t0)
 addi t1,t1,1000
 li t0,0x2004000
 sd t1,0(t0)
 li t0,128
 csrw mie,t0
 li t0,8
 csrs mstatus,t0
 la t0,timer_hits
1: ld t1,0(t0)
 beqz t1,1b
 li t0,8
 csrc mstatus,t0
 .word 0
 la t0, supervisor_trap
 csrw stvec, t0
 li t0, (1 << 13) | (1 << 8) | (1 << 2)
 csrw medeleg, t0
 li t0, -1
 csrw pmpaddr0, t0
 li t0, 15
 csrw pmpcfg0, t0
 la t0, root
 la t1, level1
 srli t1, t1, 2
 ori t1, t1, 1
 sd t1, 0(t0)
 li t1, 0x200000cf
 sd t1, 16(t0)
 la t0, level1
 li t1, 0xcf
 sd t1, 0(t0)
 li t1,0x40000cf
 sd t1,1024(t0)
 la t1, level0
 srli t1, t1, 2
 ori t1, t1, 1
 sd t1, 16(t0)
 la t0, level0
 la t1, user_code
 srli t1, t1, 2
 ori t1, t1, 0x1f
 sd t1, 0(t0)
 la t0, root
 srli t0, t0, 12
 li t1, 0x8000000000000000
 or t0, t0, t1
 csrw satp, t0
 sfence.vma
 la t0, supervisor_start
 csrw mepc, t0
 li t0, 0x800
 csrw mstatus, t0
 mret
supervisor_start:
 li t0, 0x400000
 csrw sepc, t0
 csrw sstatus, zero
 sret
supervisor_trap:
 csrr t0,scause
 li t1,8
 beq t0,t1,supervisor_done
 la t2,faults
 ld t3,0(t2)
 li t1,2
 beq t3,t1,expect_illegal
 li t1,13
 bne t0,t1,fail
 csrr t0,stval
 bnez t3,expect_uart
 li t1,0x80000000
 j check_tval
expect_uart:
 li t1,0x10000000
check_tval:
 bne t0,t1,fail
 j fault_resume
expect_illegal:
 bne t0,t1,fail
fault_resume:
 addi t3,t3,1
 sd t3,0(t2)
 csrr t0,sepc
 addi t0,t0,4
 csrw sepc,t0
 sret
supervisor_done:
 la t0,faults
 ld t1,0(t0)
 li t2,3
 bne t1,t2,fail
 la t0,pass_msg
 li t1,0x10000000
1: lbu t2,0(t0)
 beqz t2,2f
 sb t2,0(t1)
 addi t0,t0,1
 j 1b
2: li t0,0x100000
 li t1,0x5555
 sw t1,0(t0)
machine_trap:
 csrr t0,mcause
 li t1,0x8000000000000007
 beq t0,t1,timer_trap
 li t1,2
 bne t0,t1,fail
 csrr t0,mtval
 bnez t0,fail
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
timer_trap:
 csrw mie,zero
 la t0,timer_hits
 li t1,1
 sd t1,0(t0)
 mret
fail:
 li t0,0x100000
 li t1,0x3333
 sw t1,0(t0)
.balign 8
scratch: .quad 0
timer_hits: .quad 0
faults: .quad 0
pass_msg: .asciz "ISA MMU TIMER PASS\n"
.balign 4096
user_code:
 li t0, 0x80000000
 ld t1, 0(t0)
 li t0,0x10000000
 ld t1,0(t0)
 csrr t0,mstatus
 ecall
.balign 4096
root: .space 4096
level1: .space 4096
level0: .space 4096
