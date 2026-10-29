.option norvc
.section .text
.globl lt_load8, lt_load64, lt_store8, lt_store64, lt_syscall, lt_finish
lt_load8:
 lbu a0, 0(a0)
 ret
lt_load64:
 ld a0, 0(a0)
 ret
lt_store8:
 sb a1, 0(a0)
 li a0,0
 ret
lt_store64:
 sd a1, 0(a0)
 li a0,0
 ret
lt_syscall:
 mv a7,a0
 mv a0,a1
 mv a1,a2
 mv a2,a3
 mv a3,a4
 ecall
 ret
lt_finish:
 li t0,0x100000
 li t1,0x5555
 beqz a0,1f
 li t1,0x3333
1: sw t1,0(t0)
2: j 2b
