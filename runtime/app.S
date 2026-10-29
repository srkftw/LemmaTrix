.option norvc
.section .text.boot
.globl _start
_start:
 li a0,0
 call lt_Guest_appMain
 mv a1,a0
 li a0,10
 call lt_syscall
1: j 1b
