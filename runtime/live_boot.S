.option norvc
.section .text.boot
.globl _start
_start:
 li sp,0x800ff000
 la t0,mtrap
 csrw mtvec,t0
 li t0,-1
 csrw pmpaddr0,t0
 li t0,15
 csrw pmpcfg0,t0
 li t0,0xb1ff
 csrw medeleg,t0
 li t0,2
 csrw mideleg,t0
 li t0,128
 csrw mie,t0
 li t0,0x2004000
 li t1,0x200bff8
 ld t2,0(t1)
 li t3,100000
 add t2,t2,t3
 sd t2,0(t0)
 li t0,0x800
 csrw mstatus,t0
 la t0,sboot
 csrw mepc,t0
 mret
sboot:
 la t0,strap
 csrw stvec,t0
 li t0,2
 csrw sie,t0
 li a0,0
 call lt_Guest_Live_kernelMain
 j lt_enter_user
mtrap:
 csrw mscratch,t0
 li t0,0x80088000
 sd t1,0(t0)
 sd t2,8(t0)
 sd t3,16(t0)
 csrr t1,mcause
 li t2,0x8000000000000007
 bne t1,t2,mfatal
 li t1,0x200bff8
 ld t2,0(t1)
 li t3,100000
 add t2,t2,t3
 li t1,0x2004000
 sd t2,0(t1)
 li t1,2
 csrs mip,t1
 ld t1,0(t0)
 ld t2,8(t0)
 ld t3,16(t0)
 csrr t0,mscratch
 mret
mfatal:
 li t0,0x10000000
 li t1,77
 sb t1,0(t0)
 li t1,33
 sb t1,0(t0)
 li t1,10
 sb t1,0(t0)
 li t0,0x100000
 li t1,0x3333
 sw t1,0(t0)
1: j 1b
strap:
 csrrw sp,sscratch,sp
 bnez sp,1f
 csrr sp,sscratch
1:
 addi sp,sp,-272
 sd zero,0(sp)
 sd ra,8(sp)
 sd x3,24(sp)
 sd x4,32(sp)
 sd x5,40(sp)
 sd x6,48(sp)
 sd x7,56(sp)
 sd x8,64(sp)
 sd x9,72(sp)
 sd x10,80(sp)
 sd x11,88(sp)
 sd x12,96(sp)
 sd x13,104(sp)
 sd x14,112(sp)
 sd x15,120(sp)
 sd x16,128(sp)
 sd x17,136(sp)
 sd x18,144(sp)
 sd x19,152(sp)
 sd x20,160(sp)
 sd x21,168(sp)
 sd x22,176(sp)
 sd x23,184(sp)
 sd x24,192(sp)
 sd x25,200(sp)
 sd x26,208(sp)
 sd x27,216(sp)
 sd x28,224(sp)
 sd x29,232(sp)
 sd x30,240(sp)
 sd x31,248(sp)
 csrr t0,sscratch
 sd t0,16(sp)
 csrw sscratch,zero
 csrr t0,sepc
 sd t0,256(sp)
 csrr t0,sstatus
 sd t0,264(sp)
 mv a0,sp
 csrr a1,scause
 csrr a2,stval
 li t0,0x8000000000000001
 bne a1,t0,2f
 li t0,2
 csrc sip,t0
2:
 call lt_Guest_Live_trapDispatch
 j lt_enter_user
.globl lt_enter_user
lt_enter_user:
 mv sp,a0
 ld t0,256(sp)
 csrw sepc,t0
 ld t0,264(sp)
 csrw sstatus,t0
 ld t0,264(sp)
 andi t0,t0,256
 bnez t0,3f
 li t0,0x800ed000
 csrw sscratch,t0
 j 4f
3: csrw sscratch,zero
4:
 li t0,0x80900000
 ld t1,0(t0)
 slli t1,t1,12
 li t0,0x80100000
 add t0,t0,t1
 srli t0,t0,12
 li t1,0x8000000000000000
 or t0,t0,t1
 csrw satp,t0
 sfence.vma zero,zero
 .word 0x0000100f # fence.i: synchronize activated executable bytes
 ld x1,8(sp)
 ld x3,24(sp)
 ld x4,32(sp)
 ld x5,40(sp)
 ld x6,48(sp)
 ld x7,56(sp)
 ld x8,64(sp)
 ld x9,72(sp)
 ld x10,80(sp)
 ld x11,88(sp)
 ld x12,96(sp)
 ld x13,104(sp)
 ld x14,112(sp)
 ld x15,120(sp)
 ld x16,128(sp)
 ld x17,136(sp)
 ld x18,144(sp)
 ld x19,152(sp)
 ld x20,160(sp)
 ld x21,168(sp)
 ld x22,176(sp)
 ld x23,184(sp)
 ld x24,192(sp)
 ld x25,200(sp)
 ld x26,208(sp)
 ld x27,216(sp)
 ld x28,224(sp)
 ld x29,232(sp)
 ld x30,240(sp)
 ld x31,248(sp)
 ld sp,16(sp)
 sret

.globl lt_idle_pc
lt_idle_pc:
 la a0,lt_idle_loop
 ret
lt_idle_loop:
 wfi
 j lt_idle_loop
