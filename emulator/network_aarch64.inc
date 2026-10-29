/* LT-Stream-v1, independent AArch64 modern console byte device. */
network_read:
 addr x9, network_state
 cbz x5, virtio_magic
 cmp x5, #4
 b.eq modern_version
 cmp x5, #8
 b.eq network_id
 cmp x5, #12
 b.eq virtio_vendor
 cmp x5, #0x10
 b.eq network_features
 cmp x5, #0x34
 b.eq network_max
 cmp x5, #0x44
 b.eq network_ready
 cmp x5, #0x60
 b.eq network_interrupt
 cmp x5, #0x70
 b.eq network_status
 b virtio_zero
network_id:
 devget x0, network_fd
 cmp x0, #0
 b.lt virtio_zero
 mov x0, #3
 b load_return
network_features:
 ldr w0, [x9]
 cmp w0, #1
 cset x0, eq
 b load_return
network_max:
 ldr w0, [x9, #16]
 cmp w0, #1
 b.hi virtio_zero
 mov x0, #8
 b load_return
network_ready:
 bl network_selected
 ldr w0, [x9, #4]
 b load_return
network_interrupt:
 ldr w0, [x9, #32]
 b load_return
network_status:
 ldr w0, [x9, #28]
 b load_return
network_selected:
 ldr w0, [x9, #16]
 and w0, w0, #1
 add x9, x9, x0, lsl #6
 add x9, x9, #64
 ret
network_write:
 addr x9, network_state
 cmp x5, #0x14
 b.eq network_feature_sel
 cmp x5, #0x24
 b.eq network_driver_sel
 cmp x5, #0x20
 b.eq network_driver_features
 cmp x5, #0x30
 b.eq network_queue_sel
 cmp x5, #0x64
 b.eq network_ack
 cmp x5, #0x70
 b.eq network_set_status
 cmp x5, #0x50
 b.eq network_notify
 ldr w0, [x9, #16]
 cmp w0, #1
 b.hi network_fail
 bl network_selected
 cmp x5, #0x38
 b.eq network_num
 cmp x5, #0x44
 b.eq network_set_ready
 ldr w0, [x9, #4]
 cbnz w0, network_fail
 cmp x5, #0x80
 b.eq network_desc
 cmp x5, #0x90
 b.eq network_avail
 cmp x5, #0xa0
 b.eq network_used
 cmp x5, #0x84
 b.eq network_desc_high
 cmp x5, #0x94
 b.eq network_avail_high
 cmp x5, #0xa4
 b.eq network_used_high
 b store_return
network_feature_sel: str w1, [x9]
 b store_return
network_driver_sel: str w1, [x9, #8]
 b store_return
network_driver_features:
 ldr w0, [x9, #8]
 cbnz w0, 1f
 str w1, [x9, #4]
 b store_return
1: cmp w0, #1
 b.ne network_fail
 str w1, [x9, #12]
 b store_return
network_queue_sel: str w1, [x9, #16]
 b store_return
network_ack:
 ldr w0, [x9, #32]
 bic w0, w0, w1
 str w0, [x9, #32]
 b store_return
network_set_status:
 cbz w1, network_reset
 tbz w1, #3, 1f
 ldr w0, [x9, #4]
 cbnz w0, network_fail
 ldr w0, [x9, #12]
 cmp w0, #1
 b.ne network_fail
1: str w1, [x9, #28]
 b store_return
network_reset:
 mov x0, #12
1: stp xzr, xzr, [x9], #16
 subs x0, x0, #1
 b.ne 1b
 b store_return
network_num:
 ldr w0, [x9, #4]
 cbnz w0, network_fail
 cmp w1, #8
 b.ne network_fail
 str w1, [x9]
 b store_return
network_set_ready:
 cmp w1, #1
 b.hi network_fail
 str w1, [x9, #4]
 b store_return
network_desc: str w1, [x9, #16]
 b store_return
network_avail: str w1, [x9, #24]
 b store_return
network_used: str w1, [x9, #32]
 b store_return
network_desc_high: str w1, [x9, #20]
 b store_return
network_avail_high: str w1, [x9, #28]
 b store_return
network_used_high: str w1, [x9, #36]
 b store_return
network_fail:
 addr x9, network_state
 ldr w0, [x9, #28]
 orr w0, w0, #128
 str w0, [x9, #28]
 b store_return
network_notify:
 cmp w1, #1
 b.hi network_fail
 devset w1, network_direction
 ldr w0, [x9, #28]
 mov w2, #143
 and w0, w0, w2
 cmp w0, #15
 b.ne network_fail
 add x9, x9, x1, lsl #6
 add x9, x9, #64
 devset x9, network_current
 ldr w0, [x9]
 cmp w0, #8
 b.ne network_fail
 ldr w0, [x9, #4]
 cmp w0, #1
 b.ne network_fail
 ldr x0, [x9, #16]
 tst x0, #15
 b.ne network_fail
 mov x2, #128
 bl dma_pointer
 cbz x0, network_fail
 devset x0, network_desc_host
 devget x9, network_current
 ldr x0, [x9, #24]
 tst x0, #1
 b.ne network_fail
 mov x2, #22
 bl dma_pointer
 cbz x0, network_fail
 devset x0, network_avail_host
 devget x9, network_current
 ldrh w1, [x0, #2]
 ldrh w2, [x9, #8]
 sub w1, w1, w2
 and w1, w1, #65535
 cbz w1, store_return
 cmp w1, #8
 b.hi network_fail
 and w2, w2, #7
 add x0, x0, #4
 ldrh w0, [x0, x2, lsl #1]
 cmp w0, #8
 b.hs network_fail
 devset w0, network_head
 devget x10, network_desc_host
 add x10, x10, x0, lsl #4
 ldrh w0, [x10, #12]
 devget w1, network_direction
 cbnz w1, 1f
 cmp w0, #2
 b.ne network_fail
 b 2f
1: cbnz w0, network_fail
2: ldr w2, [x10, #8]
 cbz w2, network_fail
 cmp w2, #1024
 b.hi network_fail
 devset w2, network_length
 ldr x0, [x10]
 bl dma_pointer
 cbz x0, network_fail
 devget x9, network_current
 ldr w1, [x9, #12]
 devget w2, network_length
 cmp w1, w2
 b.hs network_fail
 sub w2, w2, w1
 add x1, x0, x1
 devget x0, network_fd
 devget w4, network_direction
 cbnz w4, network_send
 mov x3, #64
 mov x4, #0
 mov x5, #0
 mov x8, #207
 svc #0
 b network_io_result
network_send:
 mov x3, #16448
 mov x4, #0
 mov x5, #0
 mov x8, #206
 svc #0
network_io_result:
 cmn x0, #11
 b.eq store_return
 cmn x0, #4
 b.eq store_return
 cmp x0, #0
 b.le network_fail
 devget x9, network_current
 ldr w1, [x9, #12]
 add w1, w1, w0
 str w1, [x9, #12]
 devget w0, network_direction
 cbz w0, network_complete
 devget w0, network_length
 cmp w1, w0
 b.lo store_return
network_complete:
 devset w1, network_actual
 ldr x0, [x9, #32]
 tst x0, #3
 b.ne network_fail
 mov x2, #68
 bl dma_pointer
 cbz x0, network_fail
 mov x10, x0
 devget x9, network_current
 ldrh w2, [x9, #8]
 and w3, w2, #7
 add x11, x10, #4
 add x11, x11, x3, lsl #3
 devget w0, network_head
 devget w1, network_actual
 stp w0, w1, [x11]
 add w2, w2, #1
 strh w2, [x9, #8]
 dmb ishst
 strh w2, [x10, #2]
 str wzr, [x9, #12]
 addr x9, network_state
 ldr w0, [x9, #32]
 orr w0, w0, #1
 str w0, [x9, #32]
 b store_return
.section .bss
.balign 16
network_state: .skip 192
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
