/* PCM2 non-console port1 with bounded controls; PCM1 remains under low features0. */
pcm_read:
 addr x9, pcm_state
 cbz x5, virtio_magic
 cmp x5, #4
 b.eq modern_version
 cmp x5, #8
 b.eq pcm_id
 cmp x5, #12
 b.eq virtio_vendor
 cmp x5, #0x10
 b.eq pcm_features
 cmp x5, #0x34
 b.eq pcm_max
 cmp x5, #0x44
 b.eq pcm_ready
 cmp x5, #0x60
 b.eq pcm_interrupt
 cmp x5, #0x70
 b.eq pcm_status
 cmp x5, #0x104
 b.eq pcm_ports
 b virtio_zero
pcm_id:
 devget x0, pcm_fd
 cmp x0, #0
 b.lt virtio_zero
 mov x0, #3
 b load_return
pcm_features:
 ldr w0, [x9]
 cbnz w0, 1f
 mov x0, #2
 b load_return
1: cmp w0, #1
 cset x0, eq
 b load_return
pcm_ports:
 mov x0, #2
 b load_return
pcm_max:
 ldr w0, [x9, #16]
 cmp w0, #5
 b.hi virtio_zero
 mov x0, #8
 b load_return
pcm_ready:
 ldr w0, [x9, #16]
 cmp w0, #5
 b.hi virtio_zero
 bl pcm_selected
 ldr w0, [x9, #4]
 b load_return
pcm_interrupt:
 ldr w0, [x9, #32]
 b load_return
pcm_status:
 ldr w0, [x9, #28]
 b load_return
pcm_selected:
 ldr w0, [x9, #16]
 add x9, x9, x0, lsl #6
 add x9, x9, #64
 ret
pcm_write:
 addr x9, pcm_state
 cmp x5, #0x14
 b.eq pcm_feature_sel
 cmp x5, #0x24
 b.eq pcm_driver_sel
 cmp x5, #0x20
 b.eq pcm_driver_features
 cmp x5, #0x30
 b.eq pcm_queue_sel
 cmp x5, #0x64
 b.eq pcm_ack
 cmp x5, #0x70
 b.eq pcm_set_status
 cmp x5, #0x50
 b.eq pcm_notify
 ldr w0, [x9, #16]
 cmp w0, #5
 b.hi pcm_fail
 bl pcm_selected
 cmp x5, #0x38
 b.eq pcm_num
 cmp x5, #0x44
 b.eq pcm_set_ready
 ldr w0, [x9, #4]
 cbnz w0, pcm_fail
 cmp x5, #0x80
 b.eq pcm_desc
 cmp x5, #0x90
 b.eq pcm_avail
 cmp x5, #0xa0
 b.eq pcm_used
 cmp x5, #0x84
 b.eq pcm_desc_high
 cmp x5, #0x94
 b.eq pcm_avail_high
 cmp x5, #0xa4
 b.eq pcm_used_high
 b store_return
pcm_feature_sel: str w1, [x9]
 b store_return
pcm_driver_sel: str w1, [x9, #8]
 b store_return
pcm_driver_features:
 ldr w0, [x9, #8]
 cbnz w0, 1f
 str w1, [x9, #4]
 b store_return
1: cmp w0, #1
 b.ne pcm_fail
 str w1, [x9, #12]
 b store_return
pcm_queue_sel: str w1, [x9, #16]
 b store_return
pcm_ack:
 ldr w0, [x9, #32]
 bic w0, w0, w1
 str w0, [x9, #32]
 b store_return
pcm_set_status:
 cbz w1, pcm_reset
 tbz w1, #3, 1f
 ldr w0, [x9, #4]
 bic w0, w0, #2
 cbnz w0, pcm_fail
 ldr w0, [x9, #12]
 cmp w0, #1
 b.ne pcm_fail
1: str w1, [x9, #28]
 b store_return
pcm_reset:
 mov x0, #28
1: stp xzr, xzr, [x9], #16
 subs x0, x0, #1
 b.ne 1b
 b store_return
pcm_num:
 ldr w0, [x9, #4]
 cbnz w0, pcm_fail
 cmp w1, #8
 b.ne pcm_fail
 str w1, [x9]
 b store_return
pcm_set_ready:
 cmp w1, #1
 b.hi pcm_fail
 str w1, [x9, #4]
 b store_return
pcm_desc: str w1, [x9, #16]
 b store_return
pcm_avail: str w1, [x9, #24]
 b store_return
pcm_used: str w1, [x9, #32]
 b store_return
pcm_desc_high: str w1, [x9, #20]
 b store_return
pcm_avail_high: str w1, [x9, #28]
 b store_return
pcm_used_high: str w1, [x9, #36]
 b store_return
pcm_fail:
 addr x9, pcm_state
 ldr w0, [x9, #28]
 orr w0, w0, #128
 str w0, [x9, #28]
 b store_return
pcm_notify:
 cmp w1, #5
 b.hi pcm_fail
 ldr w0, [x9, #4]
 tbz w0, #1, pcm_legacy_notify
 cmp w1, #2
 b.eq pcm_control_notify
 cmp w1, #3
 b.eq pcm_queue_notify
 cmp w1, #5
 b.ne pcm_fail
 ldr w0, [x9, #40]
 cmp w0, #1
 b.ne pcm_fail
 b pcm_queue_notify
pcm_control_notify:
 ldr w0, [x9, #36]
 cmp w0, #1
 b.eq pcm_queue_notify
 cmp w0, #3
 b.eq pcm_queue_notify
 cmp w0, #4
 b.eq pcm_queue_notify
 b store_return
pcm_legacy_notify:
 cmp w1, #1
 b.hi pcm_fail
pcm_queue_notify:
 devset w1, pcm_direction
 ldr w0, [x9, #28]
 mov w2, #143
 and w0, w0, w2
 cmp w0, #15
 b.ne pcm_fail
 add x9, x9, x1, lsl #6
 add x9, x9, #64
 devset x9, pcm_current
 ldr w0, [x9]
 cmp w0, #8
 b.ne pcm_fail
 ldr w0, [x9, #4]
 cmp w0, #1
 b.ne pcm_fail
 ldr x0, [x9, #16]
 tst x0, #15
 b.ne pcm_fail
 mov x2, #128
 bl dma_pointer
 cbz x0, pcm_fail
 devset x0, pcm_desc_host
 devget x9, pcm_current
 ldr x0, [x9, #24]
 tst x0, #1
 b.ne pcm_fail
 mov x2, #22
 bl dma_pointer
 cbz x0, pcm_fail
 devset x0, pcm_avail_host
 devget x9, pcm_current
 ldrh w1, [x0, #2]
 ldrh w2, [x9, #8]
 sub w1, w1, w2
 and w1, w1, #65535
 cbz w1, store_return
 cmp w1, #8
 b.hi pcm_fail
 and w2, w2, #7
 add x0, x0, #4
 ldrh w0, [x0, x2, lsl #1]
 cmp w0, #8
 b.hs pcm_fail
 devset w0, pcm_head
 devget x10, pcm_desc_host
 add x10, x10, x0, lsl #4
 ldrh w0, [x10, #12]
 devget w1, pcm_direction
 cbz w1, 3f
 cmp w1, #2
 b.ne 1f
3:
 cmp w0, #2
 b.ne pcm_fail
 b 2f
1: cbnz w0, pcm_fail
2: ldr w2, [x10, #8]
 cbz w2, pcm_fail
 cmp w2, #1024
 b.hi pcm_fail
 devset w2, pcm_length
 ldr x0, [x10]
 bl dma_pointer
 cbz x0, pcm_fail
 devget x9, pcm_current
 ldr w1, [x9, #12]
 devget w2, pcm_length
 cmp w1, w2
 b.hs pcm_fail
 sub w2, w2, w1
 add x1, x0, x1
 devget w4, pcm_direction
 cmp w4, #2
 b.eq pcm_control_receive
 cmp w4, #3
 b.eq pcm_control_send
 devget x0, pcm_fd
 devget w4, pcm_direction
 cbnz w4, pcm_send
 mov x3, #64
 mov x4, #0
 mov x5, #0
 mov x8, #207
 svc #0
 b pcm_io_result
pcm_control_receive:
 cmp w2, #64
 b.ne pcm_fail
 addr x9, pcm_state
 ldr w0, [x9, #36]
 cmp w0, #1
 b.ne 1f
 mov x0, #1
 movk x0, #1, lsl #32
 movk x0, #1, lsl #48
 str x0, [x1]
 mov w0, #2
 str w0, [x9, #36]
 mov w1, #8
 b 3f
1: cmp w0, #3
 b.ne 2f
 mov x0, #1
 movk x0, #7, lsl #32
 movk x0, #1, lsl #48
 mov x3, #0x746c
 movk x3, #0x702d, lsl #16
 movk x3, #0x6d63, lsl #32
 movk x3, #0x31, lsl #48
 stp x0, x3, [x1]
 mov w0, #4
 str w0, [x9, #36]
 mov w1, #16
 b 3f
2: cmp w0, #4
 b.ne pcm_fail
 mov x0, #1
 movk x0, #6, lsl #32
 movk x0, #1, lsl #48
 str x0, [x1]
 mov w0, #5
 str w0, [x9, #36]
 mov w1, #8
3: devget x9, pcm_current
 str w1, [x9, #12]
 b pcm_complete
pcm_control_send:
 cmp w2, #8
 b.ne pcm_fail
 ldr x0, [x1]
 mov x3, #0x1000000000000
 addr x9, pcm_state
 cmp x0, x3
 b.ne 1f
 ldr w4, [x9, #36]
 cbnz w4, pcm_fail
 mov w4, #1
 str w4, [x9, #36]
 b 3f
1: mov x3, #1
 movk x3, #3, lsl #32
 movk x3, #1, lsl #48
 cmp x0, x3
 b.ne 2f
 ldr w4, [x9, #36]
 cmp w4, #2
 b.ne pcm_fail
 mov w4, #3
 str w4, [x9, #36]
 b 3f
2: mov x3, #1
 movk x3, #6, lsl #32
 movk x3, #1, lsl #48
 cmp x0, x3
 b.ne pcm_fail
 ldr w4, [x9, #36]
 cmp w4, #5
 b.ne pcm_fail
 mov w4, #1
 str w4, [x9, #40]
3: devget x9, pcm_current
 mov w1, #8
 str w1, [x9, #12]
 b pcm_complete
pcm_send:
 mov x3, #16448
 mov x4, #0
 mov x5, #0
 mov x8, #206
 svc #0
pcm_io_result:
 cmn x0, #11
 b.eq store_return
 cmn x0, #4
 b.eq store_return
 cmp x0, #0
 b.le pcm_fail
 devget x9, pcm_current
 ldr w1, [x9, #12]
 add w1, w1, w0
 str w1, [x9, #12]
 devget w0, pcm_direction
 cbz w0, pcm_complete
 devget w0, pcm_length
 cmp w1, w0
 b.lo store_return
pcm_complete:
 devset w1, pcm_actual
 ldr x0, [x9, #32]
 tst x0, #3
 b.ne pcm_fail
 mov x2, #68
 bl dma_pointer
 cbz x0, pcm_fail
 mov x10, x0
 devget x9, pcm_current
 ldrh w2, [x9, #8]
 and w3, w2, #7
 add x11, x10, #4
 add x11, x11, x3, lsl #3
 devget w0, pcm_head
 devget w1, pcm_actual
 stp w0, w1, [x11]
 add w2, w2, #1
 strh w2, [x9, #8]
 dmb ishst
 strh w2, [x10, #2]
 str wzr, [x9, #12]
 addr x9, pcm_state
 ldr w0, [x9, #32]
 orr w0, w0, #1
 str w0, [x9, #32]
 b store_return
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
