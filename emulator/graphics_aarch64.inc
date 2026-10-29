/* Independently implemented AArch64 modern virtio-mmio GPU/evdev device path.
 * Matches the bounded development profile of graphics_x86_64.inc, not host UI.
 */
graphics_open_adapters:
 stp x30, xzr, [sp, #-16]!
 addr x1, display_path
 ldr x1, [x1]
 cbz x1, 1f
 mov x0, #-100
 mov x2, #0x242
 mov x3, #384
 mov x8, #56
 svc #0
 cmp x0, #0
 b.lt io_error
 addr x1, display_fd
 str x0, [x1]
1: addr x1, input_path
 ldr x1, [x1]
 cbz x1, 2f
 mov x0, #-100
 mov x2, #0x800
 mov x3, #0
 mov x8, #56
 svc #0
 cmp x0, #0
 b.lt io_error
 addr x1, input_fd
 str x0, [x1]
2: ldp x30, xzr, [sp], #16
 ret
modern_read:
 sub x7, x6, #2
 addr x9, graphics_states
 add x9, x9, x7, lsl #7
 cbz x5, virtio_magic
 cmp x5, #4
 b.eq modern_version
 cmp x5, #8
 b.eq modern_id
 cmp x5, #12
 b.eq virtio_vendor
 cmp x5, #0x10
 b.eq modern_features
 cmp x5, #0x34
 b.eq modern_max
 cmp x5, #0x44
 b.eq modern_ready
 cmp x5, #0x60
 b.eq modern_interrupt
 cmp x5, #0x70
 b.eq modern_status
 cmp x5, #0x108
 b.ne virtio_zero
 cmp x6, #2
 b.ne virtio_zero
 mov x0, #1
 b load_return
modern_version:
 mov x0, #2
 b load_return
modern_id:
 mov x0, #16
 cmp x6, #2
 b.eq load_return
 mov x0, #18
 b load_return
modern_features:
 ldr w0, [x9]
 cmp w0, #1
 cset x0, eq
 b load_return
modern_max:
 ldr w0, [x9, #16]
 cbnz w0, virtio_zero
 mov x0, #8
 b load_return
modern_ready:
 ldr w0, [x9, #24]
 b load_return
modern_interrupt:
 ldr w0, [x9, #32]
 b load_return
modern_status:
 ldr w0, [x9, #28]
 b load_return
modern_write:
 devset w6, graphics_number
 sub x7, x6, #2
 addr x9, graphics_states
 add x9, x9, x7, lsl #7
 devset x9, graphics_current
 cmp x5, #0x14
 b.eq modern_feature_sel
 cmp x5, #0x24
 b.eq modern_driver_sel
 cmp x5, #0x20
 b.eq modern_driver_features
 cmp x5, #0x30
 b.eq modern_queue_sel
 cmp x5, #0x38
 b.eq modern_queue_num
 cmp x5, #0x44
 b.eq modern_queue_ready
 cmp x5, #0x64
 b.eq modern_ack
 cmp x5, #0x70
 b.eq modern_set_status
 cmp x5, #0x50
 b.eq modern_notify
 cmp x5, #0x80
 b.eq modern_desc_low
 cmp x5, #0x84
 b.eq modern_desc_high
 cmp x5, #0x90
 b.eq modern_avail_low
 cmp x5, #0x94
 b.eq modern_avail_high
 cmp x5, #0xa0
 b.eq modern_used_low
 cmp x5, #0xa4
 b.eq modern_used_high
 b store_return
modern_feature_sel:
 str w1, [x9]
 b store_return
modern_driver_sel:
 str w1, [x9, #8]
 b store_return
modern_driver_features:
 ldr w0, [x9, #8]
 cbnz w0, 1f
 str w1, [x9, #4]
 b store_return
1: cmp w0, #1
 b.ne modern_fail
 str w1, [x9, #12]
 b store_return
modern_queue_sel:
 str w1, [x9, #16]
 b store_return
modern_queue_num:
 ldr w0, [x9, #24]
 cbnz w0, modern_fail
 ldr w0, [x9, #16]
 cbnz w0, modern_fail
 cmp w1, #8
 b.ne modern_fail
 str w1, [x9, #20]
 b store_return
modern_queue_ready:
 ldr w0, [x9, #16]
 cbnz w0, modern_fail
 cmp w1, #1
 b.hi modern_fail
 str w1, [x9, #24]
 b store_return
modern_ack:
 and w1, w1, #3
 ldr w0, [x9, #32]
 bic w0, w0, w1
 str w0, [x9, #32]
 b store_return
modern_set_status:
 cbz w1, modern_reset
 tbz w1, #3, 1f
 ldr w0, [x9, #4]
 cbnz w0, modern_fail
 ldr w0, [x9, #12]
 cmp w0, #1
 b.ne modern_fail
1: str w1, [x9, #28]
 b store_return
modern_reset:
 devget w0, graphics_number
 cmp w0, #2
 b.ne 1f
 devset xzr, graphics_backing
 devset wzr, graphics_resource
 devset wzr, graphics_scanout
1: stp xzr, xzr, [x9]
 stp xzr, xzr, [x9, #16]
 stp xzr, xzr, [x9, #32]
 stp xzr, xzr, [x9, #48]
 stp xzr, xzr, [x9, #64]
 stp xzr, xzr, [x9, #80]
 stp xzr, xzr, [x9, #96]
 stp xzr, xzr, [x9, #112]
 b store_return
modern_desc_low:
 mov x2, #48
 b modern_address_low
modern_avail_low:
 mov x2, #56
 b modern_address_low
modern_used_low:
 mov x2, #64
modern_address_low:
 ldr w0, [x9, #24]
 cbnz w0, modern_fail
 str w1, [x9, x2]
 b store_return
modern_desc_high:
 mov x2, #52
 b modern_address_low
modern_avail_high:
 mov x2, #60
 b modern_address_low
modern_used_high:
 mov x2, #68
 b modern_address_low
modern_fail:
 devget x9, graphics_current
 ldr w0, [x9, #28]
 orr w0, w0, #128
 str w0, [x9, #28]
 b store_return
modern_notify:
 cbnz w1, modern_fail
 ldr w0, [x9, #20]
 cmp w0, #8
 b.ne modern_fail
 ldr w0, [x9, #24]
 cmp w0, #1
 b.ne modern_fail
 ldr w0, [x9, #28]
 mov w1, #143
 and w0, w0, w1
 cmp w0, #15
 b.ne modern_fail
 ldr x0, [x9, #48]
 tst x0, #15
 b.ne modern_fail
 mov x2, #128
 bl dma_pointer
 cbz x0, modern_fail
 devset x0, graphics_desc
 devget x9, graphics_current
 ldr x0, [x9, #56]
 tst x0, #1
 b.ne modern_fail
 mov x2, #22
 bl dma_pointer
 cbz x0, modern_fail
 devset x0, graphics_avail
 devget x9, graphics_current
 ldr x0, [x9, #64]
 tst x0, #3
 b.ne modern_fail
 mov x2, #68
 bl dma_pointer
 cbz x0, modern_fail
 devset x0, graphics_used
modern_consume:
 devget x9, graphics_current
 devget x10, graphics_avail
 ldrh w0, [x10, #2]
 ldrh w1, [x9, #36]
 sub w0, w0, w1
 and w0, w0, #65535
 cbz w0, store_return
 cmp w0, #8
 b.hi modern_fail
 and w1, w1, #7
 add x10, x10, #4
 ldrh w0, [x10, x1, lsl #1]
 cmp w0, #8
 b.hs modern_fail
 devset w0, graphics_head
 devget x10, graphics_desc
 add x10, x10, x0, lsl #4
 devset x10, graphics_request_desc
 devget w0, graphics_number
 cmp w0, #2
 b.ne modern_input
 bl graphics_gpu_request
 cmn w0, #1
 b.eq modern_fail
 b modern_complete
modern_input:
 cmp w0, #3
 b.ne store_return
 ldrh w0, [x10, #12]
 cmp w0, #2
 b.ne modern_fail
 ldr w0, [x10, #8]
 cmp w0, #8
 b.ne modern_fail
 ldr x0, [x10]
 mov x2, #8
 bl dma_pointer
 cbz x0, modern_fail
 devset x0, graphics_event_dest
 devget x0, input_fd
 cmp x0, #0
 b.lt store_return
 devget w3, graphics_input_count
 mov x2, #8
 sub x2, x2, x3
 addr x1, graphics_input_event
 add x1, x1, x3
 mov x8, #63
 svc #0
 cmp x0, #0
 b.le store_return
 devget w1, graphics_input_count
 add w1, w1, w0
 devset w1, graphics_input_count
 cmp w1, #8
 b.ne store_return
 devset wzr, graphics_input_count
 devget x0, graphics_event_dest
 devget x1, graphics_input_event
 str x1, [x0]
 mov w0, #8
modern_complete:
 devget x9, graphics_current
 devget x10, graphics_used
 ldrh w1, [x9, #40]
 and w1, w1, #7
 add x10, x10, #4
 add x10, x10, x1, lsl #3
 devget w2, graphics_head
 stp w2, w0, [x10]
 ldrh w0, [x9, #40]
 add w0, w0, #1
 strh w0, [x9, #40]
 ldrh w1, [x9, #36]
 add w1, w1, #1
 strh w1, [x9, #36]
 devget x10, graphics_used
 dmb ishst
 strh w0, [x10, #2]
 ldr w0, [x9, #32]
 orr w0, w0, #1
 str w0, [x9, #32]
 b modern_consume

/* All control request and response spans checked before dereferencing. */
graphics_gpu_request:
 stp x30, xzr, [sp, #-16]!
 devget x10, graphics_request_desc
 ldrh w0, [x10, #12]
 cmp w0, #1
 b.ne graphics_bad
 ldr w2, [x10, #8]
 cmp w2, #24
 b.lo graphics_bad
 cmp w2, #56
 b.hi graphics_bad
 devset w2, graphics_request_length
 ldr x0, [x10]
 bl dma_pointer
 cbz x0, graphics_bad
 devset x0, graphics_request
 devget x10, graphics_request_desc
 ldrh w0, [x10, #14]
 cmp w0, #8
 b.hs graphics_bad
 devget w1, graphics_head
 cmp w0, w1
 b.eq graphics_bad
 devget x10, graphics_desc
 add x10, x10, x0, lsl #4
 ldrh w0, [x10, #12]
 cmp w0, #2
 b.ne graphics_bad
 ldr w0, [x10, #8]
 cmp w0, #24
 b.lo graphics_bad
 ldr x0, [x10]
 mov x2, #24
 bl dma_pointer
 cbz x0, graphics_bad
 devset x0, graphics_response
 stp xzr, xzr, [x0]
 str xzr, [x0, #16]
 mov w1, #0x1200
 str w1, [x0]
 devget x10, graphics_request
 ldr w0, [x10, #4]
 cbnz w0, graphics_reply
 ldr w0, [x10]
 cmp w0, #0x101
 b.eq graphics_create
 cmp w0, #0x106
 b.eq graphics_attach
 cmp w0, #0x103
 b.eq graphics_scan
 cmp w0, #0x105
 b.eq graphics_transfer
 cmp w0, #0x104
 b.eq graphics_flush
 cmp w0, #0x102
 b.eq graphics_unref
 b graphics_reply
graphics_create:
 devget w0, graphics_request_length
 cmp w0, #40
 b.ne graphics_reply
 ldr w0, [x10, #24]
 cmp w0, #1
 b.ne graphics_reply
 ldr w0, [x10, #28]
 cmp w0, #2
 b.ne graphics_reply
 ldr w0, [x10, #32]
 cmp w0, #640
 b.ne graphics_reply
 ldr w0, [x10, #36]
 cmp w0, #400
 b.ne graphics_reply
 devget w0, graphics_resource
 cbnz w0, graphics_reply
 mov w0, #1
 devset w0, graphics_resource
 b graphics_ok
graphics_attach:
 devget w0, graphics_request_length
 cmp w0, #48
 b.ne graphics_reply
 ldr w0, [x10, #24]
 cmp w0, #1
 b.ne graphics_reply
 ldr w0, [x10, #28]
 cmp w0, #1
 b.ne graphics_reply
 devget w0, graphics_resource
 cmp w0, #1
 b.ne graphics_reply
 ldr w0, [x10, #40]
 mov w2, #0xa000
 movk w2, #15, lsl #16
 cmp w0, w2
 b.ne graphics_reply
 ldr x0, [x10, #32]
 bl dma_pointer
 cbz x0, graphics_reply
 devset x0, graphics_backing
 b graphics_ok
graphics_scan:
 devget w0, graphics_request_length
 cmp w0, #48
 b.ne graphics_reply
 ldr w0, [x10, #40]
 cbnz w0, graphics_reply
 ldr w0, [x10, #44]
 cmp w0, #1
 b.ne graphics_reply
 ldr x0, [x10, #24]
 cbnz x0, graphics_reply
 ldr w0, [x10, #32]
 cmp w0, #640
 b.ne graphics_reply
 ldr w0, [x10, #36]
 cmp w0, #400
 b.ne graphics_reply
 devget x0, graphics_backing
 cbz x0, graphics_reply
 mov w0, #1
 devset w0, graphics_scanout
 b graphics_ok
graphics_rectangle:
 ldr w0, [x10, #24]
 ldr w1, [x10, #28]
 cmp w0, #640
 b.hs graphics_rect_bad
 cmp w1, #400
 b.hs graphics_rect_bad
 ldr w2, [x10, #32]
 cbz w2, graphics_rect_bad
 add x2, x2, x0
 cmp x2, #640
 b.hi graphics_rect_bad
 ldr w2, [x10, #36]
 cbz w2, graphics_rect_bad
 add x2, x2, x1
 cmp x2, #400
 b.hi graphics_rect_bad
 mov w2, #640
 madd w0, w1, w2, w0
 lsl w0, w0, #2
 mov w1, #1
 ret
graphics_rect_bad:
 mov w1, #0
 ret
graphics_transfer:
 devget w0, graphics_request_length
 cmp w0, #56
 b.ne graphics_reply
 ldr w0, [x10, #48]
 cmp w0, #1
 b.ne graphics_reply
 devget x0, graphics_backing
 cbz x0, graphics_reply
 bl graphics_rectangle
 cbz w1, graphics_reply
 ldr x1, [x10, #40]
 cmp x0, x1
 b.ne graphics_reply
 ldr w6, [x10, #36]
 ldr w7, [x10, #32]
 lsl w7, w7, #2
 addr x4, graphics_pixels
 add x4, x4, x0
 devget x5, graphics_backing
 add x5, x5, x0
1: mov w3, w7
2: ldr w0, [x5], #4
 str w0, [x4], #4
 subs w3, w3, #4
 b.ne 2b
 mov w3, #2560
 sub w3, w3, w7
 add x4, x4, x3
 add x5, x5, x3
 subs w6, w6, #1
 b.ne 1b
 b graphics_ok
graphics_flush:
 devget w0, graphics_request_length
 cmp w0, #48
 b.ne graphics_reply
 ldr w0, [x10, #40]
 cmp w0, #1
 b.ne graphics_reply
 devget w0, graphics_scanout
 cmp w0, #1
 b.ne graphics_reply
 bl graphics_rectangle
 cbz w1, graphics_reply
 devget x0, display_fd
 cmp x0, #0
 b.lt graphics_ok
 devget x1, graphics_sequence
 add x1, x1, #2
 orr x1, x1, #1
 devset x1, graphics_sequence
 addr x1, graphics_sequence
 mov x2, #8
 mov x3, #0xa000
 movk x3, #15, lsl #16
 mov x8, #68
 svc #0
 cmp x0, #8
 b.ne graphics_reply
 devget x0, display_fd
 addr x1, graphics_pixels
 mov x2, #0xa000
 movk x2, #15, lsl #16
 mov x3, #0
 mov x8, #68
 svc #0
 mov x1, #0xa000
 movk x1, #15, lsl #16
 cmp x0, x1
 b.ne graphics_reply
 devget x1, graphics_sequence
 add x1, x1, #1
 devset x1, graphics_sequence
 devget x0, display_fd
 addr x1, graphics_sequence
 mov x2, #8
 mov x3, #0xa000
 movk x3, #15, lsl #16
 mov x8, #68
 svc #0
 cmp x0, #8
 b.ne graphics_reply
 b graphics_ok
graphics_unref:
 devget w0, graphics_request_length
 cmp w0, #32
 b.ne graphics_reply
 ldr w0, [x10, #24]
 cmp w0, #1
 b.ne graphics_reply
 devset wzr, graphics_resource
 devset wzr, graphics_scanout
 devset xzr, graphics_backing
graphics_ok:
 devget x0, graphics_response
 mov w1, #0x1100
 str w1, [x0]
graphics_reply:
 mov w0, #24
 ldp x30, xzr, [sp], #16
 ret
graphics_bad:
 mov w0, #-1
 ldp x30, xzr, [sp], #16
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
