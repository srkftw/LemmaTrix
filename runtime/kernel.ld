OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
 . = 0x80000000;
 .text : { *(.text.boot) *(.text*) }
 .rodata : { *(.rodata*) }
 .data : { *(.data*) }
 .bss : { *(.bss*) *(COMMON) }
 ASSERT(. < 0x80080000, "kernel exceeds reserved 512KiB")
 /DISCARD/ : { *(.comment) *(.eh_frame*) *(.riscv.attributes) }
}
