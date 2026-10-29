OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
 . = 0x400000;
 .text : { *(.text.boot) *(.text*) }
 .rodata : { *(.rodata*) }
 .data : { *(.data*) }
 .bss : { *(.bss*) *(COMMON) }
 ASSERT(. < 0x410000, "app code exceeds 64KiB")
 /DISCARD/ : { *(.comment) *(.eh_frame*) *(.riscv.attributes) }
}
