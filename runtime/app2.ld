OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
 . = 0x200000;
 .text : { *(.text.boot) *(.text*) }
 .rodata : { *(.rodata*) }
 .data : { *(.data*) }
 .bss : { *(.bss*) *(COMMON) }
 ASSERT(. < 0x240000, "profile2 code exceeds256KiB")
 /DISCARD/ : { *(.comment) *(.eh_frame*) *(.riscv.attributes) }
}
