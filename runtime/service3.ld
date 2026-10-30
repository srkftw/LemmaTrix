/* Built-in Objects service only. This is not an application release profile. */
OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
 . = 0x200000;
 .text : { *(.text.boot) *(.text*) }
 .rodata : { *(.rodata*) }
 .data : { *(.data*) }
 .bss : { *(.bss*) *(COMMON) }
 ASSERT(. < 0x260000, "built-in Objects code exceeds384KiB")
 /DISCARD/ : { *(.comment) *(.eh_frame*) *(.riscv.attributes) }
}
