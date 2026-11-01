/* Built-in Vault416KiB; ordinary application releases retain256KiB. */
OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
 . = 0x200000;
 .text : { *(.text.boot) *(.text*) }
 .rodata : { *(.rodata*) }
 .data : { *(.data*) }
 .bss : { *(.bss*) *(COMMON) }
 ASSERT(. < 0x268000, "built-in Vault code exceeds416KiB")
 /DISCARD/ : { *(.comment) *(.eh_frame*) *(.riscv.attributes) }
}
