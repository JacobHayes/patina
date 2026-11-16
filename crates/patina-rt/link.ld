/* Text first at the fixed base 0x6000_0000_0000; everything executable stays
   below 0x6000_1000_0000, the range the seccomp filter lets through. */
ENTRY(_start)
PHDRS {
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
  stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
  . = 0x600000000000;
  .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
  .rodata : { *(.rodata .rodata.*) } :text
  .eh_frame_hdr : { *(.eh_frame_hdr) } :text
  .eh_frame : { *(.eh_frame) } :text
  . = ALIGN(4096);
  .data : { *(.data .data.*) } :data
  .got : { *(.got .got.*) } :data
  .bss : { *(.bss .bss.*) *(COMMON) } :data
  /DISCARD/ : { *(.comment) *(.note .note.*) *(.dynamic) *(.dynsym) *(.dynstr) *(.hash) *(.gnu.hash) *(.interp) }
}
