/* Text first at the fixed base 0x6000_0000_0000, below 0x6000_1000_0000 (the control
   region's read-write window and the rest of the runtime's region follow; proto::layout).
   The base is fixed, so the syscall stub the seccomp filter lets through is at the same
   address in every image. */
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
