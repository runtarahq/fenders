/* One loadable segment at address 0, file offsets equal to addresses, as
   musl's vDSO lookup expects (it derives the base from p_offset - p_vaddr). */
SECTIONS {
  . = SIZEOF_HEADERS;
  .hash : { *(.hash) } :text
  .gnu.hash : { *(.gnu.hash) }
  .dynsym : { *(.dynsym) }
  .dynstr : { *(.dynstr) }
  .gnu.version : { *(.gnu.version) }
  .gnu.version_d : { *(.gnu.version_d) }
  .gnu.version_r : { *(.gnu.version_r) }
  .dynamic : { *(.dynamic) } :text :dynamic
  .rodata : { *(.rodata*) } :text
  .text : { *(.text*) } :text
  /DISCARD/ : { *(.note.gnu.property) *(.eh_frame*) *(.comment) *(.data*) *(.bss*) }
}
PHDRS {
  text PT_LOAD FLAGS(5) FILEHDR PHDRS;
  dynamic PT_DYNAMIC FLAGS(4);
}
