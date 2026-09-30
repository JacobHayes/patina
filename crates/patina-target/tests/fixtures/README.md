# x86 instruction-boundary corpus

`x86-avx512.s` is Patina-authored assembly, not extracted from another project.
`x86-avx512.objdump` records its 143 bytes (20 instructions, 19 EVEX) and golden
boundaries, generated with GNU as/objdump 2.42. It is never executed.

It exercises EVEX maps 1/2/3, register and memory ModRM, SIB, RIP-relative disp32,
compressed disp8, segment/address-size prefixes, broadcast, masking, embedded
rounding, and map-1/map-3 immediates. The unit tests additionally check truncation,
reserved fields and exact forbidden-opcode sentinels after each instruction.
`x86_decoder_matches_objdump_corpus` runs on every platform without a compiler,
assembler, objdump installation or AVX-512 CPU. It checks contiguous addresses,
measured lengths, map coverage, EVEX count and that the scan reaches a syscall
appended at the end.

Regenerate with an x86-64 GNU assembler and objdump:

```sh
as --64 -o /tmp/patina-evex.o crates/patina-target/tests/fixtures/x86-avx512.s
objdump -d -z -j .text --insn-width=16 /tmp/patina-evex.o
```

Keep the section heading, labels and instruction rows; omit the filename header.
Update the byte/count assertions if the authored instructions intentionally change.
The checked-in dump is an oracle output, not output from Patina's decoder.

For broader local evidence, the ignored
`x86_decoder_matches_objdump_external_corpus` test accepts
`PATINA_X86_CORPUS_ELF` and `PATINA_X86_CORPUS_OBJDUMP` pointing to any real
x86-64 ELF and its `objdump -d -z -j .text` output. It compares whole-section
boundaries and exact syscall sites and reports the number of EVEX instructions.
These optional inputs are not dependencies of the checked-in corpus test.
