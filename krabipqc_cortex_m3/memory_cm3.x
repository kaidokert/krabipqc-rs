/* QEMU mps2-an385 (Cortex-M3) memory map.
   - SSRAM1 at 0x00000000, 4 MB  (used for code + .rodata)
   - SSRAM23 at 0x20000000, 4 MB (used for stack/.bss/.data)

   We give the linker 256 KB of RAM so ML-DSA-44 verify (which peaks
   around ~50 KB of stack between PolyMatrix<4,4> and several
   PolyVec<4> temporaries) has plenty of headroom. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
_ram_length = LENGTH(RAM);
