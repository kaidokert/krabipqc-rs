MEMORY
{
    /* QEMU virt machine: DRAM at 0x80000000, length 32 MiB.
     * The BSS+stack LOAD segment spans the full LENGTH; QEMU must be
     * given at least 2× this via -m to leave room for the DTB after
     * the kernel image — qemu_wrapper.py uses -m 64M.
     * riscv-rt places the stack at the top (_stack_start) and _ebss
     * marks the end of BSS, giving the paint/watermark a safe floor. */
    RAM : ORIGIN = 0x80000000, LENGTH = 32M
}

REGION_ALIAS("REGION_TEXT",   RAM);
REGION_ALIAS("REGION_RODATA", RAM);
REGION_ALIAS("REGION_DATA",   RAM);
REGION_ALIAS("REGION_BSS",    RAM);
REGION_ALIAS("REGION_HEAP",   RAM);
REGION_ALIAS("REGION_STACK",  RAM);
