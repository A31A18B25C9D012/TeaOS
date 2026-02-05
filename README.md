
Kernel loads at 0x20000, locks itself in L2 cache using CR0 cache disable and MTRR configuration.
Size: 8368 bytes, well under 256KB L2 cache target.

XFCE components preloaded at 0x400000:
1. panel (256KB)
2. window_manager (512KB)
3. desktop (256KB)
4. menu (128KB)
5. icons (1MB)
6. themes (512KB)
7. compositor (384KB)
8. settings (256KB)

MEMORY LAYOUT:

0x00000000: Real mode IVT
0x00007C00: Boot sector
0x00020000: Kernel code (L2 locked)
0x00100000: Heap (2MB)
0x00400000: XFCE preload (8MB)
0xFD000000: Framebuffer

CACHE LOCKING:

Uses CR0 cache disable with WBINVD to lock kernel in L2.
MTRR registers 0x200/0x201 configure cache policy.
All kernel code accessed during init to load into cache.

SECURITY:

Memory wiped on halt: 4-pass (0xFF, 0xAA, 0x55, 0x00)
Framebuffer wiped
XFCE memory region cleared
L2 cache flushed via WBINVD/INVD

COMMANDS

`halt, clear, info`

BUILD

`make clean && make`
`qemu-system-i386 -drive format=raw,file=os.img -m 512M`

> [!WARNING]
> 1. NO NETWORKING
> 2. NO FILESYSTEM
> 3. NO MULTIPROCESSING
