AS = nasm
CC = gcc
LD = ld

ASFLAGS = -f bin
CFLAGS = -m32 -ffreestanding -nostdlib -fno-pie -fno-stack-protector -mno-red-zone -O2 -fno-builtin -Iinclude
LDFLAGS = -m elf_i386 -T src/linker.ld

KERNEL_OBJS = build/cache.o build/xfce.o build/memory.o build/framebuffer.o build/gui.o build/input.o build/teascript.o build/filesystem.o build/editor.o build/network.o build/compiler.o build/shell.o build/main.o

all: os.img

os.img: build/boot.bin build/kernel.bin
	cat build/boot.bin > os.img
	dd if=build/kernel.bin of=os.img bs=512 seek=1 conv=notrunc 2>/dev/null
	truncate -s 33M os.img

build:
	mkdir -p build

build/boot.bin: | build
	$(AS) $(ASFLAGS) boot/boot.asm -o build/boot.bin

build/kernel.bin: $(KERNEL_OBJS) | build
	$(LD) $(LDFLAGS) $(KERNEL_OBJS) -o build/kernel.elf
	objcopy -O binary build/kernel.elf build/kernel.bin
	@SIZE=$$(stat -c%s build/kernel.bin); \
	echo "kernel size: $$SIZE bytes"; \
	if [ $$SIZE -gt 262144 ]; then \
		echo "warning: kernel exceeds 256KB L2 cache target"; \
	fi

build/cache.o: src/kernel/cache.c include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/cache.c -o $@

build/xfce.o: src/kernel/xfce.c include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/xfce.c -o $@

build/memory.o: src/kernel/memory.c include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/memory.c -o $@

build/framebuffer.o: src/kernel/framebuffer.c include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/framebuffer.c -o $@

build/font.o: src/kernel/font.c include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/font.c -o $@

build/gui.o: src/kernel/gui.c include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/gui.c -o $@

build/input.o: src/kernel/input.c include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/input.c -o $@

build/teascript.o: src/kernel/teascript.c include/teascript.h include/shell.h include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/teascript.c -o $@

build/filesystem.o: src/kernel/filesystem.c include/filesystem.h include/shell.h include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/filesystem.c -o $@

build/editor.o: src/kernel/editor.c include/editor.h include/filesystem.h include/shell.h include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/editor.c -o $@

build/network.o: src/kernel/network.c include/network.h include/shell.h include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/network.c -o $@

build/compiler.o: src/kernel/compiler.c include/compiler.h include/shell.h include/filesystem.h include/teascript.h include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/compiler.c -o $@

build/shell.o: src/kernel/shell.c include/shell.h include/teascript.h include/filesystem.h include/editor.h include/network.h include/compiler.h include/types.h | build
	$(CC) $(CFLAGS) -c src/kernel/shell.c -o $@

build/main.o: src/kernel/main.c include/types.h include/teascript.h include/filesystem.h include/editor.h include/shell.h | build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f build/* os.img src/kernel/*.backup

run: os.img
	qemu-system-i386 -drive format=raw,file=os.img -m 512M

.PHONY: all clean run