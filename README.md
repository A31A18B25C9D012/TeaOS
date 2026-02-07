TeaOS | Micro Kernel

TeaOS is a 32-bit x86 kernel that runs on bare metal and in QEMU. It boots
from a custom two-stage bootloader, enters protected mode, sets up VGA text
output at 80x25, and drops into a command shell. The entire system fits in
about 73 KB.

It has an in-memory filesystem, a text editor with syntax highlighting, a
ternary computing virtual machine called TeaScript, two compilers (one for
TeaScript bytecode, one for x86 assembly), a network stack that builds real
Ethernet/IP/ICMP/ARP packets, six virtual terminals, and direct hardware
access commands for reading and writing memory and I/O ports.

There is no hardware NIC driver. The network stack constructs valid packets
in a buffer but cannot transmit them. Everything else works.

The bootloader occupies sector 0 of the disk image. It loads the kernel from
sectors 1-146 into memory at physical address 0x20000 using two BIOS INT 13h
CHS reads (126 sectors from CHS 0,0,2 and 20 sectors from CHS 0,2,2). It
enables the A20 line via port 0x92, loads a GDT with flat code and data
segments, switches to 32-bit protected mode, sets the stack pointer to
0x90000, configures L2 cache MTRRs, and calls into the kernel entry point.

The kernel initializes in this order: IDT (256 entries, all pointing to a
default iret handler), heap allocator, framebuffer, keyboard, mouse (PS/2),
TeaScript VM, filesystem, shell, editor, and network stack. It then sets up
all six virtual terminal buffers and enters the main polling loop.

The Display is VGA text mode. 80 columns, 25 rows. Each cell is 2 bytes: low byte is the
ASCII character, high byte is the color attribute (high nibble = background,
low nibble = foreground).

Row 0 is the status bar. It shows the OS name, current TTY number, and a
hint about Alt+F1-F6 for terminal switching.

Rows 1 through 22 are the shell output area. Text scrolls upward when this
area fills. The last 100 lines that scroll off the top are kept in a
scrollback buffer.

Row 23 is the command prompt.

Row 24 is the debug bar showing keyboard buffer head/tail positions, current
VT number, uptime, and network status.

The kernel reads scancodes from port 0x60 with modifier tracking for Shift,
Ctrl, and Alt. Extended scancodes (0xE0 prefix) are handled for arrow keys,
PageUp, and PageDown.

Key codes used internally:
```
  1       Up arrow (shell history: older)
  2       Down arrow (shell history: newer)
  3       F1
  4       Left arrow
  5       Right arrow
  6       Alt+Up
  7       Alt+Down
  8       Backspace
  10      Enter
  16-21   Alt+F1 through Alt+F6 (virtual terminal switching)
  22      Alt+PageUp (scrollback up)
  23      Alt+PageDown (scrollback down)
  27      Escape
```
Printable characters (ASCII 32-126) are mapped through a scancode table with
shift variants for symbols and uppercase.

Alt+PageUp scrolls the shell output area backward through history, 5 lines
per press. Alt+PageDown scrolls forward. The buffer holds 100 lines. When
scrollback is active, the prompt line shows an indicator bar. Pressing any
key other than Alt+PageUp or Alt+PageDown exits scrollback and returns to
the live shell.

This kernel supports six independent terminals, numbered TTY1 through TTY6. Switch with Alt+F1
through Alt+F6. Each terminal has its own input buffer, cursor state, and
command history position. The full VGA screen (all 2000 cells) is saved and
restored on each switch.

The prompt is "tea@teos:~$ " on row 23. Input is limited to 64 characters.
Up and Down arrows cycle through the last 10 commands in history.

Commands:
```
  help                   List all commands
  clear                  Clear the output area
  whoami                 Show the TeaOS logo and system summary
  info                   Show system information
  cpuid                  Show CPU vendor string and feature flags
  lspci                  Scan PCI buses 0-1 and list detected devices
  history                Show the last 10 commands entered
  halt                   Stop the system
  reboot                 Reset the CPU via keyboard controller port 0x64

  ls                     List files and directories in the current directory
  ls -l                  List with type and size
  cat <file>             Print file contents to the terminal
  touch <file>           Create an empty file
  rm <file>              Delete a file
  rm -rf <dir>           Delete a directory and everything in it
  mkdir <dir>            Create a directory
  cd <dir>               Change directory (supports ".." and "/")
  pwd                    Print working directory path
  edit <file>            Open a file in the text editor
  echo <text>            Print text to the terminal

  ifconfig               Show MAC, IP, netmask, gateway, and packet stats
  ifconfig set <ip> <mask> <gw>
                         Configure the network interface
  ping <ip>              Build an ICMP echo request packet
  arp                    Show the ARP cache
  arp send <ip>          Build an ARP request packet
  netstat                Same as ifconfig
  nettest                Run a self-test of the network stack
  netdebug               Hex dump the last packet in the buffer

  tcc <file.tea> [out]   Compile TeaScript source to bytecode (.tbin)
  asm <file.asm> [out]   Assemble x86 assembly to machine code (.bin)
  run <file>             Execute a .tbin or .bin file

  teas <instruction>     Execute a single TeaScript instruction
  teas -doc -N           Show documentation page N (0-5)
  teas help              Show documentation page 1
  tregs                  Show the current state of all 8 ternary registers

  peek <addr>            Read one byte from a memory address
  poke <addr> <val>      Write one byte to a memory address
  dump <addr> <len>      Hex dump a region of memory (up to 128 bytes)
  xxd <file>             Hex dump the first 64 bytes of a file
  inb <port>             Read one byte from an I/O port
  outb <port> <val>      Write one byte to an I/O port

  theme orange           Warm color scheme (default)
  theme blue             Cool color scheme
  theme green            Natural color scheme
```
* Every command accepts "-h" to show usage.


The Kernel has its own "like vim" text editor

Opened with "edit <filename>". Creates the file if it does not exist. (You can still use the touch command if you want.)

The editor fills the screen. Row 0 shows the filename and a modified
indicator. Rows 2-22 show the file contents with line numbers. Row 22 shows
key hints.

Controls:
```
  Arrow keys     Move cursor
  Typing         Insert characters at cursor
  Backspace      Delete character before cursor, or join lines
  Enter          Split line at cursor
  F1             Save
  Escape         Exit editor (returns to shell)
```
Supports up to 100 lines, 78 characters per line. Vertical scrolling
follows the cursor automatically.

Syntax highlighting is active for .c files (C keywords: int, char, void, if,
else, while, for, return, struct, typedef, uint32_t, uint8_t, static,
extern, include, define) and .tea files (TeaScript instructions). Comments
starting with "//" and strings in double quotes are highlighted in .c files.


When it comes to the file system it is "in-memory" only. Everything is lost on reboot(sorry :3). 32 file slots total. Each file
can hold up to 4096 bytes. Filenames are up to 32 characters.

The filesystem is a flat table with a parent field per entry to form a
directory tree. File index 0 is the root directory. The current working
directory is tracked as an index into the file table.

Directories can be nested. "cd .." goes to the parent. "cd /" goes to root.
"rm -rf" deletes a directory and its immediate children (one level deep).


What is TeaScript? TeaScript is a ternary computing system. Ternary means three-valued: each
trit is -1, 0, or +1, unlike binary which uses 0 and 1.

The TeaScript VM has 8 registers named T0 through T7, 256 memory cells, a
program counter, and a comparison flag. Registers hold signed 32-bit
integers. The ternary operations (TAND, TOR, NEG) clamp values to the trit
range of -1, 0, +1 before operating.

Interactive mode (single instructions executed from the shell prompt):
```
  teas LOAD T0 5         Load the value 5 into register T0
  teas ADD T0 T1         T0 = T0 + T1
  teas MUL T0 T1         T0 = T0 * T1
  teas NEG T0            T0 = -T0
  teas OUT T0            Print the value in T0
  teas TAND T0 T1        Ternary AND of T0 and T1, result in T0
  teas TOR T0 T1         Ternary OR of T0 and T1, result in T0
  teas STORE T0 10       Store T0 to memory cell 10
  teas LDMEM T1 10       Load memory cell 10 into T1
  teas CMP T0 T1         Compare T0 and T1, set comparison flag
```
Ternary AND truth table:
```
  If either input is -1, result is -1
  If either input is 0, result is 0
  If both inputs are +1, result is +1
```
Ternary OR truth table:
```
  If either input is +1, result is +1
  If either input is 0, result is 0
  If both inputs are -1, result is -1
```

TeaScript's **COMPILER** (tcc)

Compiles .tea source files into .tbin bytecode files that the VM can execute
with "run".

Source format: one instruction per line. Labels are written as "name:" on
their own line. Comments start with ";". Supported instructions:
```
  LOAD Tn value
  ADD Tn Tm
  SUB Tn Tm
  MUL Tn Tm
  NEG Tn
  OUT Tn
  TAND Tn Tm
  TOR Tn Tm
  STORE Tn address
  LDMEM Tn address
  CMP Tn Tm
  JMP label
  JEQ label            Jump if last CMP was equal
  JGT label            Jump if last CMP was greater
  JLT label            Jump if last CMP was less
  HALT
  NOP
```
Bytecode format: 2-byte header "TB" followed by 3 bytes per instruction
(opcode, operand A, operand B). Up to 16 labels and 512 bytes of code.
Execution stops after 10000 instructions to prevent infinite loops.

Example .tea file:
```
  LOAD T0 1
  LOAD T1 10
  loop:
  ADD T0 T0
  CMP T0 T1
  JLT loop
  OUT T0
  HALT
```

X86 ASSEMBLER (asm)

It's my favoret programming language so we gotta include it some how. This assembles .asm source files into .bin native x86 machine code. The binary
is copied to an aligned execution buffer and called as a function. The
return value in eax is printed.

Labels and fixups work the same way as in the TeaScript compiler. Comments
start with ";".

Supported instructions:
```
  mov reg, reg          Register to register
  mov reg, imm32        Immediate to register
  add reg, reg/imm32
  sub reg, reg/imm32
  xor reg, reg/imm32
  and reg, reg/imm32
  or  reg, reg/imm32
  cmp reg, reg/imm32
  inc reg
  dec reg
  push reg
  pop reg
  jmp label
  call label
  je/jz label
  jne/jnz label
  jl label
  jle label
  jg label
  jge label
  int imm8
  nop
  hlt
  ret
```
Registers: eax, ecx, edx, ebx, esp, ebp, esi, edi

The assembled code must end with "ret" to return control to the kernel.
Maximum binary size is 1024 bytes.

Example .asm file:
```
  mov eax, 0
  mov ecx, 10
  loop:
  add eax, ecx
  dec ecx
  cmp ecx, 0
  jg loop
  ret
```

How do i run bianaries? "run <file>" checks the first two bytes. If they are "TB", the file is
treated as TeaScript bytecode and run on the TVM. Otherwise, the file is
treated as native x86 machine code, copied to an executable buffer, and
called. (Even though the text editor supports the C syntax i never added a C compiler.)


The network stack builds correctly formatted Ethernet, ARP, IPv4, and ICMP packets.
There is no NIC driver, so packets are constructed in a 1518-byte buffer
but not transmitted. (I might implement something later for this.)

Default configuration:
```
  MAC       52:54:00:12:34:56
  IP        10.0.0.2
  Netmask   255.255.255.0
  Gateway   10.0.0.1
```
The ARP cache holds 8 entries. The gateway has a static entry by default.
"ping" builds a complete ICMP echo request with correct IP and ICMP
checksums. "arp send" builds a broadcast ARP request. "netdebug" shows the
raw hex of the last constructed packet.


**TEAOS MEMORY MAP**
```
  0x00007C00            Bootloader (512 bytes)
  0x00020000            Kernel load address
  0x00090000            Stack top (grows downward)
  0x000B8000            VGA text memory (4000 bytes)
  0x00100000            Heap start (2 MB)
  0x00400000            XFCE preload base (reserved, 8 MB)
```
The heap uses a linked-list allocator with first-fit. Free blocks are
coalesced on deallocation. The filesystem's 32 file entries with 4 KB of
data each account for about 132 KB of static memory.



TeaOS has three color schemes that change the status bar, accent colors, and UI elements:
```
  orange    Black background, white text, orange accents (default)
  blue      Black background, white text, blue accents
  green     Black background, white text, green accents
```
---

BUILDING

Requirements: gcc (with 32-bit support), nasm, ld, objcopy, qemu-system-i386
```
  make              Build os.img
  make run          Build and launch in QEMU
  make clean        Remove build artifacts
```
The Makefile compiles each .c file to a 32-bit freestanding object, links
them with a custom linker script, extracts the raw binary, and concatenates
it with the bootloader into a disk image. The image is padded to 33 MB for
QEMU's default hard disk geometry.

---

LIMITS

  1. Kernel binary          ~73 KB (max ~74 KB before bootloader needs changes)
  2. Files                  32 total
  3. File size              4096 bytes each
  4. Filename length        32 characters
  5. Editor lines           100
  6. Editor line length     78 characters
  7. Command input          64 characters
  8. Command history        10 entries
  9. TeaScript labels       16 per compilation
  10. TeaScript code         512 bytes per compilation
  11. Native binary          1024 bytes
  12. Scrollback             100 lines
  13. ARP cache              8 entries
  14. Packet buffer          1518 bytes
  15. Virtual terminals      6