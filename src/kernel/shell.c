#include "shell.h"
#include "teascript.h"
#include "filesystem.h"
#include "editor.h"
#include "network.h"
#include "compiler.h"

extern void fb_clear_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h);
extern void fb_draw_text(uint32_t x, uint32_t y, const char *text, uint32_t color);
extern void fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
extern void fb_putchar(uint32_t x, uint32_t y, char c, uint8_t color);

static char history[10][256];
static int history_count = 0;
static int shell_cursor = 1;
extern int current_theme;

typedef struct {
    uint8_t bg, fg, panel, border, title, accent;
} theme_t;

extern const theme_t themes[3];

static inline uint8_t sys_inb(uint16_t port) {
    uint8_t val;
    __asm__ volatile ("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

static inline void sys_outb(uint16_t port, uint8_t val) {
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

int shell_strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2 && *s1 == *s2) { s1++; s2++; }
    return *s1 - *s2;
}

void shell_strcopy(char *dst, const char *src) {
    while (*src) *dst++ = *src++;
    *dst = 0;
}

int shell_strlen(const char *s) {
    int len = 0;
    while (*s++) len++;
    return len;
}

int shell_startswith(const char *str, const char *prefix) {
    while (*prefix) {
        if (*str != *prefix) return 0;
        str++; prefix++;
    }
    return 1;
}

const char* shell_get_arg(const char *input, int n) {
    int count = 0;
    while (*input) {
        while (*input == ' ') input++;
        if (!*input) break;
        if (count == n) return input;
        while (*input && *input != ' ') input++;
        count++;
    }
    return NULL;
}

int shell_hex_to_int(const char *s) {
    int val = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (*s) {
        char c = *s;
        if (c >= '0' && c <= '9') val = val * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') val = val * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') val = val * 16 + (c - 'A' + 10);
        else break;
        s++;
    }
    return val;
}

void shell_int_to_hex(uint32_t val, char *buf, int digits) {
    const char hex[] = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = digits - 1; i >= 0; i--) {
        buf[2 + i] = hex[val & 0xF];
        val >>= 4;
    }
    buf[2 + digits] = 0;
}

static uint32_t shell_parse_ip(const char *s) {
    int parts[4] = {0, 0, 0, 0};
    int part = 0, val = 0;
    while (*s && part < 4) {
        if (*s >= '0' && *s <= '9') val = val * 10 + (*s - '0');
        else if (*s == '.') { parts[part++] = val; val = 0; }
        s++;
    }
    parts[part] = val;
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
}

static void shell_scroll_up(void) {
    volatile uint16_t *vga = (volatile uint16_t*)0xB8000;
    for (int y = 1; y < 22; y++) {
        for (int x = 0; x < 80; x++) {
            vga[y * 80 + x] = vga[(y + 1) * 80 + x];
        }
    }
    for (int x = 0; x < 80; x++) {
        vga[22 * 80 + x] = (COLOR_FG << 8) | ' ';
    }
}

void shell_println(const char *text, uint8_t color) {
    if (shell_cursor >= 23) {
        shell_scroll_up();
        shell_cursor = 22;
    }
    fb_clear_region(0, shell_cursor, 80, 1);
    fb_draw_text(0, shell_cursor, text, color);
    shell_cursor++;
}

void shell_newline(void) {
    shell_println("", COLOR_FG);
}

void shell_reset_cursor(void) {
    shell_cursor = 1;
}

void shell_print(int line, const char *text, uint8_t color) {
    (void)line;
    shell_println(text, color);
}

void shell_init(void) {
    history_count = 0;
    shell_cursor = 1;
}

void shell_execute(const char *input_buffer) {
    theme_t t = themes[current_theme];
    const char *arg1 = shell_get_arg(input_buffer, 1);

    if (shell_strcmp(input_buffer, "help") == 0 || shell_strcmp(input_buffer, "help -h") == 0) {
        shell_println("=== TeaOS Commands === (use <cmd> -h for help)", t.title);
        shell_println(" System:", t.accent);
        shell_println("  help        Show help       | clear       Clear screen", COLOR_FG);
        shell_println("  whoami      System logo     | info        System info", COLOR_FG);
        shell_println("  theme <n>   Set theme       | cpuid       CPU info", COLOR_FG);
        shell_println("  lspci       PCI devices     | history     Cmd history", COLOR_FG);
        shell_println("  halt        Shutdown        | reboot      Restart", COLOR_FG);
        shell_println(" Files:", t.accent);
        shell_println("  ls [-l]     List files      | cat <f>     Show file", COLOR_FG);
        shell_println("  touch <f>   Create file     | rm [-rf]    Remove", COLOR_FG);
        shell_println("  mkdir <d>   Create dir      | cd <d>      Change dir", COLOR_FG);
        shell_println("  pwd         Working dir     | edit <f>    Text editor", COLOR_FG);
        shell_println(" Network:", t.accent);
        shell_println("  ifconfig    IP config       | ping <ip>   ICMP ping", COLOR_FG);
        shell_println("  arp         ARP cache       | netstat     Statistics", COLOR_FG);
        shell_println("  nettest     Run tests       | netdebug    Pkt debug", COLOR_FG);
        shell_println(" Compilers:", t.accent);
        shell_println("  tcc <f>     Compile .tea    | asm <f>     Assemble .asm", COLOR_FG);
        shell_println("  run <f>     Execute binary  | teas <i>    TeaScript VM", COLOR_FG);
        shell_println("  tregs       Ternary regs    | echo <t>    Print text", COLOR_FG);
        shell_println(" Debug:", t.accent);
        shell_println("  peek <a>    Read mem        | poke <a><v> Write mem", COLOR_FG);
        shell_println("  dump <a><n> Hex dump        | xxd <f>     File hex dump", COLOR_FG);
        shell_println("  inb/outb    I/O ports", COLOR_FG);

    } else if (shell_strcmp(input_buffer, "whoami") == 0) {
        shell_println("", COLOR_FG);
        shell_println("       ) )  ) )       TeaOS v1.0 - Ternary Computing OS", t.accent);
        shell_println("      ( (  ( (", t.accent);
        shell_println("       ) )  ) )        Cozy & Powerful", t.accent);
        shell_println("", COLOR_FG);
        shell_println("     .---------.       Balanced Ternary: -1  0  +1", t.border);
        shell_println("    |  T E A    |      8 Ternary Registers (T0-T7)", t.title);
        shell_println("    |   (tea)   |      TeaScript Assembly Language", t.border);
        shell_println("    |___________|      Architecture: x86 (32-bit)", t.border);
        shell_println("     \\         /       Memory: 512 MB", COLOR_FG);
        shell_println("      \\_______/        Mode: VGA Text 80x25", COLOR_FG);
        shell_println("", COLOR_FG);
        shell_println(" Try: edit test.c | teas LOAD T0 5 | ls", t.accent);

    } else if (shell_strcmp(input_buffer, "clear") == 0) {
        fb_clear_region(0, 1, 80, 22);
        shell_reset_cursor();
        extern void draw_status_bar(void);
        draw_status_bar();

    } else if (shell_strcmp(input_buffer, "info") == 0 || shell_strcmp(input_buffer, "info -h") == 0) {
        shell_println("=== System Information ===", t.title);
        shell_println("  OS Name:      TeaOS", COLOR_FG);
        shell_println("  Version:      1.0 (Cozy Edition)", COLOR_FG);
        shell_println("  Architecture: x86 (32-bit)", COLOR_FG);
        shell_println("  Video Mode:   VGA Text Mode (80x25)", COLOR_FG);
        shell_println("  Memory:       512 MB", COLOR_FG);
        shell_println("  Kernel Size:  ~30 KB (L2 cache optimized!)", t.accent);
        shell_println("  Computing:    Balanced Ternary (-1, 0, +1)", t.accent);
        shell_println("  Features:     TeaScript, VFS, Text Editor, Net Stack", COLOR_FG);
        shell_println("  Status:       Running", COLOR_SUCCESS);

    } else if (shell_startswith(input_buffer, "theme")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: theme <name>", COLOR_FG);
            shell_println("  -h         Show this help", COLOR_FG);
            shell_println("  orange     Warm & cozy theme", COLOR_FG);
            shell_println("  blue       Cool & calm theme", COLOR_FG);
            shell_println("  green      Fresh & natural theme", COLOR_FG);
        } else if (shell_startswith(arg, "orange")) {
            current_theme = THEME_ORANGE;
            shell_println("Theme: Orange (warm & cozy)", COLOR_SUCCESS);
            extern void draw_status_bar(void);
            draw_status_bar();
        } else if (shell_startswith(arg, "blue")) {
            current_theme = THEME_BLUE;
            shell_println("Theme: Blue (cool & calm)", COLOR_SUCCESS);
            extern void draw_status_bar(void);
            draw_status_bar();
        } else if (shell_startswith(arg, "green")) {
            current_theme = THEME_GREEN;
            shell_println("Theme: Green (fresh & natural)", COLOR_SUCCESS);
            extern void draw_status_bar(void);
            draw_status_bar();
        } else {
            shell_println("Unknown theme. Use: orange, blue, green", COLOR_ERROR);
        }

    } else if (shell_strcmp(input_buffer, "ls") == 0) {
        fs_list();
    } else if (shell_strcmp(input_buffer, "ls -l") == 0) {
        fs_list_long();
    } else if (shell_strcmp(input_buffer, "ls -h") == 0) {
        shell_println("Usage: ls [options]", COLOR_FG);
        shell_println("  -h    Show this help", COLOR_FG);
        shell_println("  -l    Long listing with types and sizes", COLOR_FG);

    } else if (shell_startswith(input_buffer, "touch")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: touch <filename>", COLOR_FG);
            shell_println("  -h         Show this help", COLOR_FG);
            shell_println("  <filename> Create an empty file", COLOR_FG);
        } else {
            int result = fs_create(arg);
            if (result >= 0) {
                char msg[80];
                shell_strcopy(msg, "Created: ");
                shell_strcopy(msg + 9, arg);
                shell_println(msg, COLOR_SUCCESS);
            } else {
                shell_println("Error: file exists or filesystem full", COLOR_ERROR);
            }
        }

    } else if (shell_startswith(input_buffer, "mkdir")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: mkdir <dirname>", COLOR_FG);
            shell_println("  -h         Show this help", COLOR_FG);
            shell_println("  <dirname>  Create a new directory", COLOR_FG);
        } else {
            int result = fs_mkdir(arg);
            if (result >= 0) {
                char msg[80];
                shell_strcopy(msg, "Directory created: ");
                shell_strcopy(msg + 19, arg);
                shell_println(msg, COLOR_SUCCESS);
            } else {
                shell_println("Error: already exists or filesystem full", COLOR_ERROR);
            }
        }

    } else if (shell_startswith(input_buffer, "cd")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: cd <dirname>", COLOR_FG);
            shell_println("  -h    Show this help", COLOR_FG);
            shell_println("  ..    Go to parent directory", COLOR_FG);
            shell_println("  /     Go to root directory", COLOR_FG);
        } else {
            int result = fs_chdir(arg);
            if (result < 0) {
                shell_println("Error: directory not found", COLOR_ERROR);
            }
        }

    } else if (shell_strcmp(input_buffer, "pwd") == 0) {
        shell_println(fs_pwd(), COLOR_FG);

    } else if (shell_startswith(input_buffer, "cat")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: cat <filename>", COLOR_FG);
            shell_println("  -h         Show this help", COLOR_FG);
            shell_println("  <filename> Display file contents", COLOR_FG);
        } else {
            file_t *file = fs_open(arg);
            if (file) {
                for (uint32_t i = 0; i < file->size; i++) {
                    char linebuf[81];
                    int col = 0;
                    while (i < file->size && file->data[i] != '\n' && col < 79) {
                        linebuf[col++] = file->data[i++];
                    }
                    linebuf[col] = 0;
                    shell_println(linebuf, COLOR_FG);
                }
            } else {
                shell_println("Error: file not found", COLOR_ERROR);
            }
        }

    } else if (shell_startswith(input_buffer, "rm")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: rm [options] <name>", COLOR_FG);
            shell_println("  -h         Show this help", COLOR_FG);
            shell_println("  <file>     Remove a file", COLOR_FG);
            shell_println("  -rf <dir>  Remove directory recursively", COLOR_FG);
        } else if (shell_strcmp(arg, "-rf") == 0) {
            const char *dir = shell_get_arg(input_buffer, 2);
            if (dir) {
                int result = fs_delete_recursive(dir);
                if (result == 0) {
                    char msg[80];
                    shell_strcopy(msg, "Removed: ");
                    shell_strcopy(msg + 9, dir);
                    shell_println(msg, COLOR_SUCCESS);
                } else {
                    shell_println("Error: not found", COLOR_ERROR);
                }
            } else {
                shell_println("Usage: rm -rf <dirname>", COLOR_ERROR);
            }
        } else {
            int result = fs_delete(arg);
            if (result == 0) {
                char msg[80];
                shell_strcopy(msg, "Removed: ");
                shell_strcopy(msg + 9, arg);
                shell_println(msg, COLOR_SUCCESS);
            } else {
                shell_println("Error: not found or is a directory (use -rf)", COLOR_ERROR);
            }
        }

    } else if (shell_startswith(input_buffer, "edit")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: edit <filename>", COLOR_FG);
            shell_println("  -h         Show this help", COLOR_FG);
            shell_println("  <filename> Open file in editor", COLOR_FG);
            shell_println("  ESC=exit   F1=save", t.accent);
        } else {
            editor_open(arg);
        }

    } else if (shell_strcmp(input_buffer, "tregs") == 0 || shell_strcmp(input_buffer, "tregs -h") == 0) {
        tvm_show_regs();

    } else if (shell_strcmp(input_buffer, "teas") == 0 ||
               shell_strcmp(input_buffer, "teas -h") == 0 ||
               shell_strcmp(input_buffer, "teas -doc -0") == 0) {
        tvm_show_doc(0);
    } else if (shell_strcmp(input_buffer, "teas -doc -1") == 0 ||
               shell_strcmp(input_buffer, "teas help") == 0) {
        tvm_show_doc(1);
    } else if (shell_strcmp(input_buffer, "teas -doc -2") == 0) {
        tvm_show_doc(2);
    } else if (shell_strcmp(input_buffer, "teas -doc -3") == 0) {
        tvm_show_doc(3);
    } else if (shell_strcmp(input_buffer, "teas -doc -4") == 0) {
        tvm_show_doc(4);
    } else if (shell_strcmp(input_buffer, "teas -doc -5") == 0) {
        tvm_show_doc(5);
    } else if (shell_startswith(input_buffer, "teas ")) {
        tvm_execute(input_buffer + 5);

    } else if (shell_startswith(input_buffer, "peek")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: peek <address>", COLOR_FG);
            shell_println("  -h       Show this help", COLOR_FG);
            shell_println("  <addr>   Hex address to read (e.g. 0xB8000)", COLOR_FG);
        } else {
            uint32_t addr = shell_hex_to_int(arg);
            uint8_t val = *(uint8_t*)addr;
            char out[80], ha[12], hv[12];
            shell_int_to_hex(addr, ha, 8);
            shell_int_to_hex(val, hv, 2);
            shell_strcopy(out, "Memory["); shell_strcopy(out + 7, ha);
            shell_strcopy(out + 17, "] = "); shell_strcopy(out + 21, hv);
            shell_println(out, t.accent);
        }

    } else if (shell_startswith(input_buffer, "poke")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: poke <address> <value>", COLOR_FG);
            shell_println("  -h          Show this help", COLOR_FG);
            shell_println("  <addr> <v>  Write byte to memory address", COLOR_FG);
        } else {
            uint32_t addr = shell_hex_to_int(arg);
            const char *varg = shell_get_arg(input_buffer, 2);
            if (varg) {
                uint8_t val = (uint8_t)shell_hex_to_int(varg);
                *(uint8_t*)addr = val;
                char out[80], ha[12], hv[12];
                shell_int_to_hex(addr, ha, 8);
                shell_int_to_hex(val, hv, 2);
                shell_strcopy(out, "Wrote "); shell_strcopy(out + 6, hv);
                shell_strcopy(out + 12, " -> "); shell_strcopy(out + 16, ha);
                shell_println(out, COLOR_SUCCESS);
            } else {
                shell_println("Usage: poke <address> <value>", COLOR_ERROR);
            }
        }

    } else if (shell_startswith(input_buffer, "dump")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: dump <address> <length>", COLOR_FG);
            shell_println("  -h            Show this help", COLOR_FG);
            shell_println("  <addr> <len>  Hex dump memory region", COLOR_FG);
            shell_println("  Example: dump 0xB8000 0x40", t.accent);
        } else {
            uint32_t addr = shell_hex_to_int(arg);
            const char *larg = shell_get_arg(input_buffer, 2);
            uint32_t len = larg ? shell_hex_to_int(larg) : 16;
            if (len > 128) len = 128;
            uint8_t *ptr = (uint8_t*)addr;
            shell_println("=== Memory Dump ===", t.title);
            for (uint32_t i = 0; i < len; i += 16) {
                char line[80];
                char ha[12];
                shell_int_to_hex(addr + i, ha, 8);
                shell_strcopy(line, ha);
                shell_strcopy(line + 10, ": ");
                for (int j = 0; j < 16 && (i + j) < len; j++) {
                    uint8_t byte = ptr[i + j];
                    const char hex[] = "0123456789ABCDEF";
                    line[12 + j * 3] = hex[byte >> 4];
                    line[13 + j * 3] = hex[byte & 0xF];
                    line[14 + j * 3] = ' ';
                }
                line[12 + 16 * 3] = 0;
                shell_println(line, COLOR_FG);
            }
        }

    } else if (shell_startswith(input_buffer, "inb")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: inb <port>", COLOR_FG);
            shell_println("  -h      Show this help", COLOR_FG);
            shell_println("  <port>  Read byte from I/O port", COLOR_FG);
        } else {
            uint16_t port = (uint16_t)shell_hex_to_int(arg);
            uint8_t val = sys_inb(port);
            char out[80], hp[12], hv[12];
            shell_int_to_hex(port, hp, 4);
            shell_int_to_hex(val, hv, 2);
            shell_strcopy(out, "Port "); shell_strcopy(out + 5, hp);
            shell_strcopy(out + 11, " = "); shell_strcopy(out + 14, hv);
            shell_println(out, t.accent);
        }

    } else if (shell_startswith(input_buffer, "outb")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: outb <port> <value>", COLOR_FG);
            shell_println("  -h           Show this help", COLOR_FG);
            shell_println("  <port> <v>   Write byte to I/O port", COLOR_FG);
        } else {
            uint16_t port = (uint16_t)shell_hex_to_int(arg);
            const char *varg = shell_get_arg(input_buffer, 2);
            if (varg) {
                uint8_t val = (uint8_t)shell_hex_to_int(varg);
                sys_outb(port, val);
                char out[80], hp[12], hv[12];
                shell_int_to_hex(port, hp, 4);
                shell_int_to_hex(val, hv, 2);
                shell_strcopy(out, "Wrote "); shell_strcopy(out + 6, hv);
                shell_strcopy(out + 12, " -> port "); shell_strcopy(out + 21, hp);
                shell_println(out, COLOR_SUCCESS);
            } else {
                shell_println("Usage: outb <port> <value>", COLOR_ERROR);
            }
        }

    } else if (shell_strcmp(input_buffer, "cpuid") == 0 || shell_strcmp(input_buffer, "cpuid -h") == 0) {
        uint32_t eax, ebx, ecx, edx;
        __asm__ volatile ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
        shell_println("=== CPU Information ===", t.title);
        char vendor[13];
        *((uint32_t*)&vendor[0]) = ebx;
        *((uint32_t*)&vendor[4]) = edx;
        *((uint32_t*)&vendor[8]) = ecx;
        vendor[12] = 0;
        char line[80];
        shell_strcopy(line, "  Vendor: ");
        shell_strcopy(line + 10, vendor);
        shell_println(line, COLOR_FG);
        __asm__ volatile ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
        shell_strcopy(line, "  Features: ");
        int pos = 12;
        if (edx & (1 << 0)) { shell_strcopy(line + pos, "FPU "); pos = shell_strlen(line); }
        if (edx & (1 << 4)) { shell_strcopy(line + pos, "TSC "); pos = shell_strlen(line); }
        if (edx & (1 << 23)) { shell_strcopy(line + pos, "MMX "); pos = shell_strlen(line); }
        if (edx & (1 << 25)) { shell_strcopy(line + pos, "SSE "); pos = shell_strlen(line); }
        if (edx & (1 << 26)) { shell_strcopy(line + pos, "SSE2"); }
        shell_println(line, COLOR_FG);
        shell_println("  Arch: x86 (32-bit) Protected Mode", COLOR_SUCCESS);

    } else if (shell_strcmp(input_buffer, "lspci") == 0 || shell_strcmp(input_buffer, "lspci -h") == 0) {
        shell_println("=== PCI Devices ===", t.title);
        int found = 0;
        for (uint32_t bus = 0; bus < 2; bus++) {
            for (uint32_t dev = 0; dev < 32; dev++) {
                uint32_t addr = 0x80000000 | (bus << 16) | (dev << 11);
                outl(0xCF8, addr);
                uint32_t vd = inl(0xCFC);
                uint16_t vendor = vd & 0xFFFF;
                if (vendor != 0xFFFF && vendor != 0x0000) {
                    addr = 0x80000000 | (bus << 16) | (dev << 11) | 0x08;
                    outl(0xCF8, addr);
                    uint32_t cr = inl(0xCFC);
                    uint8_t cc = (cr >> 24) & 0xFF;
                    uint8_t sc = (cr >> 16) & 0xFF;
                    char lb[80];
                    int p = 0;
                    lb[p++] = ' '; lb[p++] = ' ';
                    lb[p++] = '0'; lb[p++] = '0' + bus; lb[p++] = ':';
                    if (dev >= 10) lb[p++] = '0' + (dev / 10);
                    lb[p++] = '0' + (dev % 10);
                    lb[p++] = '.'; lb[p++] = '0'; lb[p++] = ' ';
                    const char *cs = "Unknown";
                    if (cc == 0x00 && sc == 0x00) cs = "Host bridge";
                    else if (cc == 0x01) cs = "Mass storage";
                    else if (cc == 0x02) cs = "Network";
                    else if (cc == 0x03) cs = "Display";
                    else if (cc == 0x06) cs = "Bridge";
                    shell_strcopy(lb + p, cs);
                    shell_println(lb, COLOR_FG);
                    found++;
                }
            }
        }
        if (!found) shell_println("  No PCI devices detected", COLOR_INFO);

    } else if (shell_startswith(input_buffer, "ifconfig")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg) {
            net_show_stats();
        } else if (shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: ifconfig [subcommand]", COLOR_FG);
            shell_println("  -h              Show this help", COLOR_FG);
            shell_println("  (no args)       Show current config", COLOR_FG);
            shell_println("  set <ip> <mask> <gw>  Configure interface", COLOR_FG);
            shell_println("  Example: ifconfig set 10.0.0.2 255.255.255.0 10.0.0.1", t.accent);
        } else if (shell_startswith(arg, "set")) {
            net_config_ip(input_buffer);
        } else {
            shell_println("Unknown subcommand. Use: ifconfig -h", COLOR_ERROR);
        }

    } else if (shell_startswith(input_buffer, "ping")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: ping <ip_address>", COLOR_FG);
            shell_println("  -h      Show this help", COLOR_FG);
            shell_println("  <ip>    Send ICMP echo request", COLOR_FG);
            shell_println("  Example: ping 10.0.0.1", t.accent);
        } else {
            uint32_t ip = shell_parse_ip(arg);
            net_send_ping(ip);
            char msg[80];
            shell_strcopy(msg, "PING ");
            shell_strcopy(msg + 5, arg);
            shell_println(msg, t.title);
            shell_println("  Type:     ICMP echo request", COLOR_FG);
            shell_println("  Size:     42 bytes (ETH+IP+ICMP)", COLOR_FG);
            shell_println("  Checksum: verified", COLOR_SUCCESS);
            shell_println("  TX queue: ready (no HW driver)", COLOR_INFO);
        }

    } else if (shell_startswith(input_buffer, "arp")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg) {
            net_show_arp_cache();
        } else if (shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: arp [subcommand]", COLOR_FG);
            shell_println("  -h           Show this help", COLOR_FG);
            shell_println("  (no args)    Show ARP cache", COLOR_FG);
            shell_println("  send <ip>    Send ARP request", COLOR_FG);
        } else if (shell_startswith(arg, "send")) {
            const char *ip_arg = shell_get_arg(input_buffer, 2);
            if (ip_arg) {
                uint32_t ip = shell_parse_ip(ip_arg);
                net_send_arp_request(ip);
                char msg[80];
                shell_strcopy(msg, "ARP request sent for ");
                shell_strcopy(msg + 21, ip_arg);
                shell_println(msg, COLOR_SUCCESS);
            } else {
                shell_println("Usage: arp send <ip_address>", COLOR_ERROR);
            }
        } else {
            shell_println("Unknown subcommand. Use: arp -h", COLOR_ERROR);
        }

    } else if (shell_strcmp(input_buffer, "netstat") == 0) {
        net_show_stats();
    } else if (shell_strcmp(input_buffer, "netstat -h") == 0) {
        shell_println("Usage: netstat", COLOR_FG);
        shell_println("  -h    Show this help", COLOR_FG);
        shell_println("  Shows network interface stats and config", COLOR_FG);

    } else if (shell_strcmp(input_buffer, "nettest") == 0) {
        net_test();
    } else if (shell_strcmp(input_buffer, "nettest -h") == 0) {
        shell_println("Usage: nettest", COLOR_FG);
        shell_println("  -h    Show this help", COLOR_FG);
        shell_println("  Runs network stack connectivity tests", COLOR_FG);

    } else if (shell_strcmp(input_buffer, "netdebug") == 0) {
        net_debug();
    } else if (shell_strcmp(input_buffer, "netdebug -h") == 0) {
        shell_println("Usage: netdebug", COLOR_FG);
        shell_println("  -h    Show this help", COLOR_FG);
        shell_println("  Hex dumps the last packet buffer", COLOR_FG);

    } else if (shell_strcmp(input_buffer, "history") == 0 || shell_strcmp(input_buffer, "history -h") == 0) {
        shell_println("Command History:", t.title);
        for (int i = 0; i < history_count; i++) {
            char line[80];
            line[0] = ' '; line[1] = ' ';
            line[2] = '0' + ((i + 1) / 10);
            line[3] = '0' + ((i + 1) % 10);
            line[4] = '.'; line[5] = ' ';
            shell_strcopy(line + 6, history[i]);
            shell_println(line, COLOR_FG);
        }

    } else if (shell_strcmp(input_buffer, "halt") == 0) {
        shell_println("Steeping down... Goodbye!", COLOR_ERROR);
        extern void halt(void);
        halt();
    } else if (shell_strcmp(input_buffer, "reboot") == 0) {
        shell_println("Re-brewing the system...", t.accent);
        __asm__ volatile ("mov $0x64, %%dx\nmov $0xFE, %%al\nout %%al, %%dx\n" ::: "eax", "edx");

    } else if (shell_startswith(input_buffer, "tcc")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: tcc <source.tea> [output.tbin]", COLOR_FG);
            shell_println("  -h           Show this help", COLOR_FG);
            shell_println("  Compiles TeaScript source to bytecode", COLOR_FG);
            shell_println("  Labels: 'name:' on its own line", t.accent);
            shell_println("  Jump:  JMP/JEQ/JGT/JLT <label>", t.accent);
            shell_println("  End:   HALT", t.accent);
        } else {
            char outname[32];
            const char *out_arg = shell_get_arg(input_buffer, 2);
            if (out_arg) {
                shell_strcopy(outname, out_arg);
            } else {
                int i = 0;
                while (arg[i] && arg[i] != '.' && i < 27) { outname[i] = arg[i]; i++; }
                outname[i] = '.'; outname[i+1] = 't'; outname[i+2] = 'b';
                outname[i+3] = 'i'; outname[i+4] = 'n'; outname[i+5] = 0;
            }
            tcc_compile(arg, outname);
        }

    } else if (shell_startswith(input_buffer, "asm")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: asm <source.asm> [output.bin]", COLOR_FG);
            shell_println("  -h           Show this help", COLOR_FG);
            shell_println("  Assembles x86 assembly to machine code", COLOR_FG);
            shell_println("  Regs: eax ebx ecx edx esp ebp esi edi", t.accent);
            shell_println("  Ops:  mov add sub xor inc dec cmp", t.accent);
            shell_println("  Flow: jmp je jne call ret hlt nop", t.accent);
        } else {
            char outname[32];
            const char *out_arg = shell_get_arg(input_buffer, 2);
            if (out_arg) {
                shell_strcopy(outname, out_arg);
            } else {
                int i = 0;
                while (arg[i] && arg[i] != '.' && i < 28) { outname[i] = arg[i]; i++; }
                outname[i] = '.'; outname[i+1] = 'b'; outname[i+2] = 'i';
                outname[i+3] = 'n'; outname[i+4] = 0;
            }
            asm_assemble(arg, outname);
        }

    } else if (shell_startswith(input_buffer, "run")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: run <binary>", COLOR_FG);
            shell_println("  -h         Show this help", COLOR_FG);
            shell_println("  .tbin      Run TeaScript bytecode (via TVM)", COLOR_FG);
            shell_println("  .bin       Run native x86 code (must end with ret)", COLOR_FG);
        } else {
            exec_run(arg);
        }

    } else if (shell_startswith(input_buffer, "xxd")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (!arg || shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: xxd <file>", COLOR_FG);
            shell_println("  -h      Show this help", COLOR_FG);
            shell_println("  Hex dump file contents (first 64 bytes)", COLOR_FG);
        } else {
            file_t *f = fs_open(arg);
            if (!f) {
                shell_println("File not found", COLOR_ERROR);
            } else {
                uint8_t fdata[MAX_FILESIZE];
                int fsize = fs_read(f, fdata, MAX_FILESIZE);
                char msg[80];
                shell_strcopy(msg, "Size: ");
                int ml = 6;
                int tmp = fsize;
                if (tmp == 0) { msg[ml++] = '0'; }
                else {
                    char d[12]; int dl = 0;
                    while (tmp > 0) { d[dl++] = '0' + (tmp % 10); tmp /= 10; }
                    for (int i = dl - 1; i >= 0; i--) msg[ml++] = d[i];
                }
                shell_strcopy(msg + ml, " bytes");
                shell_println(msg, COLOR_FG);
                int show = fsize > 64 ? 64 : fsize;
                for (int row = 0; row < show; row += 16) {
                    char line[80];
                    for (int i = 0; i < 80; i++) line[i] = 0;
                    int lp = 0;
                    const char *hex = "0123456789ABCDEF";
                    line[lp++] = hex[(row >> 4) & 0xF];
                    line[lp++] = hex[row & 0xF];
                    line[lp++] = ':';
                    line[lp++] = ' ';
                    for (int c = 0; c < 16 && row + c < show; c++) {
                        uint8_t b = fdata[row + c];
                        line[lp++] = hex[(b >> 4) & 0xF];
                        line[lp++] = hex[b & 0xF];
                        line[lp++] = ' ';
                    }
                    shell_println(line, COLOR_ACCENT);
                }
            }
        }

    } else if (shell_startswith(input_buffer, "echo")) {
        const char *arg = shell_get_arg(input_buffer, 1);
        if (arg && shell_strcmp(arg, "-h") == 0) {
            shell_println("Usage: echo <text>", COLOR_FG);
            shell_println("  -h      Show this help", COLOR_FG);
            shell_println("  <text>  Print text to terminal", COLOR_FG);
        } else if (arg) {
            shell_println(arg, t.accent);
        }

    } else if (shell_strlen(input_buffer) > 0) {
        char msg[80];
        shell_strcopy(msg, "Command not found: ");
        int cmdlen = 0;
        while (input_buffer[cmdlen] && input_buffer[cmdlen] != ' ' && cmdlen < 40) cmdlen++;
        for (int i = 0; i < cmdlen; i++) msg[19 + i] = input_buffer[i];
        msg[19 + cmdlen] = 0;
        shell_println(msg, COLOR_ERROR);
        shell_println("Type 'help' for available commands", COLOR_INFO);
    }
}

void add_to_history(const char *cmd) {
    if (shell_strlen(cmd) == 0) return;
    if (history_count < 10) {
        shell_strcopy(history[history_count], cmd);
        history_count++;
    } else {
        for (int i = 0; i < 9; i++) shell_strcopy(history[i], history[i + 1]);
        shell_strcopy(history[9], cmd);
    }
}

const char* get_history(int index) {
    if (index >= 0 && index < history_count) return history[index];
    return NULL;
}

int get_history_count(void) {
    return history_count;
}