#include "teascript.h"
#include "shell.h"

ternary_vm_t tvm;

trit_t ternary_add(trit_t a, trit_t b) {
    int sum = (int)a + (int)b;
    if (sum > 1) return 1;
    if (sum < -1) return -1;
    return (trit_t)sum;
}

trit_t ternary_mul(trit_t a, trit_t b) {
    return (trit_t)((int)a * (int)b);
}

trit_t ternary_neg(trit_t a) {
    return (trit_t)(-((int)a));
}

trit_t ternary_and(trit_t a, trit_t b) {
    if (a == -1 || b == -1) return -1;
    if (a == 0 || b == 0) return 0;
    return 1;
}

trit_t ternary_or(trit_t a, trit_t b) {
    if (a == 1 || b == 1) return 1;
    if (a == 0 || b == 0) return 0;
    return -1;
}

void tvm_init(void) {
    for (int i = 0; i < 8; i++) tvm.regs[i] = 0;
    for (int i = 0; i < 256; i++) tvm.memory[i] = 0;
    tvm.pc = 0;
    tvm.running = 0;
    tvm.cmp_result = 0;
}

void tvm_show_regs(void) {
    shell_print(2, "=== Ternary Registers ===", COLOR_TITLE);
    for (int i = 0; i < 4; i++) {
        char line[80];
        line[0] = ' ';
        line[1] = ' ';
        line[2] = 'T';
        line[3] = '0' + i;
        line[4] = ':';
        line[5] = ' ';

        int val = tvm.regs[i];
        int j = 6;
        if (val < 0) {
            line[j++] = '-';
            val = -val;
        } else if (val > 0) {
            line[j++] = '+';
        } else {
            line[j++] = ' ';
        }

        line[j++] = '0' + (val / 10);
        line[j++] = '0' + (val % 10);
        line[j++] = ' ';
        line[j++] = ' ';
        line[j++] = '|';
        line[j++] = ' ';
        line[j++] = ' ';
        line[j++] = 'T';
        line[j++] = '0' + (i + 4);
        line[j++] = ':';
        line[j++] = ' ';

        val = tvm.regs[i + 4];
        if (val < 0) {
            line[j++] = '-';
            val = -val;
        } else if (val > 0) {
            line[j++] = '+';
        } else {
            line[j++] = ' ';
        }

        line[j++] = '0' + (val / 10);
        line[j++] = '0' + (val % 10);
        line[j] = 0;

        shell_print(4 + i, line, COLOR_FG);
    }
    shell_print(9, "PC (Program Counter): 0", COLOR_ACCENT);
    shell_print(10, "Use 'teas help' for TeaScript commands", COLOR_BORDER);
}

void tvm_execute(const char *cmd) {
    while (*cmd == ' ') cmd++;

    if (cmd[0] == 'L' && cmd[1] == 'O' && cmd[2] == 'A' && cmd[3] == 'D') {
        cmd += 4;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            int val = 0;
            int neg = 0;
            if (*cmd == '-') { neg = 1; cmd++; }
            while (*cmd >= '0' && *cmd <= '9') {
                val = val * 10 + (*cmd - '0');
                cmd++;
            }
            if (neg) val = -val;
            if (reg >= 0 && reg < 8) {
                tvm.regs[reg] = val;
                shell_print(2, "LOAD OK - type 'tregs' to see registers", COLOR_SUCCESS);
            } else {
                shell_print(2, "Error: Invalid register (use T0-T7)", COLOR_ERROR);
            }
        }
    } else if (cmd[0] == 'A' && cmd[1] == 'D' && cmd[2] == 'D') {
        cmd += 3;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg1 = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            if (*cmd == 'T') {
                cmd++;
                int reg2 = *cmd - '0';
                if (reg1 >= 0 && reg1 < 8 && reg2 >= 0 && reg2 < 8) {
                    tvm.regs[reg1] += tvm.regs[reg2];
                    shell_print(2, "ADD OK - type 'tregs' to see result", COLOR_SUCCESS);
                }
            }
        }
    } else if (cmd[0] == 'M' && cmd[1] == 'U' && cmd[2] == 'L') {
        cmd += 3;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg1 = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            if (*cmd == 'T') {
                cmd++;
                int reg2 = *cmd - '0';
                if (reg1 >= 0 && reg1 < 8 && reg2 >= 0 && reg2 < 8) {
                    tvm.regs[reg1] *= tvm.regs[reg2];
                    shell_print(2, "MUL OK - type 'tregs' to see result", COLOR_SUCCESS);
                }
            }
        }
    } else if (cmd[0] == 'N' && cmd[1] == 'E' && cmd[2] == 'G') {
        cmd += 3;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg = *cmd - '0';
            if (reg >= 0 && reg < 8) {
                tvm.regs[reg] = -tvm.regs[reg];
                shell_print(2, "NEG OK - type 'tregs' to see result", COLOR_SUCCESS);
            }
        }
    } else if (cmd[0] == 'O' && cmd[1] == 'U' && cmd[2] == 'T') {
        cmd += 3;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg = *cmd - '0';
            if (reg >= 0 && reg < 8) {
                char out[80];
                out[0] = 'T';
                out[1] = '0' + reg;
                out[2] = ' ';
                out[3] = '=';
                out[4] = ' ';
                int val = tvm.regs[reg];
                int i = 5;
                if (val < 0) {
                    out[i++] = '-';
                    val = -val;
                } else if (val > 0) {
                    out[i++] = '+';
                } else {
                    out[i++] = ' ';
                }
                if (val >= 100) {
                    out[i++] = '0' + (val / 100);
                    val %= 100;
                }
                out[i++] = '0' + (val / 10);
                out[i++] = '0' + (val % 10);
                out[i] = 0;
                shell_print(2, out, COLOR_ACCENT);
            }
        }
    } else if (cmd[0] == 'T' && cmd[1] == 'A' && cmd[2] == 'N' && cmd[3] == 'D') {
        cmd += 4;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg1 = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            if (*cmd == 'T') {
                cmd++;
                int reg2 = *cmd - '0';
                if (reg1 >= 0 && reg1 < 8 && reg2 >= 0 && reg2 < 8) {
                    trit_t a = (trit_t)(tvm.regs[reg1] > 0 ? 1 : (tvm.regs[reg1] < 0 ? -1 : 0));
                    trit_t b = (trit_t)(tvm.regs[reg2] > 0 ? 1 : (tvm.regs[reg2] < 0 ? -1 : 0));
                    tvm.regs[reg1] = ternary_and(a, b);
                    shell_print(2, "TAND OK - type 'tregs' to see result", COLOR_SUCCESS);
                }
            }
        }
    } else if (cmd[0] == 'T' && cmd[1] == 'O' && cmd[2] == 'R') {
        cmd += 3;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg1 = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            if (*cmd == 'T') {
                cmd++;
                int reg2 = *cmd - '0';
                if (reg1 >= 0 && reg1 < 8 && reg2 >= 0 && reg2 < 8) {
                    trit_t a = (trit_t)(tvm.regs[reg1] > 0 ? 1 : (tvm.regs[reg1] < 0 ? -1 : 0));
                    trit_t b = (trit_t)(tvm.regs[reg2] > 0 ? 1 : (tvm.regs[reg2] < 0 ? -1 : 0));
                    tvm.regs[reg1] = ternary_or(a, b);
                    shell_print(2, "TOR OK - type 'tregs' to see result", COLOR_SUCCESS);
                }
            }
        }
    } else if (cmd[0] == 'S' && cmd[1] == 'T' && cmd[2] == 'O' && cmd[3] == 'R' && cmd[4] == 'E') {
        cmd += 5;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            int addr = 0;
            while (*cmd >= '0' && *cmd <= '9') {
                addr = addr * 10 + (*cmd - '0');
                cmd++;
            }
            if (reg >= 0 && reg < 8 && addr >= 0 && addr < 256) {
                tvm.memory[addr] = tvm.regs[reg];
                shell_print(2, "STORE OK - value saved to memory", COLOR_SUCCESS);
            } else {
                shell_print(2, "Error: Invalid register or address", COLOR_ERROR);
            }
        }
    } else if (cmd[0] == 'L' && cmd[1] == 'D' && cmd[2] == 'M' && cmd[3] == 'E' && cmd[4] == 'M') {
        cmd += 5;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            int addr = 0;
            while (*cmd >= '0' && *cmd <= '9') {
                addr = addr * 10 + (*cmd - '0');
                cmd++;
            }
            if (reg >= 0 && reg < 8 && addr >= 0 && addr < 256) {
                tvm.regs[reg] = tvm.memory[addr];
                shell_print(2, "LDMEM OK - type 'tregs' to see registers", COLOR_SUCCESS);
            } else {
                shell_print(2, "Error: Invalid register or address", COLOR_ERROR);
            }
        }
    } else if (cmd[0] == 'C' && cmd[1] == 'M' && cmd[2] == 'P') {
        cmd += 3;
        while (*cmd == ' ') cmd++;
        if (*cmd == 'T') {
            cmd++;
            int reg1 = *cmd - '0';
            cmd++;
            while (*cmd == ' ') cmd++;
            if (*cmd == 'T') {
                cmd++;
                int reg2 = *cmd - '0';
                if (reg1 >= 0 && reg1 < 8 && reg2 >= 0 && reg2 < 8) {
                    int diff = tvm.regs[reg1] - tvm.regs[reg2];
                    tvm.cmp_result = diff > 0 ? 1 : (diff < 0 ? -1 : 0);
                    char out[80];
                    shell_strcopy(out, "CMP OK - result: ");
                    if (diff == 0) shell_strcopy(out + 17, "equal (0)");
                    else if (diff > 0) shell_strcopy(out + 17, "positive (+1)");
                    else shell_strcopy(out + 17, "negative (-1)");
                    shell_print(2, out, COLOR_SUCCESS);
                }
            }
        }
    } else {
        shell_print(2, "Unknown instruction. Type 'teas help' for commands", COLOR_ERROR);
    }
}

void tvm_show_doc(int page) {
    if (page == 0) {
        shell_print(2, "=== TeaScript Documentation Index ===", COLOR_TITLE);
        shell_print(4, " Page 0: Index (you are here)", COLOR_ACCENT);
        shell_print(5, " Page 1: Basic Instructions (LOAD, ADD, MUL, NEG, OUT)", COLOR_FG);
        shell_print(6, " Page 2: Logic Instructions (TAND, TOR)", COLOR_FG);
        shell_print(7, " Page 3: Comparison (CMP)", COLOR_FG);
        shell_print(8, " Page 4: Memory Operations (STORE, LDMEM)", COLOR_FG);
        shell_print(9, " Page 5: System Commands (peek, poke, dump, port)", COLOR_FG);
        shell_print(11, " Usage: teas -doc -N  (where N = page number 0-5)", COLOR_BORDER);
        shell_print(12, "        teas <instruction>  (to execute)", COLOR_BORDER);
        shell_print(14, " Example: teas -doc -1  (view page 1)", COLOR_SUCCESS);
    } else if (page == 1) {
        shell_print(2, "=== TeaScript Page 1: Basic Instructions ===", COLOR_TITLE);
        shell_print(4, " Ternary Computing: -1 (negative) | 0 (neutral) | +1 (positive)", COLOR_ACCENT);
        shell_print(6, " LOAD Tn val   - Load value into register Tn", COLOR_FG);
        shell_print(7, " ADD  Tn Tm    - Tn = Tn + Tm (ternary add)", COLOR_FG);
        shell_print(8, " SUB  Tn Tm    - Tn = Tn - Tm (ternary subtract)", COLOR_FG);
        shell_print(9, " MUL  Tn Tm    - Tn = Tn * Tm (ternary multiply)", COLOR_FG);
        shell_print(10, " NEG  Tn       - Negate register Tn", COLOR_FG);
        shell_print(11, " OUT  Tn       - Output register Tn value", COLOR_FG);
        shell_print(13, " Example: teas LOAD T0 5", COLOR_BORDER);
        shell_print(14, "          teas LOAD T1 3", COLOR_BORDER);
        shell_print(15, "          teas ADD T0 T1", COLOR_BORDER);
        shell_print(16, "          teas OUT T0     (shows T0 = +08)", COLOR_BORDER);
    } else if (page == 2) {
        shell_print(2, "=== TeaScript Page 2: Logic Instructions ===", COLOR_TITLE);
        shell_print(4, " Ternary logic uses three states: -1, 0, +1", COLOR_ACCENT);
        shell_print(6, " TAND Tn Tm    - Ternary AND operation", COLOR_FG);
        shell_print(7, "                 Returns -1 if either is -1", COLOR_FG);
        shell_print(8, "                 Returns  0 if either is  0", COLOR_FG);
        shell_print(9, "                 Returns +1 if both are  +1", COLOR_FG);
        shell_print(11, " TOR  Tn Tm    - Ternary OR operation", COLOR_FG);
        shell_print(12, "                 Returns +1 if either is +1", COLOR_FG);
        shell_print(13, "                 Returns  0 if either is  0", COLOR_FG);
        shell_print(14, "                 Returns -1 if both are  -1", COLOR_FG);
        shell_print(16, " Example: teas LOAD T0 1", COLOR_BORDER);
        shell_print(17, "          teas LOAD T1 -1", COLOR_BORDER);
        shell_print(18, "          teas TAND T0 T1  (result: -1)", COLOR_BORDER);
    } else if (page == 3) {
        shell_print(2, "=== TeaScript Page 3: Comparison ===", COLOR_TITLE);
        shell_print(4, " Comparison instruction:", COLOR_ACCENT);
        shell_print(6, " CMP  Tn Tm    - Compare registers Tn and Tm", COLOR_FG);
        shell_print(7, "                 Sets comparison result:", COLOR_FG);
        shell_print(8, "                   +1 if Tn > Tm (positive)", COLOR_FG);
        shell_print(9, "                    0 if Tn = Tm (equal)", COLOR_FG);
        shell_print(10, "                   -1 if Tn < Tm (negative)", COLOR_FG);
        shell_print(12, " Example: teas LOAD T0 5", COLOR_BORDER);
        shell_print(13, "          teas LOAD T1 3", COLOR_BORDER);
        shell_print(14, "          teas CMP T0 T1  (result: positive)", COLOR_BORDER);
        shell_print(16, " Use 'teas' to return to index", COLOR_BORDER);
    } else if (page == 4) {
        shell_print(2, "=== TeaScript Page 4: Memory Operations ===", COLOR_TITLE);
        shell_print(4, " VM Memory: 256 ternary locations (0-255)", COLOR_ACCENT);
        shell_print(6, " STORE Tn addr - Store register Tn to memory address", COLOR_FG);
        shell_print(7, " LDMEM Tn addr - Load memory address into Tn", COLOR_FG);
        shell_print(9, " Example: teas LOAD T0 42", COLOR_BORDER);
        shell_print(10, "          teas STORE T0 10  (save to mem[10])", COLOR_BORDER);
        shell_print(11, "          teas LOAD T1 0", COLOR_BORDER);
        shell_print(12, "          teas LDMEM T1 10  (load from mem[10])", COLOR_BORDER);
        shell_print(13, "          teas OUT T1       (shows 42)", COLOR_BORDER);
        shell_print(15, " Use 'teas' to return to index", COLOR_BORDER);
    } else if (page == 5) {
        shell_print(2, "=== TeaScript Page 5: System Commands ===", COLOR_TITLE);
        shell_print(4, " Hardware interaction commands:", COLOR_ACCENT);
        shell_print(6, " peek <addr>       - Read byte from memory address", COLOR_FG);
        shell_print(7, " poke <addr> <val> - Write byte to memory address", COLOR_FG);
        shell_print(8, " dump <addr> <len> - Hex dump memory region", COLOR_FG);
        shell_print(9, " inb <port>        - Read byte from I/O port", COLOR_FG);
        shell_print(10, " outb <port> <val> - Write byte to I/O port", COLOR_FG);
        shell_print(12, " Example: peek 0xB8000  (read VGA memory)", COLOR_BORDER);
        shell_print(13, "          inb 0x60      (read keyboard port)", COLOR_BORDER);
        shell_print(15, " Use 'teas' to return to index", COLOR_BORDER);
    }
}