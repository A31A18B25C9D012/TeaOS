#include "compiler.h"
#include "shell.h"
#include "filesystem.h"
#include "teascript.h"

int asm_debug = 0;

static void skip_ws(const uint8_t *s, int *p, int sz) {
    while (*p < sz && (s[*p] == ' ' || s[*p] == '\t')) (*p)++;
}

static void skip_line(const uint8_t *s, int *p, int sz) {
    while (*p < sz && s[*p] != '\n') (*p)++;
    if (*p < sz) (*p)++;
}

static int read_word(const uint8_t *s, int *p, int sz, char *buf, int bsz) {
    int len = 0;
    while (*p < sz && s[*p] != ' ' && s[*p] != '\t' && s[*p] != '\n' &&
           s[*p] != ',' && s[*p] != ':' && s[*p] != ';' && len < bsz - 1) {
        buf[len++] = s[(*p)++];
    }
    buf[len] = 0;
    return len;
}

static int streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

static int parse_int(const uint8_t *s, int *p, int sz) {
    skip_ws(s, p, sz);
    int neg = 0, val = 0;
    if (*p < sz && s[*p] == '-') { neg = 1; (*p)++; }
    if (*p + 1 < sz && s[*p] == '0' && (s[*p+1] == 'x' || s[*p+1] == 'X')) {
        *p += 2;
        while (*p < sz) {
            char c = s[*p];
            if (c >= '0' && c <= '9') val = val * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') val = val * 16 + (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val = val * 16 + (c - 'A' + 10);
            else break;
            (*p)++;
        }
    } else {
        while (*p < sz && s[*p] >= '0' && s[*p] <= '9') {
            val = val * 10 + (s[*p] - '0');
            (*p)++;
        }
    }
    return neg ? -val : val;
}

static int parse_treg(const uint8_t *s, int *p, int sz) {
    skip_ws(s, p, sz);
    if (*p + 1 < sz && s[*p] == 'T' && s[*p+1] >= '0' && s[*p+1] <= '7') {
        int r = s[*p+1] - '0';
        *p += 2;
        return r;
    }
    return -1;
}

static int parse_x86reg(const uint8_t *s, int *p, int sz) {
    skip_ws(s, p, sz);
    if (*p + 2 < sz && s[*p] == 'e') {
        char a = s[*p+1], b = s[*p+2];
        int r = -1;
        if (a == 'a' && b == 'x') r = 0;
        else if (a == 'c' && b == 'x') r = 1;
        else if (a == 'd' && b == 'x') r = 2;
        else if (a == 'b' && b == 'x') r = 3;
        else if (a == 's' && b == 'p') r = 4;
        else if (a == 'b' && b == 'p') r = 5;
        else if (a == 's' && b == 'i') r = 6;
        else if (a == 'd' && b == 'i') r = 7;
        if (r >= 0) { *p += 3; return r; }
    }
    return -1;
}

/* Parse 16-bit register names: ax,cx,dx,bx,sp,bp,si,di -> 0-7 */
static int parse_reg16(const uint8_t *s, int *p, int sz) {
    skip_ws(s, p, sz);
    if (*p + 1 >= sz) return -1;
    char a = s[*p], b = s[*p+1];
    /* make sure it's not part of a longer identifier */
    int next = *p + 2;
    if (next < sz && ((s[next] >= 'a' && s[next] <= 'z') ||
        (s[next] >= 'A' && s[next] <= 'Z') || (s[next] >= '0' && s[next] <= '9') || s[next] == '_'))
        return -1;
    int r = -1;
    if (a == 'a' && b == 'x') r = 0;
    else if (a == 'c' && b == 'x') r = 1;
    else if (a == 'd' && b == 'x') r = 2;
    else if (a == 'b' && b == 'x') r = 3;
    else if (a == 's' && b == 'p') r = 4;
    else if (a == 'b' && b == 'p') r = 5;
    else if (a == 's' && b == 'i') r = 6;
    else if (a == 'd' && b == 'i') r = 7;
    if (r >= 0) { *p += 2; return r; }
    return -1;
}

static int label_find(char labels[][16], int count, const char *name) {
    for (int i = 0; i < count; i++) {
        if (streq(labels[i], name)) return i;
    }
    return -1;
}

static void int_to_hex(int val, char *buf, int digits) {
    const char *hex = "0123456789ABCDEF";
    for (int i = digits - 1; i >= 0; i--) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }
    buf[digits] = 0;
}

static void int_to_dec(int val, char *buf) {
    if (val < 0) { *buf++ = '-'; val = -val; }
    if (val == 0) { buf[0] = '0'; buf[1] = 0; return; }
    char tmp[12]; int len = 0;
    while (val > 0) { tmp[len++] = '0' + (val % 10); val /= 10; }
    for (int i = 0; i < len; i++) buf[i] = tmp[len-1-i];
    buf[len] = 0;
}

int tcc_compile(const char *src_file, const char *out_file) {
    file_t *src = fs_open(src_file);
    if (!src) {
        shell_println("Error: source file not found", COLOR_ERROR);
        return -1;
    }

    uint8_t source[MAX_FILESIZE];
    int src_size = fs_read(src, source, MAX_FILESIZE);

    char labels[MAX_LABELS][16];
    int label_addr[MAX_LABELS];
    int label_count = 0;

    uint8_t code[MAX_CODE];
    int code_size = 0;

    int pos = 0, instr_count = 0;
    while (pos < src_size) {
        skip_ws(source, &pos, src_size);
        if (pos >= src_size) break;
        if (source[pos] == '\n') { pos++; continue; }
        if (source[pos] == ';') { skip_line(source, &pos, src_size); continue; }

        int start = pos;
        while (pos < src_size && source[pos] != '\n' && source[pos] != ':' &&
               source[pos] != ' ' && source[pos] != '\t' && source[pos] != ';') pos++;

        if (pos < src_size && source[pos] == ':') {
            int len = pos - start;
            if (len > 0 && len < 16 && label_count < MAX_LABELS) {
                for (int i = 0; i < len; i++) labels[label_count][i] = source[start + i];
                labels[label_count][len] = 0;
                label_addr[label_count] = instr_count;
                label_count++;
            }
            pos++;
            continue;
        }
        pos = start;

        char word[16];
        read_word(source, &pos, src_size, word, 16);

        uint8_t op = 0, a = 0, b = 0;

        if (streq(word, "LOAD")) {
            op = TBC_LOAD;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_int(source, &pos, src_size);
        } else if (streq(word, "ADD")) {
            op = TBC_ADD;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "SUB")) {
            op = TBC_SUB;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "MUL")) {
            op = TBC_MUL;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "NEG")) {
            op = TBC_NEG;
            a = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "OUT")) {
            op = TBC_OUT;
            a = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "TAND")) {
            op = TBC_TAND;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "TOR")) {
            op = TBC_TOR;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "STORE")) {
            op = TBC_STORE;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_int(source, &pos, src_size);
        } else if (streq(word, "LDMEM")) {
            op = TBC_LDMEM;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_int(source, &pos, src_size);
        } else if (streq(word, "CMP")) {
            op = TBC_CMP;
            a = (uint8_t)parse_treg(source, &pos, src_size);
            b = (uint8_t)parse_treg(source, &pos, src_size);
        } else if (streq(word, "JMP") || streq(word, "JEQ") ||
                   streq(word, "JGT") || streq(word, "JLT")) {
            if (streq(word, "JMP")) op = TBC_JMP;
            else if (streq(word, "JEQ")) op = TBC_JEQ;
            else if (streq(word, "JGT")) op = TBC_JGT;
            else op = TBC_JLT;
            skip_ws(source, &pos, src_size);
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            int idx = label_find(labels, label_count, lbl);
            a = (idx >= 0) ? (uint8_t)label_addr[idx] : 0;
        } else if (streq(word, "HALT")) {
            op = TBC_HALT;
        } else if (streq(word, "NOP")) {
            op = TBC_NOP;
        } else {
            char msg[80];
            shell_strcopy(msg, "Error: unknown instruction '");
            int mlen = shell_strlen(msg);
            shell_strcopy(msg + mlen, word);
            mlen = shell_strlen(msg);
            msg[mlen++] = '\''; msg[mlen] = 0;
            shell_println(msg, COLOR_ERROR);
            return -1;
        }

        if (code_size + 3 <= MAX_CODE) {
            code[code_size++] = op;
            code[code_size++] = a;
            code[code_size++] = b;
            instr_count++;
        }

        skip_line(source, &pos, src_size);
    }

    if (code_size == 0) {
        shell_println("Error: no instructions found", COLOR_ERROR);
        return -1;
    }

    fs_delete(out_file);
    int cr = fs_create(out_file);
    if (cr < 0) {
        shell_println("Error: cannot create output file", COLOR_ERROR);
        return -1;
    }

    file_t *out = fs_open(out_file);
    if (!out) return -1;

    uint8_t output[MAX_CODE + 2];
    output[0] = 'T'; output[1] = 'B';
    for (int i = 0; i < code_size; i++) output[2 + i] = code[i];
    fs_write(out, output, code_size + 2);

    char msg[80];
    shell_strcopy(msg, "Compiled: ");
    shell_strcopy(msg + 10, out_file);
    int mlen = shell_strlen(msg);
    shell_strcopy(msg + mlen, " (");
    mlen = shell_strlen(msg);
    int_to_dec(instr_count, msg + mlen);
    mlen = shell_strlen(msg);
    shell_strcopy(msg + mlen, " instructions, ");
    mlen = shell_strlen(msg);
    int_to_dec(code_size + 2, msg + mlen);
    mlen = shell_strlen(msg);
    shell_strcopy(msg + mlen, " bytes)");
    shell_println(msg, COLOR_SUCCESS);

    return 0;
}

static int parse_bracket(const uint8_t *s, int *p, int sz, int *base, int *disp) {
    skip_ws(s, p, sz);
    if (*p >= sz || s[*p] != '[') return 0;
    int save = *p;
    (*p)++;
    *base = parse_x86reg(s, p, sz);
    if (*base < 0) { *p = save; return 0; }
    skip_ws(s, p, sz);
    *disp = 0;
    if (*p < sz && (s[*p] == '+' || s[*p] == '-')) {
        int neg = (s[*p] == '-');
        (*p)++;
        int val = parse_int(s, p, sz);
        *disp = neg ? -val : val;
    }
    skip_ws(s, p, sz);
    if (*p < sz && s[*p] == ']') (*p)++;
    return 1;
}

static void emit_modrm_mem(uint8_t *code, int *cs, int reg, int base, int disp) {
    if (disp == 0 && base != 5) {
        if (base == 4) {
            code[(*cs)++] = 0x00 | (reg << 3) | 4;
            code[(*cs)++] = 0x24;
        } else {
            code[(*cs)++] = 0x00 | (reg << 3) | base;
        }
    } else if (disp >= -128 && disp <= 127) {
        if (base == 4) {
            code[(*cs)++] = 0x40 | (reg << 3) | 4;
            code[(*cs)++] = 0x24;
        } else {
            code[(*cs)++] = 0x40 | (reg << 3) | base;
        }
        code[(*cs)++] = disp & 0xFF;
    } else {
        if (base == 4) {
            code[(*cs)++] = 0x80 | (reg << 3) | 4;
            code[(*cs)++] = 0x24;
        } else {
            code[(*cs)++] = 0x80 | (reg << 3) | base;
        }
        code[(*cs)++] = disp & 0xFF;
        code[(*cs)++] = (disp >> 8) & 0xFF;
        code[(*cs)++] = (disp >> 16) & 0xFF;
        code[(*cs)++] = (disp >> 24) & 0xFF;
    }
}

int asm_assemble(const char *src_file, const char *out_file) {
    file_t *src = fs_open(src_file);
    if (!src) {
        shell_println("Error: source file not found", COLOR_ERROR);
        return -1;
    }

    uint8_t source[MAX_FILESIZE];
    int src_size = fs_read(src, source, MAX_FILESIZE);

    char labels[MAX_LABELS][16];
    int label_off[MAX_LABELS];
    int label_count = 0;

    uint8_t code[MAX_CODE];
    int code_size = 0;

    typedef struct { int code_pos; char name[16]; } fixup_t;
    fixup_t fixups[MAX_LABELS];
    int fixup_count = 0;

    int pos = 0;
    while (pos < src_size) {
        skip_ws(source, &pos, src_size);
        if (pos >= src_size) break;
        if (source[pos] == '\n') { pos++; continue; }
        if (source[pos] == ';') { skip_line(source, &pos, src_size); continue; }

        int start = pos;
        while (pos < src_size && source[pos] != '\n' && source[pos] != ':' &&
               source[pos] != ' ' && source[pos] != '\t' && source[pos] != ';') pos++;

        if (pos < src_size && source[pos] == ':') {
            int len = pos - start;
            if (len > 0 && len < 16 && label_count < MAX_LABELS) {
                for (int i = 0; i < len; i++) labels[label_count][i] = source[start + i];
                labels[label_count][len] = 0;
                label_off[label_count] = code_size;
                label_count++;
                if (asm_debug) {
                    char dbg[60];
                    shell_strcopy(dbg, "  label '");
                    int dl = shell_strlen(dbg);
                    for (int i = 0; i < len; i++) dbg[dl++] = source[start + i];
                    dbg[dl++] = '\''; dbg[dl++] = ' '; dbg[dl++] = '@'; dbg[dl++] = ' ';
                    int_to_dec(code_size, dbg + dl);
                    shell_println(dbg, COLOR_INFO);
                }
            }
            pos++;
            continue;
        }
        pos = start;

        char mnemonic[16];
        read_word(source, &pos, src_size, mnemonic, 16);
        skip_ws(source, &pos, src_size);
        int pre_size = code_size;

        if (streq(mnemonic, "nop")) {
            code[code_size++] = 0x90;
        } else if (streq(mnemonic, "hlt")) {
            code[code_size++] = 0xF4;
        } else if (streq(mnemonic, "ret")) {
            code[code_size++] = 0xC3;
        } else if (streq(mnemonic, "mov")) {
            int base, disp;
            if (parse_bracket(source, &pos, src_size, &base, &disp)) {
                skip_ws(source, &pos, src_size);
                if (pos < src_size && source[pos] == ',') pos++;
                int sr = parse_x86reg(source, &pos, src_size);
                if (sr >= 0) {
                    code[code_size++] = 0x89;
                    emit_modrm_mem(code, &code_size, sr, base, disp);
                } else {
                    int sr16 = parse_reg16(source, &pos, src_size);
                    if (sr16 >= 0) {
                        code[code_size++] = 0x66;
                        code[code_size++] = 0x89;
                        emit_modrm_mem(code, &code_size, sr16, base, disp);
                    }
                }
            } else {
                int dst = parse_x86reg(source, &pos, src_size);
                if (dst >= 0) {
                    skip_ws(source, &pos, src_size);
                    if (pos < src_size && source[pos] == ',') pos++;
                    skip_ws(source, &pos, src_size);
                    if (parse_bracket(source, &pos, src_size, &base, &disp)) {
                        code[code_size++] = 0x8B;
                        emit_modrm_mem(code, &code_size, dst, base, disp);
                    } else {
                        int src_reg = parse_x86reg(source, &pos, src_size);
                        if (src_reg >= 0) {
                            code[code_size++] = 0x89;
                            code[code_size++] = 0xC0 | (src_reg << 3) | dst;
                        } else {
                            int imm = parse_int(source, &pos, src_size);
                            code[code_size++] = 0xB8 + dst;
                            code[code_size++] = imm & 0xFF;
                            code[code_size++] = (imm >> 8) & 0xFF;
                            code[code_size++] = (imm >> 16) & 0xFF;
                            code[code_size++] = (imm >> 24) & 0xFF;
                        }
                    }
                } else {
                    int dst16 = parse_reg16(source, &pos, src_size);
                    if (dst16 >= 0) {
                        skip_ws(source, &pos, src_size);
                        if (pos < src_size && source[pos] == ',') pos++;
                        skip_ws(source, &pos, src_size);
                        if (parse_bracket(source, &pos, src_size, &base, &disp)) {
                            code[code_size++] = 0x66;
                            code[code_size++] = 0x8B;
                            emit_modrm_mem(code, &code_size, dst16, base, disp);
                        } else {
                            int src16 = parse_reg16(source, &pos, src_size);
                            if (src16 >= 0) {
                                code[code_size++] = 0x66;
                                code[code_size++] = 0x89;
                                code[code_size++] = 0xC0 | (src16 << 3) | dst16;
                            } else {
                                int imm = parse_int(source, &pos, src_size);
                                code[code_size++] = 0x66;
                                code[code_size++] = 0xB8 + dst16;
                                code[code_size++] = imm & 0xFF;
                                code[code_size++] = (imm >> 8) & 0xFF;
                            }
                        }
                    }
                }
            }
        } else if (streq(mnemonic, "add")) {
            int dst = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int save = pos;
            int sr = parse_x86reg(source, &pos, src_size);
            if (sr >= 0) {
                code[code_size++] = 0x01;
                code[code_size++] = 0xC0 | (sr << 3) | dst;
            } else {
                pos = save;
                int imm = parse_int(source, &pos, src_size);
                code[code_size++] = 0x81;
                code[code_size++] = 0xC0 | dst;
                code[code_size++] = imm & 0xFF;
                code[code_size++] = (imm >> 8) & 0xFF;
                code[code_size++] = (imm >> 16) & 0xFF;
                code[code_size++] = (imm >> 24) & 0xFF;
            }
        } else if (streq(mnemonic, "sub")) {
            int dst = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int save = pos;
            int sr = parse_x86reg(source, &pos, src_size);
            if (sr >= 0) {
                code[code_size++] = 0x29;
                code[code_size++] = 0xC0 | (sr << 3) | dst;
            } else {
                pos = save;
                int imm = parse_int(source, &pos, src_size);
                code[code_size++] = 0x81;
                code[code_size++] = 0xC0 | (5 << 3) | dst;
                code[code_size++] = imm & 0xFF;
                code[code_size++] = (imm >> 8) & 0xFF;
                code[code_size++] = (imm >> 16) & 0xFF;
                code[code_size++] = (imm >> 24) & 0xFF;
            }
        } else if (streq(mnemonic, "xor")) {
            int dst = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int save = pos;
            int sr = parse_x86reg(source, &pos, src_size);
            if (sr >= 0) {
                code[code_size++] = 0x31;
                code[code_size++] = 0xC0 | (sr << 3) | dst;
            } else {
                pos = save;
                int imm = parse_int(source, &pos, src_size);
                code[code_size++] = 0x81;
                code[code_size++] = 0xC0 | (6 << 3) | dst;
                code[code_size++] = imm & 0xFF;
                code[code_size++] = (imm >> 8) & 0xFF;
                code[code_size++] = (imm >> 16) & 0xFF;
                code[code_size++] = (imm >> 24) & 0xFF;
            }
        } else if (streq(mnemonic, "and")) {
            int dst = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int save = pos;
            int sr = parse_x86reg(source, &pos, src_size);
            if (sr >= 0) {
                code[code_size++] = 0x21;
                code[code_size++] = 0xC0 | (sr << 3) | dst;
            } else {
                pos = save;
                int imm = parse_int(source, &pos, src_size);
                code[code_size++] = 0x81;
                code[code_size++] = 0xC0 | (4 << 3) | dst;
                code[code_size++] = imm & 0xFF;
                code[code_size++] = (imm >> 8) & 0xFF;
                code[code_size++] = (imm >> 16) & 0xFF;
                code[code_size++] = (imm >> 24) & 0xFF;
            }
        } else if (streq(mnemonic, "or")) {
            int dst = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int save = pos;
            int sr = parse_x86reg(source, &pos, src_size);
            if (sr >= 0) {
                code[code_size++] = 0x09;
                code[code_size++] = 0xC0 | (sr << 3) | dst;
            } else {
                pos = save;
                int imm = parse_int(source, &pos, src_size);
                code[code_size++] = 0x81;
                code[code_size++] = 0xC0 | (1 << 3) | dst;
                code[code_size++] = imm & 0xFF;
                code[code_size++] = (imm >> 8) & 0xFF;
                code[code_size++] = (imm >> 16) & 0xFF;
                code[code_size++] = (imm >> 24) & 0xFF;
            }
        } else if (streq(mnemonic, "inc")) {
            int r = parse_x86reg(source, &pos, src_size);
            if (r >= 0) code[code_size++] = 0x40 + r;
        } else if (streq(mnemonic, "dec")) {
            int r = parse_x86reg(source, &pos, src_size);
            if (r >= 0) code[code_size++] = 0x48 + r;
        } else if (streq(mnemonic, "push")) {
            int r = parse_x86reg(source, &pos, src_size);
            if (r >= 0) code[code_size++] = 0x50 + r;
        } else if (streq(mnemonic, "pop")) {
            int r = parse_x86reg(source, &pos, src_size);
            if (r >= 0) code[code_size++] = 0x58 + r;
        } else if (streq(mnemonic, "int")) {
            int imm = parse_int(source, &pos, src_size);
            code[code_size++] = 0xCD;
            code[code_size++] = imm & 0xFF;
        } else if (streq(mnemonic, "in")) {
            int save_pos = pos;
            int r = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int port = parse_int(source, &pos, src_size);
            if (r == 0) {
                code[code_size++] = 0xE4;
                code[code_size++] = port & 0xFF;
            }
        } else if (streq(mnemonic, "out")) {
            int port = parse_int(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int save_pos = pos;
            int r = parse_x86reg(source, &pos, src_size);
            if (r == 0) {
                code[code_size++] = 0xE6;
                code[code_size++] = port & 0xFF;
            }
        } else if (streq(mnemonic, "jmp")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0xE9;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "call")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0xE8;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "je") || streq(mnemonic, "jz")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0x0F; code[code_size++] = 0x84;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "jne") || streq(mnemonic, "jnz")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0x0F; code[code_size++] = 0x85;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "jl")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0x0F; code[code_size++] = 0x8C;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "jge")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0x0F; code[code_size++] = 0x8D;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "jle")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0x0F; code[code_size++] = 0x8E;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "jg")) {
            char lbl[16];
            read_word(source, &pos, src_size, lbl, 16);
            code[code_size++] = 0x0F; code[code_size++] = 0x8F;
            if (fixup_count < MAX_LABELS) {
                fixups[fixup_count].code_pos = code_size;
                shell_strcopy(fixups[fixup_count].name, lbl);
                fixup_count++;
            }
            code[code_size++] = 0; code[code_size++] = 0;
            code[code_size++] = 0; code[code_size++] = 0;
        } else if (streq(mnemonic, "cmp")) {
            int dst = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int save = pos;
            int sr = parse_x86reg(source, &pos, src_size);
            if (sr >= 0) {
                code[code_size++] = 0x39;
                code[code_size++] = 0xC0 | (sr << 3) | dst;
            } else {
                pos = save;
                int imm = parse_int(source, &pos, src_size);
                code[code_size++] = 0x81;
                code[code_size++] = 0xC0 | (7 << 3) | dst;
                code[code_size++] = imm & 0xFF;
                code[code_size++] = (imm >> 8) & 0xFF;
                code[code_size++] = (imm >> 16) & 0xFF;
                code[code_size++] = (imm >> 24) & 0xFF;
            }
        } else if (streq(mnemonic, "movb")) {
            int base, disp;
            if (parse_bracket(source, &pos, src_size, &base, &disp)) {
                skip_ws(source, &pos, src_size);
                if (pos < src_size && source[pos] == ',') pos++;
                int sr = parse_x86reg(source, &pos, src_size);
                code[code_size++] = 0x88;
                emit_modrm_mem(code, &code_size, sr, base, disp);
            } else {
                int dst = parse_x86reg(source, &pos, src_size);
                skip_ws(source, &pos, src_size);
                if (pos < src_size && source[pos] == ',') pos++;
                skip_ws(source, &pos, src_size);
                if (parse_bracket(source, &pos, src_size, &base, &disp)) {
                    code[code_size++] = 0x0F;
                    code[code_size++] = 0xB6;
                    emit_modrm_mem(code, &code_size, dst, base, disp);
                }
            }
        } else if (streq(mnemonic, "shr")) {
            int r = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int imm = parse_int(source, &pos, src_size);
            code[code_size++] = 0xC1;
            code[code_size++] = 0xC0 | (5 << 3) | r;
            code[code_size++] = imm & 0xFF;
        } else if (streq(mnemonic, "shl")) {
            int r = parse_x86reg(source, &pos, src_size);
            skip_ws(source, &pos, src_size);
            if (pos < src_size && source[pos] == ',') pos++;
            int imm = parse_int(source, &pos, src_size);
            code[code_size++] = 0xC1;
            code[code_size++] = 0xC0 | (4 << 3) | r;
            code[code_size++] = imm & 0xFF;
        } else if (streq(mnemonic, "db")) {
            while (pos < src_size && source[pos] != '\n' && source[pos] != ';') {
                skip_ws(source, &pos, src_size);
                if (pos < src_size && source[pos] != '\n' && source[pos] != ';') {
                    int val = parse_int(source, &pos, src_size);
                    if (code_size < MAX_CODE) code[code_size++] = val & 0xFF;
                    skip_ws(source, &pos, src_size);
                    if (pos < src_size && source[pos] == ',') pos++;
                }
            }
        } else {
            char msg[80];
            shell_strcopy(msg, "Error: unknown mnemonic '");
            int mlen = shell_strlen(msg);
            shell_strcopy(msg + mlen, mnemonic);
            mlen = shell_strlen(msg);
            msg[mlen++] = '\''; msg[mlen] = 0;
            shell_println(msg, COLOR_ERROR);
            return -1;
        }

        if (asm_debug) {
            char dbg[80];
            int dl = 0;
            dbg[dl++] = ' '; dbg[dl++] = ' ';
            int_to_hex(pre_size, dbg + dl, 4); dl += 4;
            dbg[dl++] = ':'; dbg[dl++] = ' ';
            int mlen2 = shell_strlen(mnemonic);
            for (int i = 0; i < mlen2 && dl < 20; i++) dbg[dl++] = mnemonic[i];
            while (dl < 20) dbg[dl++] = ' ';
            for (int i = pre_size; i < code_size && dl < 70; i++) {
                int_to_hex(code[i], dbg + dl, 2); dl += 2;
                dbg[dl++] = ' ';
            }
            dbg[dl] = 0;
            shell_println(dbg, COLOR_BORDER);
        }

        skip_line(source, &pos, src_size);
    }

    for (int i = 0; i < fixup_count; i++) {
        if (asm_debug) {
            char dbg[60];
            shell_strcopy(dbg, "  fixup '");
            int dl = shell_strlen(dbg);
            shell_strcopy(dbg + dl, fixups[i].name);
            dl = shell_strlen(dbg);
            dbg[dl++] = '\''; dbg[dl++] = ' '; dbg[dl++] = '@'; dbg[dl++] = ' ';
            int_to_dec(fixups[i].code_pos, dbg + dl);
            shell_println(dbg, COLOR_INFO);
        }

        int idx = label_find(labels, label_count, fixups[i].name);
        if (idx < 0) {
            char msg[80];
            shell_strcopy(msg, "Error: undefined label '");
            int mlen = shell_strlen(msg);
            shell_strcopy(msg + mlen, fixups[i].name);
            mlen = shell_strlen(msg);
            msg[mlen++] = '\''; msg[mlen] = 0;
            shell_println(msg, COLOR_ERROR);
            return -1;
        }
        int target = label_off[idx];
        int from = fixups[i].code_pos + 4;
        int rel = target - from;
        int cp = fixups[i].code_pos;
        code[cp]   = rel & 0xFF;
        code[cp+1] = (rel >> 8) & 0xFF;
        code[cp+2] = (rel >> 16) & 0xFF;
        code[cp+3] = (rel >> 24) & 0xFF;
    }

    if (code_size == 0) {
        shell_println("Error: no instructions found", COLOR_ERROR);
        return -1;
    }

    fs_delete(out_file);
    fs_create(out_file);
    file_t *out = fs_open(out_file);
    if (!out) {
        shell_println("Error: cannot create output file", COLOR_ERROR);
        return -1;
    }
    fs_write(out, code, code_size);

    char msg[80];
    shell_strcopy(msg, "Assembled: ");
    int mlen = 11;
    shell_strcopy(msg + mlen, out_file);
    mlen = shell_strlen(msg);
    shell_strcopy(msg + mlen, " (");
    mlen = shell_strlen(msg);
    int_to_dec(code_size, msg + mlen);
    mlen = shell_strlen(msg);
    shell_strcopy(msg + mlen, " bytes)");
    shell_println(msg, COLOR_SUCCESS);

    return 0;
}

static void exec_tbc(uint8_t *code, int size) {
    extern ternary_vm_t tvm;
    tvm_init();

    int pc = 0;
    int max_steps = 10000;
    int instr_count = size / 3;

    char hdr[60];
    for (int i = 0; i < 60; i++) hdr[i] = 0;
    shell_strcopy(hdr, "=== Running TBC (");
    int hlen = shell_strlen(hdr);
    int_to_dec(instr_count, hdr + hlen);
    hlen = shell_strlen(hdr);
    shell_strcopy(hdr + hlen, " instr, ");
    hlen = shell_strlen(hdr);
    int_to_dec(size, hdr + hlen);
    hlen = shell_strlen(hdr);
    shell_strcopy(hdr + hlen, " bytes) ===");
    shell_println(hdr, COLOR_TITLE);

    while (pc * 3 + 2 < size && max_steps-- > 0) {
        uint8_t op = code[pc * 3];
        uint8_t a  = code[pc * 3 + 1];
        uint8_t b  = code[pc * 3 + 2];
        pc++;

        switch (op) {
        case TBC_LOAD: tvm.regs[a & 7] = (int8_t)b; break;
        case TBC_ADD:  tvm.regs[a & 7] += tvm.regs[b & 7]; break;
        case TBC_SUB:  tvm.regs[a & 7] -= tvm.regs[b & 7]; break;
        case TBC_MUL:  tvm.regs[a & 7] *= tvm.regs[b & 7]; break;
        case TBC_NEG:  tvm.regs[a & 7] = -tvm.regs[a & 7]; break;
        case TBC_OUT: {
            int r = a & 7;
            int val = tvm.regs[r];
            char line[40];
            for (int i = 0; i < 40; i++) line[i] = 0;
            line[0] = ' '; line[1] = ' ';
            line[2] = 'T'; line[3] = '0' + r;
            line[4] = ' '; line[5] = '='; line[6] = ' ';
            int_to_dec(val, line + 7);
            shell_println(line, COLOR_ACCENT);
            break;
        }
        case TBC_TAND: {
            int va = tvm.regs[a&7]>0?1:(tvm.regs[a&7]<0?-1:0);
            int vb = tvm.regs[b&7]>0?1:(tvm.regs[b&7]<0?-1:0);
            tvm.regs[a&7] = (va==-1||vb==-1)?-1:(va==0||vb==0)?0:1;
            break;
        }
        case TBC_TOR: {
            int va = tvm.regs[a&7]>0?1:(tvm.regs[a&7]<0?-1:0);
            int vb = tvm.regs[b&7]>0?1:(tvm.regs[b&7]<0?-1:0);
            tvm.regs[a&7] = (va==1||vb==1)?1:(va==0||vb==0)?0:-1;
            break;
        }
        case TBC_STORE: tvm.memory[b] = tvm.regs[a & 7]; break;
        case TBC_LDMEM: tvm.regs[a & 7] = tvm.memory[b]; break;
        case TBC_CMP: {
            int diff = tvm.regs[a&7] - tvm.regs[b&7];
            tvm.cmp_result = diff>0?1:(diff<0?-1:0);
            break;
        }
        case TBC_JMP: pc = a; break;
        case TBC_JEQ: if (tvm.cmp_result == 0) pc = a; break;
        case TBC_JGT: if (tvm.cmp_result > 0)  pc = a; break;
        case TBC_JLT: if (tvm.cmp_result < 0)  pc = a; break;
        case TBC_HALT: goto done;
        case TBC_NOP: break;
        default: goto done;
        }
    }
done:
    if (max_steps <= 0) {
        shell_println("  Stopped: max steps exceeded", COLOR_ERROR);
    } else {
        shell_println("  Program halted.", COLOR_SUCCESS);
    }
}

static uint8_t exec_buf[EXEC_BUF_SIZE] __attribute__((aligned(16)));

/* Crash recovery - defined in main.c */
extern uint32_t exec_jmp_buf[6];
extern volatile int native_running;
extern int exec_setjmp(uint32_t *buf);
extern void exec_longjmp(uint32_t *buf, int val);

static void exec_native(uint8_t *code, int size) {
    if (size > EXEC_BUF_SIZE) {
        shell_println("Error: binary too large", COLOR_ERROR);
        return;
    }

    for (int i = 0; i < size; i++) exec_buf[i] = code[i];

    char hdr[60];
    shell_strcopy(hdr, "=== Running Native (");
    int hl = shell_strlen(hdr);
    int_to_dec(size, hdr + hl);
    hl = shell_strlen(hdr);
    shell_strcopy(hdr + hl, " bytes) ===");
    shell_println(hdr, COLOR_TITLE);

    if (asm_debug) {
        char addr[40];
        shell_strcopy(addr, "  exec_buf @ 0x");
        int_to_hex((int)(unsigned long)exec_buf, addr + 15, 8);
        shell_println(addr, COLOR_INFO);

        int dump_len = size < 80 ? size : 80;
        for (int row = 0; row < dump_len; row += 16) {
            char line[80];
            int dl = 0;
            line[dl++] = ' '; line[dl++] = ' ';
            int_to_hex(row, line + dl, 4); dl += 4;
            line[dl++] = ':';
            for (int c = 0; c < 16 && row + c < dump_len; c++) {
                line[dl++] = ' ';
                int_to_hex(code[row + c], line + dl, 2); dl += 2;
            }
            line[dl] = 0;
            shell_println(line, COLOR_BORDER);
        }
    }

    native_running = 1;
    int crash = exec_setjmp(exec_jmp_buf);

    if (crash) {
        /* Returned here via longjmp from exception handler */
        shell_println("  Program terminated.", COLOR_ERROR);
    } else {
        typedef int (*func_t)(void);
        func_t fn = (func_t)exec_buf;
        int result = fn();

        char line[80];
        shell_strcopy(line, "  Return (eax): ");
        int_to_dec(result, line + 16);
        shell_println(line, COLOR_ACCENT);
        shell_println("  Program returned.", COLOR_SUCCESS);
    }

    native_running = 0;
}

int exec_run(const char *filename) {
    file_t *file = fs_open(filename);
    if (!file) {
        shell_println("Error: file not found", COLOR_ERROR);
        return -1;
    }

    uint8_t data[MAX_FILESIZE];
    int size = fs_read(file, data, MAX_FILESIZE);

    if (size >= 2 && data[0] == 'T' && data[1] == 'B') {
        exec_tbc(data + 2, size - 2);
    } else {
        exec_native(data, size);
    }
    return 0;
}