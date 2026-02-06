#ifndef COMPILER_H
#define COMPILER_H

#include "types.h"

#define TBC_LOAD  0x01
#define TBC_ADD   0x02
#define TBC_SUB   0x03
#define TBC_MUL   0x04
#define TBC_NEG   0x05
#define TBC_OUT   0x06
#define TBC_TAND  0x07
#define TBC_TOR   0x08
#define TBC_STORE 0x09
#define TBC_LDMEM 0x0A
#define TBC_CMP   0x0B
#define TBC_JMP   0x0C
#define TBC_JEQ   0x0D
#define TBC_JGT   0x0E
#define TBC_JLT   0x0F
#define TBC_HALT  0x10
#define TBC_NOP   0x11

#define MAX_LABELS 16
#define MAX_CODE 512
#define EXEC_BUF_SIZE 1024

int tcc_compile(const char *src_file, const char *out_file);
int asm_assemble(const char *src_file, const char *out_file);
int exec_run(const char *filename);

#endif