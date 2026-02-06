#ifndef TEASCRIPT_H
#define TEASCRIPT_H

#include "types.h"

typedef int8_t trit_t;
typedef int32_t tryte_t;

typedef struct {
    tryte_t regs[8];
    tryte_t memory[256];
    int pc;
    int running;
    int cmp_result;
} ternary_vm_t;

extern ternary_vm_t tvm;

void tvm_init(void);
void tvm_show_regs(void);
void tvm_execute(const char *cmd);
void tvm_show_doc(int page);

trit_t ternary_add(trit_t a, trit_t b);
trit_t ternary_mul(trit_t a, trit_t b);
trit_t ternary_neg(trit_t a);
trit_t ternary_and(trit_t a, trit_t b);
trit_t ternary_or(trit_t a, trit_t b);

#endif