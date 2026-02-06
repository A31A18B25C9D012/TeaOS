#ifndef SHELL_H
#define SHELL_H

#include "types.h"

void shell_init(void);
void shell_execute(const char *cmd);
void shell_print(int line, const char *text, uint8_t color);
void shell_println(const char *text, uint8_t color);
void shell_newline(void);
void shell_reset_cursor(void);
int shell_strcmp(const char *s1, const char *s2);
int shell_startswith(const char *str, const char *prefix);
const char* shell_get_arg(const char *input, int n);
void shell_strcopy(char *dst, const char *src);
int shell_strlen(const char *s);
int shell_hex_to_int(const char *s);
void shell_int_to_hex(uint32_t val, char *buf, int digits);
void add_to_history(const char *cmd);
const char* get_history(int index);
int get_history_count(void);

#endif