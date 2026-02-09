#ifndef EDITOR_H
#define EDITOR_H

#include "types.h"

#define EDITOR_MAX_LINES 100
#define EDITOR_MAX_LINE_LEN 78

typedef struct {
    char lines[EDITOR_MAX_LINES][EDITOR_MAX_LINE_LEN];
    int line_count;
    int cursor_x;
    int cursor_y;
    int scroll_offset;
    char filename[32];
    int modified;
    int active;
} editor_t;

void editor_init(void);
void editor_open(const char *filename);
void editor_close(void);
void editor_handle_key(uint8_t key);
void editor_render(void);
void editor_save(void);
int editor_is_active(void);

#endif