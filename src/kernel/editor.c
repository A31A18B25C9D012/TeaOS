#include "editor.h"
#include "filesystem.h"
#include "shell.h"

extern void fb_clear_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h);
extern void fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
extern void fb_draw_text(uint32_t x, uint32_t y, const char *text, uint32_t color);
extern void fb_putchar(uint32_t x, uint32_t y, char c, uint8_t color);

static editor_t editor;

static const char *c_keywords[] = {
    "int", "char", "void", "if", "else", "while", "for", "return",
    "struct", "typedef", "uint32_t", "uint8_t", "static", "extern",
    "include", "define", NULL
};

static const char *teas_keywords[] = {
    "LOAD", "ADD", "MUL", "NEG", "OUT", "TAND", "TOR",
    "STORE", "LDMEM", "CMP", NULL
};

int is_keyword(const char *word, int len, const char **keywords) {
    for (int i = 0; keywords[i] != NULL; i++) {
        int klen = shell_strlen(keywords[i]);
        if (len == klen) {
            int match = 1;
            for (int j = 0; j < len; j++) {
                if (word[j] != keywords[i][j]) {
                    match = 0;
                    break;
                }
            }
            if (match) return 1;
        }
    }
    return 0;
}

void editor_init(void) {
    editor.line_count = 1;
    editor.cursor_x = 0;
    editor.cursor_y = 0;
    editor.scroll_offset = 0;
    editor.modified = 0;
    editor.active = 0;
    editor.filename[0] = 0;

    for (int i = 0; i < EDITOR_MAX_LINES; i++) {
        editor.lines[i][0] = 0;
    }
}

void editor_open(const char *filename) {
    editor_init();
    shell_strcopy(editor.filename, filename);
    editor.active = 1;

    file_t *file = fs_open(filename);
    if (file) {
        uint8_t data[MAX_FILESIZE];
        int size = fs_read(file, data, MAX_FILESIZE);

        int line = 0, col = 0;
        for (int i = 0; i < size && line < EDITOR_MAX_LINES; i++) {
            if (data[i] == '\n') {
                editor.lines[line][col] = 0;
                line++;
                col = 0;
            } else if (col < EDITOR_MAX_LINE_LEN - 1) {
                editor.lines[line][col++] = data[i];
            }
        }
        editor.lines[line][col] = 0;
        editor.line_count = line + 1;
    }

    editor_render();
}

void editor_close(void) {
    editor.active = 0;

    extern void fb_clear_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h);
    extern void draw_status_bar(void);
    extern void draw_prompt(void);

    fb_clear_region(0, 0, 80, 24);
    draw_status_bar();
    shell_reset_cursor();
    shell_println("Editor closed.", COLOR_INFO);
    draw_prompt();
}

void editor_save(void) {
    file_t *file = fs_open(editor.filename);
    if (!file) {
        fs_create(editor.filename);
        file = fs_open(editor.filename);
    }

    if (file) {
        uint8_t data[MAX_FILESIZE];
        uint32_t size = 0;

        for (int i = 0; i < editor.line_count && size < MAX_FILESIZE - 1; i++) {
            int j = 0;
            while (editor.lines[i][j] && size < MAX_FILESIZE - 1) {
                data[size++] = editor.lines[i][j++];
            }
            if (i < editor.line_count - 1 && size < MAX_FILESIZE - 1) {
                data[size++] = '\n';
            }
        }

        fs_write(file, data, size);
        editor.modified = 0;
    }
}

void editor_render(void) {
    fb_clear_region(0, 0, 80, 24);

    fb_fill_rect(0, 0, 80, 1, COLOR_PANEL);
    fb_draw_text(2, 0, "TeaOS Editor", COLOR_PANEL);

    char status[80];
    status[0] = ' ';
    status[1] = '-';
    status[2] = ' ';
    shell_strcopy(status + 3, editor.filename);
    int len = shell_strlen(status);
    if (editor.modified) {
        status[len++] = ' ';
        status[len++] = '[';
        status[len++] = '+';
        status[len++] = ']';
    }
    status[len] = 0;
    fb_draw_text(18, 0, status, COLOR_PANEL);

    fb_draw_text(58, 0, "ESC:Exit F1:Save", COLOR_PANEL);

    const char **keywords = NULL;
    int flen = shell_strlen(editor.filename);
    if (flen > 2) {
        if (editor.filename[flen-2] == '.' && editor.filename[flen-1] == 'c') {
            keywords = c_keywords;
        } else if (editor.filename[flen-2] == '.' && editor.filename[flen-1] == 't') {
            keywords = teas_keywords;
        }
    }

    for (int i = 0; i < 21 && (i + editor.scroll_offset) < editor.line_count; i++) {
        char line_num[8];
        int line_no = i + editor.scroll_offset + 1;
        int pos = 0;
        if (line_no >= 100) line_num[pos++] = '0' + (line_no / 100);
        if (line_no >= 10) line_num[pos++] = '0' + ((line_no / 10) % 10);
        line_num[pos++] = '0' + (line_no % 10);
        line_num[pos++] = ' ';
        line_num[pos] = 0;
        fb_draw_text(0, 2 + i, line_num, COLOR_BORDER);

        char *line = editor.lines[i + editor.scroll_offset];
        int col = 0;
        int x = 4;

        while (line[col] && x < 80) {
            uint8_t color = COLOR_FG;

            if (keywords) {
                if ((line[col] >= 'A' && line[col] <= 'Z') ||
                    (line[col] >= 'a' && line[col] <= 'z')) {
                    int word_len = 0;
                    while ((line[col + word_len] >= 'A' && line[col + word_len] <= 'Z') ||
                           (line[col + word_len] >= 'a' && line[col + word_len] <= 'z') ||
                           (line[col + word_len] >= '0' && line[col + word_len] <= '9') ||
                           line[col + word_len] == '_') {
                        word_len++;
                    }

                    if (is_keyword(line + col, word_len, keywords)) {
                        color = COLOR_ACCENT;
                    }

                    for (int j = 0; j < word_len && x < 80; j++) {
                        fb_putchar(x++, 2 + i, line[col++], color);
                    }
                    continue;
                }

                if (line[col] == '/' && line[col+1] == '/') {
                    color = COLOR_SUCCESS;
                    while (line[col] && x < 80) {
                        fb_putchar(x++, 2 + i, line[col++], color);
                    }
                    continue;
                }

                if (line[col] == '"') {
                    color = COLOR_INFO;
                    fb_putchar(x++, 2 + i, line[col++], color);
                    while (line[col] && line[col] != '"' && x < 80) {
                        fb_putchar(x++, 2 + i, line[col++], color);
                    }
                    if (line[col] == '"' && x < 80) {
                        fb_putchar(x++, 2 + i, line[col++], color);
                    }
                    continue;
                }
            }

            fb_putchar(x++, 2 + i, line[col++], color);
        }
    }

    fb_fill_rect(0, 22, 80, 1, COLOR_BG);
    fb_fill_rect(0, 23, 80, 1, COLOR_BG);
    fb_draw_text(0, 22, "Arrow keys to move | Type to edit | F1:Save | ESC:Exit", COLOR_BORDER);

    if (editor.cursor_y - editor.scroll_offset >= 0 &&
        editor.cursor_y - editor.scroll_offset < 21) {
        fb_putchar(4 + editor.cursor_x, 2 + (editor.cursor_y - editor.scroll_offset), '_', COLOR_ACCENT);
    }
}

void editor_handle_key(uint8_t key) {
    if (key == 27) {
        editor_close();
        return;
    }

    if (key == 3) {
        editor_save();
        editor_render();
        return;
    }

    if (key == 1) {
        if (editor.cursor_y > 0) {
            editor.cursor_y--;
            if (editor.cursor_y < editor.scroll_offset) {
                editor.scroll_offset = editor.cursor_y;
            }
            if (editor.cursor_x > shell_strlen(editor.lines[editor.cursor_y])) {
                editor.cursor_x = shell_strlen(editor.lines[editor.cursor_y]);
            }
        }
    } else if (key == 2) {
        if (editor.cursor_y < editor.line_count - 1) {
            editor.cursor_y++;
            if (editor.cursor_y >= editor.scroll_offset + 21) {
                editor.scroll_offset = editor.cursor_y - 20;
            }
            if (editor.cursor_x > shell_strlen(editor.lines[editor.cursor_y])) {
                editor.cursor_x = shell_strlen(editor.lines[editor.cursor_y]);
            }
        }
    } else if (key == 4) {
        if (editor.cursor_x > 0) editor.cursor_x--;
    } else if (key == 5) {
        if (editor.cursor_x < shell_strlen(editor.lines[editor.cursor_y])) {
            editor.cursor_x++;
        }
    } else if (key == '\b') {
        if (editor.cursor_x > 0) {
            char *line = editor.lines[editor.cursor_y];
            int len = shell_strlen(line);
            for (int i = editor.cursor_x - 1; i < len; i++) {
                line[i] = line[i + 1];
            }
            editor.cursor_x--;
            editor.modified = 1;
        } else if (editor.cursor_y > 0) {
            int prev_len = shell_strlen(editor.lines[editor.cursor_y - 1]);
            int curr_len = shell_strlen(editor.lines[editor.cursor_y]);

            if (prev_len + curr_len < EDITOR_MAX_LINE_LEN - 1) {
                for (int i = 0; i < curr_len; i++) {
                    editor.lines[editor.cursor_y - 1][prev_len + i] = editor.lines[editor.cursor_y][i];
                }
                editor.lines[editor.cursor_y - 1][prev_len + curr_len] = 0;

                for (int i = editor.cursor_y; i < editor.line_count - 1; i++) {
                    shell_strcopy(editor.lines[i], editor.lines[i + 1]);
                }

                editor.line_count--;
                editor.cursor_y--;
                editor.cursor_x = prev_len;
                editor.modified = 1;
            }
        }
    } else if (key == '\n') {
        if (editor.line_count < EDITOR_MAX_LINES) {
            for (int i = editor.line_count; i > editor.cursor_y + 1; i--) {
                shell_strcopy(editor.lines[i], editor.lines[i - 1]);
            }

            char *curr_line = editor.lines[editor.cursor_y];
            char *next_line = editor.lines[editor.cursor_y + 1];

            int i = 0;
            while (curr_line[editor.cursor_x + i]) {
                next_line[i] = curr_line[editor.cursor_x + i];
                i++;
            }
            next_line[i] = 0;
            curr_line[editor.cursor_x] = 0;

            editor.line_count++;
            editor.cursor_y++;
            editor.cursor_x = 0;

            if (editor.cursor_y >= editor.scroll_offset + 21) {
                editor.scroll_offset++;
            }

            editor.modified = 1;
        }
    } else if (key >= 32 && key < 127) {
        char *line = editor.lines[editor.cursor_y];
        int len = shell_strlen(line);

        if (len < EDITOR_MAX_LINE_LEN - 1) {
            for (int i = len; i >= editor.cursor_x; i--) {
                line[i + 1] = line[i];
            }
            line[editor.cursor_x] = key;
            editor.cursor_x++;
            editor.modified = 1;
        }
    }

    editor_render();
}

int editor_is_active(void) {
    return editor.active;
}