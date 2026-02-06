#include "types.h"
#include "teascript.h"
#include "filesystem.h"
#include "editor.h"
#include "shell.h"
#include "network.h"

extern void cache_init(void);
extern void xfce_init(void);
extern void mem_init(void);
extern void fb_init(void);
extern void fb_clear(uint32_t color);
extern void fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
extern void fb_draw_text(uint32_t x, uint32_t y, const char *text, uint32_t color);
extern void fb_clear_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h);
extern void keyboard_init(void);
extern void keyboard_handle(void);
extern uint8_t keyboard_read(void);
extern void mouse_init(void);
extern void mouse_handle(void);

#define VT_COUNT 6

typedef struct {
    char input_buffer[256];
    int input_len;
    int cursor_visible;
    int tick_counter;
    int history_pos;
} vt_t;

static vt_t vts[VT_COUNT];
static uint16_t vt_buffers[VT_COUNT][80 * 25];
static int current_vt = 0;
static volatile int running = 1;
static int input_len_prev = 0;
int current_theme = THEME_ORANGE;

typedef struct {
    uint8_t bg, fg, panel, border, title, accent;
} theme_t;

const theme_t themes[] = {
    {0x00, 0x0F, 0x60, 0x06, 0x0E, 0x0C},
    {0x00, 0x0F, 0x10, 0x09, 0x0B, 0x03},
    {0x00, 0x0F, 0x20, 0x0A, 0x02, 0x0A}
};

typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t zero;
    uint8_t type_attr;
    uint16_t offset_high;
} __attribute__((packed)) idt_entry_t;

static idt_entry_t idt[256];

void default_handler(void) {
    __asm__ volatile ("iret");
}

void idt_set_gate(uint8_t num, uint32_t handler) {
    idt[num].offset_low = handler & 0xFFFF;
    idt[num].selector = 0x08;
    idt[num].zero = 0;
    idt[num].type_attr = 0x8E;
    idt[num].offset_high = (handler >> 16) & 0xFFFF;
}

void idt_init(void) {
    uint32_t handler = (uint32_t)default_handler;

    for (int i = 0; i < 256; i++) {
        idt_set_gate(i, handler);
    }

    struct {
        uint16_t limit;
        uint32_t base;
    } __attribute__((packed)) idtr;

    idtr.limit = sizeof(idt) - 1;
    idtr.base = (uint32_t)&idt;

    __asm__ volatile ("lidt %0" : : "m"(idtr));
}

void halt(void) {
    running = 0;
}

extern uint8_t keyboard_head;
extern uint8_t keyboard_tail;

static uint32_t system_ticks = 0;

void draw_debug_bar(void) {
    volatile uint16_t *vga = (volatile uint16_t*)0xB8000;

    vga[24 * 80 + 0] = (COLOR_INFO << 8) | 'D';
    vga[24 * 80 + 1] = (COLOR_INFO << 8) | 'E';
    vga[24 * 80 + 2] = (COLOR_INFO << 8) | 'B';
    vga[24 * 80 + 3] = (COLOR_INFO << 8) | 'U';
    vga[24 * 80 + 4] = (COLOR_INFO << 8) | 'G';
    vga[24 * 80 + 5] = (COLOR_INFO << 8) | ':';
    vga[24 * 80 + 6] = (COLOR_INFO << 8) | ' ';
    vga[24 * 80 + 7] = (COLOR_INFO << 8) | 'H';
    vga[24 * 80 + 8] = (COLOR_INFO << 8) | '=';
    vga[24 * 80 + 9] = (COLOR_INFO << 8) | ('0' + keyboard_head / 100);
    vga[24 * 80 + 10] = (COLOR_INFO << 8) | ('0' + (keyboard_head / 10) % 10);
    vga[24 * 80 + 11] = (COLOR_INFO << 8) | ('0' + keyboard_head % 10);
    vga[24 * 80 + 12] = (COLOR_INFO << 8) | ' ';
    vga[24 * 80 + 13] = (COLOR_INFO << 8) | 'T';
    vga[24 * 80 + 14] = (COLOR_INFO << 8) | '=';
    vga[24 * 80 + 15] = (COLOR_INFO << 8) | ('0' + keyboard_tail / 100);
    vga[24 * 80 + 16] = (COLOR_INFO << 8) | ('0' + (keyboard_tail / 10) % 10);
    vga[24 * 80 + 17] = (COLOR_INFO << 8) | ('0' + keyboard_tail % 10);
    vga[24 * 80 + 18] = (COLOR_INFO << 8) | ' ';
    vga[24 * 80 + 19] = (COLOR_INFO << 8) | 'V';
    vga[24 * 80 + 20] = (COLOR_INFO << 8) | 'T';
    vga[24 * 80 + 21] = (COLOR_INFO << 8) | '=';
    vga[24 * 80 + 22] = (COLOR_INFO << 8) | ('0' + current_vt);

    uint32_t seconds = system_ticks / 1000;
    uint32_t minutes = seconds / 60;
    uint32_t hours = minutes / 60;
    seconds %= 60;
    minutes %= 60;
    hours %= 24;

    vga[24 * 80 + 60] = (COLOR_INFO << 8) | ('0' + (hours / 10));
    vga[24 * 80 + 61] = (COLOR_INFO << 8) | ('0' + (hours % 10));
    vga[24 * 80 + 62] = (COLOR_INFO << 8) | ':';
    vga[24 * 80 + 63] = (COLOR_INFO << 8) | ('0' + (minutes / 10));
    vga[24 * 80 + 64] = (COLOR_INFO << 8) | ('0' + (minutes % 10));
    vga[24 * 80 + 65] = (COLOR_INFO << 8) | ':';
    vga[24 * 80 + 66] = (COLOR_INFO << 8) | ('0' + (seconds / 10));
    vga[24 * 80 + 67] = (COLOR_INFO << 8) | ('0' + (seconds % 10));

    vga[24 * 80 + 70] = (COLOR_INFO << 8) | 'N';
    vga[24 * 80 + 71] = (COLOR_INFO << 8) | 'e';
    vga[24 * 80 + 72] = (COLOR_INFO << 8) | 't';
    vga[24 * 80 + 73] = (COLOR_INFO << 8) | ':';
    vga[24 * 80 + 74] = (COLOR_SUCCESS << 8) | '1';
    vga[24 * 80 + 75] = (COLOR_INFO << 8) | '/';
    vga[24 * 80 + 76] = (COLOR_ERROR << 8) | '0';
}

void draw_status_bar(void) {
    if (editor_is_active()) return;

    theme_t t = themes[current_theme];
    fb_fill_rect(0, 0, 80, 1, t.panel);
    fb_draw_text(2, 0, "TeaOS v1.0", t.panel);
    fb_draw_text(20, 0, "- A cozy kernel", t.panel);

    char vt_str[20];
    vt_str[0] = '[';
    vt_str[1] = 'T';
    vt_str[2] = 'T';
    vt_str[3] = 'Y';
    vt_str[4] = '0' + (current_vt + 1);
    vt_str[5] = ']';
    vt_str[6] = 0;
    fb_draw_text(55, 0, vt_str, t.accent);

    fb_draw_text(65, 0, "[Alt+F1-F6]", t.panel);
}

void draw_prompt(void) {
    theme_t t = themes[current_theme];
    fb_draw_text(0, 23, "tea@teos:~$ ", t.accent);
}

void vt_save(int vt_num) {
    volatile uint16_t *vga = (volatile uint16_t*)0xB8000;
    for (int i = 0; i < 80 * 25; i++) {
        vt_buffers[vt_num][i] = vga[i];
    }
}

void vt_restore(int vt_num) {
    volatile uint16_t *vga = (volatile uint16_t*)0xB8000;
    for (int i = 0; i < 80 * 25; i++) {
        vga[i] = vt_buffers[vt_num][i];
    }
}

void vt_switch(int new_vt) {
    if (new_vt == current_vt || new_vt < 0 || new_vt >= VT_COUNT) return;

    vt_save(current_vt);
    current_vt = new_vt;
    vt_restore(current_vt);
}

void vt_init_all(void) {
    for (int i = 0; i < VT_COUNT; i++) {
        for (int j = 0; j < 256; j++) {
            vts[i].input_buffer[j] = 0;
        }
        vts[i].input_len = 0;
        vts[i].cursor_visible = 1;
        vts[i].tick_counter = 0;
        vts[i].history_pos = -1;

        for (int j = 0; j < 80 * 25; j++) {
            vt_buffers[i][j] = 0x0F00 | ' ';
        }
    }
}

void handle_input(void) {
    uint8_t key = keyboard_read();
    if (key == 0) return;

    if (key >= 16 && key <= 21) {
        vt_switch(key - 16);
        return;
    }

    vt_t *vt = &vts[current_vt];

    if (editor_is_active()) {
        editor_handle_key(key);
        return;
    }

    if (key == '\n') {
        theme_t t = themes[current_theme];
        char prompt_line[80];
        shell_strcopy(prompt_line, "tea@teos:~$ ");
        int plen = 12;
        int max_cmd = 79 - plen;
        int cmd_len = vt->input_len < max_cmd ? vt->input_len : max_cmd;
        for (int i = 0; i < cmd_len; i++)
            prompt_line[plen + i] = vt->input_buffer[i];
        prompt_line[plen + cmd_len] = 0;
        shell_println(prompt_line, t.accent);

        if (vt->input_len > 0) {
            add_to_history(vt->input_buffer);
            shell_execute(vt->input_buffer);
        }
        vt->input_len = 0;
        for (int i = 0; i < 256; i++) vt->input_buffer[i] = 0;
        vt->history_pos = -1;
        input_len_prev = 0;
        fb_clear_region(12, 23, 68, 1);
        draw_prompt();
    } else if (key == '\b') {
        if (vt->input_len > 0) {
            vt->input_len--;
            vt->input_buffer[vt->input_len] = 0;
        }
    } else if (key == 1) {
        int count = get_history_count();
        if (count > 0 && vt->history_pos < count - 1) {
            if (vt->history_pos == -1) vt->history_pos = count - 1;
            else vt->history_pos++;
            const char *hist = get_history(vt->history_pos);
            if (hist) {
                shell_strcopy(vt->input_buffer, hist);
                vt->input_len = shell_strlen(vt->input_buffer);
            }
        }
    } else if (key == 2) {
        if (vt->history_pos > 0) {
            vt->history_pos--;
            const char *hist = get_history(vt->history_pos);
            if (hist) {
                shell_strcopy(vt->input_buffer, hist);
                vt->input_len = shell_strlen(vt->input_buffer);
            }
        } else if (vt->history_pos == 0) {
            vt->history_pos = -1;
            vt->input_len = 0;
            for (int i = 0; i < 256; i++) vt->input_buffer[i] = 0;
        }
    } else if (vt->input_len < 64 && key >= 32 && key < 127) {
        vt->input_buffer[vt->input_len++] = key;
        vt->input_buffer[vt->input_len] = 0;
    }
}

void __attribute__((section(".text.entry"))) kmain(void) {
    running = 1;

    idt_init();
    mem_init();
    fb_init();
    keyboard_init();
    mouse_init();
    tvm_init();
    fs_init();
    shell_init();
    editor_init();
    net_init();

    vt_init_all();

    fb_clear(COLOR_FG);
    draw_status_bar();

    theme_t t = themes[current_theme];
    fb_draw_text(2, 2, "Welcome to TeaOS - A cozy kernel experience!", t.title);
    fb_draw_text(2, 3, "Type 'whoami' to meet TeaOS, or 'help' for commands.", COLOR_FG);
    fb_draw_text(2, 4, "Try: edit test.c | teas LOAD T0 5 | touch hello.txt", t.accent);
    fb_draw_text(2, 5, "Switch terminals with Alt+F1 through Alt+F6", COLOR_INFO);
    draw_prompt();
    vt_save(0);

    for (int i = 1; i < VT_COUNT; i++) {
        fb_clear(COLOR_FG);
        current_vt = i;
        draw_status_bar();

        char tty_msg[30];
        tty_msg[0] = 'T';
        tty_msg[1] = 'T';
        tty_msg[2] = 'Y';
        tty_msg[3] = '0' + (i + 1);
        tty_msg[4] = ' ';
        tty_msg[5] = '-';
        tty_msg[6] = ' ';
        tty_msg[7] = 'T';
        tty_msg[8] = 'e';
        tty_msg[9] = 'a';
        tty_msg[10] = 'O';
        tty_msg[11] = 'S';
        tty_msg[12] = 0;

        fb_draw_text(2, 2, tty_msg, t.title);
        fb_draw_text(2, 3, "Type 'help' for available commands", COLOR_FG);
        draw_prompt();
        vt_save(i);
    }

    current_vt = 0;
    vt_restore(0);

    __asm__ volatile ("sti");

    while (running) {
        system_ticks++;

        keyboard_handle();
        mouse_handle();
        handle_input();

        vt_t *vt = &vts[current_vt];

        if (vt->input_len != input_len_prev) {
            fb_clear_region(12, 23, 68, 1);
            draw_prompt();
            fb_draw_text(12, 23, vt->input_buffer, COLOR_FG);
            input_len_prev = vt->input_len;
        }

        vt->tick_counter++;
        if (vt->tick_counter > 50000) {
            vt->cursor_visible = !vt->cursor_visible;
            vt->tick_counter = 0;

            if (vt->input_len < 67) {
                theme_t t = themes[current_theme];
                fb_draw_text(12 + vt->input_len, 23, vt->cursor_visible ? "_" : " ", vt->cursor_visible ? t.accent : COLOR_FG);
            }
        }

        draw_debug_bar();

        for (volatile int i = 0; i < 1000; i++);
    }

    __asm__ volatile (
        "cli\n"
        "hlt\n"
    );
}