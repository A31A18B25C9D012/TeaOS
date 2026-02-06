#include "types.h"

extern void fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
extern void fb_draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
extern void fb_draw_text(uint32_t x, uint32_t y, const char *text, uint32_t color);
extern void fb_clear(uint32_t color);
extern void* mem_alloc(size_t size);
extern void mem_free(void *ptr);
extern void* xfce_get_component(const char *name);

typedef struct window {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    char *title;
    int visible;
    int focus;
    struct window *next;
} window_t;

static window_t *windows = NULL;
static window_t *focus_window = NULL;

typedef struct button {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    char *text;
    void (*callback)(void);
    struct button *next;
} button_t;

static button_t *buttons = NULL;

window_t* gui_create_window(uint32_t x, uint32_t y, uint32_t w, uint32_t h, const char *title) {
    window_t *win = (window_t*)mem_alloc(sizeof(window_t));
    if (!win) return NULL;
    
    win->x = x;
    win->y = y;
    win->width = w;
    win->height = h;
    win->visible = 1;
    win->focus = 0;
    
    size_t title_len = 0;
    while (title[title_len]) title_len++;
    win->title = (char*)mem_alloc(title_len + 1);
    if (win->title) {
        for (size_t i = 0; i <= title_len; i++) {
            win->title[i] = title[i];
        }
    }
    
    win->next = windows;
    windows = win;
    
    if (!focus_window) {
        focus_window = win;
        win->focus = 1;
    }
    
    return win;
}

void gui_draw_window(window_t *win) {
    if (!win || !win->visible) return;
    
    fb_fill_rect(win->x, win->y, win->width, 28, win->focus ? COLOR_TITLE : COLOR_BORDER);
    fb_fill_rect(win->x, win->y + 28, win->width, win->height - 28, COLOR_BG);
    fb_draw_rect(win->x, win->y, win->width, win->height, COLOR_BORDER);
    
    if (win->title) {
        fb_draw_text(win->x + 10, win->y + 10, win->title, COLOR_FG);
    }
    
    fb_fill_rect(win->x + win->width - 24, win->y + 4, 20, 20, COLOR_ACCENT);
    fb_draw_text(win->x + win->width - 20, win->y + 8, "X", COLOR_BG);
}

void gui_destroy_window(window_t *win) {
    if (!win) return;
    
    window_t **current = &windows;
    while (*current) {
        if (*current == win) {
            *current = win->next;
            if (focus_window == win) {
                focus_window = windows;
                if (windows) windows->focus = 1;
            }
            if (win->title) mem_free(win->title);
            mem_free(win);
            return;
        }
        current = &(*current)->next;
    }
}

button_t* gui_create_button(uint32_t x, uint32_t y, uint32_t w, uint32_t h, const char *text, void (*cb)(void)) {
    button_t *btn = (button_t*)mem_alloc(sizeof(button_t));
    if (!btn) return NULL;
    
    btn->x = x;
    btn->y = y;
    btn->width = w;
    btn->height = h;
    btn->callback = cb;
    
    size_t text_len = 0;
    while (text[text_len]) text_len++;
    btn->text = (char*)mem_alloc(text_len + 1);
    if (btn->text) {
        for (size_t i = 0; i <= text_len; i++) {
            btn->text[i] = text[i];
        }
    }
    
    btn->next = buttons;
    buttons = btn;
    
    return btn;
}

void gui_draw_button(button_t *btn) {
    if (!btn) return;
    
    fb_fill_rect(btn->x, btn->y, btn->width, btn->height, COLOR_ACTIVE);
    fb_draw_rect(btn->x, btn->y, btn->width, btn->height, COLOR_BORDER);
    
    if (btn->text) {
        uint32_t text_len = 0;
        while (btn->text[text_len]) text_len++;
        uint32_t text_x = btn->x + (btn->width / 2) - (text_len * 4);
        uint32_t text_y = btn->y + (btn->height / 2) - 6;
        fb_draw_text(text_x, text_y, btn->text, COLOR_FG);
    }
}

void gui_draw_panel(void) {
    fb_fill_rect(0, 0, FB_WIDTH, 36, COLOR_PANEL);
    fb_draw_rect(0, 0, FB_WIDTH, 36, COLOR_BORDER);
    
    fb_draw_text(12, 12, "sys", COLOR_FG);
}

void gui_render(void) {
    fb_clear(COLOR_BG);
    
    gui_draw_panel();
    
    window_t *win = windows;
    while (win) {
        gui_draw_window(win);
        win = win->next;
    }
    
    button_t *btn = buttons;
    while (btn) {
        gui_draw_button(btn);
        btn = btn->next;
    }
}

void gui_handle_click(uint32_t x, uint32_t y) {
    button_t *btn = buttons;
    while (btn) {
        if (x >= btn->x && x < btn->x + btn->width &&
            y >= btn->y && y < btn->y + btn->height) {
            if (btn->callback) btn->callback();
            return;
        }
        btn = btn->next;
    }
    
    window_t *win = windows;
    while (win) {
        if (x >= win->x && x < win->x + win->width &&
            y >= win->y && y < win->y + 28) {
            if (x >= win->x + win->width - 24 && x < win->x + win->width - 4) {
                gui_destroy_window(win);
                return;
            }
            if (focus_window) focus_window->focus = 0;
            focus_window = win;
            win->focus = 1;
            return;
        }
        win = win->next;
    }
}

void gui_cleanup(void) {
    while (windows) {
        window_t *next = windows->next;
        if (windows->title) mem_free(windows->title);
        mem_free(windows);
        windows = next;
    }
    
    while (buttons) {
        button_t *next = buttons->next;
        if (buttons->text) mem_free(buttons->text);
        mem_free(buttons);
        buttons = next;
    }
}