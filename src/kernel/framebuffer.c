#include "types.h"

static uint16_t *fb = (uint16_t*)FB_BASE;
static uint32_t fb_width = FB_WIDTH;
static uint32_t fb_height = FB_HEIGHT;

void fb_init(void) {
    for (uint32_t i = 0; i < fb_width * fb_height; i++) {
        fb[i] = 0x0F00 | ' ';
    }
}

void fb_putchar(uint32_t x, uint32_t y, char c, uint8_t color) {
    if (x >= fb_width || y >= fb_height) return;
    fb[y * fb_width + x] = (color << 8) | c;
}

void fb_put_pixel(uint32_t x, uint32_t y, uint32_t color) {
    fb_putchar(x, y, ' ', color);
}

void fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    for (uint32_t j = y; j < y + h && j < fb_height; j++) {
        for (uint32_t i = x; i < x + w && i < fb_width; i++) {
            fb_putchar(i, j, ' ', color);
        }
    }
}

void fb_draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    for (uint32_t i = x; i < x + w && i < fb_width; i++) {
        fb_putchar(i, y, ' ', color);
        if (y + h > 0 && y + h - 1 < fb_height) fb_putchar(i, y + h - 1, ' ', color);
    }
    for (uint32_t j = y; j < y + h && j < fb_height; j++) {
        fb_putchar(x, j, ' ', color);
        if (x + w > 0 && x + w - 1 < fb_width) fb_putchar(x + w - 1, j, ' ', color);
    }
}

void fb_clear(uint32_t color) {
    for (uint32_t i = 0; i < fb_width * fb_height; i++) {
        fb[i] = (color << 8) | ' ';
    }
}

void fb_draw_char(uint32_t x, uint32_t y, char c, uint32_t color) {
    fb_putchar(x, y, c, color);
}

void fb_draw_text(uint32_t x, uint32_t y, const char *text, uint32_t color) {
    uint32_t cx = x;
    while (*text && cx < fb_width) {
        if (*text == '\n') {
            y++;
            cx = x;
        } else {
            fb_putchar(cx, y, *text, color);
            cx++;
        }
        text++;
    }
}

void fb_wipe(void) {
    for (uint32_t i = 0; i < fb_width * fb_height; i++) {
        fb[i] = 0;
    }
}

void fb_clear_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    for (uint32_t j = y; j < y + h && j < fb_height; j++) {
        for (uint32_t i = x; i < x + w && i < fb_width; i++) {
            fb_putchar(i, j, ' ', COLOR_FG);
        }
    }
}

void fb_draw_text_clear(uint32_t x, uint32_t y, const char *text, uint32_t width) {
    fb_clear_region(x, y, width, 1);
    fb_draw_text(x, y, text, COLOR_FG);
}

void fb_scroll_up(void) {
    for (uint32_t y = 1; y < 23; y++) {
        for (uint32_t x = 0; x < fb_width; x++) {
            fb[y * fb_width + x] = fb[(y + 1) * fb_width + x];
        }
    }

    for (uint32_t x = 0; x < fb_width; x++) {
        fb[23 * fb_width + x] = (COLOR_FG << 8) | ' ';
    }
}

void fb_scroll_down(void) {
    for (uint32_t y = 22; y >= 1 && y < 25; y--) {
        for (uint32_t x = 0; x < fb_width; x++) {
            fb[(y + 1) * fb_width + x] = fb[y * fb_width + x];
        }
    }

    for (uint32_t x = 0; x < fb_width; x++) {
        fb[1 * fb_width + x] = (COLOR_FG << 8) | ' ';
    }
}