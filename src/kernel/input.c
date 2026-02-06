#include "types.h"

static uint8_t keyboard_buffer[256];
uint8_t keyboard_head = 0;
uint8_t keyboard_tail = 0;
static uint8_t shift_pressed = 0;
static uint8_t ctrl_pressed = 0;
static uint8_t alt_pressed = 0;

static uint32_t mouse_x = 0;
static uint32_t mouse_y = 0;
static uint8_t mouse_buttons = 0;

extern void gui_handle_click(uint32_t x, uint32_t y);

void keyboard_init(void) {
    keyboard_head = 0;
    keyboard_tail = 0;
}

uint8_t keyboard_read(void) {
    if (keyboard_head == keyboard_tail) {
        return 0;
    }
    uint8_t key = keyboard_buffer[keyboard_tail];
    keyboard_tail = (keyboard_tail + 1) % 256;
    return key;
}

void keyboard_handle(void) {
    uint8_t status = inb(0x64);
    if (!(status & 1)) return;
    if (status & 0x20) return;

    static uint8_t extended = 0;
    uint8_t scancode = inb(0x60);

    if (scancode == 0xE0) {
        extended = 1;
        return;
    }

    if (scancode & 0x80) {
        uint8_t key = scancode & 0x7F;
        if (key == 0x2A || key == 0x36) shift_pressed = 0;
        if (key == 0x1D) ctrl_pressed = 0;
        if (key == 0x38) alt_pressed = 0;
        extended = 0;
        return;
    }

    if (scancode == 0x2A || scancode == 0x36) {
        shift_pressed = 1;
        return;
    }
    if (scancode == 0x1D) {
        ctrl_pressed = 1;
        return;
    }
    if (scancode == 0x38) {
        alt_pressed = 1;
        return;
    }

    if (extended) {
        extended = 0;
        if (scancode == 0x48) {
            keyboard_buffer[keyboard_head] = alt_pressed ? 6 : 1;
            keyboard_head = (keyboard_head + 1) % 256;
        } else if (scancode == 0x50) {
            keyboard_buffer[keyboard_head] = alt_pressed ? 7 : 2;
            keyboard_head = (keyboard_head + 1) % 256;
        } else if (scancode == 0x4B) {
            keyboard_buffer[keyboard_head] = 4;
            keyboard_head = (keyboard_head + 1) % 256;
        } else if (scancode == 0x4D) {
            keyboard_buffer[keyboard_head] = 5;
            keyboard_head = (keyboard_head + 1) % 256;
        } else if (scancode == 0x1C) {
            keyboard_buffer[keyboard_head] = 10;
            keyboard_head = (keyboard_head + 1) % 256;
        }
        return;
    }

    if (scancode == 0x1C) {
        keyboard_buffer[keyboard_head] = 10;
        keyboard_head = (keyboard_head + 1) % 256;
        return;
    }

    if (scancode == 0x3B && !alt_pressed) {
        keyboard_buffer[keyboard_head] = 3;
        keyboard_head = (keyboard_head + 1) % 256;
        return;
    }

    if (alt_pressed && scancode >= 0x3B && scancode <= 0x40) {
        keyboard_buffer[keyboard_head] = 16 + (scancode - 0x3B);
        keyboard_head = (keyboard_head + 1) % 256;
        return;
    }

    static const char scancode_map[] = {
        0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 8,
        9, 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 0,
        0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
        0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
        '*', 0, ' '
    };

    if (scancode < sizeof(scancode_map)) {
        char c = scancode_map[scancode];
        if (c) {
            if (shift_pressed && c >= 'a' && c <= 'z') {
                c = c - 'a' + 'A';
            } else if (shift_pressed) {
                const char shift_map[][2] = {
                    {'1', '!'}, {'2', '@'}, {'3', '#'}, {'4', '$'},
                    {'5', '%'}, {'6', '^'}, {'7', '&'}, {'8', '*'},
                    {'9', '('}, {'0', ')'}, {'-', '_'}, {'=', '+'},
                    {'[', '{'}, {']', '}'}, {';', ':'}, {'\'', '"'},
                    {',', '<'}, {'.', '>'}, {'/', '?'}, {'\\', '|'},
                    {'`', '~'}, {0, 0}
                };
                for (int i = 0; shift_map[i][0]; i++) {
                    if (c == shift_map[i][0]) {
                        c = shift_map[i][1];
                        break;
                    }
                }
            }
            keyboard_buffer[keyboard_head] = c;
            keyboard_head = (keyboard_head + 1) % 256;
        }
    }
}

uint8_t keyboard_get_modifiers(void) {
    uint8_t mods = 0;
    if (shift_pressed) mods |= 1;
    if (ctrl_pressed) mods |= 2;
    if (alt_pressed) mods |= 4;
    return mods;
}

void mouse_init(void) {
    outb(0x64, 0xA8);
    outb(0x64, 0x20);
    uint8_t status = inb(0x60) | 2;
    outb(0x64, 0x60);
    outb(0x60, status);

    outb(0x64, 0xD4);
    outb(0x60, 0xF4);
    inb(0x60);

    mouse_x = FB_WIDTH / 2;
    mouse_y = FB_HEIGHT / 2;
    mouse_buttons = 0;
}

void mouse_handle(void) {
    static int packet_index = 0;
    static uint8_t packet[3];

    uint8_t status = inb(0x64);
    if (!(status & 0x21)) return;
    if (!(status & 0x20)) return;

    uint8_t data = inb(0x60);

    if (packet_index == 0 && !(data & 0x08)) return;

    packet[packet_index++] = data;
    if (packet_index == 3) {
        packet_index = 0;

        int dx = packet[1];
        int dy = packet[2];

        if (packet[0] & 0x10) dx |= 0xFFFFFF00;
        if (packet[0] & 0x20) dy |= 0xFFFFFF00;

        int new_x = (int)mouse_x + dx;
        int new_y = (int)mouse_y - dy;

        if (new_x < 0) new_x = 0;
        if (new_x >= (int)FB_WIDTH) new_x = FB_WIDTH - 1;
        if (new_y < 0) new_y = 0;
        if (new_y >= (int)FB_HEIGHT) new_y = FB_HEIGHT - 1;

        mouse_x = new_x;
        mouse_y = new_y;

        uint8_t old_buttons = mouse_buttons;
        mouse_buttons = packet[0] & 0x07;

        if ((mouse_buttons & 1) && !(old_buttons & 1)) {
            gui_handle_click(mouse_x, mouse_y);
        }
    }
}

void mouse_get_pos(uint32_t *x, uint32_t *y) {
    *x = mouse_x;
    *y = mouse_y;
}

uint8_t mouse_get_buttons(void) {
    return mouse_buttons;
}