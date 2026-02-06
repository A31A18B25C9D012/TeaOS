#ifndef TYPES_H
#define TYPES_H

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long long int64_t;

typedef uint32_t size_t;
typedef uint32_t uintptr_t;

#define NULL ((void*)0)

#define FB_WIDTH 80
#define FB_HEIGHT 25
#define FB_BPP 16
#define FB_BASE 0xB8000

#define XFCE_PRELOAD_BASE 0x400000
#define XFCE_PRELOAD_SIZE 0x800000

#define L2_CACHE_SIZE 0x40000
#define L2_CACHE_BASE 0x20000

#define HEAP_START 0x100000
#define HEAP_SIZE 0x200000

#define THEME_ORANGE 0
#define THEME_BLUE 1
#define THEME_GREEN 2

#define COLOR_BG 0x00
#define COLOR_FG 0x0F
#define COLOR_PANEL 0x60
#define COLOR_BORDER 0x06
#define COLOR_TITLE 0x0E
#define COLOR_ACCENT 0x0C
#define COLOR_ACTIVE 0x06
#define COLOR_ERROR 0x0C
#define COLOR_SUCCESS 0x0A
#define COLOR_INFO 0x0B

static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint16_t inw(uint16_t port) {
    uint16_t ret;
    __asm__ volatile ("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile ("outw %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t ret;
    __asm__ volatile ("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outl(uint16_t port, uint32_t val) {
    __asm__ volatile ("outl %0, %1" : : "a"(val), "Nd"(port));
}

#endif