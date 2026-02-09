#include "types.h"

static inline void wbinvd(void) {
    __asm__ volatile ("wbinvd");
}

static inline void invd(void) {
    __asm__ volatile ("invd");
}

static inline void clflush(void *addr) {
    __asm__ volatile ("clflush (%0)" : : "r"(addr));
}

static inline void wrmsr(uint32_t msr, uint32_t low, uint32_t high) {
    __asm__ volatile ("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}

static inline void rdmsr(uint32_t msr, uint32_t *low, uint32_t *high) {
    __asm__ volatile ("rdmsr" : "=a"(*low), "=d"(*high) : "c"(msr));
}

void cache_lock_region(uintptr_t base, size_t size) {
    uint32_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1 << 30);
    cr0 &= ~(1 << 29);
    __asm__ volatile ("mov %0, %%cr0" : : "r"(cr0));
    
    wrmsr(0x200, 0, 0);
    wrmsr(0x201, 0x06, 0);
    
    for (size_t i = 0; i < size; i += 64) {
        volatile uint8_t *ptr = (volatile uint8_t*)(base + i);
        uint8_t dummy = *ptr;
        (void)dummy;
    }
}

void cache_unlock_all(void) {
    uint32_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~((1 << 30) | (1 << 29));
    __asm__ volatile ("mov %0, %%cr0" : : "r"(cr0));
    
    wbinvd();
}

void cache_init(void) {
    wbinvd();
}

void cache_wipe(void) {
    wbinvd();
    invd();
}