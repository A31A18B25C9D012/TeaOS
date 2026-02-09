#include "types.h"

static uint8_t heap[HEAP_SIZE] __attribute__((aligned(4096)));
static size_t heap_offset __attribute__((unused)) = 0;

typedef struct block {
    size_t size;
    int used;
    struct block *next;
} block_t;

static block_t *head = NULL;

void mem_init(void) {
    head = (block_t*)heap;
    head->size = HEAP_SIZE - sizeof(block_t);
    head->used = 0;
    head->next = NULL;
}

void* mem_alloc(size_t size) {
    if (size == 0) return NULL;
    
    size = (size + 7) & ~7;
    
    block_t *current = head;
    while (current) {
        if (!current->used && current->size >= size) {
            if (current->size >= size + sizeof(block_t) + 8) {
                block_t *new = (block_t*)((uint8_t*)current + sizeof(block_t) + size);
                new->size = current->size - size - sizeof(block_t);
                new->used = 0;
                new->next = current->next;
                current->next = new;
                current->size = size;
            }
            current->used = 1;
            return (void*)((uint8_t*)current + sizeof(block_t));
        }
        current = current->next;
    }
    
    return NULL;
}

void mem_free(void *ptr) {
    if (!ptr) return;
    
    block_t *block = (block_t*)((uint8_t*)ptr - sizeof(block_t));
    
    volatile uint8_t *vptr = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < block->size; i++) {
        vptr[i] = 0;
    }
    
    block->used = 0;
    
    block_t *current = head;
    while (current && current->next) {
        if (!current->used && current->next && !current->next->used) {
            current->size += sizeof(block_t) + current->next->size;
            current->next = current->next->next;
        } else {
            current = current->next;
        }
    }
}

void mem_copy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t*)dst;
    const uint8_t *s = (const uint8_t*)src;
    while (n--) {
        *d++ = *s++;
    }
}

void mem_set(void *dst, uint8_t val, size_t n) {
    uint8_t *d = (uint8_t*)dst;
    while (n--) {
        *d++ = val;
    }
}

void mem_wipe_all(void) {
    volatile uint8_t *vheap = (volatile uint8_t*)heap;
    
    for (size_t i = 0; i < HEAP_SIZE; i++) {
        vheap[i] = 0xFF;
    }
    for (size_t i = 0; i < HEAP_SIZE; i++) {
        vheap[i] = 0xAA;
    }
    for (size_t i = 0; i < HEAP_SIZE; i++) {
        vheap[i] = 0x55;
    }
    for (size_t i = 0; i < HEAP_SIZE; i++) {
        vheap[i] = 0x00;
    }
}