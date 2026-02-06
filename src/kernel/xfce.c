#include "types.h"

extern void mem_copy(void *dst, const void *src, size_t n);
extern void mem_set(void *dst, uint8_t val, size_t n);

typedef struct xfce_component {
    char name[32];
    void *data;
    size_t size;
    int loaded;
} xfce_component_t;

static xfce_component_t components[16];
static int component_count = 0;

static uint8_t *preload_memory = (uint8_t*)XFCE_PRELOAD_BASE;
static size_t preload_offset = 0;

void xfce_register_component(const char *name, size_t size) {
    if (component_count >= 16) return;
    
    xfce_component_t *comp = &components[component_count];
    
    int i = 0;
    while (name[i] && i < 31) {
        comp->name[i] = name[i];
        i++;
    }
    comp->name[i] = 0;
    
    comp->data = preload_memory + preload_offset;
    comp->size = size;
    comp->loaded = 0;
    
    preload_offset += size;
    component_count++;
}

void xfce_preload_all(void) {
    for (int i = 0; i < component_count; i++) {
        xfce_component_t *comp = &components[i];
        
        volatile uint8_t *vdata = (volatile uint8_t*)comp->data;
        for (size_t j = 0; j < comp->size; j++) {
            vdata[j] = 0;
        }
        
        comp->loaded = 1;
    }
}

void* xfce_get_component(const char *name) {
    for (int i = 0; i < component_count; i++) {
        xfce_component_t *comp = &components[i];
        
        int match = 1;
        for (int j = 0; j < 32; j++) {
            if (comp->name[j] != name[j]) {
                match = 0;
                break;
            }
            if (comp->name[j] == 0) break;
        }
        
        if (match && comp->loaded) {
            return comp->data;
        }
    }
    
    return NULL;
}

void xfce_init(void) {
    xfce_register_component("panel", 0x40000);
    xfce_register_component("window_manager", 0x80000);
    xfce_register_component("desktop", 0x40000);
    xfce_register_component("menu", 0x20000);
    xfce_register_component("icons", 0x100000);
    xfce_register_component("themes", 0x80000);
    xfce_register_component("compositor", 0x60000);
    xfce_register_component("settings", 0x40000);
    
    xfce_preload_all();
}

void xfce_wipe(void) {
    volatile uint8_t *vmem = (volatile uint8_t*)XFCE_PRELOAD_BASE;
    for (size_t i = 0; i < XFCE_PRELOAD_SIZE; i++) {
        vmem[i] = 0;
    }
    
    for (int i = 0; i < component_count; i++) {
        components[i].loaded = 0;
    }
}