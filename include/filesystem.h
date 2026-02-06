#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include "types.h"

#define MAX_FILES 32
#define MAX_FILENAME 32
#define MAX_FILESIZE 4096

#define FS_TYPE_FILE 0
#define FS_TYPE_DIR  1

typedef struct {
    char name[MAX_FILENAME];
    uint32_t size;
    uint8_t data[MAX_FILESIZE];
    uint8_t used;
    uint8_t type;
    uint32_t parent;
} file_t;

void fs_init(void);
int fs_create(const char *name);
int fs_delete(const char *name);
int fs_delete_recursive(const char *name);
file_t* fs_open(const char *name);
int fs_write(file_t *file, const uint8_t *data, uint32_t size);
int fs_read(file_t *file, uint8_t *data, uint32_t size);
void fs_list(void);
void fs_list_long(void);
int fs_mkdir(const char *name);
int fs_chdir(const char *name);
const char* fs_pwd(void);
int fs_is_dir(const char *name);
uint32_t fs_get_cwd(void);

#endif