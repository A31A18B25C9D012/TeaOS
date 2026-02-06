#include "filesystem.h"
#include "shell.h"

extern void fb_draw_text(uint32_t x, uint32_t y, const char *text, uint32_t color);

static file_t files[MAX_FILES];
static uint32_t cwd = 0;
static char pwd_buf[128];

void fs_init(void) {
    for (int i = 0; i < MAX_FILES; i++) {
        files[i].used = 0;
        files[i].size = 0;
        files[i].name[0] = 0;
        files[i].type = FS_TYPE_FILE;
        files[i].parent = 0;
    }
    files[0].used = 1;
    files[0].type = FS_TYPE_DIR;
    files[0].name[0] = '/';
    files[0].name[1] = 0;
    files[0].parent = 0;
    cwd = 0;
}

int fs_create(const char *name) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (files[i].used && files[i].parent == cwd &&
            files[i].type == FS_TYPE_FILE &&
            shell_strcmp(files[i].name, name) == 0)
            return -1;
    }

    for (int i = 1; i < MAX_FILES; i++) {
        if (!files[i].used) {
            files[i].used = 1;
            files[i].size = 0;
            files[i].type = FS_TYPE_FILE;
            files[i].parent = cwd;
            shell_strcopy(files[i].name, name);
            return i;
        }
    }
    return -1;
}

int fs_delete(const char *name) {
    for (int i = 1; i < MAX_FILES; i++) {
        if (files[i].used && files[i].parent == cwd &&
            files[i].type == FS_TYPE_FILE &&
            shell_strcmp(files[i].name, name) == 0) {
            files[i].used = 0;
            files[i].size = 0;
            files[i].name[0] = 0;
            return 0;
        }
    }
    return -1;
}

int fs_delete_recursive(const char *name) {
    for (int i = 1; i < MAX_FILES; i++) {
        if (files[i].used && files[i].parent == cwd &&
            shell_strcmp(files[i].name, name) == 0) {
            if (files[i].type == FS_TYPE_DIR) {
                for (int j = 1; j < MAX_FILES; j++) {
                    if (files[j].used && files[j].parent == (uint32_t)i) {
                        files[j].used = 0;
                        files[j].size = 0;
                        files[j].name[0] = 0;
                    }
                }
            }
            files[i].used = 0;
            files[i].size = 0;
            files[i].name[0] = 0;
            return 0;
        }
    }
    return -1;
}

file_t* fs_open(const char *name) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (files[i].used && files[i].parent == cwd &&
            shell_strcmp(files[i].name, name) == 0) {
            return &files[i];
        }
    }
    return NULL;
}

int fs_write(file_t *file, const uint8_t *data, uint32_t size) {
    if (!file || size > MAX_FILESIZE) return -1;

    for (uint32_t i = 0; i < size; i++) {
        file->data[i] = data[i];
    }
    file->size = size;
    return size;
}

int fs_read(file_t *file, uint8_t *data, uint32_t size) {
    if (!file) return -1;

    uint32_t read_size = size < file->size ? size : file->size;
    for (uint32_t i = 0; i < read_size; i++) {
        data[i] = file->data[i];
    }
    return read_size;
}

int fs_mkdir(const char *name) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (files[i].used && files[i].parent == cwd &&
            shell_strcmp(files[i].name, name) == 0)
            return -1;
    }

    for (int i = 1; i < MAX_FILES; i++) {
        if (!files[i].used) {
            files[i].used = 1;
            files[i].size = 0;
            files[i].type = FS_TYPE_DIR;
            files[i].parent = cwd;
            shell_strcopy(files[i].name, name);
            return i;
        }
    }
    return -1;
}

int fs_chdir(const char *name) {
    if (shell_strcmp(name, "/") == 0) {
        cwd = 0;
        return 0;
    }

    if (shell_strcmp(name, "..") == 0) {
        cwd = files[cwd].parent;
        return 0;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (files[i].used && files[i].parent == cwd &&
            files[i].type == FS_TYPE_DIR &&
            shell_strcmp(files[i].name, name) == 0) {
            cwd = i;
            return 0;
        }
    }
    return -1;
}

const char* fs_pwd(void) {
    if (cwd == 0) {
        pwd_buf[0] = '/';
        pwd_buf[1] = 0;
        return pwd_buf;
    }

    char parts[8][MAX_FILENAME];
    int depth = 0;
    uint32_t idx = cwd;

    while (idx != 0 && depth < 8) {
        shell_strcopy(parts[depth], files[idx].name);
        depth++;
        idx = files[idx].parent;
    }

    int pos = 0;
    for (int i = depth - 1; i >= 0; i--) {
        pwd_buf[pos++] = '/';
        int len = shell_strlen(parts[i]);
        for (int j = 0; j < len && pos < 126; j++) {
            pwd_buf[pos++] = parts[i][j];
        }
    }
    pwd_buf[pos] = 0;
    return pwd_buf;
}

int fs_is_dir(const char *name) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (files[i].used && files[i].parent == cwd &&
            shell_strcmp(files[i].name, name) == 0) {
            return files[i].type == FS_TYPE_DIR;
        }
    }
    return 0;
}

uint32_t fs_get_cwd(void) {
    return cwd;
}

static void int_to_str(uint32_t val, char *buf) {
    if (val == 0) { buf[0] = '0'; buf[1] = 0; return; }
    char tmp[12];
    int len = 0;
    while (val > 0) { tmp[len++] = '0' + (val % 10); val /= 10; }
    for (int i = 0; i < len; i++) buf[i] = tmp[len - 1 - i];
    buf[len] = 0;
}

void fs_list(void) {
    shell_println("=== File System ===", COLOR_TITLE);
    int count = 0;

    for (int i = 0; i < MAX_FILES && count < 18; i++) {
        if (files[i].used && files[i].parent == cwd && (uint32_t)i != cwd) {
            char line[80];
            int pos = 0;
            line[pos++] = ' '; line[pos++] = ' ';

            if (files[i].type == FS_TYPE_DIR) {
                line[pos++] = '[';
                int nlen = shell_strlen(files[i].name);
                for (int j = 0; j < nlen; j++) line[pos++] = files[i].name[j];
                line[pos++] = ']';
            } else {
                int nlen = shell_strlen(files[i].name);
                for (int j = 0; j < nlen; j++) line[pos++] = files[i].name[j];
            }
            line[pos] = 0;

            shell_println(line, files[i].type == FS_TYPE_DIR ? COLOR_TITLE : COLOR_FG);
            count++;
        }
    }

    if (count == 0) {
        shell_println("  No files found. Use 'touch <name>' to create.", COLOR_INFO);
    }
}

void fs_list_long(void) {
    shell_println("=== File System (detailed) ===", COLOR_TITLE);
    int count = 0;

    for (int i = 0; i < MAX_FILES && count < 18; i++) {
        if (files[i].used && files[i].parent == cwd && (uint32_t)i != cwd) {
            char line[80];
            int pos = 0;
            line[pos++] = ' '; line[pos++] = ' ';

            if (files[i].type == FS_TYPE_DIR) {
                line[pos++] = 'd'; line[pos++] = 'i'; line[pos++] = 'r';
            } else {
                line[pos++] = ' '; line[pos++] = ' '; line[pos++] = ' ';
            }

            for (int j = pos; j < 8; j++) line[j] = ' ';
            pos = 8;

            char sizebuf[12];
            int_to_str(files[i].size, sizebuf);
            int slen = shell_strlen(sizebuf);
            for (int j = 0; j < 6 - slen; j++) line[pos++] = ' ';
            for (int j = 0; j < slen; j++) line[pos++] = sizebuf[j];
            line[pos++] = 'B'; line[pos++] = ' '; line[pos++] = ' ';

            int nlen = shell_strlen(files[i].name);
            for (int j = 0; j < nlen; j++) line[pos++] = files[i].name[j];
            line[pos] = 0;

            shell_println(line, files[i].type == FS_TYPE_DIR ? COLOR_TITLE : COLOR_FG);
            count++;
        }
    }

    if (count == 0) {
        shell_println("  No files found.", COLOR_INFO);
    }
}