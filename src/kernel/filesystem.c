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

    /* built-in kernel.asm - MicroKernel with Interactive Shell */
    {
        static const char kernel_asm[] =
            "; TeaOS MicroKernel - Interactive Shell\n"
            "push ebp\n"
            "push ebx\n"
            "push esi\n"
            "push edi\n"
            "\n"
            "; Clear screen (white on blue)\n"
            "mov edi, 0xB8000\n"
            "mov ecx, 2000\n"
            "mov ax, 0x1F20\n"
            "clear_loop:\n"
            "mov [edi], ax\n"
            "add edi, 2\n"
            "dec ecx\n"
            "jnz clear_loop\n"
            "\n"
            "; Header row 0 col 2\n"
            "mov edi, 0xB8004\n"
            "mov edx, 0x1F00\n"
            "call puts_inline\n"
            "db 0x54,0x65,0x61,0x4F,0x53,0x20,0x4D,0x69,0x63,0x72,0x6F,0x4B,0x65,0x72,0x6E,0x65,0x6C,0\n"
            "\n"
            "; Status row 2 col 2\n"
            "mov edi, 0xB8144\n"
            "mov edx, 0x0A00\n"
            "call puts_inline\n"
            "db 0x53,0x74,0x61,0x74,0x75,0x73,0x3A,0x20,0x52,0x75,0x6E,0x6E,0x69,0x6E,0x67,0\n"
            "\n"
            "; Tasks row 4 col 2\n"
            "mov edi, 0xB8284\n"
            "mov edx, 0x0E00\n"
            "call puts_inline\n"
            "db 0x54,0x61,0x73,0x6B,0x73,0x3A,0\n"
            "\n"
            "; Task 1 row 5 col 4\n"
            "mov edi, 0xB8328\n"
            "mov edx, 0x0A00\n"
            "call puts_inline\n"
            "db 0x31,0x2E,0x20,0x49,0x64,0x6C,0x65,0x20,0x20,0x20,0x20,0x20,0x52,0x45,0x41,0x44,0x59,0\n"
            "\n"
            "; Task 2 row 6 col 4\n"
            "mov edi, 0xB83C8\n"
            "mov edx, 0x0A00\n"
            "call puts_inline\n"
            "db 0x32,0x2E,0x20,0x53,0x63,0x68,0x65,0x64,0x20,0x20,0x20,0x20,0x52,0x45,0x41,0x44,0x59,0\n"
            "\n"
            "; Task 3 row 7 col 4\n"
            "mov edi, 0xB8468\n"
            "mov edx, 0x0A00\n"
            "call puts_inline\n"
            "db 0x33,0x2E,0x20,0x4D,0x65,0x6D,0x6F,0x72,0x79,0x20,0x20,0x20,0x52,0x45,0x41,0x44,0x59,0\n"
            "\n"
            "; Memory row 9 col 2\n"
            "mov edi, 0xB85A4\n"
            "mov edx, 0x0B00\n"
            "call puts_inline\n"
            "db 0x4D,0x65,0x6D,0x6F,0x72,0x79,0x3A,0x20,0x35,0x38,0x34,0x4B,0x20,0x66,0x72,0x65,0x65,0\n"
            "\n"
            "; Shell separator row 11 col 2\n"
            "mov edi, 0xB86E4\n"
            "mov edx, 0x0E00\n"
            "call puts_inline\n"
            "db 0x3D,0x3D,0x3D,0x20,0x53,0x68,0x65,0x6C,0x6C,0x20,0x3D,0x3D,0x3D,0\n"
            "\n"
            "; Hint row 23 col 2\n"
            "mov edi, 0xB8E64\n"
            "mov edx, 0x0800\n"
            "call puts_inline\n"
            "db 0x54,0x79,0x70,0x65,0x20,0x27,0x68,0x65,0x6C,0x70,0x27,0x20,0x66,0x6F,0x72,0x20,0x63,0x6F,0x6D,0x6D,0x61,0x6E,0x64,0x73,0\n"
            "\n"
            "; Init input\n"
            "xor ebx, ebx\n"
            "jmp cmd_done\n"
            "\n"
            "; === Shell input loop ===\n"
            "shell_loop:\n"
            "mov eax, 2\n"
            "int 0x80\n"
            "cmp eax, 10\n"
            "je process_cmd\n"
            "cmp eax, 8\n"
            "je handle_bs\n"
            "cmp eax, 32\n"
            "jl shell_loop\n"
            "cmp ebx, 40\n"
            "jge shell_loop\n"
            "; Store char in buffer\n"
            "mov ecx, 0x50000\n"
            "add ecx, ebx\n"
            "movb [ecx], eax\n"
            "; Echo to screen\n"
            "mov ecx, ebx\n"
            "shl ecx, 1\n"
            "add ecx, 0xB8C8C\n"
            "or eax, 0x0F00\n"
            "mov [ecx], ax\n"
            "inc ebx\n"
            "jmp shell_loop\n"
            "\n"
            "handle_bs:\n"
            "cmp ebx, 0\n"
            "je shell_loop\n"
            "dec ebx\n"
            "mov ecx, ebx\n"
            "shl ecx, 1\n"
            "add ecx, 0xB8C8C\n"
            "mov ax, 0x1F20\n"
            "mov [ecx], ax\n"
            "mov ecx, 0x50000\n"
            "add ecx, ebx\n"
            "xor eax, eax\n"
            "movb [ecx], eax\n"
            "jmp shell_loop\n"
            "\n"
            "; === Process command ===\n"
            "process_cmd:\n"
            "mov ecx, 0x50000\n"
            "add ecx, ebx\n"
            "xor eax, eax\n"
            "movb [ecx], eax\n"
            "cmp ebx, 0\n"
            "je cmd_done\n"
            "; Clear output rows 13-20\n"
            "push ebx\n"
            "mov edi, 0xB8820\n"
            "mov ecx, 640\n"
            "mov ax, 0x1F20\n"
            "co_loop:\n"
            "mov [edi], ax\n"
            "add edi, 2\n"
            "dec ecx\n"
            "jnz co_loop\n"
            "pop ebx\n"
            "; Match commands\n"
            "mov esi, 0x50000\n"
            "; Check exit\n"
            "mov eax, [esi]\n"
            "cmp eax, 0x74697865\n"
            "jne check_help\n"
            "movb eax, [esi+4]\n"
            "cmp eax, 0\n"
            "jne check_help\n"
            "jmp do_exit\n"
            "\n"
            "check_help:\n"
            "mov eax, [esi]\n"
            "cmp eax, 0x706C6568\n"
            "jne check_clear\n"
            "movb eax, [esi+4]\n"
            "cmp eax, 0\n"
            "jne check_clear\n"
            "; Show help\n"
            "mov edi, 0xB8824\n"
            "mov edx, 0x0E00\n"
            "call puts_inline\n"
            "db 0x41,0x76,0x61,0x69,0x6C,0x61,0x62,0x6C,0x65,0x20,0x63,0x6F,0x6D,0x6D,0x61,0x6E,0x64,0x73,0x3A,0\n"
            "mov edi, 0xB88C8\n"
            "mov edx, 0x0F00\n"
            "call puts_inline\n"
            "db 0x65,0x78,0x69,0x74,0x20,0x20,0x20,0x20,0x2D,0x20,0x52,0x65,0x74,0x75,0x72,0x6E,0x20,0x74,0x6F,0x20,0x54,0x65,0x61,0x4F,0x53,0\n"
            "mov edi, 0xB8968\n"
            "call puts_inline\n"
            "db 0x77,0x68,0x6F,0x61,0x6D,0x69,0x20,0x20,0x2D,0x20,0x53,0x68,0x6F,0x77,0x20,0x63,0x75,0x72,0x72,0x65,0x6E,0x74,0x20,0x75,0x73,0x65,0x72,0\n"
            "mov edi, 0xB8A08\n"
            "call puts_inline\n"
            "db 0x68,0x65,0x6C,0x70,0x20,0x20,0x20,0x20,0x2D,0x20,0x53,0x68,0x6F,0x77,0x20,0x74,0x68,0x69,0x73,0x20,0x6D,0x65,0x73,0x73,0x61,0x67,0x65,0\n"
            "mov edi, 0xB8AA8\n"
            "call puts_inline\n"
            "db 0x63,0x6C,0x65,0x61,0x72,0x20,0x20,0x20,0x2D,0x20,0x43,0x6C,0x65,0x61,0x72,0x20,0x6F,0x75,0x74,0x70,0x75,0x74,0\n"
            "jmp cmd_done\n"
            "\n"
            "check_clear:\n"
            "mov eax, [esi]\n"
            "cmp eax, 0x61656C63\n"
            "jne check_whoami\n"
            "movb eax, [esi+4]\n"
            "cmp eax, 0x72\n"
            "jne check_whoami\n"
            "movb eax, [esi+5]\n"
            "cmp eax, 0\n"
            "jne check_whoami\n"
            "jmp cmd_done\n"
            "\n"
            "check_whoami:\n"
            "mov eax, [esi]\n"
            "cmp eax, 0x616F6877\n"
            "jne unknown_cmd\n"
            "movb eax, [esi+4]\n"
            "cmp eax, 0x6D\n"
            "jne unknown_cmd\n"
            "movb eax, [esi+5]\n"
            "cmp eax, 0x69\n"
            "jne unknown_cmd\n"
            "movb eax, [esi+6]\n"
            "cmp eax, 0\n"
            "jne unknown_cmd\n"
            "; Show whoami\n"
            "mov edi, 0xB8824\n"
            "mov edx, 0x0A00\n"
            "call puts_inline\n"
            "db 0x55,0x73,0x65,0x72,0x3A,0x20,0x20,0x20,0x72,0x6F,0x6F,0x74,0\n"
            "mov edi, 0xB88C4\n"
            "call puts_inline\n"
            "db 0x48,0x6F,0x73,0x74,0x3A,0x20,0x20,0x20,0x74,0x65,0x61,0x6F,0x73,0x2D,0x75,0x6B,0\n"
            "mov edi, 0xB8964\n"
            "call puts_inline\n"
            "db 0x53,0x79,0x73,0x74,0x65,0x6D,0x3A,0x20,0x54,0x65,0x61,0x4F,0x53,0x20,0x4D,0x69,0x63,0x72,0x6F,0x4B,0x65,0x72,0x6E,0x65,0x6C,0\n"
            "mov edi, 0xB8A04\n"
            "call puts_inline\n"
            "db 0x41,0x72,0x63,0x68,0x3A,0x20,0x20,0x20,0x69,0x33,0x38,0x36,0\n"
            "jmp cmd_done\n"
            "\n"
            "unknown_cmd:\n"
            "mov edi, 0xB8824\n"
            "mov edx, 0x0C00\n"
            "call puts_inline\n"
            "db 0x55,0x6E,0x6B,0x6E,0x6F,0x77,0x6E,0x20,0x63,0x6F,0x6D,0x6D,0x61,0x6E,0x64,0\n"
            "jmp cmd_done\n"
            "\n"
            "; === Reset prompt ===\n"
            "cmd_done:\n"
            "xor ebx, ebx\n"
            "mov edi, 0x50000\n"
            "xor eax, eax\n"
            "mov ecx, 64\n"
            "clr_buf:\n"
            "movb [edi], eax\n"
            "inc edi\n"
            "dec ecx\n"
            "jnz clr_buf\n"
            "; Clear prompt row 20\n"
            "mov edi, 0xB8C80\n"
            "mov ecx, 80\n"
            "mov ax, 0x1F20\n"
            "clr_prompt:\n"
            "mov [edi], ax\n"
            "add edi, 2\n"
            "dec ecx\n"
            "jnz clr_prompt\n"
            "; Draw prompt\n"
            "mov edi, 0xB8C84\n"
            "mov edx, 0x1E00\n"
            "call puts_inline\n"
            "db 0x75,0x4B,0x3E,0x20,0\n"
            "jmp shell_loop\n"
            "\n"
            "; === Exit ===\n"
            "do_exit:\n"
            "mov edi, 0xB8000\n"
            "mov ecx, 2000\n"
            "mov ax, 0x0720\n"
            "exit_clr:\n"
            "mov [edi], ax\n"
            "add edi, 2\n"
            "dec ecx\n"
            "jnz exit_clr\n"
            "mov eax, 5\n"
            "int 0x80\n"
            "pop edi\n"
            "pop esi\n"
            "pop ebx\n"
            "pop ebp\n"
            "xor eax, eax\n"
            "ret\n"
            "\n"
            "; === puts_inline: print inline string ===\n"
            "; edi=VGA addr, edx=color<<8\n"
            "puts_inline:\n"
            "pop esi\n"
            "pi_loop:\n"
            "movb eax, [esi]\n"
            "cmp eax, 0\n"
            "je pi_done\n"
            "or eax, edx\n"
            "mov [edi], ax\n"
            "inc esi\n"
            "add edi, 2\n"
            "jmp pi_loop\n"
            "pi_done:\n"
            "inc esi\n"
            "push esi\n"
            "ret\n";
        files[1].used = 1;
        files[1].type = FS_TYPE_FILE;
        files[1].parent = 0;
        shell_strcopy(files[1].name, "kernel.asm");
        int sz = 0;
        while (kernel_asm[sz]) {
            files[1].data[sz] = kernel_asm[sz];
            sz++;
        }
        files[1].size = sz;
    }
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