[BITS 16]
[ORG 0x7C00]

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    mov si, msg_load
    call print

    mov ax, 0x2000
    mov es, ax
    xor bx, bx
    mov ah, 0x02
    mov al, 126
    mov ch, 0
    mov cl, 2
    mov dh, 0
    mov dl, 0x80
    int 0x13
    jc error

    mov ax, 0x2FC0
    mov es, ax
    xor bx, bx
    mov ah, 0x02
    mov al, 20
    mov ch, 0
    mov cl, 2
    mov dh, 2
    mov dl, 0x80
    int 0x13
    jc error

    call enable_a20
    call load_gdt
    call enter_protected

error:
    mov si, msg_err
    call print
    hlt

print:
    lodsb
    or al, al
    jz print_done
    mov ah, 0x0E
    int 0x10
    jmp print
print_done:
    ret

enable_a20:
    in al, 0x92
    or al, 2
    out 0x92, al
    ret

load_gdt:
    lgdt [gdt_descriptor]
    ret

enter_protected:
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:protected_start

[BITS 32]
protected_start:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x90000

    call setup_l2_cache
    call 0x20000

setup_l2_cache:
    mov eax, cr0
    and eax, 0x9FFFFFFF
    mov cr0, eax
    
    mov ecx, 0x200
    xor eax, eax
    xor edx, edx
    wrmsr
    
    mov ecx, 0x201
    mov eax, 0x06
    xor edx, edx
    wrmsr
    
    mov eax, cr0
    or eax, 0x60000000
    mov cr0, eax
    
    wbinvd
    ret

halt:
    hlt
    jmp halt

gdt_start:
    dq 0x0000000000000000
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

msg_load db 'load', 13, 10, 0
msg_err db 'err', 13, 10, 0

times 510-($-$$) db 0
dw 0xAA55