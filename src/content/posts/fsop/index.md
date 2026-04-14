---
title: FSOP-Notes
published: 2026-04-14
description: "Notes on FSOP"
tags: ["Pwn", "Heap", "FSOP", "Libc"]
image: "image-1.png"
category: Notes
draft: false
---

# Descrption
This is the reference material for me to learn about File Structure Exploitation, As I am new here , there may not be advanced explanation here but I hope it can be of some help in understanding the File Structure and Its attack premitive here, '-' -

## File Structure Internals
### _IO_FILE
```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

To Get a better understanding of this file struct refer [[here](https://github.com/Rahulrajln1111/Writeups/tree/main/FSOPhttps://github.com/Rahulrajln1111/Writeups/tree/main/FSOP)].  
So getting good understanding on these internals helps us in exploitation part.

### Leak & Write a memory
`_IO_new_file_xsputn` - This function internally calls the write function, which does write syscall to fd and by corroupting the FileStructure like `stdout`, we can get a arbitary memory leak.   
Trigger function : `puts`, `fwrite` etc...  
`_IO_new_file_underflow` - This function internally calls read syscall , Which does read to a arbitary memory , by corroupting the FileStructure.  
Trigger function : `scanf`, `fread` etc..  

### Vtable hijacking
In the Phase of Exploiting the File Structure, The most important thing is vable , cause it has pointer that points to a jump table (like _IO_file_jumps or _IO_wfile_jumps), So by faking a prt, we can trick the libc to jump/call arbitary controlled address.  

Here we cannot directly control the vtable to point the abitary address because, there is a check `_IO_vtable_check`, that check if the call address is inside a specic location inside the libc , if not then it aborts , but it can be bypassed by making the vtable to jump to `wide vtable`, which is used when there is a wide char set in the file operations. As wide vtable is inside the protected area and the wide vtable does not have that `_IO_vtable_check` check , we can make this wide vtable to point to a arbitary location to jump/call our controlled memory. 

### pwn tool
```python
from pwn import FileStructure

fp = FileStructure()
{ flags: 0x0
 _IO_read_ptr: 0x0
 _IO_read_end: 0x0
 _IO_read_base: 0x0
 _IO_write_base: 0x0
 _IO_write_ptr: 0x0
 _IO_write_end: 0x0
 _IO_buf_base: 0x0
 _IO_buf_end: 0x0
 _IO_save_base: 0x0
 _IO_backup_base: 0x0
 _IO_save_end: 0x0
 markers: 0x0
 chain: 0x0
 fileno: 0x0
 _flags2: 0x0
 _old_offset: 0xffffffff
 _cur_column: 0x0
 _vtable_offset: 0x0
 _shortbuf: 0x0
 unknown1: 0x0
 _lock: 0x0
 _offset: 0xffffffffffffffff
 _codecvt: 0x0
 _wide_data: 0x0
 unknown2: 0x0
 vtable: 0x0}
```
pwn has its own structure to use for FSOP exploitation.

## Reference
https://github.com/Rahulrajln1111/Writeups/tree/main/FSOP  
https://pwn.college/software-exploitation/file-struct-exploits/  
https://niftic.ca/posts/fsop/  -> for detailed explanation
