---
title: Jump Oriented Programming
published: 2026-01-06
description: "Notes on JOP"
tags: ["Pwn", "Stack","Jop",]
#image: "./rop_vs_jop.png"
category: Notes
draft: false
---

# ???
As i was looking online I found a interesting technique JOP that is similar to ROP but is used when there are limited or no return gadgets found on the binary and when jmp gadgets are abudent espically indirect jmp's.

# Intro
The JOP (Jump Oriented Programming) uses indirect jmp instructions to execute some user controlled instrunctions or used to load the registers with the arbitary value for futher exploitation.


### How the execution is controlled here?  
So as to make the controlled execution possible, we are gonna introduce a gadget known as `dispatch_gadget`, which will help us a lot when we are building a JOP chain for exploitation.

#### Dispatch Gatget Example:
```asm
dispatch:
  add rax, 8
  jmp [rax]
```
The dispatcher gadget is fully controlled by the attacker via overflow or in any other possible way and is used to jump to other gadgets in the binary or to any controlled memory address for execution.

#### Functional Gadgets
Then there are other gadgets does some operation and jump via a controlled register or controlled memory location and these gadgets that helps us in buiding a valuable exploit chain are `functional_gadget`. 

There are some other gadgets here based on the behaviour but they are not as important as these two types now.

### Interworking

![ROP vs JOP Illustration](./rop_vs_jop.png)

Now we have introducted these both dispatch and functional gadgets, we can start to understand how both these are used to work on exploit process. 
Now looking at the image above, we can see that the rop is quite simple as it executes some instruction and returns to user controlled memory to execute next instruction but in JOP it simply uses a indirect jump to a memory and here there is no ret so it won't automatically come back again to execute next gadget, So we making the both dispatch gadget and the functional gadget to work together to create a chain of execution that leads to some intent behaviour, So flow be like,
```flow
dispatch_gadget -> gadget1 -> dispatch_gadget -> gadget2 -> dispatch_gadget -> ...
```

As we can see that purpose of `dispatch_gadget` is to jump to a controlled `functional_gadget` and then every functional gadgets needs to do its computation and should return back to the `dispatch_gadget` in one way or other, So that it can jump to next `functional_gadget` for controlling the program memory.

##### Flow Illustration:
```asm
/* Example Gadgets */
  add rax, 8  /* 1st gadget say -> Dispatch_gadget */
  jmp [rax] 

  pop rdi    /* 2nd gadget a functional gadget */
  jmp [rsp -8] 

  mov r10, rdi  /* 3rd gadget a functional gadget */
  add rax, r10
  jmp [rsp -8]

  syscall
```

As 1st gadget is fully controlled by us , we can jump to the 2nd gadget then effectively be able to set rdi here via pop rdi, then jumps to a address in stack , So here we can make a jump to 3rd gadget to set the rax then we can again make jump back to the dispatch gadget then again jump to the pop rdi to set a arg for syscall and then we can jump to syscall gadget for exploitation, so thats how in basic way the JOP works.


As it is uses indirect jump it become more messy and complex to build a ROP chain, As sometimes we need to uses multiple gadgets together to make a jump back to the dispatch gadget.

##### References:  
https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf  
https://youtu.be/5SLPaYOVMBw?si=hPoESM_UIF9WlurL  
https://c4ebt.github.io/2020/05/26/PWNDAY-01-Juujuu-Writeup.html  
