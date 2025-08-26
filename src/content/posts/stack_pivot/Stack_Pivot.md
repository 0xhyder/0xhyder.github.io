---
title: Simple Notes on Stack Pivot
published: 2025-08-22
description: "A small notes on stack pivot technique for ROP."
tags: ["Pwn", "Stack"]
#image: "./cover.jpeg"
category: Notes
draft: false
---

This is short notes about the technique for ROP known as Stack_Pivot.

Stack_Pivot:
It is a technique used where our input size is limited after overflow to kidnap and create a fake stack that points to our arbitary instructions.

It can be done by,
```asm
mov rsp, [reg]	
pop rsp ;a gadget to set address directly.
xchg [reg] , rsp ; where we control a reg and using xchg to exchange the reg value with rsp.

leave; ret 
;It is a mostly available gadget since, leave performs 
mov rsp, rbp
pop rbp
```

![Stack Pivot Illustration](./stack_pivot_img.png)

	Basically how this is performed , the controlled memory , which is usually heap or BSS section writable segments or with read or gets by invoking it via ROP , we store the arbitary code in that memory and using buffer overflow, we control the rsp register to point to the controlled memory by creating a fake stack frame.
	so when ret instruction is met , it continues the execution to the create fake stack frame .
	we may get the doubt here , since the bss or heap , they are non-executable memory , then how does our code executes in that location.
	well since it holds the address of existing instruction from .text_section , which is executable , the arbitary code from the location say [heap], is executed in order with the help of created fake stack frame.
