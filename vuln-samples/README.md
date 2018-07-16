vuln-samples
====

### libshell.so
libshell prepares shellcode to mmaped memory.

```
K_atc% ./libshell.so
[*] mmapped shellcode at 0x600000
[katc@K_atc vuln-samples]$ 
```

### fl0ppy
fl0ppy is pwn plobrem of Codegate CTF 2016 Quals.
Run this vulnerable program with:

```
LD_PRELOAD=./libshell.so ./fl0ppy
```

and try to spawn shell!

### notes
Another attack vector was found in `result-notes-2`.
As you see, end of 2nd line `t\n` can take over $rbp.
In other words, $rbp can be arbitrary value under this instruction.

```
gdb-peda$ shell cat result/crashes/id:000000*
n
titletttttttttttttttttttttttttttttttttttttttttttÿttttttttttttÿnt
s
n
e 2

s
u
3
nñe 3
con!!
s
q

gdb-peda$ r < result/crashes/id:000000*
... snipped ...
[----------------------------------registers-----------------------------------]
RAX: 0x63 ('c')
RBX: 0x0 
RCX: 0x7ffff7b05901 (<read+17>: cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd28e4 --> 0xf7dd473000000000 
RSI: 0x7ffff7dd28e3 --> 0xdd47300000000063 
RDI: 0x0 
RBP: 0xa74 ('t\n')
RSP: 0x7fffffffe0a0 --> 0x7ffff7dd35c0 --> 0xfbad2887 
RIP: 0x7ffff7a8c231 (<__GI__IO_getline_info+193>:   mov    BYTE PTR [rbp+0x0],al)
R8 : 0x7ffff7dd35c0 --> 0xfbad2887 
R9 : 0x7ffff7dd4720 --> 0x0 
R10: 0x7ffff7fa9500 (0x00007ffff7fa9500)
R11: 0x246 
R12: 0xa ('\n')
R13: 0x7ffff7dd28e4 --> 0xf7dd473000000000 
R14: 0x3fe 
R15: 0x7ffff7dd2860 --> 0xfbad208b
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7a8c224 <__GI__IO_getline_info+180>:  cmp    eax,r12d
   0x7ffff7a8c227 <__GI__IO_getline_info+183>:  
    je     0x7ffff7a8c2b7 <__GI__IO_getline_info+327>
   0x7ffff7a8c22d <__GI__IO_getline_info+189>:  sub    r14,0x1
=> 0x7ffff7a8c231 <__GI__IO_getline_info+193>:  mov    BYTE PTR [rbp+0x0],al
   0x7ffff7a8c234 <__GI__IO_getline_info+196>:  add    rbp,0x1
   0x7ffff7a8c238 <__GI__IO_getline_info+200>:  test   r14,r14
   0x7ffff7a8c23b <__GI__IO_getline_info+203>:  
    jne    0x7ffff7a8c203 <__GI__IO_getline_info+147>
   0x7ffff7a8c23d <__GI__IO_getline_info+205>:  nop    DWORD PTR [rax]
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe0a0 --> 0x7ffff7dd35c0 --> 0xfbad2887 
0008| 0x7fffffffe0a8 --> 0xa74 ('t\n')
0016| 0x7fffffffe0b0 --> 0x100000000 
0024| 0x7fffffffe0b8 --> 0x0 
0032| 0x7fffffffe0c0 --> 0x603120 --> 0x604260 --> 0xa73 ('s\n')
0040| 0x7fffffffe0c8 --> 0x7ffff7dd2860 --> 0xfbad208b 
0048| 0x7fffffffe0d0 --> 0x0 
0056| 0x7fffffffe0d8 --> 0xa74 ('t\n')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007ffff7a8c231 in __GI__IO_getline_info () from /usr/lib/libc.so.6
```