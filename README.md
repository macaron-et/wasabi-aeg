Wasabi AEG
====

This is yet another implementation (demonstration) of [AEG (Automated Exploit Generation)](http://security.ece.cmu.edu/aeg/) using Symbolic Executor Triton.


Requirements
-----
* [Triton](https://github.com/JonathanSalwan/Triton)
* Python2


Build
----
```
cd vuln-samples
make
cd -
```


Demo
-----
```
time ~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton solve-notes.py vuln-samples/notes < vuln-samples/crash-inputs/notes-1
time ~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton solve-notes-phase-2.py vuln-samples/notes < crash_inputs
xxd 
```
```
K_atc% xxd crash_inputs-2 
00000000: 6e0a 7469 740a 636f 6e0a 6e0a 7469 7421  n.tit.con.n.tit!
00000010: 0a63 6f6e 210a 750a 310a 4141 4125 4141  .con!.u.1.AAA%AA
00000020: 7341 4142 4141 2441 416e 7820 6000 0000  sAABAA$AAnx `...
00000030: 0000 0a63 6f6e 2121 0a75 0a32 0a74 6974  ...con!!.u.2.tit
00000040: 2121 0ab2 0840 0000 0000 0073 680a       !!...@.....sh.
```