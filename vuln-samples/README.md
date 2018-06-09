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
```
LD_PRELOAD=./libshell.so ./fl0ppy
```