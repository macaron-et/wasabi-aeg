/*
 * Exercise:
 *      Exploit this program to invoke /bin/sh
 *
 * Pro Tips:
 *      Fuzz this program wih afl
 *          for example: `afl-fuzz -Q -i inputs -o result ./notes`
 *          for example: `afl-fuzz -n -i inputs -o result ./notes` (without QEMU)
 *      Put some input file into `inputs` folder beforehand
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

// Call me!!
void instant_win() {
    puts("Congratz!");
    execve("/bin/sh", NULL, NULL);
    exit(1);
}

// GOT (Global Offset Tables)
// with binding
 __attribute__((section(".my_got")))
void (*got[4]) () = {fgets, vscanf, vprintf, puts};

// fgets@.plt
void _fgets(char* buf, unsigned int len, FILE* fp) {
    // puts("_fgets");
    got[0](buf, len, fp);
}

// scanf@.plt
void _scanf(const char* fmt, ...) {
    // puts("_scanf");
    va_list ap;
    va_start(ap, fmt);
    got[1](fmt, ap);
    va_end(ap);
}

// printf@.plt
void _printf(const char* fmt, ...) {
    // puts("_printf");
    va_list va;
    va_start(va, fmt);
    got[2](fmt, va);
    va_end(va);
}

// puts@.plt
void _puts(char * msg) {
    // puts("_puts");
    got[3](msg);
}


typedef struct {
    char* content;
    char title[16];
} note;

#define MAX_NUM_NOTES 8
note notes[MAX_NUM_NOTES];

void update_note(unsigned int note_id) {
    if (notes[note_id].content == NULL) {
        printf("Note #%d does not exests.\n", note_id);
        return;
    }
    _printf("\n==== [note #%d] ====\n", note_id);
    _printf("title: ");
    _fgets(notes[note_id].title, 1024, stdin);
    _printf("content: ");
    _fgets(notes[note_id].content, 1024, stdin);
}

void new_note(unsigned int note_id) {
    notes[note_id].content = (char *) malloc(1024);
    update_note(note_id);
}

void show_notes(unsigned int num_notes) {
    for (unsigned int i = 0; i < num_notes; i++) {
        _printf("note #%d:%s\t%s", i, notes[i].title, notes[i].content);
    }
}

char menu() {
    char res;
    _puts("\n---- [menu] ----");
    _puts("n: new note");
    _puts("u: update note");
    _puts("s: show notes");
    _puts("q: quit");
    _printf("input command: ");
    _scanf("%c", &res);
    _scanf("%*c");
    // printf("your input: %c\n", res);
    return res;
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 1);
    setvbuf(stdout, NULL, _IONBF, 1);
    // raise(SIGBUS);

    _puts("Exploit Me!!");

    unsigned int num_notes = 0;
    while(num_notes < MAX_NUM_NOTES) {
        char select = menu();
        switch (select) {
            case 'n':
                new_note(num_notes++);
                break;
            case 'u':
                _printf("input note id: ");
                unsigned int id = 0;
                _scanf("%u", &id);
                _scanf("%*c");
                update_note(id);
                break;
            case 's':
                show_notes(num_notes);
                break;
            case 'q':
                _puts("Bye.");
                return 0;
            case 'i':
                // instant_win();
            default:
                _puts("Unkown command.");
        }
    }
    _puts("Too much notes. Bye.");
    return 0;
}