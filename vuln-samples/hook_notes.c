#include <stdio.h>

unsigned int count = 0;

void my_new_note(unsigned int note_id) {
    puts("[+] HOOK new_note()");
    notes[note_id].content = (char *) (0x600000 + (count++) * 0x1000);
    update_note(note_id);
}