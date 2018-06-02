import lief
from os import system

target = lief.parse("notes")
hook    = lief.parse("hook_malloc")

segment_added  = target.add(hook.segments[0])

my_malloc      = hook.get_symbol("my_malloc")
my_malloc_addr = segment_added.virtual_address + my_malloc.value

target.patch_pltgot('malloc', my_malloc_addr)
target.write("notes.hooked")

system("chmod +x notes.hooked")