BIN := notes notes.inspect libshell.so
LDFLAGS := -pie -Wl,-E
CC := afl-gcc

all: $(BIN)
	@### Do Nothing

# notes.hooked: hook_notes.c
# 	gcc -Os -nostdlib -nodefaultlibs -fPIC -Wl,-shared $^ -o hook_notes
# 	python hook_notes.py

libshell.so: shell.c
	gcc -shared -fPIC $(LDFLAGS) -m32 -o $@ $^

%.inspect: %.c
	clang -g -fsanitize=address -fno-omit-frame-pointer -o $@ $^

%: %.c
	$(CC) -O0 -no-pie -Wno-incompatible-pointer-types -o $@ $^

clean:
	rm -f $(BIN)