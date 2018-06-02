BIN := notes

all: $(BIN)
	@### Do Nothing

notes.hooked: hook_notes.c
	gcc -Os -nostdlib -nodefaultlibs -fPIC -Wl,-shared $^ -o hook_notes
	python hook_notes.py

%: %.c
	gcc -O0 -no-pie -Wno-incompatible-pointer-types -o $@ $^

clean:
	rm $(BIN)