BIN := notes

all: $(BIN)
	@### Do Nothing

%: %.c
	gcc -O0 -no-pie -Wno-incompatible-pointer-types -o $@ $^

clean:
	rm $(BIN)