CFLAGS += -Wall -fPIC

all:
	$(CC) $(CFLAGS) -c -o b64otf.o b64otf.c

dev:
	make clean && CFLAGS="-g -O0" make && make -C tests/ clean && make -C tests/ && make -C tests/ run

clean:
	rm -f b64otf.o
