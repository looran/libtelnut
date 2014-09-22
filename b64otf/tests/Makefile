LD_LIBRARY_PATH = $(LD_LIBRARY_PATH):../

CFLAGS += -Wall

all:
	$(CC) $(CFLAGS) -c -I../ -o test_b64otf.o test_b64otf.c
	$(CC) $(CFLAGS) -I../ -L../ -o test_b64otf test_b64otf.o ../b64otf.o

run: all
	./test_b64otf

clean:
	rm -f test_b64otf

