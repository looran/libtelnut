LD_LIBRARY_PATH = $(LD_LIBRARY_PATH):../

all:
	gcc $(CFLAGS) -I../ -L../ -o test_tfp test_tfp.c -ltelnut -ltelnet -levent

run: all
	./test_tfp
