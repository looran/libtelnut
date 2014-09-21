LD_LIBRARY_PATH = $(LD_LIBRARY_PATH):../

all:
	$(CC) -I../ -L../ -o exec exec.c -ltelnut -levent -ltelnet
	$(CC) -I../ -L../ -o push push.c -ltelnut -levent -ltelnet

clean:
	rm -f exec push

