LD_LIBRARY_PATH = $(LD_LIBRARY_PATH):../

PREFIX ?= /usr/local
BINDIR = $(DESTDIR)$(PREFIX)/bin

all:
	$(CC) -I../ -L../ -o telnut telnut.c -ltelnut -levent -ltelnet

install:
	@echo "installation of $(BINNAME)"
	mkdir -p $(BINDIR)
	install -m 0755 telnut $(BINDIR)

clean:
	rm -f telnut
