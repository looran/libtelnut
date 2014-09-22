CFLAGS += -Wall -fPIC
ifdef TFP_DATA_EXTERNAL_H
	CFLAGS += -DTFP_DATA_EXTERNAL_H
endif

PREFIX=/usr/local
INCLUDEDIR=$(PREFIX)/include
LIBDIR=$(PREFIX)/lib
LIBNAME=libtelnut

TARGET  = ${LIBNAME}.so
SOURCES = telnut.c tfp.c
HEADERS = telnut.h
OBJECTS = $(SOURCES:.c=.o) b64otf/b64otf.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -fPIC -shared -o $(TARGET) $(OBJECTS)

install:
	@echo "installation of $(LIBNAME)"
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)
	install -m 0644 $(TARGET) $(LIBDIR)
	install -m 0644 $(HEADERS) $(INCLUDEDIR)

dev:
	export CFLAGS="-g -O0"; make clean && make && make -C tests && make -C examples && make -C bin/ && make -C tests run && sudo make install && sudo make -C bin/ install

clean:
	rm -f $(TARGET) $(OBJECTS)
	make -C tests/ clean
	make -C examples/ clean
	make -C bin/ clean

