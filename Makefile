ifeq ($(RELAYDNS_DEBUG), 1)
OPTS = -DRELAYDNS_DEBUG
endif
SOURCES = add.c db.c relaydns.c misc.c parse.c resp.c
OBJECTS = add.o db.o relaydns.o misc.o parse.o resp.o
OUTPUT = relaydns
CC = gcc
LIBS = -lhiredis
CFLAGS = -I/usr/include/hiredis -Wall $(OPTS)

all: relaydns

relaydns: $(OBJECTS)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(OBJECTS) $(LIBS)

clean:
	rm -f relaydns *core* *.o
