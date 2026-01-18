CC=gcc
CFLAGS=-g -Wall -Wextra -O2 $(shell pkg-config fuse3 --cflags)
LDFLAGS=-lm $(shell pkg-config fuse3 --libs)

OBJ=myfs.o block.o

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

myfs: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o myfs

.PHONY: clean

clean:
	rm -f *.o myfs
