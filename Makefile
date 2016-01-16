CC = gcc
CFLAGS = -Wall -O3
LD = gcc
LDFLAGS = -s
BIN = irkdump
SRC = irkdump.c
OBJ = $(SRC:.c=.o)

$(BIN): $(OBJ)
	$(LD) $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean
clean:
	-rm -f $(BIN) $(OBJ)
