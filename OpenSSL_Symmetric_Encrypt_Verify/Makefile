CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBSSL = -lssl -lcrypto 

TARGETS = assign_2


all: $(TARGETS)

assign_2: assign_2.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS)
