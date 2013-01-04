CC=gcc
CFLAGS=-O2

all: a.out

a.out: server.c
	$(CC) $(CFLAGS) -o $@ $^ -lgnutls
