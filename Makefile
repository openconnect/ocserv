CC=gcc
CFLAGS=-O2

all: server

server: server.c
	$(CC) $(CFLAGS) -o $@ $^ -lgnutls
