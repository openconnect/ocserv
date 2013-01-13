CC=gcc
CFLAGS=-O2 -I. -Wall -Ihttp-parser/

all: ocserv

FILES=main.c vpn.c auth.c tlslib.c cookies.c \
	http-parser/http_parser.c

ocserv: $(FILES)
	$(CC) $(CFLAGS) -o $@ $^ -L/usr/local/lib -lgnutls -lgdbm
