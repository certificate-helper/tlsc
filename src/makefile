CC = g++
CFLAGS = -pthread -I ./include
LDFLAGS = -L. -lssl -lcrypto -Wl,--no-as-needed -ldl -Wall -Wextra
FILES = *.cpp

all:
	$(CC) -std=c++11 $(CFLAGS) -o tlsc $(FILES) $(LDFLAGS)
