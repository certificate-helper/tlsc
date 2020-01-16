CC = g++
override CFLAGS += -std=c++11 -pthread -I ./include -o tlsc
LDFLAGS = -L. -lssl -lcrypto -Wl,--no-as-needed -ldl -Wall -Wextra
FILES = *.cpp

all:
	$(CC) $(CFLAGS) $(FILES) $(LDFLAGS)
