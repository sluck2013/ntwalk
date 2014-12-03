CC = gcc
UNP_PATH = ../unpv13e
LIBS = $(UNP_PATH)/libunp.a 

CFLAGS = -g -O2 -std=gnu99 -Wno-unused-result
IFLAGS = -I$(UNP_PATH)/lib
FLAGS = $(IFLAGS) $(CFLAGS)

all: tour18 arp18

tour18: tour.o api.o common.o utility.o get_hw_addrs.o
	$(CC) $(CFLAGS) -o tour18 tour.o api.o common.o utility.o get_hw_addrs.o $(LIBS)
arp18: arp.o get_hw_addrs.o utility.o common.o
	$(CC) $(CFLAGS) -o arp18 arp.o get_hw_addrs.o common.o utility.o $(LIBS)

tour.o: tour.c tour.h constants.h
	$(CC) $(FLAGS) -c tour.c
arp.o: arp.c arp.h constants.h
	$(CC) $(FLAGS) -c arp.c
utility.o: utility.h utility.c constants.h
	$(CC) $(FLAGS) -c utility.c
get_hw_addrs.o: lib/get_hw_addrs.c lib/hw_addrs.h
	$(CC) $(FLAGS) -c lib/get_hw_addrs.c
api.o: api.h api.c constants.h
	$(CC) $(FLAGS) -c api.c
common.o: common.h common.c constants.h
	$(CC) $(FLAGS) -c common.c

clean:
	echo "Removing executable files..."
	rm -f arp18 tour18
	echo "Removing object files..."
	rm -f *.o
