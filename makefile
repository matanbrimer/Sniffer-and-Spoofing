FLAGS = -Wall -g
CC = gcc
all: sniffer spoofing sinff_spoof


sniffer: 
	$(CC) $(FLAGS) sniffer.c -o sniffer -lpcap

spoofing:
	$(CC) $(FLAGS) spoofing.c -o spoofing

sinff_spoof:
	$(CC) $(FLAGS) sinff_spoof.c -o sinff_spoof -lpcap

clean:
	rm -f *.o *.a *.so sniffer spoofing sinff_spoof
