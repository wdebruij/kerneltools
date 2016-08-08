
.PHONY: all clean distclean

all: tcplate

tcplate: tcplate.o libnflog.o libpsock.o
	gcc -static $+ -o $@

%.o: %.c
	gcc -c -Wall -Werror $< -o $@

clean:
	-rm -f *.o

distclean: clean
	-rm -f tcplate
