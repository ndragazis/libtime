all: printf

printf.o: printf.c
	@gcc -g -Wall -c printf.c -o printf.o

printf: printf.o
	@#gcc -g -Wall printf.o -o printf
	@#gcc -g -Wall -Wl,-z,norelro printf.o -o printf
	@#gcc -g -Wall -Wl,-z,lazy printf.o -o printf
	@gcc -g -Wall -Wl,-z,lazy,-z,norelro printf.o -o printf

clean:
	@rm -f printf.o printf

.PHONY: all clean
