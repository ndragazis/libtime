all: libtime.so

time.o: time.c
	@gcc -g -Wall -fPIC -c time.c -o time.o

logging.o: logging.c
	@gcc -g -Wall -fPIC -c logging.c -o logging.o

libtime.so: time.o logging.o
	@gcc -g -Wall -fPIC -shared -Wl,--version-script=./libtime.map time.o logging.o -o libtime.so

clean:
	@rm -f time.o logging.o libtime.so

.PHONY: all clean
