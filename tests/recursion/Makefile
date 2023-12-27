all: recurse

recurse.o: recurse.c
	@gcc -g -Wall -c recurse.c -o recurse.o

foo.o: foo.c
	@gcc -g -Wall -fPIC -c foo.c -o foo.o

bar.o: bar.c
	@gcc -g -Wall -fPIC -c bar.c -o bar.o

libfoo.so: foo.o libbar.so
	@gcc -g -Wall -Wl,-rpath,. -fPIC -shared foo.o -o libfoo.so -lbar -L.

libbar.so: bar.o
	@gcc -g -Wall -fPIC -shared bar.o -o libbar.so

recurse: recurse.o libfoo.so
	@gcc -g -Wall -Wl,-rpath,. recurse.o -o recurse -lfoo -L.

clean:
	@rm -f recurse.o recurse foo.o bar.o libfoo.so libbar.so

.PHONY: all clean
