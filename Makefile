CC := gcc
CFLAGS := -g -Wall -fPIC
LDFLAGS := -shared -Wl,--version-script=./libtime.map
SOURCES := $(wildcard *.c)
OBJS := $(SOURCES:%.c=%.o)
TARGET := libtime.so

all: $(TARGET)

%.o: %.c
	@$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	@$(CC) $(LDFLAGS) $(OBJS) -o $(TARGET)

clean:
	@rm -f $(OBJS) $(TARGET)

.PHONY: all clean
