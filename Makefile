CC      := gcc
CFLAGS  := -std=gnu11 -Wall -Wextra -Werror -O2 -Isrc
LDFLAGS := -lz -lncurses

TARGET  := aigit
SRCDIR  := src
SRCS    := $(wildcard $(SRCDIR)/*.c)
OBJS    := $(SRCS:$(SRCDIR)/%.c=build/%.o)

.PHONY: all clean install

all: $(TARGET)

build:
	mkdir -p build

$(TARGET): build $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

build/%.o: $(SRCDIR)/%.c $(SRCDIR)/aigit.h | build
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -rf build $(TARGET)
