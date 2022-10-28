TARGET = btp
CC = gcc
INCLUDES = -Iinclude/
CFLAGS = -liw -lexplain -DLOG_USE_COLOR -g3 $(INCLUDES)
CFLAGS += -Werror -Wl,--fatal-warnings
CFLAGS += -pipe -fPIE -fdiagnostics-color -Wpedantic
CFLAGS += -Wall -Werror-implicit-function-declaration
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
CFLAGS += -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare -Wswitch-enum
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Werror=format-security
CFLAGS += -Wunused-parameter -Wuninitialized -Wformat-security -Wstrict-overflow=2

SOURCEDIR = src
BUILDDIR = build
INCLUDEDIR = include

SOURCES = $(wildcard $(SOURCEDIR)/*.c)
OBJECTS = $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
HEADERS = $(wildcard $(INCLUDEDIR)/*.h)

.PHONY: default all clean

default: $(TARGET)
all: default

$(OBJECTS): $(BUILDDIR)/%.o: $(SOURCEDIR)/%.c
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

clean:
	-rm -rf $(BUILDDIR)
	-rm -f $(TARGET)