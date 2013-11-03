target := ausec
sourcedir := source
includedir := include
builddir := .build

CFLAGS += -I$(includedir) `pkg-config --cflags openssl` -MMD -MP -O3 -g -std=gnu11 -Wall -Wextra -Wpedantic -Werror
LDFLAGS += `pkg-config --libs openssl`
MKDIR := mkdir -p

default: $(target)

sources := $(wildcard $(sourcedir)/*.c) $(tests)
dependencies := $(patsubst %.c, $(builddir)/%.d, $(sources))
objects := $(patsubst %.c, $(builddir)/%.o, $(sources))

$(target): $(objects)
	$(CC) -o $@ $(objects) $(LDFLAGS)

$(builddir)/%.o: %.c
	$(MKDIR) $(dir $@) && \
	$(CC) $(CFLAGS) -o $@ -c $< >$(basename $@).l

$(objects): Makefile

clean:
	$(RM) $(objects)

-include $(dependencies)
