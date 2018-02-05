SRCDIR		= src
OBJDIR		= obj
BINDIR		= target
BIN			= wpscrack

CC			= ./bin/mipsel-openwrt-linux-gcc
CFLAGS   = -Wall -g -I./usrinc -I./include -I$(SRCDIR) -fdump-rtl-expand
LFLAGS   = -Wall -g -L./usrlib -static -lpcap -lcrypto -ldl

SOURCES  := $(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/**/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h) $(wildcard $(SRCDIR)/**/*.h)
OBJECTS  := $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:%.c=%.o)))
VPATH = $(dir $(SOURCES))

export STAGING_DIR=

$(BINDIR)/$(BIN): $(OBJECTS)
	@echo "Linking"
	$(CC) $(OBJECTS) $(LFLAGS) -o $@

$(OBJECTS): $(OBJDIR)/%.o : %.c
	mkdir -p $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

.PHONY: clean install help

help:
	@echo $(SOURCES)
	@echo $(OBJECTS)
	@echo $(VPATH)

clean:
	rm -rf $(BINDIR)/* $(OBJDIR)/*

install: $(BINDIR)/$(BIN)
	scp target/wpscrack root@192.168.1.173:/root
