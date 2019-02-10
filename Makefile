include config.mk

.POSIX:
.SUFFIXES: .c .o

HDR = util.h arg.h
LIB = \
	util/strlcpy.o \
	util/eprintf.o

SRC = sdhcp.c

OBJ = $(SRC:.c=.o) $(LIB)
BIN = $(SRC:.c=)
MAN = $(SRC:.c=.1)

all: options binlib

options:
	@echo sdhcp build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

binlib: util.a
	$(MAKE) bin

bin: $(BIN)

$(OBJ): $(HDR) config.mk

.o:
	@echo LD $@
	@$(LD) -o $@ $< util.a $(LDFLAGS)

.c.o:
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

util.a: $(LIB)
	@echo AR $@
	@$(AR) -r -c $@ $(LIB)
	@ranlib $@

install: all
	@echo installing executables to $(DESTDIR)$(PREFIX)/sbin
	@mkdir -p $(DESTDIR)$(PREFIX)/sbin
	@cp -f $(BIN) $(DESTDIR)$(PREFIX)/sbin
	@cd $(DESTDIR)$(PREFIX)/sbin && chmod 755 $(BIN)
	@echo installing manual pages to $(DESTDIR)$(MANPREFIX)/man1
	@mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	@for m in $(MAN); do sed "s/VERSION/$(VERSION)/g" < "$$m" > $(DESTDIR)$(MANPREFIX)/man1/"$$m"; done
	@cd $(DESTDIR)$(MANPREFIX)/man1 && chmod 644 $(MAN)

uninstall:
	@echo removing executables from $(DESTDIR)$(PREFIX)/sbin
	@cd $(DESTDIR)$(PREFIX)/sbin && rm -f $(BIN)
	@echo removing manual pages from $(DESTDIR)$(MANPREFIX)/man1
	@cd $(DESTDIR)$(MANPREFIX)/man1 && rm -f $(MAN)

clean:
	@echo cleaning
	@rm -f $(BIN) $(OBJ) util.a

.PHONY: all options clean install uninstall
