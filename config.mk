# sdhcp version
VERSION   = 0.1

PREFIX    = /usr/local
DESTDIR   =
MANPREFIX = $(PREFIX)/share/man

CC        = cc
LD        = $(CC)
CPPFLAGS  = -D_DEFAULT_SOURCE
CFLAGS    = -Wall -Wextra -pedantic -std=c99 $(CPPFLAGS)
LDFLAGS   = -s

SYS = $(shell uname -s)

ifeq ($(SYS), QNX)
# QNX will not compile with -std=c99
CFLAGS    = -Wall -Wextra -pedantic $(CPPFLAGS)
LDFLAGS += -lsocket
endif

ifeq ($(findstring BSD, $(SYS)), BSD)
# Needed on BSD for timer_*
LDFLAGS += -lrt
endif
