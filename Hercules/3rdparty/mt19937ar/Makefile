# Copyright (c) Hercules Dev Team, licensed under GNU GPL.
# See the LICENSE file

# 3rdparty/mt19937ar/Makefile.  Generated from Makefile.in by configure.

MT19937AR_OBJ = mt19937ar.o
MT19937AR_H = mt19937ar.h



CC = gcc
export CC

#####################################################################
.PHONY: all clean buildclean help

all: $(MT19937AR_OBJ)

buildclean:
	@echo "	CLEAN	mt19937ar (build temp files)"
	@rm -rf *.o

clean: buildclean
	@echo "	CLEAN	mt19937ar"

help:
	@echo "possible targets are 'all' 'clean' 'buildclean' 'help'"
	@echo "'all'                 - builds $(MT19937AR_OBJ)"
	@echo "'clean', 'buildclean' - deletes $(MT19937AR_OBJ)"
	@echo "'help'                - outputs this message"

#####################################################################

Makefile: Makefile.in
	@$(MAKE) -C ../.. 3rdparty/mt19937ar/Makefile

%.o: %.c $(LIBCONFIG_H) Makefile
%.o: %.c $(MT19937AR_H)
	@echo "	CC	$<"
	@$(CC) -g -O2 -pipe -ffast-math -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fPIC -fno-strict-aliasing -ggdb  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK -c $(OUTPUT_OPTION) $<
