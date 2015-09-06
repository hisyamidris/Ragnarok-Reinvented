# Copyright (c) Hercules Dev Team, licensed under GNU GPL.
# See the LICENSE file

# src/tool/Makefile.  Generated from Makefile.in by configure.

CONFIG_D = ../config
CONFIG_H = $(wildcard $(CONFIG_D)/*.h) $(wildcard $(CONFIG_D)/*/*.h)

COMMON_D = ../common
COMMON_H = $(wildcard $(COMMON_D)/*.h)
SYSINFO_INC = $(COMMON_D)/sysinfo.inc
COMMON_INCLUDE = -I..

THIRDPARTY_D = ../../3rdparty
THIRDPARTY_INCLUDE = -I$(THIRDPARTY_D)

LIBCONFIG_D = $(THIRDPARTY_D)/libconfig
LIBCONFIG_OBJ = $(addprefix $(LIBCONFIG_D)/, libconfig.o grammar.o scanctx.o \
                scanner.o strbuf.o)
LIBCONFIG_H = $(addprefix $(LIBCONFIG_D)/, libconfig.h grammar.h parsectx.h \
              scanctx.h scanner.h strbuf.h wincompat.h)

MAPCACHE_OBJ = obj_all/mapcache.o
MAPCACHE_C = mapcache.c
MAPCACHE_H =
MAPCACHE_DEPENDS = $(MAPCACHE_OBJ) $(COMMON_D)/obj_all/common_mini.a $(LIBCONFIG_OBJ $(SYSINFO_INC))



CC = gcc
export CC

#####################################################################
.PHONY: all mapcache clean buildclean help

all: mapcache Makefile

mapcache: ../../mapcache

../../mapcache: $(MAPCACHE_DEPENDS) Makefile
	@echo "	LD	$(notdir $@)"
	@$(CC)   -rdynamic -L/usr/lib -o ../../mapcache $(MAPCACHE_DEPENDS) -lrt -lm -lz  -ldl

buildclean:
	@echo "	CLEAN	tool (build temp files)"
	@rm -rf obj_all/*.o

clean: buildclean
	@echo "	CLEAN	tool"
	@rm -rf ../../mapcache

help:
	@echo "possible targets are 'mapcache' 'all' 'clean' 'help'"
	@echo "'mapcache'   - mapcache generator"
	@echo "'all'        - builds all above targets"
	@echo "'clean'      - cleans builds and objects"
	@echo "'buildclean' - cleans build temporary (object) files, without deleting the"
	@echo "               executables"
	@echo "'help'       - outputs this message"

#####################################################################

Makefile: Makefile.in
	@$(MAKE) -C ../.. src/tool/Makefile

$(SYSINFO_INC): $(MAPCACHE_C) $(MAPCACHE_H) $(COMMON_H) $(CONFIG_H) $(LIBCONFIG_H)
	@echo "	MAKE	$@"
	@$(MAKE) -C ../.. sysinfo

obj_all:
	@echo "	MKDIR	obj_all"
	@-mkdir obj_all

obj_all/%.o: %.c $(MAPCACHE_H) $(COMMON_H) $(CONFIG_H) $(LIBCONFIG_H) | obj_all
	@echo "	CC	$<"
	@$(CC) -g -O2 -pipe -ffast-math -fvisibility=hidden -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fno-strict-aliasing -ggdb -DHAVE_EXECINFO -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 -DHAVE_EXECINFO_H=1 $(COMMON_INCLUDE) $(THIRDPARTY_INCLUDE)  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK -c $(OUTPUT_OPTION) $<

# missing common object files
$(COMMON_D)/obj_all/common_mini.a:
	@echo "	MAKE	$@"
	@$(MAKE) -C $(COMMON_D) common_mini

$(LIBCONFIG_OBJ):
	@echo "	MAKE	$@"
	@$(MAKE) -C $(LIBCONFIG_D)
