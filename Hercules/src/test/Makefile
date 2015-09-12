# Copyright (c) Hercules Dev Team, licensed under GNU GPL.
# See the LICENSE file

# src/test/Makefile.  Generated from Makefile.in by configure.

CONFIG_D = ../config
CONFIG_H = $(wildcard $(CONFIG_D)/*.h) $(wildcard $(CONFIG_D)/*/*.h)

COMMON_D = ../common
COMMON_H = $(wildcard $(COMMON_D)/*.h)
SYSINFO_INC = $(COMMON_D)/sysinfo.inc

LIBCONFIG_D = ../../3rdparty/libconfig
LIBCONFIG_OBJ = $(addprefix $(LIBCONFIG_D)/, libconfig.o grammar.o scanctx.o \
                scanner.o strbuf.o)
LIBCONFIG_H = $(addprefix $(LIBCONFIG_D)/, libconfig.h grammar.h parsectx.h \
              scanctx.h scanner.h strbuf.h wincompat.h)
LIBCONFIG_INCLUDE = -I$(LIBCONFIG_D)

MT19937AR_D = ../../3rdparty/mt19937ar
MT19937AR_OBJ = $(MT19937AR_D)/mt19937ar.o
MT19937AR_H = $(MT19937AR_D)/mt19937ar.h
MT19937AR_INCLUDE = -I$(MT19937AR_D)

TEST_SPINLOCK_OBJ = obj/test_spinlock.o
TEST_SPINLOCK_C = test_spinlock.c
TEST_SPINLOCK_H =
TEST_SPINLOCK_DEPENDS = $(TEST_SPINLOCK_OBJ) $(COMMON_D)/obj_sql/common_sql.a $(COMMON_D)/obj_all/common.a $(MT19937AR_OBJ) $(LIBCONFIG_OBJ $(SYSINFO_INC))



CC = gcc
export CC

#####################################################################
.PHONY: all test_spinlock clean buildclean

all: test_spinlock Makefile

buildclean:
	@echo "	CLEAN	test (build temp files)"
	@rm -rf *.o obj

clean: buildclean
	@echo "	CLEAN	test"
	@rm -rf ../../test_spinlock

#####################################################################

Makefile: Makefile.in
	@$(MAKE) -C ../.. src/test/Makefile

$(SYSINFO_INC): $(TEST_SPINLOCK_C) $(TEST_SPINLOCK_H) $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H)
	@echo "	MAKE	$@"
	@$(MAKE) -C ../.. sysinfo

# object directories

obj:
	@echo "	MKDIR	obj"
	@-mkdir obj

#executables

test_spinlock: $(TEST_SPINLOCK_DEPENDS) Makefile
	@echo "	LD	$@"
	@$(CC)  -L/usr/lib -o ../../test_spinlock $(TEST_SPINLOCK_DEPENDS) -lrt -lm -lz  -ldl -rdynamic -L/usr/lib64/mysql -lmysqlclient -lz -lcrypt -lnsl -lm -lssl -lcrypto

# object files

obj/%.o: %.c $(TEST_SPINLOCK_H) $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H) | obj
	@echo "	CC	$<"
	@$(CC) -g -O2 -pipe -ffast-math -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fPIC -fno-strict-aliasing -ggdb -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 $(MT19937AR_INCLUDE) $(LIBCONFIG_INCLUDE) -DWITH_SQL -I/usr/include/mysql  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK -c $(OUTPUT_OPTION) $<

# missing object files
$(COMMON_D)/obj_all/common.a:
	@echo "	MAKE	$@"
	@$(MAKE) -C $(COMMON_D) sql

$(COMMON_D)/obj_sql/common_sql.a:
	@echo "	MAKE	$@"
	@$(MAKE) -C $(COMMON_D) sql

$(MT19937AR_OBJ):
	@echo "	MAKE	$@"
	@$(MAKE) -C $(MT19937AR_D)

$(LIBCONFIG_OBJ):
	@echo "	MAKE	$@"
	@$(MAKE) -C $(LIBCONFIG_D)
