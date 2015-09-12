# Copyright (c) Hercules Dev Team, licensed under GNU GPL.
# See the LICENSE file

# src/common/Makefile.  Generated from Makefile.in by configure.

CONFIG_D = ../config
CONFIG_H = $(wildcard $(CONFIG_D)/*.h) $(wildcard $(CONFIG_D)/*/*.h)

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

COMMON_SHARED_C = conf.c db.c des.c ers.c grfio.c HPM.c mapindex.c md5calc.c \
                  mutex.c nullpo.c random.c showmsg.c strlib.c sysinfo.c \
                  thread.c timer.c utils.c
COMMON_C = $(COMMON_SHARED_C)
COMMON_SHARED_OBJ = $(patsubst %.c,%.o,$(COMMON_SHARED_C))
COMMON_OBJ = $(addprefix obj_all/, $(COMMON_SHARED_OBJ) \
             console.o core.o malloc.o socket.o)
COMMON_MINI_OBJ = $(addprefix obj_all/, $(COMMON_SHARED_OBJ) \
                  miniconsole.o minicore.o minimalloc.o minisocket.o)
COMMON_C += console.c core.c malloc.c socket.c
COMMON_H = atomic.h cbasetypes.h conf.h console.h core.h db.h des.h ers.h \
           grfio.h HPM.h HPMi.h malloc.h mapindex.h md5calc.h mmo.h mutex.h \
           nullpo.h random.h showmsg.h socket.h spinlock.h sql.h strlib.h \
           sysinfo.h thread.h timer.h utils.h winapi.h

COMMON_SQL_OBJ = obj_sql/sql.o
COMMON_SQL_H = sql.h
COMMON_C += sql.c
SYSINFO_INC = sysinfo.inc

HAVE_MYSQL=yes
ifeq ($(HAVE_MYSQL),yes)
	SQL_DEPENDS=common common_sql common_mini
else
	SQL_DEPENDS=needs_mysql
endif



CC = gcc
export CC

#####################################################################
.PHONY: all sql common common_sql common_mini clean buildclean help

all: sql

sql: $(SQL_DEPENDS)

buildclean:
	@echo "	CLEAN	common (build temp files)"
	@rm -rf *.o obj_all obj_sql sysinfo.inc

clean: buildclean
	@echo "	CLEAN	common"

help:
	@echo "possible targets are 'sql' 'all' 'clean' 'help'"
	@echo "'sql'                 - builds object files used in sql servers"
	@echo "'all'                 - builds all above targets"
	@echo "'clean', 'buildclean' - cleans builds and objects"
	@echo "'help'                - outputs this message"

#####################################################################

Makefile: Makefile.in
	@$(MAKE) -C ../.. src/common/Makefile

$(SYSINFO_INC): $(COMMON_C) $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H)
	@echo "	MAKE	$@"
	@$(MAKE) -C ../.. sysinfo

needs_mysql:
	@echo "MySQL not found or disabled by the configure script"
	@exit 1

# object directories

obj_all:
	@echo "	MKDIR	obj_all"
	@-mkdir obj_all

obj_sql:
	@echo "	MKDIR	obj_sql"
	@-mkdir obj_sql

obj_all/common.a: $(COMMON_OBJ) Makefile
	@echo "	AR	$@"
	@/usr/bin/ar rcs obj_all/common.a $(COMMON_OBJ)

obj_all/common_mini.a: $(COMMON_MINI_OBJ) Makefile
	@echo "	AR	$@"
	@/usr/bin/ar rcs obj_all/common_mini.a $(COMMON_MINI_OBJ)

obj_sql/common_sql.a: $(COMMON_SQL_OBJ) Makefile
	@echo "	AR	$@"
	@/usr/bin/ar rcs obj_sql/common_sql.a $(COMMON_SQL_OBJ)

common: $(COMMON_OBJ) $(MT19937AR_OBJ) $(LIBCONFIG_OBJ) obj_all/common.a Makefile

common_mini: $(COMMON_MINI_OBJ) $(MT19937AR_OBJ) $(LIBCONFIG_OBJ) obj_all/common_mini.a Makefile

common_sql: $(COMMON_SQL_OBJ) obj_sql/common_sql.a Makefile

obj_all/sysinfo.o: sysinfo.c $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H) $(SYSINFO_INC) | obj_all

obj_all/%.o: %.c $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H) | $(SYSINFO_INC) obj_all
	@echo "	CC	$<"
	@$(CC) -g -O2 -pipe -ffast-math -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fPIC -fno-strict-aliasing -ggdb -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 $(MT19937AR_INCLUDE) $(LIBCONFIG_INCLUDE)  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK -c $(OUTPUT_OPTION) $<

obj_all/mini%.o: %.c $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H) | $(SYSINFO_INC) obj_all
	@echo "	CC	$<"
	@$(CC) -g -O2 -pipe -ffast-math -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fPIC -fno-strict-aliasing -ggdb -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 $(MT19937AR_INCLUDE) $(LIBCONFIG_INCLUDE) -DMINICORE  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK -c $(OUTPUT_OPTION) $<

obj_sql/%.o: %.c $(COMMON_H) $(COMMON_SQL_H) $(CONFIG_H) $(LIBCONFIG_H) | $(SYSINFO_INC) obj_sql
	@echo "	CC	$<"
	@$(CC) -g -O2 -pipe -ffast-math -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fPIC -fno-strict-aliasing -ggdb -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 $(LIBCONFIG_INCLUDE) -I/usr/include/mysql  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK -c $(OUTPUT_OPTION) $<

# missing object files
$(MT19937AR_OBJ):
	@echo "	MAKE	$@"
	@$(MAKE) -C $(MT19937AR_D)

$(LIBCONFIG_OBJ):
	@echo "	MAKE	$@"
	@$(MAKE) -C $(LIBCONFIG_D)
