# Copyright (c) Hercules Dev Team, licensed under GNU GPL.
# See the LICENSE file

# src/map/Makefile.  Generated from Makefile.in by configure.

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

MT19937AR_D = $(THIRDPARTY_D)/mt19937ar
MT19937AR_OBJ = $(MT19937AR_D)/mt19937ar.o
MT19937AR_H = $(MT19937AR_D)/mt19937ar.h

MAP_C = atcommand.c battle.c battleground.c buyingstore.c channel.c chat.c \
        chrif.c clif.c date.c duel.c elemental.c guild.c homunculus.c HPMmap.c \
        instance.c intif.c irc-bot.c itemdb.c log.c mail.c map.c mapreg_sql.c \
        mercenary.c mob.c npc.c npc_chat.c party.c path.c pc.c pc_groups.c \
        pet.c quest.c script.c searchstore.c skill.c status.c storage.c \
        trade.c unit.c vending.c
MAP_OBJ = $(addprefix obj_sql/, $(patsubst %c,%o,$(MAP_C)))
MAP_H = atcommand.h battle.h battleground.h buyingstore.h channel.h chat.h \
        chrif.h clif.h date.h duel.h elemental.h guild.h homunculus.h HPMmap.h \
        instance.h intif.h irc-bot.h itemdb.h log.h mail.h map.h mapreg.h \
        mercenary.h mob.h npc.h packets.h packets_struct.h party.h path.h \
        pc.h pc_groups.h pet.h quest.h script.h searchstore.h skill.h \
        status.h storage.h trade.h unit.h vending.h

HAVE_MYSQL=yes
ifeq ($(HAVE_MYSQL),yes)
	MAP_SERVER_SQL_DEPENDS=$(MAP_OBJ) $(COMMON_D)/obj_sql/common_sql.a $(COMMON_D)/obj_all/common.a $(MT19937AR_OBJ) $(LIBCONFIG_OBJ $(SYSINFO_INC))
else
	MAP_SERVER_SQL_DEPENDS=needs_mysql
endif

HAVE_PCRE=yes
ifeq ($(HAVE_PCRE),yes)
	PCRE_CFLAGS=-DPCRE_SUPPORT 
else
	PCRE_CFLAGS=
endif



CC = gcc
export CC

#####################################################################
.PHONY: all sql map-server clean buildclean help

all: sql

sql: map-server

buildclean:
	@echo "	CLEAN	map (build temp files)"
	@rm -rf *.o obj_sql

clean: buildclean
	@echo "	CLEAN	map"
	@rm -rf ../../map-server

help:
	@echo "possible targets are 'map-server' 'all' 'clean' 'help'"
	@echo "'map-server'   - map server"
	@echo "'all'          - builds all above targets"
	@echo "'clean'        - cleans builds and objects"
	@echo "'buildclean'   - cleans build temporary (object) files, without deleting the"
	@echo "                 executables"
	@echo "'help'         - outputs this message"

#####################################################################

Makefile: Makefile.in
	@$(MAKE) -C ../.. src/map/Makefile

$(SYSINFO_INC): $(MAP_C) $(MAP_H) $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H)
	@echo "	MAKE	$@"
	@$(MAKE) -C ../.. sysinfo

needs_mysql:
	@echo "MySQL not found or disabled by the configure script"
	@exit 1

# object directories

obj_sql:
	@echo "	MKDIR	obj_sql"
	@-mkdir obj_sql

# executables

map-server: ../../map-server

../../map-server: $(MAP_SERVER_SQL_DEPENDS) Makefile
	@echo "	LD	$(notdir $@)"
	@$(CC)   -rdynamic -L/usr/lib -o ../../map-server $(MAP_OBJ) $(COMMON_D)/obj_sql/common_sql.a \
		$(COMMON_D)/obj_all/common.a $(MT19937AR_OBJ) $(LIBCONFIG_OBJ) -lrt -lm -lz  -ldl -lpcre -rdynamic -L/usr/lib64/mysql -lmysqlclient -lz -lcrypt -lnsl -lm -lssl -lcrypto

# map object files

obj_sql/%.o: %.c $(MAP_H) $(COMMON_H) $(CONFIG_H) $(MT19937AR_H) $(LIBCONFIG_H) | obj_sql
	@echo "	CC	$<"
	@$(CC) -g -O2 -pipe -ffast-math -fvisibility=hidden -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fno-strict-aliasing -ggdb -DHAVE_EXECINFO -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 -DHAVE_EXECINFO_H=1 $(COMMON_INCLUDE) $(THIRDPARTY_INCLUDE) $(PCRE_CFLAGS) -I/usr/include/mysql  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK -c $(OUTPUT_OPTION) $<

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
