# Copyright (c) Hercules Dev Team, licensed under GNU GPL.
# See the LICENSE file

# src/plugins/Makefile.  Generated from Makefile.in by configure.

################  PLUGIN CONFIGURATION  ##############################
#                                                                    #
# When you add a plugin, add its name here:                          #
# Example: if you have a plugin named my_cool_plugin.c and another   #
# one named my_second_plugin.c, add them to the list like this:      #
#                                                                    #
# MYPLUGINS = my_cool_plugin my_second_plugin                        #
#                                                                    #
# This is only needed if you want to build your plugin through       #
#   'make plugins' or 'make all'. If you don't add it to this list,  #
#   you will still be able to build your plugin through              #
#   'make plugin.my_plugin'                                          #
#                                                                    #
# Note: DO NOT include the .c extension!!!                           #

MYPLUGINS = 

#                                                                    #
#########  DO NOT EDIT ANYTHING BELOW THIS LINE!!!  ##################

# All plugins in the src/plugins directory
HPMHOOKING = $(addprefix HPMHooking_, login char map)
ALLPLUGINS = $(filter-out HPMHooking, $(basename $(wildcard *.c))) $(HPMHOOKING)

# Plugins that will be built through 'make plugins' or 'make all'
PLUGINS = sample db2sql HPMHooking_char HPMHooking_login HPMHooking_map $(MYPLUGINS)

COMMON_D = ../common
COMMON_H = $(wildcard $(COMMON_D)/*.h)
COMMON_INCLUDE = -I..

THIRDPARTY_INCLUDE = -I../../3rdparty

CONFIG_D = ../config
CONFIG_H = $(wildcard $(CONFIG_D)/*.h) $(wildcard $(CONFIG_D)/*/*.h)

MAP_H = $(wildcard ../map/*.h)
CHAR_H = $(wildcard ../char/*.h)
LOGIN_H = $(wildcard ../login/*.h)
ALL_H = $(COMMON_H) $(CONFIG_H) $(MAP_H) $(CHAR_H) $(LOGIN_H)



CC = gcc
export CC

#####################################################################
.PHONY: all $(ALLPLUGINS) HPMHooking clean buildclean help

all: $(PLUGINS) Makefile

$(ALLPLUGINS): %: ../../plugins/%.so
	@echo "	PLUGIN	$@"

HPMHooking: $(HPMHOOKING)

buildclean:
	@echo "	CLEAN	plugins (build temp files)"
	@rm -rf *.o

clean: buildclean
	@echo "	CLEAN	plugins"
	@rm -rf ../../plugins/*.so

help:
	@echo "possible targets are $(PLUGINS:%='%') 'all' 'clean' 'help'"
	@echo ""
	@echo "$(PLUGINS:%='%')"
	@echo "              - builds a specific plugin"
	@echo "'all'         - builds all above targets"
	@echo "'clean'       - cleans builds and objects"
	@echo "'buildclean'  - cleans build temporary (object) files, without deleting the"
	@echo "                compiled plugins"
	@echo "'help'        - outputs this message"

#####################################################################

Makefile: Makefile.in
	@$(MAKE) -C ../.. src/plugins/Makefile

.SECONDEXPANSION:

../../plugins/%.so: %.c $(ALL_H) $$(shell ls %/* 2>/dev/null)
	@echo "	CC	$<"
	@$(CC) $(COMMON_INCLUDE) $(THIRDPARTY_INCLUDE)  -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 -DHAVE_EXECINFO_H=1 -g -O2 -pipe -ffast-math -fvisibility=hidden -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fno-strict-aliasing -ggdb -DHAVE_EXECINFO  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK  -rdynamic -L/usr/lib  -fPIC -shared -Wl,--no-undefined -o $@ $<

../../plugins/HPMHooking_login.so: HPMHOOKINGTYPE = LOGIN
../../plugins/HPMHooking_char.so: HPMHOOKINGTYPE = CHAR
../../plugins/HPMHooking_map.so: HPMHOOKINGTYPE = MAP

../../plugins/HPMHooking_%.so: HPMHooking.c $(ALL_H) $$(shell ls HPMHooking/*_%* HPMHooking/*_common* 2>/dev/null)
	@echo "	CC	$< ($(HPMHOOKINGTYPE))"
	@$(CC) -DHPMHOOKING_$(HPMHOOKINGTYPE) $(COMMON_INCLUDE) $(THIRDPARTY_INCLUDE)  -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 -DHAVE_XLOCALE_H=1 -DHAVE_EXECINFO_H=1 -g -O2 -pipe -ffast-math -fvisibility=hidden -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered -Wempty-body -Wformat-security -Wno-format-nonliteral -Wno-switch -Wno-missing-field-initializers -fno-strict-aliasing -ggdb -DHAVE_EXECINFO  -DMAXCONN=16384 -I../common -DHAS_TLS -DHAVE_SETRLIMIT -DHAVE_STRNLEN -DDEBUG -I/usr/include -DHAVE_MONOTONIC_CLOCK  -rdynamic -L/usr/lib  -fPIC -shared -Wl,--no-undefined -o $@ $<
