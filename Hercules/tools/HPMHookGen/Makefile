# Copyright (c) Hercules Dev Team, licensed under GNU GPL.
# See the LICENSE file

# tools/HPMHookGen/Makefile.  Generated from Makefile.in by configure.



COMMON_D = ../../src/common
MAP_D = ../../src/map
CHAR_D = ../../src/char
LOGIN_D = ../../src/login
PLUGIN_D = ../../src/plugins
COMMON_C = $(wildcard $(COMMON_D)/*.c)
COMMON_H = $(filter-out $(COMMON_D)/HPMDataCheck.%,$(wildcard $(COMMON_D)/*.h))
MAP_C = $(wildcard $(MAP_D)/*.c)
MAP_H = $(wildcard $(MAP_D)/*.h)
CHAR_C = $(wildcard $(CHAR_D)/*.c)
CHAR_H = $(wildcard $(CHAR_D)/*.h)
LOGIN_C = $(wildcard $(LOGIN_D)/*.c)
LOGIN_H = $(wildcard $(LOGIN_D)/*.h)
ALL_C = $(COMMON_C) $(MAP_C) $(CHAR_C) $(LOGIN_C)
ALL_H = $(COMMON_H) $(MAP_H) $(CHAR_H) $(LOGIN_H)

HOOK_INC = $(addprefix $(PLUGIN_D)/HPMHooking., \
           $(addsuffix .inc, HookingPoints sources GetSymbol HPMHooksCore Hooks)) \
           $(COMMON_D)/HPMDataCheck.h

HAVE_DOXYGEN=no
HAVE_PERL=yes
ifeq ($(HAVE_DOXYGEN)$(HAVE_PERL),yesyes)
	ALL_DEPENDS = hooks
else
	ifeq ($(HAVE_PERL),no)
		ALL_DEPENDS = needs_perl
	else
		ifeq ($(HAVE_DOXYGEN),no)
			ALL_DEPENDS = needs_doxygen
		endif
	endif
endif

#####################################################################
.PHONY: hooks clean buildclean generate

all: $(ALL_DEPENDS)

buildclean:

clean: buildclean
	@echo "	CLEAN	HPMHookGen"
	@rm -rf doxyoutput

Makefile: Makefile.in
	@$(MAKE) -C ../.. tools/HPMHookGen/Makefile

hooks: $(HOOK_INC)

#####################################################################

$(HOOK_INC): generate

generate: doxyoutput
	@echo "	Regenerating HPM Hook definitions..."
	@perl HPMHookGen.pl
	@echo "	Regenerating HPM Data Check definitions..."
	@perl HPMDataCheckGen.pl

doxyoutput: $(ALL_C) $(ALL_H) doxygen.conf
	@echo "	Extracting functions information..."
	@doxygen doxygen.conf

#####################################################################

needs_doxygen:
	@echo "doxygen not found or disabled by the configure script"
	@exit 1

needs_perl:
	@echo "perl not found or disabled by the configure script"
	@exit 1
