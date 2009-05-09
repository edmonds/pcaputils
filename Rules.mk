# Standard stuff

.SUFFIXES:
.SUFFIXES:	.c .o .d

all:		targets

# Subdirectories

dir	:= util
include $(dir)/Rules.mk
dir	:= src
include $(dir)/Rules.mk

# General directory independent rules

%.o:	%.c
	$(COMP)

%:	%.o
	$(LINK)

%:	%.c
	$(COMPLINK)

%.d:	%.c
	$(MAKEDEP)

.PHONY:		targets
targets:	bin lib

.PHONY:		bin
bin:		$(TGT_BIN)

.PHONY:		lib
lib:		$(TGT_LIB)

.PHONY:		clean
clean:
		rm -f $(CLEAN)

.SECONDARY:	$(CLEAN)
