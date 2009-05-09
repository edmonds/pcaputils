# Standard things

sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)


# Local variables

PKGNAME := pcaputils
PKGVER  := 0.7

CF_$(d)		:= -I$(d)
LL_$(d)		:= util/util.a

OBJS_$(d)	:= \
		$(d)/pcapdump.o \
		$(d)/pcapip.o \
		$(d)/pcappick.o \
		$(d)/pcapuc.o
DEPS_$(d)	:= $(OBJS_$(d):%.o=%.d)
TGTS_$(d)	:= \
		$(d)/pcapdump \
		$(d)/pcapip \
		$(d)/pcappick \
		$(d)/pcapuc
TGT_BIN		:= $(TGT_BIN) $(TGTS_$(d))
CLEAN		:= $(CLEAN) $(TGTS_$(d)) $(OBJS_$(d)) $(DEPS_$(d))

# Local rules

$(OBJS_$(d)):	CF_TGT := $(CF_$(d))

$(d)/pcapdump:	LL_TGT := -lpcap
$(d)/pcapdump:	$(d)/pcapdump.o $(LL_$(d))
	$(LINK)

$(d)/pcapip:	LL_TGT := -lpcap -lJudy
$(d)/pcapip:	$(d)/pcapip.o $(LL_$(d))
	$(LINK)

$(d)/pcappick:	LL_TGT := -lpcap
$(d)/pcappick:	$(d)/pcappick.o $(LL_$(d))
	$(LINK)

$(d)/pcapuc:	LL_TGT := -lpcap -lJudy
$(d)/pcapuc:	$(d)/pcapuc.o $(LL_$(d))
	$(LINK)

.PHONY: export
EXPORT = ../build/$(PKGNAME)-$(PKGVER)
export:
	rm -rf $(EXPORT)
	svn export . $(EXPORT)
	svn export util $(EXPORT)/util

# Standard things

-include	$(DEPS_$(d))

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
