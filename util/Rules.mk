# Standard things

sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

# Local variables

OBJS_$(d)	:= \
		$(d)/byte.o \
		$(d)/cfgopt.o \
		$(d)/checksum.o \
		$(d)/file.o \
		$(d)/daemon.o \
		$(d)/net.o \
		$(d)/pcapnet.o \
		$(d)/rate.o \
		$(d)/ring.o \
		$(d)/rng.o \
		$(d)/scanfmt.o \
		$(d)/server.o \
		$(d)/socket.o \
		$(d)/uint.o \
		$(d)/util.o
DEPS_$(d)	:= $(OBJS_$(d):%.o=%.d)
TGTS_$(d)	:= $(d)/util.a

TGT_LIB		:= $(TGT_LIB) $(TGTS_$(d))
CLEAN		:= $(CLEAN) $(TGTS_$(d)) $(OBJS_$(d)) $(DEPS_$(d))

# Local rules

$(d)/util.a: $(OBJS_$(d))
	$(ARCH)

# Standard things

-include	$(DEPS_$(d))

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
