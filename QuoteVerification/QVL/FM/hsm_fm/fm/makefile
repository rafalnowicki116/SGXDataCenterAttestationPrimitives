##############################################################################
#
# Copyright (c) 2018 SafeNet. All rights reserved.
#
# This file contains information that is proprietary to SafeNet and may not be
# distributed or copied without written consent from SafeNet.
#
##############################################################################

# default the FMSDK path
FMSDK?=/usr/safenet/lunafmsdk

LUNASDK=/usr/safenet/lunaclient

include $(FMSDK)/samples/fmconfig.mk

NAME = fmqvl

FMTARGETDIR ?= .

ODIR = $(FMTARGETDIR)/obj-ppc
BDIR = $(FMTARGETDIR)/bin-ppc

CC = /usr/bin/powerpc-linux-gnu-gcc-7
# CC = gcc
# CC = /opt/eldk-5.6/powerpc-4xx/sysroots/i686-eldk-linux/usr/bin/powerpc-linux/powerpc-linux-cpp
#CC=gcc
#CPP=g++

_OBJS = \
	hdr.o \
	qvl.o

OBJS = $(patsubst %,$(ODIR)/%,$(_OBJS))

INCLUDE += \
    ${LUNASDK}/samples/include \
    $(FMSDK)/include \
    $(FMSDK)/include/fm/hsm \
    $(FMSDK)/include/fm/host \
	../../HelloCPP \
	../../../Src/Build/Release/dist/include/SgxEcdsaAttestation \
	../include

FMLIBS:= \
	fmsupt

DEFINES+=

L_FLAGS +=-Wl,-t

LIBS := -L$(FMLIBDIR) $(addprefix -l,$(FMLIBS))

C_FLAGS += -O2

I_OPT    := $(addprefix -I, $(INCLUDE))

all: $(BDIR)/$(NAME).bin

$(BDIR):
	mkdir -p $(BDIR)

$(ODIR):
	mkdir -p $(ODIR)

$(ODIR)/%.o: %.c $(ODIR)
	$(CC) -c $(I_OPT) $(DEFINES) $(C_FLAGS) -o$@ $<


# Original
# $(BDIR)/$(NAME).bin : $(BDIR) $(OBJS) $(OBJSC)
# $(CC) $(L_FLAGS) $(L_FLAGS2) -o $@ $(OBJS) $(LIBS) -lgcc -lfmsupt

#Build FM with HelloCPP + stdc++ and libc modified
# $(BDIR)/$(NAME).bin : $(BDIR) $(OBJS) $(OBJSC)
# 	$(CC) $(L_FLAGS) $(L_FLAGS2) \
# 	../../HelloCPP/build/library.o \
# 	../../lib/standard/crti.o \
# 	../../lib/standard/crtbeginT.o \
# 	../../lib/standard/crtend.o \
# 	-o $@ $(OBJS) $(LIBS) \
# 	-Wl,--start-group \
# 	../../lib/standard/libgcc.a \
# 	../../lib/standard/libgcc_eh.a \
# 	../../lib/standard/libc.a \
# 	../../lib/standard/libstdc++.a \
# 	-Wl,--end-group \
# 	-lfmsupt

$(BDIR)/$(NAME).bin : $(BDIR) $(OBJS) $(OBJSC)
	$(CC) $(L_FLAGS) $(L_FLAGS2) \
	../../lib/standard/crti.o \
	../../lib/standard/crtbeginT.o \
	../../lib/standard/crtend.o \
	-o $@ $(OBJS) $(LIBS) \
	../../../Src/Build/Release/dist/lib/libQuoteVerificationStatic.a \
	../../../Src/Build/Release/dist/lib/libAttestationParsersStatic.a \
	../../../Src/Build/Release/dist/lib/libAttestationCommonsStatic.a \
	/OpenSSL/openssl-1.1.1j/libcrypto.a \
	/OpenSSL/openssl-1.1.1j/libssl.a \
	/usr/powerpc-linux-gnu/lib/libpthread.a \
	/usr/powerpc-linux-gnu/lib/libdl.a \
	-Wl,--start-group \
	../../lib/standard/libgcc.a \
	../../lib/standard/libgcc_eh.a \
	../../lib/standard/libc.a \
	../../lib/standard/libstdc++.a \
	-Wl,--end-group \
	-lfmsupt
	
clean:
	-rm -r $(BDIR) $(ODIR)

dirs: $(BDIR) $(ODIR)




