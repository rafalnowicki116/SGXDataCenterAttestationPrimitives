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

DEFINES=-DOS_LINUX -DOS_UNIX -D__EXTENSIONS__ -D_RWSTD_MULTI_THREAD -D_REENTRANT -D_THREAD_SAFE -DLUNA_LITTLE_ENDIAN -DUSE_PTHREADS -DLUNA_LP64_CORRECT -DDEBUG -D_USESSL -DDISABLE_CA_EXT

# linux with GNU C defines
CC=gcc
CPP=g++
CFLAGS=-fPIC -c -Wall -Werror
# -x c

ifeq ($(DEBUG),)
CFLAGS+=-O2
EXTRALFLAGS=
else
CFLAGS+=-ggdb
EXTRALFLAGS=-ggdb
endif

EXTRALIBS=-lc -lpthread -ldl -lrt
INCLUDES=-I$(LUNASDK)/samples/include -I$(FMSDK)/include/fm/host -I$(FMSDK)/include -I../include

# specify a different output directory on make command line to chage o/p folder
OUTDIR?=output

# normal rules
$(OUTDIR)/obj/%.o : %.cpp  $(OUTDIR)/obj
	$(CPP) $(CFLAGS) $(INCLUDES) $(DEFINES)  $< -o$@

# define primary target
all: $(OUTDIR)/bin $(OUTDIR)/bin/qvl

# rules to create output dirs
$(OUTDIR)/obj:
	mkdir -p $@

$(OUTDIR)/bin:
	mkdir -p $@

OBJS=\
	$(OUTDIR)/obj/main.o

# link the test app
ifneq ("$(wildcard $(LUNASDK)/lib/libCryptoki2_64.so)", "")
LIB_CRYPTOKI=Cryptoki2_64
else
LIB_CRYPTOKI=Cryptoki2
endif

$(OUTDIR)/bin/qvl: $(OBJS)
	$(CPP) -o$@ $(EXTRALFLAGS) $^ -L$(LUNASDK)/lib -l$(LIB_CRYPTOKI) -lethsm $(EXTRALIBS) -Wl,-rpath=$(LUNASDK)/lib

clean:
	-rm -r $(OUTDIR)/bin $(OUTDIR)/obj