# IPA-DN-Ultra UltraTest Source Code
# 
# License: The Apache License, Version 2.0
# https://www.apache.org/licenses/LICENSE-2.0
# 
# Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
# Copyright (c) Daiyuu Nobori.
# Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
# Copyright (c) SoftEther Corporation.
# Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
# 
# All Rights Reserved.

.PHONY: all build clean

UNAME_P := $(shell uname -p)

ifeq ($(UNAME_P),aarch64)
	GCC_ADDITIONAL_FLAGS := -fPIE -fno-builtin-ffs
	CROSSLIB_DIR_NAME := linux-arm64-64bit
else
	GCC_ADDITIONAL_FLAGS := -fPIE -m64
	CROSSLIB_DIR_NAME := linux-x86-64bit
endif

CFLAGS_DEBUG := -D_DEBUG -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./ -I./Mayaqua/ -I./ -I./Vars/ -g -fsigned-char $(GCC_ADDITIONAL_FLAGS)

CFLAGS_RELEASE := -DNDEBUG -DVPN_SPEED -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./ -I./Mayaqua/ -I./ -I./Vars/ -g -O2 -fsigned-char $(GCC_ADDITIONAL_FLAGS)


CROSSLIBS := libssl.a libcrypto.a libiconv.a libcharset.a libedit.a libncurses.a libz.a

CROSSLIBS_FULLPATH := $(addprefix ./BuildFiles/CrossLib/$(CROSSLIB_DIR_NAME)/,$(CROSSLIBS))

LDLIBS := -lm -ldl -lrt -lpthread -pthread $(CROSSLIBS_FULLPATH)

LDFLAGS_DEBUG := -g -fsigned-char $(GCC_ADDITIONAL_FLAGS)

LDFLAGS_RELEASE := -g -O2 -fsigned-char $(GCC_ADDITIONAL_FLAGS)


ifeq ($(DEBUG),YES)
	CFLAGS := $(CFLAGS_DEBUG)
	LDFLAGS := $(LDFLAGS_DEBUG)
	DEBUG_OR_RELEASE := debug
else
	CFLAGS := $(CFLAGS_RELEASE)
	LDFLAGS := $(LDFLAGS_RELEASE)
	DEBUG_OR_RELEASE := release
endif


# Mayaqua source files
MAYAQUA_SRCS := $(wildcard ./Mayaqua/*.c)
MAYAQUA_HEADERS := $(wildcard ./Mayaqua/*.h)
MAYAQUA_OBJS := $(addprefix tmp/unix/$(DEBUG_OR_RELEASE)/submodules/,$(addsuffix .o,$(sort $(basename $(MAYAQUA_SRCS)))))

tmp/unix/$(DEBUG_OR_RELEASE)/submodules/./Mayaqua/%.o: ./Mayaqua/%.c $(MAYAQUA_HEADERS)
	@if [ ! -e `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(CC) $(CFLAGS) -o $@ -c $<


# Cedar source files
CEDAR_SRCS := $(wildcard ./Cedar/*.c)
CEDAR_HEADERS := $(wildcard ./Cedar/*.h)
CEDAR_OBJS := $(addprefix tmp/unix/$(DEBUG_OR_RELEASE)/submodules/,$(addsuffix .o,$(sort $(basename $(CEDAR_SRCS)))))

tmp/unix/$(DEBUG_OR_RELEASE)/submodules/./Cedar/%.o: ./Cedar/%.c $(CEDAR_HEADERS) $(MAYAQUA_HEADERS)
	@if [ ! -e `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(CC) $(CFLAGS) -o $@ -c $<


# UltraTest source files
ULTRATEST_SRCS := $(wildcard UltraTest/*.c)
ULTRATEST_HEADERS := $(wildcard UltraTest/*.h)
ULTRATEST_OBJS := $(addprefix tmp/unix/$(DEBUG_OR_RELEASE)/,$(addsuffix .o,$(sort $(basename $(ULTRATEST_SRCS)))))

tmp/unix/$(DEBUG_OR_RELEASE)/UltraTest/%.o: UltraTest/%.c $(ULTRATEST_HEADERS) $(CEDAR_HEADERS) $(MAYAQUA_HEADERS)
	@if [ ! -e `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(CC) $(CFLAGS) -o $@ -c $<


# Targets and build rules
all:	build

build:	bin/UltraTest

clean:
	-rm -fr tmp/unix/debug/ tmp/unix/release/
	-rm -f bin/UltraTest

bin/UltraTest:	$(MAYAQUA_OBJS) $(CEDAR_OBJS) $(ULTRATEST_OBJS)
	$(CC) $(LDFLAGS_DEBUG) $^ $(LDLIBS) -o $@







