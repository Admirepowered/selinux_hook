SELINUX_VERSION := 1.1.5

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set; use aarch64-none-elf- from arm-gnu-toolchain, \
           see https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
OBJCOPY = $(TARGET_COMPILE)objcopy

CFLAGS += -Wall -O2 -fno-builtin -std=gnu11 -nostdinc -mgeneral-regs-only
CFLAGS += -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common

ifdef ANDROID
	CFLAGS += -DANDROID
endif

ifdef DEBUG
	CFLAGS += -DDEBUG -DMAP_DEBUG -g
endif

CFLAGS += -DSELINUX_VERSION=\"$(SELINUX_VERSION)\"

INCLUDE_DIRS := . include patch/include linux linux/include linux/security/selinux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := selinux_hook.o

all: selinux_hook_$(SELINUX_VERSION).kpm

selinux_hook_$(SELINUX_VERSION).kpm: ${objs}
	${CC} -r -nostdlib -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
