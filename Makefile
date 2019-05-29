obj-m = pid_maps.o

KERNEL = $(shell uname -r)
KDIR ?= /lib/modules/$(KERNEL)/build

BUILD_DIR ?= $(PWD)/build
BUILD_DIR_MAKEFILE = $(BUILD_DIR)/Makefile

all: $(BUILD_DIR_MAKEFILE)
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) modules

clean:
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) clean
	rm -rf $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR_MAKEFILE): $(BUILD_DIR)
	touch "$@"
