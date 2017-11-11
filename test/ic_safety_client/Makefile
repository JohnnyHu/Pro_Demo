PWD         := $(shell pwd)
CC          := gcc
AT          := @

INCLUDE_DIR :=
LIB_DIR     :=
CFLAGS      := -std=gnu99 -Wall  -I$(INCLUDE_DIR) -L$(LIB_DIR)
LDFLAGS     :=
MAKE        := make

target := ic_safety_client
srcs   := $(wildcard $(PWD)/*.c)

PHONY+=all $(target) clean distclean
all: $(target)

$(target): FORCE
	$(AT)$(CC) $(CFLAGS) $(srcs) -o $(target) $(LDFLAGS)
clean:
	-$(AT)rm -f $(target)
distclean: clean

FORCE:

