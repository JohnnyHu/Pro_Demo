PWD     	:= $(shell pwd)
CC      	:= gcc
AT      	:= @

INCLUDE_DIR	:=
LIB_DIR		:=
CFLAGS		:= -std=gnu99 -Wall  -I$(INCLUDE_DIR) -L$(LIB_DIR)
LDFLAGS		:= -pthread
MAKE		:= make

target := ic_host_client
srcs   := $(wildcard $(PWD)/*.c)
#srcs   := $(wildcard $(PWD)/test_syslog.c)

PHONY+=all $(target) clean distclean
all: $(target)

$(target): FORCE
	$(AT)$(CC) $(CFLAGS) $(srcs) -o $(target) $(LDFLAGS)
clean:
	-$(AT)rm -f $(target)
distclean: clean

FORCE:

