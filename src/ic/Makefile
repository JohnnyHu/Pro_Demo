#
# Makefile for src/ic of Pro_Demo project 
#

#
# compiler arguments
#
CC              := gcc
MAKE            := make
AT              := @
AR              := ar
CFLAGS          := -std=gnu99 -g -O2 -Wall -I./inc -I../../include
SHARED          := -fPIC --shared

#
# misc compiler arguments
#
REDIS_LIBS      :=
#REDIS_LIBS 	:= -lhiredis -lbasedb
SMS_LIBS        := -L../../lib -ldl -lpthread  $(REDIS_LIBS)
SNMP_LIBS       := `net-snmp-config --libs`


SRC_BINS = ic_host ic_network ic_trap ic_ping ic_safety
SRC_FILES = 

SRC_FILES = $(wildcard src/*.c) 
SRC_OBJ  = $(SRC_FILES:.c=.o) 


all: $(foreach v, $(SRC_BINS), $(v))

#
# compile ic_host
#
ic_host : src/Utility.o src/ic_host.o
	$(CC) -o $@ $^ $(CFLAGS) $(SMS_LIBS)
	cp $@ ../../bin

#
# compile ic_network
#
ic_network: src/Utility.o src/ic_network.o
	$(CC) -o $@ $^ $(CFLAGS) $(SMS_LIBS) $(SNMP_LIBS)
	cp $@ ../../bin

#
# compile ic_trap
#
ic_trap: src/Utility.o src/ic_trap.o
	$(CC) -o $@ $^ $(CFLAGS) $(SMS_LIBS)
	cp $@ ../../bin

#
# compile ic_ping
#
ic_ping: src/Utility.o src/ic_ping.o
	$(CC) -o $@ $^ $(CFLAGS) $(SMS_LIBS)
	cp $@ ../../bin

#
# compile ic_safety
#
ic_safety: src/Utility.o src/ic_safety.o
	$(CC) -o $@ $^ $(CFLAGS) $(SMS_LIBS)
	cp $@ ../../bin

obj: $(SRC_OBJ)

clean:
	$(RM) $(SRC_OBJ) $(SRC_BINS)  ../../bin/ic_*

distclean:
	$(RM) $(SRC_OBJ) $(SRC_BINS) ../../bin/ic_*


.PHONY: all obj clean distclean
