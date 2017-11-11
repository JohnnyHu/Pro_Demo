#
# Top Makefile for Pro_Demo project 
#


DIR = src
MODULES = $(shell ls $(DIR)) 

all: $(MODULES)

$(MODULES):
	$(MAKE) -C $(DIR)/$@

obj:
	$(MAKE) -C $(DIR)/ic $@

clean:
	$(MAKE) -C $(DIR)/ic $@

distclean:
	@for subdir in $(MODULES); \
	do $(MAKE) -C $(DIR)/$$subdir $@; \
	done


.PHONY: all obj clean distclean
