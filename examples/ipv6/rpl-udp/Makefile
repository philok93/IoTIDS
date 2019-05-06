all: udp-client-ids2 udp-server
CONTIKI=../../..

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\" -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__
 
ifdef WITH_COMPOWER
APPS+=powertrace
CFLAGS+= -DCONTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1 -DQUEUEBUF_CONF_NUM=4
endif

ifdef SERVER_REPLY
CFLAGS+=-DSERVER_REPLY=$(SERVER_REPLY)
endif
ifdef PERIOD
CFLAGS+=-DPERIOD=$(PERIOD)
endif

ifeq ($(MAKE_WITH_NON_STORING),1)
CFLAGS += -DWITH_NON_STORING=1
endif

#CONTIKI_WITH_IPV6 = 1
UIP_CONF_ICMP6=1
UIP_CONF_IPV6=1
include $(CONTIKI)/Makefile.include
