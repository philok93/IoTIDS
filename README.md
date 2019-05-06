# IoTIDS
A new IDS for IoT. See below for configurations.

My current IDS: Uses ids server and ids detector (under **/ipv6/rpl-udp**)
ICTF - Configured for for ICTF paper under **/ipv6/rpl-collect**, 

To disable ACKs from server: go to /platform/z1: set conf_autoack 1 or 0 (1 to reply)

**For IDS detector:**
ids-client-ids2: uncomment checkIDS function in rpl-icmp6
server: comment checkIDS function

CHECKLIST FOR normal SENSOR:
1)MAKEFILE.include NO -mal.
2)FOR **SENSOR rpl-udp/project-conf.h to compile contikimac_driver(sleep),csma_driver
**FOR SERVER USE nullmac, nullrdc
3)platform/z1/Makefile.z1: NO net/mac-mal
4)platform/z1/contiki-conf.h:check CC2420_CONF_AUTOACK=1 (for server turn off autoack)
5)rpl-mal/rpl-timers.c: check for malicious code "DIS flood",comment it
6)rpl-mal/rpl-icmp6.c: comment code for IDS or ip/uip6.c
7) net/mac/nullrdc is used and not /net/mac-mal/nullrdc.c
8) net/uip6.c: comment countOutNodes (its for counting nodes in range for IDS detector)
9) COMMENT struct IDS_ctr{
  uint8_t address;
  uint32_t counterMsg;
  uint32_t counterDIS;
  uint8_t msgtype;
  unsigned long intervals;
  unsigned long timestamp;
};

//Mine for  IDS
uint32_t ip_end;
extern uint16_t countOutNodes;
uint32_t countInNodes=0;
uint32_t DISvalues=0;
uint32_t intervals=0;
*/
This is ONLY for ids-server is compiled.

CHECKLIST FOR malicious SENSOR:
1)MAKEFILE.include uncheck ipv6-mal but check rpl-mal ONLY.
2)rpl-udp/project-conf.h to compile nullrdc(sleep),csma_driver (verified)
3)platform/z1/Makefile.z1: NOO net/mac-mal
4)platform/z1/contiki-conf.h:check CC2420_CONF_AUTOACK=1
5)rpl-mal/rpl-icmp6.c: check for malicious code "DIS flood",uncomment it
6)rpl-icmp6.c: comment code for IDS
7) check RPL-CONF.H to have 0 RPL_DIS_INTERVALand 180 RPL_DIS_DELAY
7)uses net/mac/
8( COMMENT IDS server variables in rpl-icmp6
USE RPL normal for malicious node, just uncomment IDS code in rpl-timers.


CHECKLIST FOR IDS SERVER SENSOR:
same 1-3
1)MAKEFILE.include remove ipv6-mal and check other ...-mal.
2)rpl-udp/project-conf.h to compile nullmac,nullrdc
4)platform/z1/contiki-conf.h:check CC2420_CONF_AUTOACK=0
5)rpl/rpl-timers.c: check for malicious code "DIS flood",comment it
6)rpl-icmp6.c: comment code for IDS, uip6 code for IDS
7) net/mac-mal/nullrdc.c uses
8) check for normal RPL_DIS_INTERVAL in RPL-CONF.
9) uncomment IDS server variables in rpl-icmp6.
10) uncomment rpl-private.h in udp-server.c

Problems: 
1)Not all DIS messages are detected from IDS. 
2)UDP packets not detected!
#)DIS attack can be multicaste (now) or unicast to all neighbours.

code:
1)check if the coming packet is from node 1 or from myself( ids_input)
