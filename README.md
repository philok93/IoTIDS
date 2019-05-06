# IoTIDS #
A new IDS for IoT that uses Contiki 3.0.

My current IDS: Uses ids server and ids detector (under **/ipv6/rpl-udp**). 

ICTF - Configured for ICTF paper under **/ipv6/rpl-collect**, use the ready z1 files udp-client and udp-server.

***To use IDS, replace the normal /net/ with /net-for_IDS/ ***

**The /net-for_IDS contains modifications in rpl, ipv6 and mac to enable IDS modules communication with ids_input messages, and sniff messages.**

Disable ACKs from server: go to /platform/z1: set conf_autoack 1 or 0 (1 to reply). 

# Instructions: #
1. Replace in core/net-for_IDS to core/net so that you can compile the files for IDS.
2. You see 3 rpl folders in core/net-for_IDS. The rpl is the original, rpl-mal is for IDS detector (or udp-client-ids2.z1) and rpl-mal-server for udp-server-ids.z1. So you need to rename and compile each time the proper rpl folder because they contain changes that needed.
3. See below for extra changes oyu have to make in order to properly compile the IDS detector and server.
4. To test the IDS, go to examples/ipv6/rpl-udp/ and just load the firmware from IDS files_improved. Load the "udp-client-ids2.z1" (IDS detector), "udp-server.z1" (IDS server).
Also loads "udp-client-mal.z1" from /malic/ (it is the malicious node). Then load norma/udp-client.z1 to have a normal client (original file).
Then run the simulation.
 

## Checklist for IDS detector: ##
udp-client-ids2.z1: uncomment checkIDS function in rpl/rpl-icmp6
Read below for checks of normal sensor

## Checklist when compiling normal (no malicious) sensor: ##

	1. MAKEFILE.include: the /rpl and /ipv6 must be without -mal.
	2. FOR **SENSOR rpl-udp/project-conf.h to compile contikimac_driver(sleep. ,csma_driver**
	FOR SERVER USE nullmac, nullrdc
	3. platform/z1/Makefile.z1: Must be net/mac (to make sure that is the normal nullrdc file) 
	4. platform/z1/contiki-conf.h:check CC2420_CONF_AUTOACK=1 (for server turn off autoack.)
	5. rpl-mal/rpl-timers.c: find malicious code "DIS flood", and comment it
	6. rpl-mal/rpl-icmp6.c: comment code for IDS or ip/uip6.c
	7.  Normal nullrdc is used, not /net/mac-mal/nullrdc.c
	8.  net/uip6.c: comment countOutNodes (it's for counting nodes in range for IDS detector)
	9.  COMMENT in rpl-udp/udp-server.h:
	 struct IDS_ctr{
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

	The above are ONLY for ids-server when compiling.

## Checklist when compiling malicious sensor: ##
	
	1. MAKEFILE.include uncheck ipv6-mal but check rpl-mal ONLY.
	2. rpl-udp/project-conf.h to compile nullrdc(no sleep) , csma_driver (verified works). 
	3. platform/z1/Makefile.z1: NO net/mac-mal, use net/mac
	4. platform/z1/contiki-conf.h: check CC2420_CONF_AUTOACK=1
	5. rpl-mal/rpl-icmp6.c: check for malicious code "DIS flood", and uncomment it. Comment code for IDS.
	6. check rpl-conf.H to have 0 RPL_DIS_INTERVAL and 0 RPL_DIS_DELAY
	7.  COMMENT IDS server variables in rpl-icmp6
	USE RPL normal for malicious node, just uncomment IDS code in rpl-timers.


## Checklist for IDS SERVER sensor: ##
	
	1. MAKEFILE.include remove ipv6-mal and other -mal folders from compiling.
	2. rpl-udp/project-conf.h to compile nullmac,nullrdc
	4. platform/z1/contiki-conf.h:check CC2420_CONF_AUTOACK=0
	5. rpl/rpl-timers.c: check for malicious code "DIS flood",comment it
	6. rpl-icmp6.c: comment code for IDS, uip6 code for IDS
	7.  net/mac-mal/nullrdc.c uses
	8.  check for normal RPL_DIS_INTERVAL and RPL_DIS_DELAY in rpl-conf.h
	9.  Uncomment IDS server variables in rpl-icmp6.
	10.  Uncomment rpl-private.h in udp-server.c

## General Problems: ## 
1. Not all DIS messages are detected from IDS. 
2. UDP packets not detected!
3. DIS attack can be multicast (now works like this.  or unicast to all neighbours.
