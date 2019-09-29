#ifndef IDS_H
#define IDS_H
#include "net/ip/uip.h"
#include "net/net-debug.h"
#include "contiki.h"
#include <stdio.h>
#include <string.h>

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/rpl/rpl.h"
#include "net/rpl/rpl-private.h"

#include <stdlib.h>
#include <ctype.h>

#if IDS_SERVER
#define NODES_NUM 5
#else
#define NODES_NUM_CL 30
#endif

#define DETECTORS_NUM 2


struct IDS_ctr{
  
  uint32_t address;
  //IDS detectors are 6
  #if IDS_SERVER /*IDS_SERVER 3 detectors*/
  uip_ip6addr_t fromNode[DETECTORS_NUM];
 // uint32_t counterDetect[3];
  #endif  /*IDS_SERVER 3 detectors*/
  uint32_t counterMsg;
  uint32_t counterDIS;
  uint32_t intervals;
  uint32_t timestamp;
  
};
typedef struct IDS_ctr ids_ctr_t;


//Mine for  IDS
extern uip_ipaddr_t IdsServerAddr;
extern uint32_t ip_end;
extern uint16_t countInNodes;

//3 instead of 6 detectors, 6 mal nodes
#if IDS_SERVER /*IDS_SERVER*/
extern uint16_t detectorsIP[DETECTORS_NUM];
#endif /*IDS_SERVER*/


//Average time,number of DIS for IDS
//typedef struct IDS_ctr ids_ctr_t;

#if IDS_SERVER /*IDS_SERVER*/
ids_ctr_t nodes[NODES_NUM];
#endif

//void ids_start(clock_time_t perioc);

PROCESS_NAME(ids_process);
#endif