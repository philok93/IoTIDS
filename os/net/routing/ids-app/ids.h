#ifndef IDS_H
#define IDS_H

#include "os/net/ipv6/uip-debug.h"
#include "contiki.h"
#include <stdio.h>
#include <string.h>


#include "sys/ctimer.h"
#include "os/net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "os/net/routing/rpl-lite/rpl.h"
#include "net/nbr-table.h"

#include <stdlib.h>
#include <ctype.h>

#if IDS_SERVER==1
#pragma message ("IDS_SERVER")
#define NODES_NUM 10 //Change this for future simulations
#define DETECTORS_NUM 10
#elif IDS_CLIENT==1
#pragma message ("IDS_CLIENT")
#define NODES_NUM_CL 10
#else
#pragma message ("IDS_GENERAL")
#endif


//Detectors_num=number of ids detectors
//Nodes_num= number of neighbour malicious nodes
//BR can save 5 mal nodes, ids det. save 10 mal
// #if IDS_OF==0

typedef struct IDS_ctr{
  
  uint16_t address;
  //IDS detectors are 6
  #if IDS_SERVER==1 /*IDS_SERVER 3 detectors*/
  uip_ip6addr_t fromNode[DETECTORS_NUM];
  uint8_t counterDetect[DETECTORS_NUM];
  uint8_t blackhole_mal;
  #endif  /*IDS_SERVER 3 detectors*/
  uint16_t counterMsg;
  uint16_t counterDIS;
  uint32_t intervals;
  uint32_t timestamp;
  char detected;
  uint16_t last_avg_rss;
  char spoof_suspicious;
  
} ids_ctr_t;


//Mine for  IDS
extern uip_ipaddr_t IdsServerAddr;
extern uint16_t ip_end;
extern uint16_t countInNodes;

// #endif

//3 instead of 6 detectors, 6 mal nodes
#if IDS_SERVER==1 /*IDS_SERVER*/
extern uint16_t detectorsIP[DETECTORS_NUM];
void checkNodes();
#endif /*IDS_SERVER*/


//Average time,number of DIS for IDS
//typedef struct IDS_ctr ids_ctr_t;

#if IDS_SERVER==1 /*IDS_SERVER*/
ids_ctr_t nodes[NODES_NUM];
#elif IDS_CLIENT==1
ids_ctr_t nodes[NODES_NUM_CL];
struct etimer time_sniff,packet_fw_timer;

//IDS client struct to check Blackhole attack
typedef struct tagids{
  uint8_t dest[4]; //max number of parents to send packet
  // char from;
  uint8_t verified[4];
  uint8_t index;
  uint16_t count_fw_packets[4];
} fw_stats;

NBR_TABLE_DECLARE(nbr_fw_stats);

fw_stats tmp_ip_senders[NODES_NUM_CL];
#endif


#if IDS_OF==1

// typedef struct ids_item ids_item_t;

void update_list(uint8_t mal_node);
int check_list(uint8_t item);
void remove_from_list(uint8_t ip);

#endif

#endif