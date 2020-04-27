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

#include "lib/list.h"

#include <stdlib.h>
#include <ctype.h>

#if IDS_SERVER
#pragma message ("IDS_SERVER")
#define NODES_NUM 5
#define DETECTORS_NUM 10
#elif IDS_CLIENT
#pragma message ("IDS_CLIENT")
#define NODES_NUM_CL 5
#else
#pragma message ("IDS_GENERAL")
#endif


//Detectors_num=number of ids detectors
//Nodes_num= number of neighbour malicious nodes
//BR can save 5 mal nodes, ids det. save 10 mal

typedef struct IDS_ctr{
  
  uint16_t address;
  //IDS detectors are 6
  #if IDS_SERVER /*IDS_SERVER 3 detectors*/
  uip_ip6addr_t fromNode[DETECTORS_NUM];
  uint8_t counterDetect[DETECTORS_NUM];
  #endif  /*IDS_SERVER 3 detectors*/
  uint16_t counterMsg;
  uint16_t counterDIS;
  uint32_t intervals;
  uint32_t timestamp;
  char detected;
  int8_t last_avg_rss;
  char spoof_suspicious;
  
} ids_ctr_t;


//Mine for  IDS
extern uip_ipaddr_t IdsServerAddr;
extern uint16_t ip_end;
extern uint16_t countInNodes;

//3 instead of 6 detectors, 6 mal nodes
#if IDS_SERVER /*IDS_SERVER*/
extern uint16_t detectorsIP[DETECTORS_NUM];
void checkNodes();
#endif /*IDS_SERVER*/


//Average time,number of DIS for IDS
//typedef struct IDS_ctr ids_ctr_t;

#if IDS_SERVER /*IDS_SERVER*/
ids_ctr_t nodes[NODES_NUM];
#elif IDS_CLIENT
ids_ctr_t nodes[NODES_NUM_CL];
struct etimer time_sniff,packet_fw_timer;

typedef struct tagids{
  uint8_t dest[4]; //max number of parents to send packet
  // char from;
  uint8_t verified[4];
  uint8_t index;
  uint16_t count_fw_packets[4];
} fw_stats;

NBR_TABLE_DECLARE(nbr_fw_stats);
// fw_stats _nbr_fw_stats_mem[NBR_TABLE_MAX_NEIGHBORS];
// nbr_table_t nbr_fw_stats_struct; 
// //  NBR_TABLE(fw_stats,nbr_fw_stats);

typedef struct tag1{
  char to_ip;
} final_dest_ip;

fw_stats tmp_ip_senders[NODES_NUM_CL];
#endif

//void ids_start(clock_time_t perioc);

// PROCESS_NAME(ids_process);
#endif