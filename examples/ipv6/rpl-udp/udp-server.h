#ifndef SERVER_H
#define SERVER_H

struct IDS_ctr{
  uint32_t address;
  //IDS detectors are 6
  //uip_ip6addr_t fromNode[3];
  //uint32_t counterDetect[3];
  
  uint32_t counterMsg;
  uint32_t counterDIS;
  //uint8_t flag;
  uint32_t intervals;
  uint32_t timestamp;
};

//Mine for  IDS
extern uip_ipaddr_t IdsServerAddr;
extern uint32_t ip_end;
//extern uint16_t countOutNodes;
extern uint16_t countInNodes;
//3 instead of 6 detectors, 6 mal nodes
extern uint32_t detectorsIP[3];

//extern uint32_t DISvalues=0;
//extern uint32_t intervals=0;

//Average time,number of DIS for IDS
typedef struct IDS_ctr ids_ctr_t;
//Uncomment for server
//extern ids_ctr_t nodes[6];
extern ids_ctr_t nodes[30]; //ids  client
//extern char data_input;
//Tha valo 6 detectors, 36 nodes sinolo, 6 mal

#endif