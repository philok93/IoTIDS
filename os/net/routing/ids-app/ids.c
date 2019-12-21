
//#include "net/rpl/rpl-icmp6.c"

#include "ids.h"
#include "sys/log.h"



//void ids_output(uip_ipaddr_t *addr);

// #if IDS_SERVER
// #define NODES_NUM 5
// #elif IDS_CLIENT
// #define NODES_NUM_CL 30
// #endifs

#if IDS_SERVER
ids_ctr_t nodes[NODES_NUM];

#define LOG_MODULE "IDS"
#define LOG_LEVEL LOG_LEVEL_INFO

void checkNodes();
// PROCESS(ids_process, "Chk");

void checkNodes(){
	uint8_t j=0;
  LOG_INFO("Running IDS\n");
	for (j=0; j<NODES_NUM;j++){
         
        if (nodes[j].address>0 && nodes[j].address!=0 && nodes[j].address!=1){
           
           LOG_INFO("adr:%d %u disnum:%u %u t_in:%u\n",j,(unsigned)nodes[j].address,
           (unsigned)nodes[j].counterDIS,(unsigned)nodes[j].counterMsg,(unsigned)nodes[j].intervals);
            if (nodes[j].intervals<=30 && nodes[j].counterDIS>=3){
              uint8_t count=0,c=0;
              for (c=0;c<DETECTORS_NUM;c++){		
                      // LOG_INFO("TI:%d\n",nodes[j].counterDetect[c]);		
                      // LOG_INFO_6ADDR(&nodes[j].fromNode[c]);
                      // LOG_INFO("\n");

                      count+=nodes[j].counterDetect[c];
              }
              LOG_INFO("c;%d %d\n",count,nodes[j].detected);

              if (count>=2 && nodes[j].detected==1){
                LOG_INFO("sure mal ID %u!\n",(unsigned)nodes[j].address);
                

                uint8_t k=0;

                  for (k=0;k<DETECTORS_NUM;k++){  
                //  nodes[j].counterDetect[k]=0;
                  nodes[j].fromNode[k].u8[sizeof(nodes[j].fromNode[k].u8)-1]=0;
                }

              }
              /*for (k=0;k<5;k++){
                  tmp=nodes[j].counterDetect[k]+tmp;
              }*/
              //if (tmp>3){
                nodes[j].detected=1;
                LOG_INFO("warning!ID mal %u!\n",(unsigned)nodes[j].address);
                // nodes[j].address=0;
                nodes[j].counterDIS=0;
                nodes[j].counterMsg=0;
                nodes[j].intervals=999;

                
               
		          }
              

        }else
          nodes[j].detected=0;
        
    }
    
 //ctimer_reset(&mytimer);
}

#endif
// PROCESS_THREAD(ids_process, ev, data)
// {
 
//   static struct etimer mytimer;

//   PROCESS_BEGIN();
 
// uint8_t i=0;
// for (i=0;i<NODES_NUM;i++){
//   nodes[i].address=0;
// }


//  // if(period == NULL) {
//  //   PROCESS_EXIT();
//   //}
  

//   while(1) {
//     etimer_set(&mytimer, 5*CLOCK_SECOND);
//     PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&mytimer));
//     //etimer_reset(&mytimer);
//     checkNodes();
//     //PROCESS_WAIT_UNTIL(etimer_expired(&periodic));
//     //checkNodes();
//   }

//   PROCESS_END();
// }