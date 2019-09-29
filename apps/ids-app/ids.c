
//#include "net/rpl/rpl-icmp6.c"

#include "ids.h"

//void ids_output(uip_ipaddr_t *addr);
extern ids_ctr_t nodes[NODES_NUM];
#define DEBUG 1


PROCESS(ids_process, "Chk");

void checkNodes(){
	uint8_t j=0;
  
	for (j=0; j<NODES_NUM;j++){        
        if (nodes[j].address>0 && nodes[j].address!=0 && nodes[j].address!=1){
           
          //  PRINTF("adr:%d %u disnum:%u %u time_in:%u\n",j,(unsigned)nodes[j].address,
           // (unsigned)nodes[j].counterDIS,(unsigned)nodes[j].counterMsg,(unsigned)nodes[j].intervals);
            if (nodes[j].intervals<30 && nodes[j].counterDIS>=3){
              uint8_t k=0;
              /*for (k=0;k<5;k++){
                  tmp=nodes[j].counterDetect[k]+tmp;
              }*/
              //if (tmp>3){
                PRINTF("warning!ID mal %u!\n",(unsigned)nodes[j].address);
                
                nodes[j].counterDIS=0;
                nodes[j].counterMsg=0;
                nodes[j].intervals=999;
                for (k=0;k<DETECTORS_NUM;k++){
                  
                  if (nodes[j].fromNode[k].u8[sizeof(nodes[j].fromNode[k].u8)-1]!=0){
                      //PRINTF("sent reset to");
                     // PRINT6ADDR(&nodes[j].fromNode[k]);
                      //PRINTF("\n");
                      ids_output(&(nodes[j].fromNode[k]));
                  }
              //    nodes[j].counterDetect[k]=0;
                  nodes[j].fromNode[k].u8[sizeof(nodes[j].fromNode[k].u8)-1]=0;
                }
               
		          }
              

        }
        
    }
    
 //ctimer_reset(&mytimer);
}

PROCESS_THREAD(ids_process, ev, data)
{
 
  static struct etimer mytimer;

  PROCESS_BEGIN();
 
uint8_t i=0;
for (i=0;i<NODES_NUM;i++){
  nodes[i].address=0;
}


 // if(period == NULL) {
 //   PROCESS_EXIT();
  //}
  

  while(1) {
    etimer_set(&mytimer, 5*CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&mytimer));
    //etimer_reset(&mytimer);
    checkNodes();
    //PROCESS_WAIT_UNTIL(etimer_expired(&periodic));
    //checkNodes();
  }

  PROCESS_END();
}