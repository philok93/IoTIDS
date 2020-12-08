#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/routing/rpl-lite/rpl.h"
#include "os/net/routing/rpl-lite/rpl-neighbor.h"

#if IDS_OF==1
#include "ids.h"
#include "lib/list.h"
#endif


#include "sys/log.h"


#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define SEND_INTERVAL		  (60 * CLOCK_SECOND)



static struct simple_udp_connection udp_conn;

#if IDS_OF==1

#define ELEMENT_COUNT 5

LIST(blacklist);

typedef struct ids_item {
  struct ids_item *next;
  uint8_t ipaddr;
} ids_item_t;

static ids_item_t nodes[ELEMENT_COUNT];
static struct ctimer time_to_reset; //Reset stats of nbr
void reset_pkt_fw(void *ptr);

#endif

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{

  LOG_INFO("Received response '%.*s' from ", datalen, (char *) data);
  LOG_INFO_6ADDR(sender_addr);
#if LLSEC802154_CONF_ENABLED
  LOG_INFO_(" LLSEC LV:%d", uipbuf_get_attr(UIPBUF_ATTR_LLSEC_LEVEL));
#endif
  LOG_INFO_("\n");

}

#if IDS_OF ==1
int check_list(uint8_t item){
    if(list_head(blacklist) == NULL) {
            return 0;
        }
        
    uint8_t size=list_length(blacklist);
    // LOG_INFO("checking item:%d\n",item);
    uint8_t i=0;
    for(ids_item_t *node = list_head(blacklist); node != NULL && i<size; node = node->next, i++) {
        if (node->ipaddr==item){
            return 1;
        }
                
    }
    
    return 0;
}

void update_list(uint8_t ip){
    uint8_t chk=check_list(ip);
    // LOG_INFO("already in=%d\n",chk);

    uint8_t size=list_length(blacklist);

    if (!chk && size+1<ELEMENT_COUNT){

        nodes[size].ipaddr=ip;
        list_add(blacklist,&nodes[size]);
        //  LOG_INFO("updating len:%d\n",list_length(blacklist));

    }else
        LOG_INFO("no space or %d\n",chk);   
}

void rm_bh_from_nbr_table(uip_ipaddr_t** from){
        uip_ds6_nbr_t *ds6_nbr;

        if ((ds6_nbr = uip_ds6_nbr_lookup(*from)) != NULL)
        {
            LOG_INFO("insiderm %d\n",ds6_nbr==NULL);
    	const linkaddr_t *nbr_lladdr = (const linkaddr_t *)uip_ds6_nbr_get_ll(ds6_nbr);
            rpl_nbr_t *rpl_nbr = rpl_neighbor_get_from_lladdr((uip_lladdr_t *)nbr_lladdr);

            if (rpl_nbr != NULL && rpl_neighbor_is_parent(rpl_nbr)){
                rpl_neighbor_set_preferred_parent(NULL);
            }
            
            remove_neighbor(rpl_nbr);	    
	    uip_ds6_nbr_rm(ds6_nbr);   
        }
          
}


void remove_from_list(uint8_t ip){
    if (!check_list(ip))
        return;
    for(ids_item_t *node = list_head(blacklist); node != NULL; node = node->next) {
        if (node->ipaddr==ip){
            list_remove(blacklist,node);
            return;
        }
                
    }
     
}

void reset_pkt_fw(void *ptr){
    rpl_nbr_t *nbr;
    for (nbr = nbr_table_head(rpl_neighbors);
            nbr != NULL;
            nbr = nbr_table_next(rpl_neighbors, nbr))
    {
        nbr->fw_packets=0; 
    }

    ctimer_reset(&time_to_reset);
}

#endif
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  static unsigned count;
  static char str[32];
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);

#if IDS_OF ==1
    ctimer_set(&time_to_reset,930*CLOCK_SECOND,reset_pkt_fw,NULL);
#endif

// LOG_INFO("hereeeee");
#if IDS_OF==1
    memset(nodes, 0, sizeof(nodes));
  list_init(blacklist); //keep blacklisted nodes
#endif



  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      /* Send to DAG root */
      LOG_INFO("Sending request %u to ", count);
      LOG_INFO_6ADDR(&dest_ipaddr);
      LOG_INFO_("\n");
      snprintf(str, sizeof(str), "hello %d", count);
      simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);
      count++;
    } else {
      LOG_INFO("Not reachable yet\n");
    }

    /* Add some jitter */
    etimer_set(&periodic_timer, SEND_INTERVAL
      - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
