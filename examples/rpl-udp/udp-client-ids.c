#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"

#include "sys/log.h"

#include "ids.h"
#define LOG_MODULE "IDS"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define SEND_INTERVAL		  (60 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

 static struct ctimer time_to_reset;
 static void reset_stats();
// static struct etimer time_sniff;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "IDS client");
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

static void reset_stats(void *ptr){
  uint8_t i=0;
  for (i=0;i<NODES_NUM_CL;i++){
    nodes[i].address=0;
    nodes[i].counterMsg=0;
    nodes[i].counterDIS=0;
    nodes[i].intervals=999;
    nodes[i].timestamp=0;
  }
  ctimer_reset(&time_to_reset);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  static unsigned count;
  // static char str[32];
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

// //Initialize array with nodes
//  uint8_t i=0;
// for (i=0;i<30;i++){
//   nodes[i].address=0;
//   nodes[i].counterMsg=0;
//   nodes[i].counterDIS=0;
//   nodes[i].intervals=999;
//   nodes[i].timestamp=0;
// }

  // radio_value_t radio_rx_mode;
  NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, 0);
  /* Entering promiscuous mode so that the radio accepts the enhanced ACK */

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  //Used in uip6.c, starts detecting after 1 minute
  etimer_set(&time_sniff, (60*CLOCK_SECOND));

    etimer_set(&periodic_timer, (10*CLOCK_SECOND));  
  ctimer_set(&time_to_reset,180*CLOCK_SECOND,reset_stats,NULL);

  while(1) {
    // PROCESS_YIELD();
        // PROCESS_WAIT_EVENT();


    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    

    // if(etimer_expired(&periodic_timer)){
          etimer_reset(&periodic_timer);

      if (NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.node_has_joined() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      // NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr);
      /* Send to DAG root */
      LOG_INFO("Check IDS.Attempt: %u \n", count);
      // LOG_INFO_6ADDR(&dest_ipaddr);
      // LOG_INFO_("\n");
      // snprintf(str, sizeof(str), "hello %d", count);
      // simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);
      // sett inn output_tru kall!
      ids_output(&dest_ipaddr);
      count++; 
      
    } else {
      LOG_INFO("Not reachable yet\n");
    }
  

    /* Add some jitter */
    // etimer_set(&periodic_timer, SEND_INTERVAL
    //   - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
