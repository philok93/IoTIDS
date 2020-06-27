/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"

#if IDS_SERVER
#include "ids.h"
#pragma message "added ids"
#endif

#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

extern void checkNodes();
static struct simple_udp_connection udp_conn;
 static struct ctimer time_to_reset;
 static void reset_stats();


PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);
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
  LOG_INFO("Received request '%.*s' from ", datalen, (char *) data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
#if WITH_SERVER_REPLY
  /* send back the same string to the client as an echo reply */
  LOG_INFO("Sending response.\n");
  simple_udp_sendto(&udp_conn, data, datalen, sender_addr);
#endif /* WITH_SERVER_REPLY */
}

static void reset_stats(void *ptr){
  uint8_t i=0;
  for (i=0;i<NODES_NUM;i++){
    nodes[i].address=0;
    nodes[i].counterMsg=0;
    nodes[i].counterDIS=0;
    nodes[i].intervals=999;
    nodes[i].timestamp=0;
    nodes[i].detected=0;
    nodes[i].last_avg_rss=0;
    nodes[i].spoof_suspicious=0;

    uint8_t c=0;
    for (c=0;c<DETECTORS_NUM;c++){		
        nodes[i].counterDetect[c]=0;
        nodes[i].fromNode[c].u8[sizeof(nodes[i].fromNode[c].u8)-1]=0;

      }
  }

  
  ctimer_reset(&time_to_reset);
}


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  static struct etimer mytimer;

  PROCESS_BEGIN();

  /* Initialize DAG root */
  NETSTACK_ROUTING.root_start();

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);

  etimer_set(&mytimer, 20*CLOCK_SECOND);
  //Reset after 10 min
  ctimer_set(&time_to_reset,600*CLOCK_SECOND,reset_stats,NULL);
    
  while(1){

      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&mytimer));

    // PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&mytimer));
    // if (etimer_expired(&mytimer)) {
      
      checkNodes();

      etimer_reset(&mytimer);
    // }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
