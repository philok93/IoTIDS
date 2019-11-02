/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
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

/**
 * \addtogroup rpl-lite
 * @{
 *
 * \file
 *         ICMP6 I/O for RPL control messages.
 *
 * \author Joakim Eriksson <joakime@sics.se>, Nicolas Tsiftes <nvt@sics.se>,
 * Simon Duquennoy <simon.duquennoy@inria.fr>
 * Contributors: Niclas Finne <nfi@sics.se>, Joel Hoglund <joel@sics.se>,
 *               Mathieu Pouillot <m.pouillot@watteco.com>,
 *               George Oikonomou <oikonomou@users.sourceforge.net> (multicast)
 */

#include "net/routing/rpl-lite/rpl.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/packetbuf.h"
#include "lib/random.h"

#if IDS_SERVER || IDS_CLIENT
#include "ids.h"
#endif

#include <limits.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "RPL"
#define LOG_LEVEL LOG_LEVEL_RPL

/*---------------------------------------------------------------------------*/
#define RPL_DIO_GROUNDED                 0x80
#define RPL_DIO_MOP_SHIFT                3
#define RPL_DIO_MOP_MASK                 0x38
#define RPL_DIO_PREFERENCE_MASK          0x07

/*---------------------------------------------------------------------------*/
static void dis_input(void);
static void dio_input(void);
static void dao_input(void);


//Added IDS
#if IDS_CLIENT || IDS_SERVER
//void ids_output(uip_ipaddr_t *addr);
//void ids_input(void);
uip_ipaddr_t IdsServerAddr;
uint32_t ip_end=0;
uint8_t endofIP=0;
uint16_t countInNodes=0;
#endif /*IDS_CLIENT || IDS_SERVER*/

#if IDS_CLIENT
  uint32_t DISvalues=0;
  uint32_t intervals=0;
  extern ids_ctr_t nodes[NODES_NUM_CL];
#elif IDS_SERVER
  //char data_input;
  uint16_t detectorsIP[DETECTORS_NUM];
  //Average time,number of DIS for IDS
  extern ids_ctr_t nodes[NODES_NUM];
#endif /*IDS_SERVER*/

#if MAL_EXT
//Malicious flag ext
extern char flag_ext;
#endif

/*---------------------------------------------------------------------------*/
/* Initialize RPL ICMPv6 message handlers */
UIP_ICMP6_HANDLER(dis_handler, ICMP6_RPL, RPL_CODE_DIS, dis_input);
UIP_ICMP6_HANDLER(dio_handler, ICMP6_RPL, RPL_CODE_DIO, dio_input);
UIP_ICMP6_HANDLER(dao_handler, ICMP6_RPL, RPL_CODE_DAO, dao_input);


#if MAL_EXT
//Malicious input handler
UIP_ICMP6_HANDLER(mal_handler, ICMP6_RPL, RPL_CODE_MAL, mal_input);
#endif

#if IDS_CLIENT || IDS_SERVER
UIP_ICMP6_HANDLER(ids_handler, ICMP6_RPL, RPL_CODE_IDS, ids_input);

#endif /*IDS_CLIENT*/


#if RPL_WITH_DAO_ACK
static void dao_ack_input(void);
UIP_ICMP6_HANDLER(dao_ack_handler, ICMP6_RPL, RPL_CODE_DAO_ACK, dao_ack_input);
#endif /* RPL_WITH_DAO_ACK */

/*---------------------------------------------------------------------------*/
static uint32_t
get32(uint8_t *buffer, int pos)
{
  return ((uint32_t)buffer[pos] << 24 | (uint32_t)buffer[pos + 1] << 16 |
          (uint32_t)buffer[pos + 2] << 8 | buffer[pos + 3]);
}
/*---------------------------------------------------------------------------*/
static void
set32(uint8_t *buffer, int pos, uint32_t value)
{
  buffer[pos++] = value >> 24;
  buffer[pos++] = (value >> 16) & 0xff;
  buffer[pos++] = (value >> 8) & 0xff;
  buffer[pos++] = value & 0xff;
}
/*---------------------------------------------------------------------------*/
static uint16_t
get16(uint8_t *buffer, int pos)
{
  return (uint16_t)buffer[pos] << 8 | buffer[pos + 1];
}
/*---------------------------------------------------------------------------*/
static void
set16(uint8_t *buffer, int pos, uint16_t value)
{
  buffer[pos++] = value >> 8;
  buffer[pos++] = value & 0xff;
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
rpl_icmp6_update_nbr_table(uip_ipaddr_t *from, nbr_table_reason_t reason, void *data)
{
  uip_ds6_nbr_t *nbr;

  if((nbr = uip_ds6_nbr_lookup(from)) == NULL) {
    if((nbr = uip_ds6_nbr_add(from, (uip_lladdr_t *)
                              packetbuf_addr(PACKETBUF_ADDR_SENDER),
                              0, NBR_REACHABLE, reason, data)) == NULL) {
      LOG_ERR("could not add neighbor to cache ");
      LOG_ERR_6ADDR(from);
      LOG_ERR_(", ");
      LOG_ERR_LLADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
      LOG_ERR_("\n");
    }
  }

  return nbr;
}
/*---------------------------------------------------------------------------*/
static void
dis_input(void)
{
  if(!curr_instance.used) {
    LOG_WARN("dis_input: not in an instance yet, discard\n");
    goto discard;
  }

  LOG_INFO("received a DIS from ");
  LOG_INFO_6ADDR(&UIP_IP_BUF->srcipaddr);
  LOG_INFO_("\n");

  rpl_process_dis(&UIP_IP_BUF->srcipaddr, uip_is_addr_mcast(&UIP_IP_BUF->destipaddr));

  discard:
    uipbuf_clear();
}
/*---------------------------------------------------------------------------*/
void
rpl_icmp6_dis_output(uip_ipaddr_t *addr)
{
  unsigned char *buffer;

  /* Make sure we're up-to-date before sending data out */
  rpl_dag_update_state();

  buffer = UIP_ICMP_PAYLOAD;
  buffer[0] = buffer[1] = 0;

  if(addr == NULL) {
    addr = &rpl_multicast_addr;
  }

  LOG_INFO("sending a DIS to ");
  LOG_INFO_6ADDR(addr);
  LOG_INFO_("\n");

  uip_icmp6_send(addr, ICMP6_RPL, RPL_CODE_DIS, 2);
}
/*---------------------------------------------------------------------------*/
static void
dio_input(void)
{
  unsigned char *buffer;
  uint8_t buffer_length;
  rpl_dio_t dio;
  uint8_t subopt_type;
  int i;
  int len;
  uip_ipaddr_t from;

  memset(&dio, 0, sizeof(dio));

  /* Set default values in case the DIO configuration option is missing. */
  dio.dag_intdoubl = RPL_DIO_INTERVAL_DOUBLINGS;
  dio.dag_intmin = RPL_DIO_INTERVAL_MIN;
  dio.dag_redund = RPL_DIO_REDUNDANCY;
  dio.dag_min_hoprankinc = RPL_MIN_HOPRANKINC;
  dio.dag_max_rankinc = RPL_MAX_RANKINC;
  dio.ocp = RPL_OF_OCP;
  dio.default_lifetime = RPL_DEFAULT_LIFETIME;
  dio.lifetime_unit = RPL_DEFAULT_LIFETIME_UNIT;

  uip_ipaddr_copy(&from, &UIP_IP_BUF->srcipaddr);

  buffer_length = uip_len - uip_l3_icmp_hdr_len;

  /* Process the DIO base option. */
  i = 0;
  buffer = UIP_ICMP_PAYLOAD;

  dio.instance_id = buffer[i++];
  dio.version = buffer[i++];
  dio.rank = get16(buffer, i);
  i += 2;

  dio.grounded = buffer[i] & RPL_DIO_GROUNDED;
  dio.mop = (buffer[i]& RPL_DIO_MOP_MASK) >> RPL_DIO_MOP_SHIFT;
  dio.preference = buffer[i++] & RPL_DIO_PREFERENCE_MASK;

  dio.dtsn = buffer[i++];
  /* two reserved bytes */
  i += 2;

  memcpy(&dio.dag_id, buffer + i, sizeof(dio.dag_id));
  i += sizeof(dio.dag_id);

  /* Check if there are any DIO suboptions. */
  for(; i < buffer_length; i += len) {
    subopt_type = buffer[i];
    if(subopt_type == RPL_OPTION_PAD1) {
      len = 1;
    } else {
      /* Suboption with a two-byte header + payload */
      len = 2 + buffer[i + 1];
    }

    if(len + i > buffer_length) {
      LOG_ERR("dio_input: malformed packet, discard\n");
      goto discard;
    }

    switch(subopt_type) {
      case RPL_OPTION_DAG_METRIC_CONTAINER:
        if(len < 6) {
          LOG_WARN("dio_input: invalid DAG MC, len %u, discard\n", len);
          goto discard;
        }
        dio.mc.type = buffer[i + 2];
        dio.mc.flags = buffer[i + 3] << 1;
        dio.mc.flags |= buffer[i + 4] >> 7;
        dio.mc.aggr = (buffer[i + 4] >> 4) & 0x3;
        dio.mc.prec = buffer[i + 4] & 0xf;
        dio.mc.length = buffer[i + 5];

        if(dio.mc.type == RPL_DAG_MC_NONE) {
          /* No metric container: do nothing */
        } else if(dio.mc.type == RPL_DAG_MC_ETX) {
          dio.mc.obj.etx = get16(buffer, i + 6);
        } else if(dio.mc.type == RPL_DAG_MC_ENERGY) {
          dio.mc.obj.energy.flags = buffer[i + 6];
          dio.mc.obj.energy.energy_est = buffer[i + 7];
        } else {
          LOG_WARN("dio_input: unsupported DAG MC type %u, discard\n", (unsigned)dio.mc.type);
          goto discard;
        }
        break;
      case RPL_OPTION_ROUTE_INFO:
        if(len < 9) {
          LOG_WARN("dio_input: invalid destination prefix option, len %u, discard\n", len);
          goto discard;
        }

        /* The flags field includes the preference value. */
        dio.destination_prefix.length = buffer[i + 2];
        dio.destination_prefix.flags = buffer[i + 3];
        dio.destination_prefix.lifetime = get32(buffer, i + 4);

        if(((dio.destination_prefix.length + 7) / 8) + 8 <= len &&
           dio.destination_prefix.length <= 128) {
          memcpy(&dio.destination_prefix.prefix, &buffer[i + 8],
                 (dio.destination_prefix.length + 7) / 8);
        } else {
          LOG_WARN("dio_input: invalid route info option, len %u, discard\n", len);
          goto discard;
        }

        break;
      case RPL_OPTION_DAG_CONF:
        if(len != 16) {
          LOG_WARN("dio_input: invalid DAG configuration option, len %u, discard\n", len);
          goto discard;
        }

        /* Path control field not yet implemented - at i + 2 */
        dio.dag_intdoubl = buffer[i + 3];
        dio.dag_intmin = buffer[i + 4];
        dio.dag_redund = buffer[i + 5];
        dio.dag_max_rankinc = get16(buffer, i + 6);
        dio.dag_min_hoprankinc = get16(buffer, i + 8);
        dio.ocp = get16(buffer, i + 10);
        /* buffer + 12 is reserved */
        dio.default_lifetime = buffer[i + 13];
        dio.lifetime_unit = get16(buffer, i + 14);
        break;
      case RPL_OPTION_PREFIX_INFO:
        if(len != 32) {
          LOG_WARN("dio_input: invalid DAG prefix info, len %u, discard\n", len);
          goto discard;
        }
        dio.prefix_info.length = buffer[i + 2];
        dio.prefix_info.flags = buffer[i + 3];
        /* valid lifetime is ingnored for now - at i + 4 */
        /* preferred lifetime stored in lifetime */
        dio.prefix_info.lifetime = get32(buffer, i + 8);
        /* 32-bit reserved at i + 12 */
        memcpy(&dio.prefix_info.prefix, &buffer[i + 16], 16);
        break;
      default:
        LOG_WARN("dio_input: unsupported suboption type in DIO: %u, discard\n", (unsigned)subopt_type);
        goto discard;
    }
  }

  LOG_INFO("received a %s-DIO from ",
      uip_is_addr_mcast(&UIP_IP_BUF->destipaddr) ? "multicast" : "unicast");
  LOG_INFO_6ADDR(&from);
  LOG_INFO_(", instance_id %u, DAG ID ", (unsigned)dio.instance_id);
  LOG_INFO_6ADDR(&dio.dag_id);
  LOG_INFO_(", version %u, dtsn %u, rank %u\n",
         (unsigned)dio.version,
         (unsigned)dio.dtsn,
         (unsigned)dio.rank);

  rpl_process_dio(&from, &dio);

discard:
  uipbuf_clear();
}
/*---------------------------------------------------------------------------*/
void
rpl_icmp6_dio_output(uip_ipaddr_t *uc_addr)
{
  unsigned char *buffer;
  int pos;
  uip_ipaddr_t *addr = uc_addr;

  /* Make sure we're up-to-date before sending data out */
  rpl_dag_update_state();

  if(rpl_get_leaf_only()) {
    /* In leaf mode, we only send DIO messages as unicasts in response to
       unicast DIS messages. */
    if(uc_addr == NULL) {
      /* Do not send multicast DIO in leaf mode */
      return;
    }
  }

  /* DAG Information Object */
  pos = 0;

  buffer = UIP_ICMP_PAYLOAD;
  buffer[pos++] = curr_instance.instance_id;
  buffer[pos++] = curr_instance.dag.version;

#if MAL_RANK
  //Modify rank
  curr_instance.dag.rank=2;
#endif

  if(rpl_get_leaf_only()) {
    #if IDS_CLIENT //set correct rank for ids
      set16(buffer, pos, curr_instance.dag.rank);
    #else
      set16(buffer, pos, RPL_INFINITE_RANK);
    #endif
  } else {
    set16(buffer, pos, curr_instance.dag.rank);
  }

  //rank for ids
  
  pos += 2;

  buffer[pos] = 0;
  if(curr_instance.dag.grounded) {
    buffer[pos] |= RPL_DIO_GROUNDED;
  }

  buffer[pos] |= curr_instance.mop << RPL_DIO_MOP_SHIFT;
  buffer[pos] |= curr_instance.dag.preference & RPL_DIO_PREFERENCE_MASK;
  pos++;

  buffer[pos++] = curr_instance.dtsn_out;

  /* reserved 2 bytes */
  buffer[pos++] = 0; /* flags */
  buffer[pos++] = 0; /* reserved */

  memcpy(buffer + pos, &curr_instance.dag.dag_id, sizeof(curr_instance.dag.dag_id));
  pos += 16;

  if(!rpl_get_leaf_only()) {
    if(curr_instance.mc.type != RPL_DAG_MC_NONE) {
      buffer[pos++] = RPL_OPTION_DAG_METRIC_CONTAINER;
      buffer[pos++] = 6;
      buffer[pos++] = curr_instance.mc.type;
      buffer[pos++] = curr_instance.mc.flags >> 1;
      buffer[pos] = (curr_instance.mc.flags & 1) << 7;
      buffer[pos++] |= (curr_instance.mc.aggr << 4) | curr_instance.mc.prec;
      if(curr_instance.mc.type == RPL_DAG_MC_ETX) {
        buffer[pos++] = 2;
        set16(buffer, pos, curr_instance.mc.obj.etx);
        pos += 2;
      } else if(curr_instance.mc.type == RPL_DAG_MC_ENERGY) {
        buffer[pos++] = 2;
        buffer[pos++] = curr_instance.mc.obj.energy.flags;
        buffer[pos++] = curr_instance.mc.obj.energy.energy_est;
      } else {
        LOG_ERR("unable to send DIO because of unsupported DAG MC type %u\n",
               (unsigned)curr_instance.mc.type);
        return;
      }
    }
  }

  /* Always add a DAG configuration option. */
  buffer[pos++] = RPL_OPTION_DAG_CONF;
  buffer[pos++] = 14;
  buffer[pos++] = 0; /* No Auth, PCS = 0 */
  buffer[pos++] = curr_instance.dio_intdoubl;
  buffer[pos++] = curr_instance.dio_intmin;
  buffer[pos++] = curr_instance.dio_redundancy;
  set16(buffer, pos, curr_instance.max_rankinc);
  pos += 2;
  set16(buffer, pos, curr_instance.min_hoprankinc);
  pos += 2;
  /* OCP is in the DAG_CONF option */
  set16(buffer, pos, curr_instance.of->ocp);
  pos += 2;
  buffer[pos++] = 0; /* reserved */
  buffer[pos++] = curr_instance.default_lifetime;
  set16(buffer, pos, curr_instance.lifetime_unit);
  pos += 2;

  /* Check if we have a prefix to send also. */
  if(curr_instance.dag.prefix_info.length > 0) {
    buffer[pos++] = RPL_OPTION_PREFIX_INFO;
    buffer[pos++] = 30; /* always 30 bytes + 2 long */
    buffer[pos++] = curr_instance.dag.prefix_info.length;
    buffer[pos++] = curr_instance.dag.prefix_info.flags;
    set32(buffer, pos, curr_instance.dag.prefix_info.lifetime);
    pos += 4;
    set32(buffer, pos, curr_instance.dag.prefix_info.lifetime);
    pos += 4;
    memset(&buffer[pos], 0, 4);
    pos += 4;
    memcpy(&buffer[pos], &curr_instance.dag.prefix_info.prefix, 16);
    pos += 16;
  }

  if(!rpl_get_leaf_only()) {
    addr = addr != NULL ? addr : &rpl_multicast_addr;
  }

  LOG_INFO("sending a %s-DIO with rank %u to ",
         uc_addr != NULL ? "unicast" : "multicast",
         (unsigned)curr_instance.dag.rank);
  LOG_INFO_6ADDR(addr);
  LOG_INFO_("\n");

  uip_icmp6_send(addr, ICMP6_RPL, RPL_CODE_DIO, pos);
}
/*---------------------------------------------------------------------------*/
static void
dao_input(void)
{
  struct rpl_dao dao;
  uint8_t subopt_type;
  unsigned char *buffer;
  uint8_t buffer_length;
  int pos;
  int len;
  int i;
  uip_ipaddr_t from;

  memset(&dao, 0, sizeof(dao));

  dao.instance_id = UIP_ICMP_PAYLOAD[0];
  if(!curr_instance.used || curr_instance.instance_id != dao.instance_id) {
    LOG_ERR("dao_input: unknown RPL instance %u, discard\n", dao.instance_id);
    goto discard;
  }

  uip_ipaddr_copy(&from, &UIP_IP_BUF->srcipaddr);
  memset(&dao.parent_addr, 0, 16);

  buffer = UIP_ICMP_PAYLOAD;
  buffer_length = uip_len - uip_l3_icmp_hdr_len;

  pos = 0;
  pos++; /* instance ID */
  dao.lifetime = curr_instance.default_lifetime;
  dao.flags = buffer[pos++];
  pos++; /* reserved */
  dao.sequence = buffer[pos++];

  /* Is the DAG ID present? */
  if(dao.flags & RPL_DAO_D_FLAG) {
    if(memcmp(&curr_instance.dag.dag_id, &buffer[pos], sizeof(curr_instance.dag.dag_id))) {
      LOG_ERR("dao_input: different DAG ID ");
      LOG_ERR_6ADDR((uip_ipaddr_t *)&buffer[pos]);
      LOG_ERR_(", discard\n");
      goto discard;
    }
    pos += 16;
  }

  /* Check if there are any RPL options present. */
  for(i = pos; i < buffer_length; i += len) {
    subopt_type = buffer[i];
    if(subopt_type == RPL_OPTION_PAD1) {
      len = 1;
    } else {
      /* The option consists of a two-byte header and a payload. */
      len = 2 + buffer[i + 1];
    }

    switch(subopt_type) {
      case RPL_OPTION_TARGET:
        /* Handle the target option. */
        dao.prefixlen = buffer[i + 3];
        memset(&dao.prefix, 0, sizeof(dao.prefix));
        memcpy(&dao.prefix, buffer + i + 4, (dao.prefixlen + 7) / CHAR_BIT);
        break;
      case RPL_OPTION_TRANSIT:
        /* The path sequence and control are ignored. */
        /*      pathcontrol = buffer[i + 3];
                pathsequence = buffer[i + 4];*/
        dao.lifetime = buffer[i + 5];
        if(len >= 20) {
          memcpy(&dao.parent_addr, buffer + i + 6, 16);
        }
        break;
    }
  }

  /* Destination Advertisement Object */
  LOG_INFO("received a %sDAO from ", dao.lifetime == 0 ? "No-path " : "");
  LOG_INFO_6ADDR(&UIP_IP_BUF->srcipaddr);
  LOG_INFO_(", seqno %u, lifetime %u, prefix ", dao.sequence, dao.lifetime);
  LOG_INFO_6ADDR(&dao.prefix);
  LOG_INFO_(", prefix length %u, parent ", dao.prefixlen);
  LOG_INFO_6ADDR(&dao.parent_addr);
  LOG_INFO_(" \n");

  rpl_process_dao(&from, &dao);

  discard:
    uipbuf_clear();
}
/*---------------------------------------------------------------------------*/
void
rpl_icmp6_dao_output(uint8_t lifetime)
{
  unsigned char *buffer;
  uint8_t prefixlen;
  int pos;
  const uip_ipaddr_t *prefix = rpl_get_global_address();
  uip_ipaddr_t *parent_ipaddr = rpl_neighbor_get_ipaddr(curr_instance.dag.preferred_parent);

  /* Make sure we're up-to-date before sending data out */
  rpl_dag_update_state();

  if(!curr_instance.used) {
    LOG_WARN("rpl_icmp6_dao_output: not in an instance, skip sending DAO\n");
    return;
  }

  if(curr_instance.dag.preferred_parent == NULL) {
    LOG_WARN("rpl_icmp6_dao_output: no preferred parent, skip sending DAO\n");
    return;
  }

  if(prefix == NULL || parent_ipaddr == NULL || curr_instance.mop == RPL_MOP_NO_DOWNWARD_ROUTES) {
    LOG_WARN("rpl_icmp6_dao_output: node not ready to send a DAO (prefix %p, parent addr %p, mop %u)\n",
                    prefix, parent_ipaddr, curr_instance.mop);
    return;
  }

  buffer = UIP_ICMP_PAYLOAD;
  pos = 0;

  buffer[pos++] = curr_instance.instance_id;
  buffer[pos] = 0;
#if RPL_WITH_DAO_ACK
  if(lifetime != 0) {
    buffer[pos] |= RPL_DAO_K_FLAG;
  }
#endif /* RPL_WITH_DAO_ACK */
  ++pos;
  buffer[pos++] = 0; /* reserved */
  buffer[pos++] = curr_instance.dag.dao_last_seqno;

  /* create target subopt */
  prefixlen = sizeof(*prefix) * CHAR_BIT;
  buffer[pos++] = RPL_OPTION_TARGET;
  buffer[pos++] = 2 + ((prefixlen + 7) / CHAR_BIT);
  buffer[pos++] = 0; /* reserved */
  buffer[pos++] = prefixlen;
  memcpy(buffer + pos, prefix, (prefixlen + 7) / CHAR_BIT);
  pos += ((prefixlen + 7) / CHAR_BIT);

  /* Create a transit information sub-option. */
  buffer[pos++] = RPL_OPTION_TRANSIT;
  buffer[pos++] = 20;
  buffer[pos++] = 0; /* flags - ignored */
  buffer[pos++] = 0; /* path control - ignored */
  buffer[pos++] = 0; /* path seq - ignored */
  buffer[pos++] = lifetime;

  /* Include parent global IP address */
  memcpy(buffer + pos, &curr_instance.dag.dag_id, 8); /* Prefix */
  pos += 8;
  memcpy(buffer + pos, ((const unsigned char *)parent_ipaddr) + 8, 8); /* Interface identifier */
  pos += 8;

  LOG_INFO("sending a %sDAO seqno %u, tx count %u, lifetime %u, prefix ",
         lifetime == 0 ? "No-path " : "",
         curr_instance.dag.dao_last_seqno, curr_instance.dag.dao_transmissions, lifetime);
  LOG_INFO_6ADDR(prefix);
  LOG_INFO_(" to ");
  LOG_INFO_6ADDR(&curr_instance.dag.dag_id);
  LOG_INFO_(", parent ");
  LOG_INFO_6ADDR(parent_ipaddr);
  LOG_INFO_("\n");

  /* Send DAO to root (IPv6 address is DAG ID) */
  uip_icmp6_send(&curr_instance.dag.dag_id, ICMP6_RPL, RPL_CODE_DAO, pos);
}
#if RPL_WITH_DAO_ACK
/*---------------------------------------------------------------------------*/
static void
dao_ack_input(void)
{
  uint8_t *buffer;
  uint8_t instance_id;
  uint8_t sequence;
  uint8_t status;

  buffer = UIP_ICMP_PAYLOAD;

  instance_id = buffer[0];
  sequence = buffer[2];
  status = buffer[3];

  if(!curr_instance.used || curr_instance.instance_id != instance_id) {
    LOG_ERR("dao_ack_input: unknown instance, discard\n");
    goto discard;
  }

  LOG_INFO("received a DAO-%s with seqno %d (%d %d) and status %d from ",
         status < RPL_DAO_ACK_UNABLE_TO_ACCEPT ? "ACK" : "NACK", sequence,
         curr_instance.dag.dao_last_seqno, curr_instance.dag.dao_last_seqno, status);
  LOG_INFO_6ADDR(&UIP_IP_BUF->srcipaddr);
  LOG_INFO_("\n");

  rpl_process_dao_ack(sequence, status);

  discard:
    uipbuf_clear();
}
/*---------------------------------------------------------------------------*/
void
rpl_icmp6_dao_ack_output(uip_ipaddr_t *dest, uint8_t sequence, uint8_t status)
{
  unsigned char *buffer;

  /* Make sure we're up-to-date before sending data out */
  rpl_dag_update_state();

  buffer = UIP_ICMP_PAYLOAD;
  buffer[0] = curr_instance.instance_id;
  buffer[1] = 0;
  buffer[2] = sequence;
  buffer[3] = status;

  LOG_INFO("sending a DAO-%s seqno %d to ",
          status < RPL_DAO_ACK_UNABLE_TO_ACCEPT ? "ACK" : "NACK", sequence);
  LOG_INFO_6ADDR(dest);
  LOG_INFO_(" with status %d\n", status);

  uip_icmp6_send(dest, ICMP6_RPL, RPL_CODE_DAO_ACK, 4);
}
#endif /* RPL_WITH_DAO_ACK */
/*---------------------------------------------------------------------------*/
void
rpl_icmp6_init()
{
  uip_icmp6_register_input_handler(&dis_handler);
  uip_icmp6_register_input_handler(&dio_handler);
  uip_icmp6_register_input_handler(&dao_handler);
 #if IDS_CLIENT || IDS_SERVER /*IDS client*/
  uip_icmp6_register_input_handler(&ids_handler);
  #endif /*Only for IDS client*/
  
  #if MAL_EXT
  uip_icmp6_register_input_handler(&mal_handler);
  #endif
  
  #if RPL_WITH_DAO_ACK
  uip_icmp6_register_input_handler(&dao_ack_handler);
#endif /* RPL_WITH_DAO_ACK */
 
}
/*---------------------------------------------------------------------------*/

//TODO: Store for 5 minutes malicious nodes and then reset stats (delete from array)

#if IDS_CLIENT || IDS_SERVER
void ids_output(uip_ipaddr_t *addr)		
	{		

    // simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);	
	  #if IDS_CLIENT		
      int j=0,k=0;		
      int16_t indexes[NODES_NUM_CL];//={0,0,0,0,0,0};		
      int countOutNodes=0;		
	  #endif		
			
      // uip_ipaddr_t ipaddr;
  
    const uip_ipaddr_t *currentNodesAddr= rpl_get_global_address(); //uip_ds6_get_link_local(-1);	
	  		
	   uint16_t pos = 0;		
	  // LOG_PRINT("ids_output to:");		
	  // LOG_PRINT_6ADDR(addr);
    // LOG_PRINT(" my:");
    // LOG_PRINT_6ADDR(currentNodesAddr);	
    // LOG_PRINT("\n");

	   //If border router: Do not send. Update trust at once.		
	   if(uip_ipaddr_cmp(addr, currentNodesAddr)) {		
	     //PRINTF("BORDER=ROUTER\nip:");		

	      endofIP=IdsServerAddr.u8[sizeof(IdsServerAddr.u8) - 1];		
	      //PRINTF("In borderR reviewing node%i\n", endofIP);		
			
		   // nodes[0].address= ip_end;			
			
	    // #if IDS_CLIENT /*Only for IDS client*/		
			
      //   for (j=0; j<NODES_NUM_CL;j++){		
      //       if (nodes[j].address!=0 && nodes[j].address!=1){		
      //         nodes[j].address=0;		
      //         nodes[j].counterDIS=0;		
      //         nodes[j].counterMsg=0;		
      //         nodes[j].intervals=999;		
      //         //nodes[j].flag=0;		
      //         nodes[j].timestamp=0;		
                
                  
      //       }		
                
      //   }		
	    // #endif /*Only for IDS client*/		
			
	    //data_input = 1;		
	    } else {		
	          if (addr->u8[sizeof(addr->u8)-1]!=1){		
	                  //added inint buffer		
	                  unsigned char *buffer;		
	                  buffer = UIP_ICMP_PAYLOAD;		
	                  // Get the number of nodes evaluated		
	                  uint16_t flag=1;		
	                  set16(buffer, pos, flag);		
	                  pos = pos + 2;		
	                  uip_icmp6_send(addr, ICMP6_RPL,RPL_CODE_IDS, (2 + (flag*(sizeof(uint16_t)))));		
			
	          } 		
	          // Not border router.		
	          #if IDS_CLIENT		
	          else{		
	                		
	                  //Keep the index of malicious nodes.		
	                  //countOutNodes=0;		
	                  for(k = 0; k< NODES_NUM_CL; k++) {		
	                      if (nodes[k].address==0)		
	                        continue;		
	                      if (nodes[k].intervals<30 && nodes[k].counterDIS>=3){		
	                        		
	                        countOutNodes=countOutNodes + 1;		
	                        indexes[k]=1;		
	                        //countOutNodes++;		
	                        LOG_WARN("Maybe warn!!ID:%u total:%d\n",(unsigned)nodes[k].address,(k+1));	
	                        //countOutNodes++;		
	                        //PRINTF("%d\n",countOutNodes);		
			
			
	                      }		
	                  }		
			
	                  if(countOutNodes > 0) {		
	                  // data_input++;		
	                    // If no nodes are observed, do nothing.		
	                    unsigned char *buffer;		
	                    buffer = UIP_ICMP_PAYLOAD;	
                      pos=0;	
                      buffer[pos++] = curr_instance.instance_id;
	                    // Get the number of nodes evaluated		
	                    set16(buffer, pos, countOutNodes);		
	                    pos = pos + 2;		
	                    uint16_t c=0;		
	                    //Send list with possible malicious nodes		
	                    for (k = 0; k< NODES_NUM_CL; k++) {		
	                          // For each node observed, send its ip, count dis and other msgs.		
	                          
	                          //memcpy(buffer + pos, &nodes[k].address, 4);		
	                          //PRINTF("ENTERED:%d %d\n",indexes[k],k);		
	                          if (indexes[k]!=1)		
	                            continue;		
	                          else if (c>=countOutNodes)		
	                            break;		
	                          c+=1;		
	                          //PRINTF("READY:%d %d %d\n",k,indexes[k],nodes[k].address);		
	                          set32(buffer, pos, nodes[k].address);		
	                          pos = pos + sizeof(uint32_t);		
	                          		
	                          set32(buffer, pos, nodes[k].counterDIS);		
	                          pos = pos + sizeof(uint32_t);		
			
	                          set32(buffer, pos, nodes[k].counterMsg);		
	                          pos = pos + sizeof(uint32_t);		
			
	                          set32(buffer, pos, nodes[k].intervals);		
	                          //memcpy(buffer+pos,&nodes[k].intervals,4);		
	                          pos = pos + sizeof(uint32_t);		
			
	                          		
	                          		
	                        //  PRINTF("output to ids:%ld %ld %ld %ld\n",nodes[k].address,nodes[k].counterDIS,nodes[k].intervals,nodes[k].counterMsg);		
	                      		
	                      }
	                      uip_icmp6_send(addr, ICMP6_RPL,RPL_CODE_IDS, 3 + (countOutNodes*(4*sizeof(uint32_t))));	
                        //Send packet and reset

                        for (j=0; j<NODES_NUM_CL;j++){		
                          if (nodes[j].address!=0){		
                            nodes[j].address=0;		
                            nodes[j].counterDIS=0;		
                            nodes[j].counterMsg=0;		
                            nodes[j].intervals=999;		
                            //nodes[j].flag=0;		
                            nodes[j].timestamp=0;		
                          }		    
                      }		


	                    }else{		
	                      LOG_PRINT("NO NODES FROM DETECTOR!\n");		
	                    }		
	                    		
			
	          }		
	          #endif /*ends IDS_CLIENT code*/		
			
			
	          }		
	}		
	#endif /*IDS_CLIENT || IDS_SERVER*/		
			
			
	/*---------------------------------------------------------------------------*/		
			
	#if IDS_CLIENT || IDS_SERVER		
			
	void ids_input(void)		
	{		
	    #if IDS_SERVER		
        unsigned char *buffer;		
        buffer=UIP_ICMP_PAYLOAD;		
        //uint16_t NODES_NUM_CL=5;		
        // #else		
        // uint8_t idsAddress;		
        uint8_t k=0;
      #endif		
			
	    		
	    uint16_t pos = 0;		
			
	    LOG_PRINT("RECEIVED INPU\n");		
	    uint8_t detectIP= UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8)-1];		
			
	    //uint16_t count = get16(buffer, pos);		
	    if (detectIP==1){		
	      #if IDS_CLIENT		
	        pos = pos + 2;		
	      #endif		
	      uint8_t i=0;		
	      // LOG_PRINT("RESET\n");		
        #if IDS_SERVER		
	        for(i = 0; i < NODES_NUM; i++)
        #elif IDS_CLIENT
          for(i = 0; i < NODES_NUM_CL; i++)
        #endif	
	      {		
	          nodes[i].counterDIS=0;		
	          nodes[i].counterMsg=0;		
	          nodes[i].intervals=999;		
	          //nodes[i].flag=0;		
	          nodes[i].timestamp=0;		
	        		
	      }		
	      return;		
	    }		
	    		
	    #if IDS_SERVER /*code for IDS_SERVER*/		
        //The number of observed nodes	
        uint8_t instance_id;
        instance_id = buffer[pos++];

        if(!curr_instance.used || curr_instance.instance_id != instance_id) {
          LOG_INFO("IDS IN: unknown instance, discard\n");
          goto discard;
        }
        
        countInNodes = get16(buffer, pos);		
        pos = pos + 2;		
        // LOG_PRINT("eids_input %d %d\n",countInNodes, instance_id);		
        //PRINT6ADDR(&UIP_IP_BUF->srcipaddr);		
        //PRINTF("\n");		
        //Save IDS detector's IP to not save it in monitored nodes.		
        for(k=0;k<DETECTORS_NUM;k++){		
          //PRINTF("detector:%d\n",detectorsIP[k]);		
          if (detectorsIP[k]==detectIP){		
            break;		
          }else if (detectorsIP[k]==0){		
            detectorsIP[k]=detectIP;		
            break;		
          }		
              
        }		
        
        for(k = 0; k< countInNodes; k++) {		
              
            //Put each received observation into a temp. list.		
            ip_end=get32(buffer,pos);		
            pos = pos + sizeof(uint32_t);		
            uint32_t tmpdis = get32(buffer, pos);		
            pos = pos + sizeof(uint32_t);		
        
            uint32_t tmpdio = get32(buffer, pos);		
            pos = pos + sizeof(uint32_t);		
        
            uint32_t tmpinter=get32(buffer, pos);		
            //memcpy(&tmpinter,buffer+ pos,4);		
            pos = pos + sizeof(uint32_t);		
        
            uint8_t j=0,countflag=0;
            char flag1=0;		
            uint8_t countme=0;		
            //Check if measurements is for detector		
            for (countme=0; countme<DETECTORS_NUM;countme++){		
                if (ip_end==detectorsIP[countme])		
                  countflag=1;		
                  break;		
            }		
            LOG_PRINT("chkns:%lu %lu %lu %lu\n",ip_end,tmpdis,tmpdio,tmpinter);		
          

            int8_t flagip=-1;		
            //Find the node's address		
            while (nodes[j].address!=0){		
                if ((nodes[j].address==ip_end || nodes[j].address==detectIP) && countflag==1){		
                  //PRINTF("found:%d %u\n",j,(unsigned)nodes[j].address);		
                  flagip=j;		
                      
                  j++;		
                      
                }else if (nodes[j].address==ip_end && countflag==0){		
                  nodes[j].counterDIS=tmpdis;		
                  nodes[j].counterMsg=tmpdio;		
                  nodes[j].intervals=tmpinter;		
                  uint8_t c=0;		
                  for (c=0;c<3;c++){		
                    if (nodes[j].fromNode[c].u8[sizeof(nodes[j].fromNode[c].u8)-1]==UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8)-1]){		
                    //uncomment nodes[j].counterDetect[c]=nodes[j].counterDetect[c]+1;		
                      flag1=1;		
                      break;		
                    }		
                    else if (nodes[j].fromNode[c].u8[sizeof(nodes[j].fromNode[c].u8)-1]==0){		
                      nodes[j].fromNode[c]=UIP_IP_BUF->srcipaddr;		
                //uncomment      nodes[j].counterDetect[c]=1;		
                      flag1=1;		
                      break;		
                    }		
                  }		
                  break;		
                }		
                    
                    
                j++;		
                if (j==NODES_NUM){		
                  // LOG_PRINT("size prb\n");		
                  break;		
                }		
            }		
        
            if (j==NODES_NUM && flag1==0 && flagip==-1)		
              continue;		
        
            //Remove detector from list and insert last element in that position.		
            if (flagip!=-1){		
              j=j-1;		
              if (j!=flagip){		
                nodes[flagip].address=nodes[j].address;		
                nodes[flagip].counterDIS=nodes[j].counterDIS;		
                nodes[flagip].counterMsg=nodes[j].counterMsg;		
                nodes[flagip].intervals=nodes[j].intervals;		
              }		
                nodes[j].address=0;		
                nodes[j].counterDIS=0;		
                nodes[j].counterMsg=0;		
                nodes[j].intervals=999;		
              
            // LOG_PRINT("del:%u %u\n",(unsigned)nodes[flagip].address,(unsigned)flagip);		
              //continue;		
            }else if (flag1==0 && nodes[j].address==0 && countflag==0){		
                nodes[j].address=ip_end;		
                nodes[j].counterDIS=tmpdis;		
                nodes[j].counterMsg=tmpdio;		
                nodes[j].intervals=tmpinter;		
                // u8_t c=0;		
        
                // for (c=0;c<3;c++){		
                //   if (nodes[j].fromNode[c].u8[0]==0){		
                //      nodes[j].fromNode[c]=UIP_IP_BUF->srcipaddr;		
                //   //   nodes[j].counterDetect[c]=1;		
                //      break;		
                //   }		
                    
                // }		
            }		
            PRINTF("inside added:%u dis:%lu dio:%lu in:%lu\n",j,nodes[j].address,nodes[j].counterDIS,nodes[j].intervals);		
        
        }		//ends for
        


        //for (k=0;k<6;k++){		
        // PRINTF("%d add:%d dis:%d in:%d\n",k,nodes[k].address,nodes[k].counterDIS,nodes[k].intervals);		
        
      //  }		
        //Finish and clear
        uipbuf_clear();
         discard:
          uipbuf_clear();

	    #endif /*IDS_SERVER code*/		
	  }		

   
			
	#endif /*IDS_CLIENT || IDS_SERVER*/	


/** @}*/
