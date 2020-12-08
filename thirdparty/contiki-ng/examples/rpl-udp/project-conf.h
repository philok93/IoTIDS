#ifndef IDS_CLIENT
#define IDS_CLIENT       0
#pragma message "undefined ids client"
#endif

#ifndef IDS_SERVER
#define IDS_SERVER       0
#pragma message "undefined ids server"
#endif

#ifndef RPL_SERVER
#define RPL_SERVER       0
#endif

#ifndef MALICIOUS
#define MALICIOUS       0
#endif

#ifndef MAL_RANK
#define MAL_RANK       0
#endif

#ifndef MAL_DIS
#define MAL_DIS       0
#endif

#ifndef MAL_EXT
#define MAL_EXT       0
#endif

#ifndef MAL_BLACKHOLE
#define MAL_BLACKHOLE       0
#endif

#ifndef CLONE_ATTACK
#define CLONE_ATTACK       0
#endif

#ifndef IDS_OF
#define IDS_OF       0
#endif



#ifdef DEBUG
#undef DEBUG
#define DEBUG   1
#endif

// #undef LOG_CONF_LEVEL_RPL
// #undef LOG_CONF_LEVEL_6LOWPAN
// #define LOG_CONF_LEVEL_RPL                         LOG_LEVEL_DBG
// #define LOG_CONF_LEVEL_IPV6                        LOG_LEVEL_WARN
// #define LOG_CONF_LEVEL_6LOWPAN                     LOG_LEVEL_NONE
// #define LOG_CONF_LEVEL_TCPIP                       LOG_LEVEL_NONE
// #define LOG_CONF_LEVEL_MAC                         LOG_LEVEL_DBG
// #define LOG_CONF_LEVEL_MAIN                        LOG_LEVEL_INFO
// #define LOG_CONF_LEVEL_IDS                         LOG_LEVEL_INFO

#define LOG_CONF_LEVEL_IPV6                        LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_RPL                         LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_6LOWPAN                     LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_TCPIP                       LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAC                         LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_FRAMER                      LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_COAP                        LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_LWM2M                       LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_6TOP                        LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAIN                        LOG_LEVEL_INFO

#if IDS_OF || IDS_CLIENT
/* configure network size and density */
#undef NETSTACK_MAX_ROUTE_ENTRIES
#define UIP_CONF_MAX_ROUTES 15
#define NETSTACK_MAX_ROUTE_ENTRIES   15

#undef NBR_TABLE_CONF_MAX_NEIGHBORS
#define NBR_TABLE_CONF_MAX_NEIGHBORS 15
#endif /* NETSTACK_MAX_ROUTE_ENTRIES */



//------My IDS conf--------

// #if !IDS_SERVER
// #undef NETSTACK_CONF_MAC
// // #ifndef NETSTACK_CONF_MAC
//  #define NETSTACK_CONF_MAC	csma_driver //csma_driver nullmac_driver
// // #endif
// #endif

//#ifdef IDS_CLIENT
//#undef CC2420_CONF_AUTOACK
//#define CC2420_CONF_AUTOACK 0
//#endif

// #endif
// #ifdef RADIO_RX_MODE_ADDRESS_FILTER
// #undef RADIO_RX_MODE_ADDRESS_FILTER
// #define RADIO_RX_MODE_ADDRESS_FILTER   (0 << 0)
// #endif
// #endif

// #ifdef IDS_SERVER
//     #undef NBR_TABLE_CONF_MAX_NEIGHBORS
//     #define NBR_TABLE_CONF_MAX_NEIGHBORS 7
//     #undef UIP_CONF_MAX_ROUTES
//     #define UIP_CONF_MAX_ROUTES 7
// #endif