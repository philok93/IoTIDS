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
#define DEBUG   0
#endif

#define LOG_CONF_LEVEL_RPL                         LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_IPV6                        LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_6LOWPAN                     LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_TCPIP                       LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAC                         LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAIN                        LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_IDS                         LOG_LEVEL_INFO
// #define RPL_CONF_DEFAULT_LEAF_ONLY 1

//------My IDS conf--------

#if !IDS_SERVER
#undef NETSTACK_CONF_MAC
// #ifndef NETSTACK_CONF_MAC
 #define NETSTACK_CONF_MAC	csma_driver //csma_driver nullmac_driver
// #endif
#endif

// #ifdef IDS_SERVER
//     #undef NBR_TABLE_CONF_MAX_NEIGHBORS
//     #define NBR_TABLE_CONF_MAX_NEIGHBORS 7
//     #undef UIP_CONF_MAX_ROUTES
//     #define UIP_CONF_MAX_ROUTES 7
// #endif