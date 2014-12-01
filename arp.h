#ifndef ARP_H
#define ARP_H

#include "constants.h"

/*
 * This structs stores local mapping from IP to Mac address
 */
typedef struct LocalMapping {
    char IP[IP_LEN];
    char mac[MAC_LEN];
    struct LocalMapping* next;
} LocalMap;

/*
 * entry of ARP cache table
 */
typedef struct ARPCacheEntry {
    char IP[IP_LEN];
    char mac[MAC_LEN];
    int ifindex;
    int hatype;
    int connfd;
    struct ARPCacheEntry *next;
    struct ARPCacheEntry *prev;
} ACacheEnt;

/*
 * ARP Cache table
 */
typedef struct ARPCacheTable {
    ACacheEnt *head;
    ACacheEnt *tail;
} ACacheTab;

LocalMap* getLocalMap();
void prtLocalMap(const LocalMap* localMap);
void replyTour(const int iSock);

ACacheTab* createACacheTab();
ACacheEnt* findACacheEntByIP(const ACacheTab* tab, const char *IP);

#endif
