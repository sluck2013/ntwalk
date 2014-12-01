#ifndef ARP_H
#define ARP_H

#include "constants.h"
#include "unp.h"
#include <linux/if_ether.h>

/*
 * This structs stores local mapping from IP to Mac address
 */
typedef struct LocalMapping {
    char IP[IP_STR_LEN];
    char mac[ETH_ALEN];
    int ifIndex;
    struct LocalMapping* next;
} LocalMap;

/*
 * entry of ARP cache table
 */
typedef struct ARPCacheEntry {
    char IP[IP_STR_LEN];
    unsigned char mac[ETH_ALEN];
    int ifindex;
    unsigned short hatype;
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

typedef enum {ARP_REQ = 1, ARP_REP = 2} ArpOp;

LocalMap* getLocalMap();
void prtLocalMap(const LocalMap* localMap);
void replyTour(const int iSock, const int iRawSock, int* iConnSock);
int sendARPPacket(const int iSockfd, const unsigned char* destMac, const unsigned char* srcMac, const unsigned char* senderIP, const unsigned char* targetIP, const int iIfIndex, ArpOp arpOp);
int sendARPRequest(const int iSockfd, const unsigned char* targetIP);
void sprtIP(char* dest, const unsigned char *src);
void parseIP(unsigned char *dest, const char *src);

ACacheTab* createACacheTab();
ACacheEnt* findACacheEntByIP(const ACacheTab* tab, const char *IP);
ACacheEnt* insertIntoACacheTab(ACacheTab* tab, const char* IP, const char* mac, unsigned char macLen, const int ifindex, const unsigned short hatype, const int connfd);
void removeIncompACacheEnt(ACacheTab* tab);
int isACacheEntComplete(const ACacheEnt* e);

#endif
