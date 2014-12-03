#ifndef ARP_H
#define ARP_H

#include "constants.h"
#include "unp.h"
#include <linux/if_packet.h>
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

typedef struct ARPMsg {
    ArpOp op;
    unsigned char destMac[ETH_ALEN];
    unsigned char srcMac[ETH_ALEN]; //also senderMac
    unsigned char targetMac[ETH_ALEN];
    unsigned char srcIP[IP_LEN];
    unsigned char targetIP[IP_LEN];
} ARPMsg;

void makeARPMsg(ARPMsg* arpMsg, ArpOp op, const unsigned char* destMac, const unsigned char* srcMac, const unsigned char* targetMac, const char* srcDecIP, const char* targetDecIP);
short parseEthFrame(ARPMsg* arpMsg, const void* eth);

LocalMap* getLocalMap();
void prtLocalMap(const LocalMap* localMap);
const LocalMap* getLocalMapEntByIP(const LocalMap* mp, const char *IP);
void handleArpReply(const ARPMsg* arpMsg, const int iRawSock, const int iListenSock);
void handleAppReq(const int iSock, const int iRawSock, int* iConnSock);
void handleArpReq(const int iSock, ARPMsg* arpMsg, const struct sockaddr_ll* slSrcAddr);
int sendARPPacket(const int iSockfd, const ARPMsg* arpMsg, const int iIfIndex);
int sendARPRequest(const int iSockfd, const char* targetIP);
int sendARPReply(const int iSockfd, ARPMsg* arpMsg, const int ifindex);


ACacheTab* createACacheTab();
ACacheEnt* findACacheEntByIP(const ACacheTab* tab, const char *IP);
ACacheEnt* insertIntoACacheTab(ACacheTab* tab, const char* IP, const unsigned char* mac, const int ifindex, const unsigned short hatype, const int connfd);
ACacheEnt* updateACacheEnt(ACacheEnt* e, const char* IP, const unsigned char* mac, const int ifindex, const unsigned short hatype, const int connfd);
void prtACacheEnt(const char* title, const ACacheEnt* e);
void removeIncompACacheEnt(ACacheTab* tab);
int isACacheEntComplete(const ACacheEnt* e);

#endif
