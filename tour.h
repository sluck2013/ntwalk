#ifndef TOUR_H
#define TOUR_H
#include "constants.h"
#include "unp.h"
#include "common.h"

/*typedef struct IPList {
    char IP[IP_STR_LEN];
    struct IPList* next;
} IPList;
*/
char* getIPByHostName(char* IP, const char* name);
//char* getHostNameByIP(char* name, const char* IP);
char* getHostNameByAddr(char* name, struct sockaddr_in* sa);
char* getLocalIP(char* IP);
unsigned char* getLocalMac(unsigned char* mac);
int sendRoutingMsg(const int iSockfd, const int hostNum, char** hostList);
int relayRoutingMsg(const int iSockfd, unsigned char* data);
void handleRoutingMsg(const int iSockRt, const int iSockICMP, const int iSockUdp);
int joinMulticast(const int iSockfd, const char* grpIP, const unsigned short grpPort);
unsigned short getPingSeqNum();
int sendICMP(const int iSockfd, const Hwaddr *targetHwAddr, const char* targetIP);
void handleICMPMsg(const int iSockPg);

#endif
