#ifndef TOUR_H
#define TOUR_H
#include "constants.h"
#include "unp.h"
#include "common.h"

typedef struct PingTargetEntry {
    struct in_addr addr;
    struct PingTargetEntry* next;
} PingEnt;

typedef struct PingTargetList {
    PingEnt* head;
} PingList;

char* getIPByHostName(char* IP, const char* name);
char* getHostNameByIP(char* name, const char* IP);
char* getHostNameByAddr(char* name, struct sockaddr_in* sa);
char* getLocalIP(char* IP);
unsigned char* getLocalMac(unsigned char* mac);
int sendRoutingMsg(const int hostNum, char** hostList);
int relayRoutingMsg(unsigned char* data);
void handleRoutingMsg();
int joinMulticast(const int iSockfd, const char* grpIP, const unsigned short grpPort);
unsigned short getPingSeqNum();
int sendICMP(const Hwaddr *targetHwAddr, const char* targetIP);
void handleICMPMsg();
void ping();
void pingAlarm(int signo);
void exitAlarm(int signo);
int sendMCastMsg(const char* msg, const size_t msgSize);
void handleMCastMsg();

PingList* newPingList();
PingEnt* insertIntoPingList(PingList* lst, const struct in_addr *addr);
int existInPingList(const PingList* list, const struct in_addr* addr);
void deletePingList(PingList* lst);

#endif
