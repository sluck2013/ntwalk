#include "arp.h"
#include "common.h"
#include "lib/hw_addrs.h"
#include "unp.h"
#include "utility.h"
#include <stdlib.h>
#include <string.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

int iMaxFd;
fd_set fsAll;

ACacheTab *pARPCahceTab;
LocalMap *pLocalMap;

int main() {
    pLocalMap = getLocalMap();
    prtLocalMap(pLocalMap);
    pARPCahceTab = createACacheTab();

    struct sockaddr_un suArpAddr;
    const int iDomSock = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (iDomSock == -1) {
        errExit(ERR_ARP_CREATE_DOM_SOCK);
    }
    bzero(&suArpAddr, sizeof(suArpAddr));
    suArpAddr.sun_family = AF_LOCAL;
    strcpy(suArpAddr.sun_path, ARP_SUN_PATH);
    unlink(ARP_SUN_PATH);
    Bind(iDomSock, (SA*)&suArpAddr, sizeof(suArpAddr));
    Listen(iDomSock, LISTENQ);

    const int iRawSock = socket(PF_PACKET, SOCK_RAW, htons(ARP_ETH_PROT));
    if (iRawSock == -1) {
        errExit(ERR_ARP_CREATE_RAW_SOCK);
    }

    iMaxFd = max(iRawSock, iDomSock);
    int iConnSock = -1;

    fd_set fsRead;
    FD_ZERO(&fsAll);
    FD_SET(iDomSock, &fsAll);
    FD_SET(iRawSock, &fsAll);

    while (1) {
        fsRead = fsAll;
        int iReadyNum = select(iMaxFd + 1, &fsRead, NULL, NULL, NULL);
        if (iReadyNum > 0) {
            if (FD_ISSET(iDomSock, &fsRead)) {
                replyTour(iDomSock, iRawSock, &iConnSock);
            }
            if (FD_ISSET(iRawSock, &fsRead)) {
                void* readBuf = malloc(ETH_FRAME_LEN);
                struct sockaddr_ll srcAddr;
                int len = sizeof(srcAddr);
                int n = recvfrom(iRawSock, readBuf, ETH_FRAME_LEN, 0, (SA*)&srcAddr, &len);
                short *op = (short*)(readBuf + ETH_HLEN + 8);
                if (*op == ARP_REQ) {
                    //getLocalMapEntByIP(pLocalMap, 
                } else if (*op == ARP_REP) {
                }
            }
            if (FD_ISSET(iConnSock, &fsRead)) {
                removeIncompACacheEnt(pARPCahceTab);
                FD_CLR(iConnSock, &fsAll);
                iMaxFd = max(iRawSock, iDomSock);
            }
        }
    }
    //free(pLocalMap);
    return 0;
}

void makeARPMsg(ARPMsg* arpMsg, ArpOp op, const unsigned char* destMac, const unsigned char* srcMac, const unsigned char* targetMac, const char* srcDecIP, const char* targetDecIP) {
    memcpy((void*)arpMsg->destMac, (void*)destMac, ETH_ALEN);
    memcpy((void*)arpMsg->srcMac, (void*)srcMac, ETH_ALEN);
    if (targetMac != NULL) {
        memcpy((void*)arpMsg->targetMac, (void*)targetMac, ETH_ALEN);
    } else {
        memset((void*)arpMsg->targetMac, 0, ETH_ALEN);
    }
    parseIP(arpMsg->srcIP, srcDecIP);
    parseIP(arpMsg->targetIP, targetDecIP);
}

short parseEthFrame(ARPMsg* msg, const void* eth) {
    memcpy((void*)msg->destMac, eth, ETH_ALEN);
    memcpy((void*)msg->srcMac, eth + ETH_ALEN, ETH_ALEN);
    short typeId;
    memcpy((void*)&typeId, eth + ETH_HLEN, 2);
    memcpy((void*)&msg->op, eth + ETH_HLEN + 8, 2);
    memcpy((void*)msg->srcIP, eth + ETH_HLEN + 10 + ETH_ALEN, IP_LEN);
    memcpy((void*)msg->targetMac, eth + ETH_HLEN + 10 + ETH_ALEN + IP_LEN, ETH_ALEN);
    memcpy((void*)msg->targetIP, eth + ETH_HLEN + 10 + 2 * ETH_ALEN + IP_LEN, IP_LEN);
}

/*
 * retrieve <IP, HW addr> pairs of local machine
 * @return pointer to LocalMap structure which stores <IP, HW addr> pairs
 */
LocalMap* getLocalMap() {
    LocalMap *mapPtr = NULL;
    LocalMap *mapHead = NULL;
    struct hwa_info *hwaHead, *hwaPtr;
    hwaHead = hwaPtr = Get_hw_addrs();
    while (hwaPtr!= NULL) {
        if (strcmp(hwaPtr->if_name, "eth0") == 0) {
            mapPtr = malloc(sizeof(LocalMap));
            struct sockaddr *sa = hwaPtr->ip_addr;
            char *addr = Sock_ntop_host(sa, sizeof(*sa));
            strcpy(mapPtr->IP, addr);
            memcpy(mapPtr->mac, hwaPtr->if_haddr, ETH_ALEN);
            mapPtr->ifIndex = hwaPtr->if_index;

            mapPtr->next = NULL;
            if (mapHead == NULL) {
                mapHead = mapPtr;
            }
            mapPtr = mapPtr->next;
        }
        hwaPtr = hwaPtr->hwa_next;
    }
    free_hwa_info(hwaHead);
    return mapHead;
}

const LocalMap* getLocalMapEntByIP(const LocalMap* mp, const char *IP) {
    const LocalMap* p = mp;
    while (p != NULL) {
        if (strcmp(IP, p->IP)) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

/* 
 * print <IP, HW addr> entries in LocalMap structure
 * @param pLocalMap pointer to LocalMap struct to be printed
 */
void prtLocalMap(const LocalMap* pLocalMap) {
    prtln("===== Local <IP addr, HW addr> found for eth0 BEGIN =====");
    const LocalMap *lmPtr = pLocalMap;
    while (lmPtr != NULL) {
        char mac[MAC_STR_LEN];
        sprtMac(mac, lmPtr->mac);
        prtln("    <%s, %s>", lmPtr->IP, mac);
        lmPtr = lmPtr->next;
    }
    prtln("====== Local <IP addr, HW addr> found for eth0 END ======");
}


void replyTour(const int iListenSock, const int iRawSock, int *piConnSock) {
    struct sockaddr_un suSender;
    socklen_t senderLen = sizeof(suSender);
    *piConnSock = accept(iListenSock, (SA*)&suSender, &senderLen);
    if (*piConnSock < 0) {
        if (errno == EINTR) {
            return;
        } else {
            errExit(ERR_ARP_ACCEPT);
        }
    }

    unsigned char readBuf[IP_STR_LEN + HWADDR_SIZE + 1];
    read(*piConnSock, readBuf, IP_STR_LEN + HWADDR_SIZE + 1);
    char targetIP[IP_STR_LEN];
    Hwaddr tourHwAddr;
    unmarshalAreq(targetIP, &tourHwAddr, readBuf);
#ifdef DEBUG
    prtln("===== recv from application =====");
    prtln("IP:%s", targetIP);
    prtln("index:%d", tourHwAddr.sll_ifindex);
    prtln("hatype:%d", tourHwAddr.sll_hatype);
    prtln("halen:%d", tourHwAddr.sll_halen);
    prtln("addr:%s", tourHwAddr.sll_addr);
    prtln("=================================");
#endif
    //check cache table
    ACacheEnt* pEnt = findACacheEntByIP(pARPCahceTab, targetIP);
    if (pEnt == NULL) {
        insertIntoACacheTab(pARPCahceTab, targetIP, "", 0, tourHwAddr.sll_ifindex, tourHwAddr.sll_hatype, *piConnSock);
        int n = sendARPRequest(iRawSock, targetIP);
        if (n <= 0) {
            prtErr(ERR_SEND_ARP_REQ);
        }
        FD_SET(*piConnSock, &fsAll);
        iMaxFd = max(iMaxFd, *piConnSock);
    } else {
        unsigned char data[IP_STR_LEN + HWADDR_SIZE];
        //sendBack
    }

}

/*
 * create and returns a null ARP cache table
 * @return pointer to created cache table.
 */
ACacheTab* createACacheTab() {
    ACacheTab* tab = malloc(sizeof(*tab));
    tab->head = tab->tail = NULL;
    return tab;
}

/*
 * find entry in ARP cache table with designated IP address
 * @return pointer to found entry if found, NULL otherwise
 * @param IP string representing IP address to be found
 * @param tab pointer to cache table in which search is performed.
 */
ACacheEnt* findACacheEntByIP(const ACacheTab* tab, const char* IP) {
    ACacheEnt* p = tab->head;
    while (p != NULL) {
        if (strcmp(p->IP, IP) == 0) {
            return p;
        }
    }
    return NULL;
}

ACacheEnt* insertIntoACacheTab(ACacheTab* tab, const char* IP, const char* mac, unsigned char macLen, const int ifindex, const unsigned short hatype, const int connfd) {
    ACacheEnt* e = malloc(sizeof(*e));
    strcpy(e->IP, IP);
    memset(e->mac, 0, ETH_ALEN);
    memcpy(e->mac, mac, macLen);
    e->ifindex = ifindex;
    e->hatype = hatype;
    e->connfd = connfd;
    if (tab->head == NULL) {
        tab->head = e;
        tab->tail = e;
        e->prev = NULL;
        e->next = NULL;
    } else {
        e->prev = tab->tail;
        e->next = tab->tail->next;
        tab->tail = e;
    }
    return e;
}

void removeIncompACacheEnt(ACacheTab* tab) {
    ACacheEnt* e = tab->head;
    while (e != NULL) {
        if (!isACacheEntComplete(e)) {
            if (e != tab->head) {
                e->prev->next = e->next;
            }
            if (e != tab->tail) {
                e->next->prev = e->prev;
            }
            free(e);
            return;
        } else {
            e = e->next;
        }
    }
}

int isACacheEntComplete(const ACacheEnt* ent) {
    return ent->connfd < 0;
}

int sendARPRequest(const int iSockfd, const char* targetIP) {
    ARPMsg arpReqMsg;
    arpReqMsg.op = ARP_REQ;
    memset((void*)arpReqMsg.destMac, 0xff, ETH_ALEN);
    memcpy((void*)arpReqMsg.srcMac, (void*)pLocalMap->mac, ETH_ALEN);
    memset((void*)arpReqMsg.targetMac, 0, ETH_ALEN);
    parseIP(arpReqMsg.srcIP, pLocalMap->IP);
    parseIP(arpReqMsg.targetIP, targetIP);

    return sendARPPacket(iSockfd, &arpReqMsg, pLocalMap->ifIndex);
}

void sprtIP(char* dest, const unsigned char *src) {
    dest[0] = '\0';
    for (int i = 0; i < IP_LEN; ++i) {
        char seg[5];
        if (i > 0) {
            sprintf(seg, ".%d", src[i]);
        } else {
            sprintf(seg, "%d", src[i]);
        }
        strcat(dest, seg);
    }
}

void parseIP(unsigned char *dest, const char *src) {
    char src2[IP_STR_LEN];
    strcpy(src2, src);
    char* p = strtok(src2, ".");
    dest[0] = atoi(p);
    for (int i = 1; i < 4; ++i) {
        p = strtok(NULL, ".");
        dest[i] = atoi(p);
    }
}

int sendARPPacket(const int iSockfd, const ARPMsg* arpMsg, const int iIfIndex) {
    struct sockaddr_ll sockAddrRecv;
    void *buffer = malloc(ETH_FRAME_LEN);

    // fill ether header
    memcpy(buffer, (void*)arpMsg->destMac, ETH_ALEN);
    memcpy(buffer + ETH_ALEN, (void*)arpMsg->srcMac, ETH_ALEN);
    struct ethhdr *eh = (struct ethhdr*)buffer;
    eh->h_proto = htons(ARP_ETH_PROT);

    // fill payload
    void *payload = buffer + ETH_HLEN;
    short* typeId = (short*)payload;
    *typeId = htons(ARP_TYPE_ID);
    short* hardType = (short*)(payload + 2);
    *hardType = htons(1);
    short* protType = (short*)(payload + 4);
    *protType = htons(0x0800);
    unsigned char* hardSize = (unsigned char*)(payload + 6);
    *hardSize = 6;
    unsigned char* protSize = (unsigned char*)(payload + 7);
    *protSize = 4;
    short* op = (short*)(payload + 8);
    *op = arpMsg->op;
    
    memcpy(payload + 10, (void*)arpMsg->srcMac, ETH_ALEN);
    memcpy(payload + 10 + ETH_ALEN, (void*)arpMsg->srcIP, IP_LEN);
    memcpy(payload + 10 + ETH_ALEN + IP_LEN, (void*)arpMsg->targetMac, ETH_ALEN);
    memcpy(payload + 10 + 2 * ETH_ALEN + IP_LEN, (void*)arpMsg->targetIP, IP_LEN); 
    
    sockAddrRecv.sll_family = PF_PACKET;
    sockAddrRecv.sll_protocol = htons(ARP_ETH_PROT);
    sockAddrRecv.sll_ifindex = iIfIndex;
    sockAddrRecv.sll_hatype = ARPHRD_ETHER;
    sockAddrRecv.sll_pkttype = PACKET_OTHERHOST;
    sockAddrRecv.sll_halen = ETH_ALEN;
    memset(sockAddrRecv.sll_addr, 0, 8);
    memcpy(sockAddrRecv.sll_addr, (void*)arpMsg->destMac, ETH_ALEN);
    
    return sendto(iSockfd, buffer, ETH_FRAME_LEN, 0, (SA*)&sockAddrRecv, sizeof(sockAddrRecv));
}
