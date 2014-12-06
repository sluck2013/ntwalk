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

int iMaxFd;     // max socket descriptor
fd_set fsAll;   // all listened sockets

ACacheTab *pARPCahceTab;  //pointer to cache table
LocalMap *pLocalMap;      //pointer to <mac, IP> pair table

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
                handleAppReq(iDomSock, iRawSock, &iConnSock);
            }
            if (iConnSock > 0 && FD_ISSET(iConnSock, &fsRead)) {
                removeIncompACacheEnt(pARPCahceTab);
                FD_CLR(iConnSock, &fsAll);
                iMaxFd = max(iRawSock, iDomSock);
            }
            if (FD_ISSET(iRawSock, &fsRead)) {
                void* readBuf = malloc(ETH_FRAME_LEN);
                struct sockaddr_ll srcAddr;
                int len = sizeof(srcAddr);
                recvfrom(iRawSock, readBuf, ETH_FRAME_LEN, 0, (SA*)&srcAddr, &len);
                ARPMsg arpMsg;
                short manId = parseEthFrame(&arpMsg, readBuf);
                if (manId != ARP_MAN_ID) {
                    prtln("Received Ethernet frame with ID=%d, omitted!", manId);
                    continue;
                }

                if (arpMsg.op == ARP_REQ) {
                    handleArpReq(iRawSock, &arpMsg, &srcAddr);
                } else if (arpMsg.op == ARP_REP) {
                    handleArpReply(&arpMsg, iRawSock, iDomSock);
                }
            }
        }
    }
    //free(pLocalMap);
    return 0;
}
/*
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
*/

/*
 * parse received Ethernet frame into ARPMsg
 * @return manID of ARPMsg
 * @param msg pointer to ARPMsg to store result
 * @param eth pointer to Ethernet frame
 */
short parseEthFrame(ARPMsg* msg, const void* eth) {
    memcpy((void*)msg->destMac, eth, ETH_ALEN);
    memcpy((void*)msg->srcMac, eth + ETH_ALEN, ETH_ALEN);
    short manId;
    memcpy((void*)&manId, eth + ETH_HLEN, 2);
    short op;
    memcpy((void*)&op, eth + ETH_HLEN + 8, 2);
    msg->op = ntohs(op);
    memcpy((void*)msg->srcIP, eth + ETH_HLEN + 10 + ETH_ALEN, IP_LEN);
    memcpy((void*)msg->targetMac, eth + ETH_HLEN + 10 + ETH_ALEN + IP_LEN, ETH_ALEN);
    memcpy((void*)msg->targetIP, eth + ETH_HLEN + 10 + 2 * ETH_ALEN + IP_LEN, IP_LEN);
    return ntohs(manId);
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
        if (strstr(hwaPtr->if_name, "eth0") != NULL) {
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

/*
 * retrieve entry from local <HWaddr, IP> table, with IP=designated IP
 * @return pointer to found entry
 * @param mp pointer to <HWaddr, IP> table
 * @param IP designated IP
 */
const LocalMap* getLocalMapEntByIP(const LocalMap* mp, const char *IP) {
    const LocalMap* p = mp;
    while (p != NULL) {
        if (strcmp(IP, p->IP) == 0) {
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
    prtln("====== Local <IP addr, HW addr> found for eth0 END ======\n");
}

/*
 * On receiving ARP reply message, complete newly inserted cache table entry,
 * reply to application, close connection socket.
 * @param arpMsg ARPMsg structure that stores ARP reply reading off raw socket.
 * @param iRawSock PF_PACKET raw socket
 * @param iListenSock Unix domain socket for responding application's request
 */
void handleArpReply(const ARPMsg* arpMsg, const int iRawSock, const int iListenSock) {
    char sSrcMac[MAC_STR_LEN], sDestMac[MAC_STR_LEN], sTargetMac[MAC_STR_LEN];
    char sSrcIP[IP_STR_LEN], sTargetIP[IP_STR_LEN];

    //print
    sprtMac(sSrcMac, arpMsg->srcMac);
    sprtMac(sDestMac, arpMsg->destMac);
    sprtMac(sTargetMac, arpMsg->targetMac);
    sprtIP(sSrcIP, arpMsg->srcIP);
    sprtIP(sTargetIP, arpMsg->targetIP);
    prtln("=============== Received ARP Reply ==============");
    prtln("* Ethernet Header");
    prtln("    destination addr: %s", sDestMac);
    prtln("    source addr     : %s", sSrcMac);
    prtln("* ARP Reply                             ID: %d", ARP_MAN_ID);
    prtln("    sender Eth addr: %s  sender IP: %s", sSrcMac, sSrcIP);
    prtln("    target Eth addr: %s  target IP: %s", sTargetMac, sTargetIP);
    prtln("================ ARP Reply End ==================\n");

    ACacheEnt* e = findACacheEntByIP(pARPCahceTab, sSrcIP);
    if (e == NULL) {
#ifdef DEBUG
        prtln("No cache entry for %s", sSrcIP);
#endif
        //entry has been deleted due to timeout
        return;
    }
   
    updateACacheEnt(e, NULL, arpMsg->srcMac, -1, 0, -1);
    Hwaddr hwAddr;
    hwAddr.sll_ifindex = e->ifindex;
    hwAddr.sll_hatype = e->hatype;
    hwAddr.sll_halen = ETH_ALEN;
    memcpy((void*)hwAddr.sll_addr, (void*)e->mac, ETH_ALEN);
    unsigned char writeBuf[UXDOM_BUF_SIZE];
    struct sockaddr_in IPAddr;
    inet_pton(AF_INET, e->IP, &IPAddr.sin_addr);
    marshalAreq(writeBuf, (SA*)&IPAddr, &hwAddr);
    write(e->connfd, writeBuf, sizeof(writeBuf));
    close(e->connfd);
    FD_CLR(e->connfd, &fsAll);
    iMaxFd = max(iRawSock, iListenSock);
    e->connfd = -1;
#ifdef DEBUG
    prtln("Replied to application. Connection closed!\n");
#endif
}

/*
 * On receiving ARP request, insert into or update cache table entry based on
 * source and destination IP address. If destination is local host, send back
 * ARP reply message.
 * @param iRawSock PF_PACKET raw socket
 * @param arpMsg pointer to ARPMsg structure that stores ARP request message
 *        read off iRawSock
 * @param slSrcAddr pointer to source address read returned by recvfrom when
 *        reading ARP request message
 */
void handleArpReq(const int iRawSock, ARPMsg* arpMsg, const struct sockaddr_ll* slSrcAddr) {
    char srcIP[IP_STR_LEN], targetIP[IP_STR_LEN];
    sprtIP(srcIP, arpMsg->srcIP);
    sprtIP(targetIP, arpMsg->targetIP);
    char sDestMac[MAC_STR_LEN], sSrcMac[MAC_STR_LEN];
    sprtMac(sDestMac, arpMsg->destMac);
    sprtMac(sSrcMac, arpMsg->srcMac);
    
    //print info
    prtln("============== Received ARP Request ==============");
    prtln("* Ethernet Header");
    prtln("    destination addr: %s", sDestMac);
    prtln("    source addr     : %s", sSrcMac);
    prtln("* ARP Request                           ID: %d", ARP_MAN_ID);
    prtln("    sender Eth addr: %s  sender IP: %s", sSrcMac, srcIP);
    prtln("    target Eth addr:                    target IP: %s", targetIP);
    prtln("=============== ARP Request End =================\n");

    ACacheEnt* e = findACacheEntByIP(pARPCahceTab, srcIP);
    const LocalMap *lm = getLocalMapEntByIP(pLocalMap, targetIP);
    if (e == NULL) {
        if (lm != NULL) {
            e = insertIntoACacheTab(pARPCahceTab, srcIP, arpMsg->srcMac, slSrcAddr->sll_ifindex, slSrcAddr->sll_hatype, -1);
        }
    } else {
        updateACacheEnt(e, srcIP, arpMsg->srcMac, slSrcAddr->sll_ifindex, slSrcAddr->sll_hatype, -1);
    }

    if (lm != NULL) {
        sendARPReply(iRawSock, arpMsg, e->ifindex);
    }
}

/*
 * On receiving applications's request, check if target information is in cache
 * table. If yes, reply to application and return; otherwise insert into cache
 * table an incomplete entry and broadcast ARP request message.
 * @param iLIstenSock Unix domain socket used for responding application's request
 * @param iRawSock PF_PACKET raw socket
 * @param *piConnSock pointer to connection socket used for reading application's
 *        request
 */
void handleAppReq(const int iListenSock, const int iRawSock, int *piConnSock) {
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

    unsigned char readBuf[UXDOM_BUF_SIZE];
    read(*piConnSock, readBuf, UXDOM_BUF_SIZE);
    char targetIP[IP_STR_LEN];
    Hwaddr tourHwAddr;
    unmarshalAreq(targetIP, &tourHwAddr, readBuf);
    //check cache table
    ACacheEnt* pEnt = findACacheEntByIP(pARPCahceTab, targetIP);
    if (pEnt == NULL) {
        insertIntoACacheTab(pARPCahceTab, targetIP, "\0\0\0\0\0\0", pLocalMap->ifIndex, ARPHRD_ETHER, *piConnSock);
        int n = sendARPRequest(iRawSock, targetIP);
        if (n <= 0) {
            prtErr(ERR_SEND_ARP_REQ);
        }
        FD_SET(*piConnSock, &fsAll);
        iMaxFd = max(iMaxFd, *piConnSock);
    } else {
#ifdef DEBUG
        prtln("Found target HWaddr of %s in cache table.", targetIP);
#endif
        unsigned char data[UXDOM_BUF_SIZE];
        tourHwAddr.sll_ifindex = pEnt->ifindex;
        tourHwAddr.sll_hatype = pEnt->hatype;
        tourHwAddr.sll_halen = ETH_ALEN;
        memcpy((void*)tourHwAddr.sll_addr, (void*)pEnt->mac, ETH_ALEN);
        struct sockaddr_in IPaddr;
        inet_pton(AF_INET, targetIP, &IPaddr.sin_addr);
        marshalAreq(data, (SA*)&IPaddr, &tourHwAddr);
        write(*piConnSock, data, sizeof(data));
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
        p = p->next;
    }
    return NULL;
}

/*
 * insert new entry into ARP cache table
 * @return pointer to inserted entry
 * @param tab pointer to ARP cache table where entry is inserted
 * @param IP string storing IP in dotted decimal format to be inserted
 * @param mac string storing IP in value format (6 bits) to be inserted
 * @param ifindex sll_ifindex to be inserted
 * @param hatype Hard type to be inserted
 * @param connfd connection socket to be inserted
 */
ACacheEnt* insertIntoACacheTab(ACacheTab* tab, const char* IP, 
        const unsigned char* mac, const int ifindex, 
        const unsigned short hatype, const int connfd) {
    ACacheEnt* e = malloc(sizeof(*e));
    strcpy(e->IP, IP);
    memcpy(e->mac, mac, ETH_ALEN);
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
        e->next = NULL;
        tab->tail->next = e;
        tab->tail = e;
    }
#ifdef DEBUG
    prtACacheEnt("Entry inserted into cache table", e);
#endif
    return e;
}

/*
 * update ARP cache table entry
 * @return pointer to updated ARP cache table entry
 * @param e pointer to ARP cache table entry to be updated
 * @param tab pointer to ARP cache table where entry is updated
 * @param IP string storing IP in dotted decimal format to be updated, if passed
 *        NULL, IP will not be updated
 * @param mac string storing IP in value format (6 bits) to be updated, if passed
 *        NULL, mac will not be updated
 * @param ifindex sll_ifindex to be updated, if passed -1, ifindex will not be updated
 * @param hatype Hard type to be updated, if passed 0, hatype will not be updated
 * @param connfd connection socket to be updated, if passed -1, connfd will not
 *        be updated
 */
ACacheEnt* updateACacheEnt(ACacheEnt* e, const char* IP, const unsigned char* mac, 
        const int ifindex, const unsigned short hatype, const int connfd) {
#ifdef DEBUG
    char sMac[MAC_STR_LEN];
    printf("Updating cache table... Updated field: ");
    fflush(stdout);
#endif
    if (IP != NULL) {
       strcpy(e->IP, IP);
#ifdef DEBUG
       printf("IP ");
#endif
    }
    if (mac != NULL) {
        memcpy(e->mac, mac, ETH_ALEN);
#ifdef DEBUG
        printf("mac ");
        sprtMac(sMac, mac);
#endif
    }
    if (ifindex != -1) {
#ifdef DEBUG
        printf("ifindex ");
#endif
        e->ifindex = ifindex;
    }
    if (hatype != 0) {
        e->hatype = hatype;
#ifdef DEBUG
        printf("hatype ");
#endif
    }
    if (connfd != -1) {
#ifdef DEBUG
        printf("connfd");
#endif
        e->connfd = connfd;
    }
#ifdef DEBUG
    printf("\n");
    prtACacheEnt("Cache table entry updated", e);
#endif
}

/*
 * remove incomplete entries in ARP cache table
 * @param tab pointer ARP table where incomplete entries to be removed
 */
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
#ifdef DEBUG
            prtACacheEnt("Removed incomplete cache entry", e);
#endif
            free(e);
            return;
        } else {
            e = e->next;
        }
    }
}

/*
 * print ARP cache table entry
 * @param title title string
 * @param e pointer to ARP cache table entry to be printed
 */
void prtACacheEnt(const char* title, const ACacheEnt* e) {
    size_t len = strlen(title);
    size_t leftPad = (42 - len) / 2;
    size_t rightPad = 44 - leftPad - len - 2;
    for (size_t i = 0; i < leftPad; ++i) {
        printf("=");
    }
    printf(" %s ", title);
    for (size_t i = 0; i < rightPad; ++i) {
        printf("=");
    }
    printf("\n");
    char sMac[MAC_STR_LEN];
    sprtMac(sMac, e->mac);
    prtln("IP: %s  HWAddr: %s", e->IP, sMac);
    prtln("interface index: %d  hard type: %u    sockfd: %d", e->ifindex, e->hatype, e->connfd);
    prtln("================= Entry End ================\n");
}

/*
 * check if a ARP cache table entry is complete
 * @return 1 if complete, 0 otherwise
 * @param ent pointer to ARP cache table entry to be checked
 */
int isACacheEntComplete(const ACacheEnt* ent) {
    return ent->connfd < 0;
}

/*
 * send ARP request
 * @return number of bytes sent out on success, -1 on failure
 * @param iSockfd socket through which request is sent
 * @param targetIP string of IP whose corresponding mac address is searched for
 */
int sendARPRequest(const int iSockfd, const char* targetIP) {
    ARPMsg arpReqMsg;
    arpReqMsg.op = ARP_REQ;
    memset((void*)arpReqMsg.destMac, 0xff, ETH_ALEN);
    memcpy((void*)arpReqMsg.srcMac, (void*)pLocalMap->mac, ETH_ALEN);
    memset((void*)arpReqMsg.targetMac, 0, ETH_ALEN);
    parseIP(arpReqMsg.srcIP, pLocalMap->IP);
    parseIP(arpReqMsg.targetIP, targetIP);

    //print info
    char sDestMac[MAC_STR_LEN], sSrcMac[MAC_STR_LEN];
    sprtMac(sDestMac, arpReqMsg.destMac);
    sprtMac(sSrcMac, arpReqMsg.srcMac);
    prtln("============== Sending ARP Request ==============");
    prtln("* Ethernet Header");
    prtln("    destination addr: %s", sDestMac);
    prtln("    source addr     : %s", sSrcMac);
    prtln("* ARP Request                           ID: %d", ARP_MAN_ID);
    prtln("    sender Eth addr: %s  sender IP: %s", sSrcMac, pLocalMap->IP);
    prtln("    target Eth addr:                    target IP: %s", targetIP);
    prtln("=============== ARP Request End =================\n");

    return sendARPPacket(iSockfd, &arpReqMsg, pLocalMap->ifIndex);
} 

/* 
 * send ARP reply
 * @return number of bytes sent out on success, -1 on failure
 * @param iSockfd socket through which reply is sent
 * @param arpMsg pointer to ARPMsg that stores ARP request, which this ARP
 *        reply is responding to
 * @param ifindex outgoing interface index
 */
int sendARPReply(const int iSockfd, ARPMsg* arpMsg, const int ifindex) {
    memcpy((void*)arpMsg->destMac, (void*)arpMsg->srcMac, ETH_ALEN);
    memcpy((void*)arpMsg->targetMac, (void*)arpMsg->srcMac, ETH_ALEN);
    memcpy((void*)arpMsg->srcMac, pLocalMap->mac, ETH_ALEN);

    arpMsg->op = ARP_REP;
    unsigned char tmpIP[IP_LEN];
    memcpy((void*)tmpIP, (void*)arpMsg->srcIP, IP_LEN);
    memcpy((void*)arpMsg->srcIP, (void*)arpMsg->targetIP, IP_LEN);
    memcpy((void*)arpMsg->targetIP, (void*)tmpIP, IP_LEN);

    //print info
    char sDestMac[MAC_STR_LEN], sTargetMac[MAC_STR_LEN], sSrcMac[MAC_STR_LEN];
    char sSrcIP[IP_STR_LEN], sTargetIP[IP_STR_LEN];
    sprtMac(sDestMac, arpMsg->destMac);
    sprtMac(sTargetMac, arpMsg->targetMac);
    sprtMac(sSrcMac, arpMsg->srcMac);
    sprtIP(sSrcIP, arpMsg->srcIP);
    sprtIP(sTargetIP, arpMsg->targetIP);

    prtln("=============== Sending ARP Reply ===============");
    prtln("* Ethernet Header");
    prtln("    destination addr: %s", sDestMac);
    prtln("    source addr     : %s", sSrcMac);
    prtln("* ARP Reply                             ID: %d", ARP_MAN_ID);
    prtln("    sender Eth addr: %s  sender IP: %s", sSrcMac, sSrcIP);
    prtln("    target Eth addr: %s  target IP: %s", sTargetMac, sTargetIP);
    prtln("================ ARP Reply End ==================\n");

    return sendARPPacket(iSockfd, arpMsg, ifindex);
}

/*
 * send ARP request or reply message
 * @return number of bytes sent on on success, -1 on failure
 * @param iSockfd socket through which message is sent out
 * @param arpMsg pointer to ARPMsg structure that stores ARP request/reply message
 * @param iIfIndex outgoing interface index
 */
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
    short* manId = (short*)payload;
    *manId = htons(ARP_MAN_ID);
    short* hardType = (short*)(payload + 2);
    *hardType = htons(1);
    short* protType = (short*)(payload + 4);
    *protType = htons(0x0800);
    unsigned char* hardSize = (unsigned char*)(payload + 6);
    *hardSize = 6;
    unsigned char* protSize = (unsigned char*)(payload + 7);
    *protSize = 4;
    short* op = (short*)(payload + 8);
    *op = htons(arpMsg->op);
    
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
