#include "tour.h"
#include "unp.h"
#include "api.h"
#include "common.h"
#include "constants.h"
#include "utility.h"
#include "lib/hw_addrs.h"
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>

PingList *pPingTargets = NULL;  //ping targets
int iSockICMP;                  //ICMP socket
int iSockUdp;                   //UDP socket
int iSockRt;                    //rt socket
int iSockPg;                    //pg socket
int iRecvICMPCtr = 0;           //received ICMP reply counter
int isLastNode = 0;             //last node flag
int isPinging= 0;               //pinging flag
int isJoinedMCast = 0;          //joined multicast group flag
unsigned short uMCastPort = 0;  //multicast group port
char sMCastIP[IP_STR_LEN];      //multicast group IP

int main(int argc, char** argv) {
    iSockRt = socket(AF_INET, SOCK_RAW, IPPROTO_RT);
    if (iSockRt < 0) {
        errExit(ERR_CREATE_RT);
    }
    int on = 1;
    setsockopt(iSockRt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    iSockPg = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (iSockPg < 0) {
        errExit(ERR_CREATE_PG);
    }
    setsockopt(iSockPg, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    iSockICMP = socket(PF_PACKET, SOCK_RAW, ETH_P_IP);
    if (iSockICMP < 0) {
        errExit(ERR_CREATE_ICMP);
    }

    iSockUdp = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(iSockUdp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (iSockUdp < 0) {
        errExit(ERR_CREATE_UDP);
    }

    pPingTargets = newPingList();

    fd_set fsAll, fsRead;
    FD_ZERO(&fsAll);
    FD_SET(iSockRt, &fsAll);
    FD_SET(iSockPg, &fsAll);
    FD_SET(iSockUdp, &fsAll);
    int iMaxFd = max(iSockRt, iSockPg);
    iMaxFd = max(iMaxFd, iSockUdp);

    if (argc > 1) {
        sendRoutingMsg(argc - 1, &argv[1]);
        if (joinMulticast(iSockUdp, TOUR_MCAST_IP, TOUR_MCAST_PORT) < 0) {
            prtErr(ERR_JOIN_MCAST);
        } else {
            isJoinedMCast = 1;
        }
        uMCastPort = TOUR_MCAST_PORT;
        strcpy(sMCastIP, TOUR_MCAST_IP);
    }

    while (1) {
        fsRead = fsAll;
        int iReadyNum = select(iMaxFd + 1, &fsRead, NULL, NULL, NULL);
        if (iReadyNum > 0) {
            if (FD_ISSET(iSockRt, &fsRead)) {
                handleRoutingMsg();
            }
            if (FD_ISSET(iSockUdp, &fsRead)) {
                handleMCastMsg();
            }
            if (FD_ISSET(iSockPg, &fsRead)) {
                handleICMPMsg();
            }
        } else if (iReadyNum < 0) {
            if (errno == EINTR) {
                continue;
            }
        } else {
            continue;
        }
    }
    return 0;
}

/*
 * On receiving multicast message, reply with multicast message or set 5 seconds
 * time out. Stop pinging meanwhile if ping is in progress
 */
void handleMCastMsg() {
    char buffer[MAXLINE];
    struct sockaddr_in srcAddr;
    int iAddrLen = sizeof(srcAddr);
    if (isPinging) {
        alarm(0);
        isPinging = 0;
#ifdef DEBUG
        prtln("Ping stopped!");
#endif
    }

    recvfrom(iSockUdp, buffer, MAXLINE, 0, (SA*)&srcAddr, &iAddrLen);
    char localHost[10];
    gethostname(localHost, sizeof(localHost));
    prtln("Node %s. Received %s", localHost, buffer);

    if (strstr(buffer, "identify") != NULL) {
        sprintf(buffer, "<<<<< Node %s. I am a member of the group. >>>>>", localHost);
        sendMCastMsg(buffer, MAXLINE);
    }

    Signal(SIGALRM, exitAlarm);
    alarm(5);
    //isLastNode = 0;
}

/*
 * join socket into multicast group
 * @return negative integer if failed, positive if succeed
 * @param grpIP string of target multicast group IP address
 * @param grpPort target multicast group port
 */
int joinMulticast(const int iSockfd, const char* grpIP, const unsigned short grpPort) {
    struct sockaddr_in mcastAddr;
    bzero(&mcastAddr, sizeof(mcastAddr));
    inet_pton(AF_INET, grpIP, &mcastAddr.sin_addr);
    mcastAddr.sin_family = AF_INET;
    mcastAddr.sin_port = htons(grpPort);
    bind(iSockfd, (SA*)&mcastAddr, sizeof(mcastAddr));
    mcast_set_ttl(iSockfd, 1);
    return mcast_join(iSockfd, (SA*)&mcastAddr, sizeof(mcastAddr), NULL, 0); 
}

/*
 * On receiving ICMP message, check type and ID. If passed, update received ICMP
 * echo reply counter, stop pinging, and send multicast message if local host
 * is last node in tour and it has received at least 5 echo replies from
 * preceding node
 */
void handleICMPMsg() {
    unsigned char data[RT_PACKET_SIZE];
    struct sockaddr_in srcAddr;
    int srcAddrLen = sizeof(srcAddr);
    int n = recvfrom(iSockPg, data, RT_PACKET_SIZE, 0, (SA*)&srcAddr, &srcAddrLen);

    struct icmp* icmpHdr = (struct icmp*)(data + 20);
    unsigned char icmpType = icmpHdr->icmp_type;
    if (icmpType != ICMP_ECHOREPLY) {
        return;
    }

    if (ntohs(icmpHdr->icmp_id) != (unsigned short)getpid()) {
        return;
    }
    
#ifdef DEBUG
    char srcHost[128];
    getHostNameByAddr(srcHost, &srcAddr);
    prtln("Received ping reply from %s", srcHost);
#endif
    if (srcAddr.sin_addr.s_addr == pPingTargets->head->addr.s_addr) {
        ++iRecvICMPCtr;
    }
    if (iRecvICMPCtr >= 5 && isLastNode) {
        if (!isPinging) {
            return;
        }
#ifdef DEBUG
        prtln("Ping stopped!");
#endif
        char sendBuf[1024];
        char localHost[10];
        gethostname(localHost, sizeof(localHost));
        sprintf(sendBuf, "<<<<< This is node %s. Tour has ended. Group members please identify yourselves. >>>>>", localHost);
        sendMCastMsg(sendBuf, sizeof(sendBuf));
        alarm(0);
        isPinging = 0;
    }
}

/*
 * send multicast message
 * @return number of bytes sent out on success, -1 on failure
 * @param msg string of msg to be sent out
 * @param msgSize length of msg buffer
 */
int sendMCastMsg(const char* msg, const size_t msgSize) {
    char localHost[10];
    gethostname(localHost, sizeof(localHost));
    prtln("Node %s. Sending: %s", localHost, msg);
    struct sockaddr_in dstAddr;
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_port = htons(uMCastPort);
    inet_pton(AF_INET, sMCastIP, &dstAddr.sin_addr);
    return sendto(iSockUdp, msg, msgSize, 0, (SA*)&dstAddr, sizeof(dstAddr));
}

/*
 * On receiving routing packet, join UDP socket ot multicast, ping
 */
void handleRoutingMsg() {
    unsigned char data[RT_PACKET_SIZE];
    struct sockaddr_in srcAddr;
    int srcAddrLen = sizeof(srcAddr);
    recvfrom(iSockRt, data, RT_PACKET_SIZE, 0, (SA*)&srcAddr, &srcAddrLen);
    struct ip* ipHdr = (struct ip*)data;

    // check id
    if (ntohs(ipHdr->ip_id) != IPID_RT) {
        prtln("Received routing packet with ID=%u, packet is omitted", ntohs(ipHdr->ip_id));
        return;
    }
    
    time_t curTime = time(NULL);
    char senderHostName[128];
    prtln("%.24s received source routing packet from %s",
            ctime(&curTime), getHostNameByAddr(senderHostName, &srcAddr));

    // join multicast group
    unsigned char* payload = data + 20;
    if (!isJoinedMCast) {
        char grpIP[IP_STR_LEN];
        sprtIP(grpIP, payload + 2);
        unsigned short* grpPort = (unsigned short*)(payload + 2 + IP_LEN);
        strcpy(sMCastIP, grpIP);
        uMCastPort = ntohs(*grpPort);
        int r = joinMulticast(iSockUdp, sMCastIP, uMCastPort);
        if (r < 0) {
            prtErr(ERR_JOIN_MCAST);
        } else {
            isJoinedMCast = 1;
        }
#ifdef DEBUG
        prtln("Joined multicast group %s:%u", sMCastIP, uMCastPort);
#endif
    }

    //if (!isPinging) {
    if (!existInPingList(pPingTargets, &ipHdr->ip_src)) {
        // send ping
        //iaPingTarget = ipHdr->ip_src;
        insertIntoPingList(pPingTargets, &ipHdr->ip_src);
        ping();
        signal(SIGALRM, pingAlarm);
        alarm(1);
    }

    // relay routing pkg to next node
    // WARNING:d data will be modified after call
    int r = relayRoutingMsg(data);
    if (r == 0) {
        // last Node
        iRecvICMPCtr = 0;
        isLastNode = 1;
    }
}

/*
 * alarm handler
 */
void pingAlarm(int signo) {
    ping();
    alarm(1);
}

/*
 * alarm handler
 */
void exitAlarm(int signo) {
    prtln("5 seconds times out, exiting tour...");
    close(iSockICMP);
    close(iSockUdp);
    close(iSockRt);
    close(iSockPg);
    deletePingList(pPingTargets);
    exit(0);
}

/*
 * send ICMP echo requests to address in pPingTargets
 */
void ping() {
    isPinging = 1;
    struct sockaddr_in targetAddr;
    PingEnt *e = pPingTargets->head;
    while (e != NULL) {
        bzero(&targetAddr, sizeof(targetAddr));
        targetAddr.sin_addr = e->addr;
        Hwaddr targetHwAddr;
        targetHwAddr.sll_ifindex = 0;
        targetHwAddr.sll_hatype = 0;
        targetHwAddr.sll_halen = 0;
        memset((void*)targetHwAddr.sll_addr, 0, 8);
        if (areq((SA*)&targetAddr, sizeof(targetAddr), &targetHwAddr) == 0) {
            char targetIP[IP_STR_LEN];
            inet_ntop(AF_INET, &e->addr, targetIP, IP_STR_LEN);
            prtln("targetIP:%s", targetIP);
            int n = sendICMP(&targetHwAddr, targetIP);
        }
        e = e->next;
    }
}

/*
 * Modify received routing packet data and relay it to next node
 * @return number of bytes sent out on success, -1 on failure
 * @param data string buffer of received routing packet
 */
int relayRoutingMsg(unsigned char* data) {
    struct ip* ipHdr = (struct ip*)data;
    unsigned char *usrData = data + 20;
    unsigned short *pNextOffset = (unsigned short*)usrData;
    unsigned short nextOffset = ntohs(*pNextOffset);
    if (nextOffset == 0) {
        return 0;
    }

    char nextIP[IP_STR_LEN];
    sprtIP(nextIP, usrData + nextOffset);
    nextOffset += IP_LEN;
    if (nextOffset + 20 > RT_PACKET_SIZE) {
        nextOffset = 0;
    }
    unsigned char* next1stByte = (unsigned char*)usrData + nextOffset;
    if (*next1stByte == 0) {
        nextOffset = 0;
    }
    *pNextOffset = htons(nextOffset);

    char localIP[IP_STR_LEN];
    inet_pton(AF_INET, nextIP, &ipHdr->ip_dst);
    inet_pton(AF_INET, getLocalIP(localIP), &ipHdr->ip_src);

    struct sockaddr_in dstAddr;
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_port = htons(0);
    inet_pton(AF_INET, nextIP, &dstAddr.sin_addr);
    return sendto(iSockRt, data, RT_PACKET_SIZE, 0, (SA*)&dstAddr, sizeof(dstAddr));
}

/*
 * sent ICMP echo request to target
 * @return number of bytes sent out on success, -1 on failure
 * @param targetHwAddr HWaddr of receiver
 * @param targetIP dotted-decimal IP string of receiver
 */
int sendICMP(const Hwaddr *targetHwAddr, const char* targetIP) {
    struct sockaddr_ll destAddr;
    void* buffer = malloc(ETH_FRAME_LEN);
    unsigned char* data = buffer + ETH_HLEN;

    destAddr.sll_family = PF_PACKET;
    destAddr.sll_protocol = htons(ETH_P_IP);
    destAddr.sll_ifindex = targetHwAddr->sll_ifindex;
    destAddr.sll_hatype = targetHwAddr->sll_hatype;
    destAddr.sll_pkttype = PACKET_OTHERHOST;
    destAddr.sll_halen = targetHwAddr->sll_halen;
    memset(destAddr.sll_addr, 0, 8);
    memcpy(destAddr.sll_addr, targetHwAddr->sll_addr, targetHwAddr->sll_halen);

    //fill ethernet header
    memcpy((void*)buffer, (void*)targetHwAddr->sll_addr, ETH_ALEN);
    getLocalMac((void*)buffer + ETH_ALEN);
    struct ethhdr *eh = (struct ethhdr*)buffer;
    eh->h_proto = htons(ETH_P_IP);

    //fill IP header
    struct ip* ipHdr = (struct ip*) data;
    ipHdr->ip_v = 4;
    ipHdr->ip_hl = sizeof(*ipHdr) >> 2;
    ipHdr->ip_tos = 0;
    ipHdr->ip_len = htons(76 + sizeof(struct icmphdr));
    ipHdr->ip_id = htons(IPID_ICMP);
    ipHdr->ip_off = 0;
    ipHdr->ip_ttl = 255;
    ipHdr->ip_p = IPPROTO_ICMP;
    ipHdr->ip_sum = 0;
    char localIP[IP_STR_LEN];
    inet_pton(AF_INET, getLocalIP(localIP), &ipHdr->ip_src);
    inet_pton(AF_INET, targetIP, &ipHdr->ip_dst);
    ipHdr->ip_sum = in_cksum((unsigned short*)ipHdr, 20);

    //fill payload
    struct icmp* icmpHdr = (struct icmp*)(data + 20);
    int datalen = 56;
    icmpHdr->icmp_type = ICMP_ECHO;
    icmpHdr->icmp_code = 0;
    icmpHdr->icmp_id = htons((unsigned short)getpid());
    icmpHdr->icmp_seq = getPingSeqNum();
    memset(icmpHdr->icmp_data, 0xa5, datalen);
    Gettimeofday((struct timeval*)icmpHdr->icmp_data, NULL);
    int len = datalen + 8;

    icmpHdr->icmp_cksum = 0;
    icmpHdr->icmp_cksum = in_cksum((unsigned short*)icmpHdr, len);
    int n = sendto(iSockICMP, buffer, ETH_HLEN + 20 + len, 0, (SA*)&destAddr, sizeof(destAddr));
    char dstHostName[128];
    getHostNameByIP(dstHostName, targetIP);
    prtln("PING %s(%s): %d data bytes", dstHostName, targetIP, n);
#ifdef DEBUG
    time_t curTime = time(NULL);
    prtln("PING message sent at %.24s", ctime(&curTime));
#endif
    return n;
}

/*
 * Get ICMP echo request sequence number
 * @return returned sequence number
 */
unsigned short getPingSeqNum() {
    static unsigned short seq = 0;
    return ++seq;
}

/*
 * Retrieve local mac address
 * @return mac paramter
 * @param mac buffer storing returned value
 */
unsigned char* getLocalMac(unsigned char* mac) {
    struct hwa_info *hwaHead, *hwaPtr;
    hwaHead = hwaPtr = Get_hw_addrs();
    while (hwaPtr != NULL) {
        if (strstr(hwaPtr->if_name, "eth0") != NULL) {
            memcpy(mac, hwaPtr->if_haddr, ETH_ALEN);
            return mac;
        }
        hwaPtr = hwaPtr->hwa_next;
    }
}

/*
 * Retrieve IP of a given host name
 * @return same as IP parameter
 * @param IP string buffer used to store return value
 * @param name host name string
 */
char* getIPByHostName(char* IP, const char* name) {
    struct hostent* e = gethostbyname(name);
    struct in_addr **lst = (struct in_addr**)e->h_addr_list;
    inet_ntop(AF_INET, lst[0], IP, IP_STR_LEN);
    return IP;
}

/*
 * Retrieve host name of given address
 * @return same as name parameter
 * @param name string buffer to store return value
 * @param sa pointer to sockaddr_in that stores target address
 */
char* getHostNameByAddr(char* name, struct sockaddr_in* sa) {
    struct hostent* e = gethostbyaddr(&sa->sin_addr, sizeof(sa->sin_addr), AF_INET);
    strcpy(name, e->h_name);
    return name;
}

/*
 * Retrieve host name of given IP
 * @return same as name parameter
 * @param name string buffer to store return value
 * @param IP target IP in dotted-decimal format
 */
char* getHostNameByIP(char* name, const char* IP) {
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, IP, &addr.sin_addr);
    return getHostNameByAddr(name, &addr);
}

/*
 * Send routing message
 * @return number of bytes sent out on success, -1 on failure
 * @param hostNum number of hosts in host list
 * @param hostList pointer to array that stores of IPs which are associated with
 *        target sequence of hosts
 */
int sendRoutingMsg(const int hostNum, char** hostList) {
    unsigned char data[RT_PACKET_SIZE];
    unsigned char *usrData = data + 20;
    unsigned char *pcListStart = usrData + 4 + IP_LEN;
    struct ip* ipHdr = (struct ip*)data;
    char localIP[IP_STR_LEN], dstIP[IP_STR_LEN];
    int maxIPNum = (RT_PACKET_SIZE - 24 - IP_LEN) / IP_LEN;
    if (hostNum > maxIPNum) {
        prtErr(ERR_TOUR_HOSTS_EXCEED);
    }

    memset((void*)data, 0, RT_PACKET_SIZE);

    //fill ip header
    ipHdr->ip_v = 4;
    ipHdr->ip_hl = sizeof(*ipHdr) >> 2;
    ipHdr->ip_tos = 0;
    ipHdr->ip_len = htons(RT_PACKET_SIZE);
    ipHdr->ip_id = htons(IPID_RT);
    ipHdr->ip_off = 0;
    ipHdr->ip_ttl = 255;
    ipHdr->ip_p = IPPROTO_RT;
    ipHdr->ip_sum = 0;
    inet_pton(AF_INET, getLocalIP(localIP), &ipHdr->ip_src); 
    inet_pton(AF_INET, getIPByHostName(dstIP, hostList[0]), &ipHdr->ip_dst);

    //fill payload data
    unsigned short* nextOffset = (unsigned short*)usrData;
    //offset from usrData
    if (hostNum <= 1) {
        *nextOffset = htons(0);
    } else {
        *nextOffset = htons(4 + 2 * IP_LEN);
    }

    parseIP(usrData + 2, TOUR_MCAST_IP);
    unsigned short *mcastPort = (unsigned short*)(usrData + 2 + IP_LEN);
    *mcastPort = htons(TOUR_MCAST_PORT);

    for (int i = 0; i < hostNum; ++i) {
        char IP[IP_STR_LEN];
        parseIP(pcListStart + IP_LEN * i, getIPByHostName(IP, hostList[i]));
    }

    struct sockaddr_in dstAddr;
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_port = htons(0);
    inet_pton(AF_INET, dstIP, &dstAddr.sin_addr);
    return sendto(iSockRt, data, RT_PACKET_SIZE, 0, (SA*)&dstAddr, sizeof(dstAddr));
}

/*
 * Retrieve local primary IP associated with eth0
 * @return same as IP parameter
 * @param IP string buffer to store return value
 */
char* getLocalIP(char* IP) {
    char hostName[128];
    gethostname(hostName, sizeof(hostName));
    return getIPByHostName(IP, hostName);
}

/*
 * Create new ping list
 * @return pointer to created list
 */
PingList* newPingList() {
    PingList* p = malloc(sizeof(*p));
    p->head = NULL;
    return p;
}

/*
 * Insert new entry into pinglist
 * @return inserted entry
 * @param lst pointer to ping list to be inserted into
 * @param addr new address value to be inserted
 */
PingEnt* insertIntoPingList(PingList* lst, const struct in_addr *addr) {
    PingEnt* e = malloc(sizeof(*e));
    e->addr = *addr;
    if (lst->head == NULL) {
        e->next = NULL;
    } else {
        e->next = lst->head;
    }
    lst->head = e;
    return e;
}

/*
 * Check if an address is in current ping list
 * @return 1 if exists, 0 otherwise
 * @param lst pointer to ping list to be examined
 * @param addr pointer to address to be inserted
 */
int existInPingList(const PingList* lst, const struct in_addr *addr) {
    PingEnt* p = lst->head;
    while (p != NULL) {
        if (p->addr.s_addr == addr->s_addr) {
            return 1;
        }
        p = p->next;
    }
    return 0;
}

/*
 * Delete ping list
 * @param lst pointer to ping list to be deleted
 */
void deletePingList(PingList* lst) {
    while (lst->head != NULL) {
        PingEnt* p = lst->head;
        lst->head = p->next;
        free(p);
    }  
    free(lst);
}
