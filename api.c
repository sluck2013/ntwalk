#include "api.h"
#include "constants.h"
#include "utility.h"

int areq(struct sockaddr* IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr) {
    unsigned char data[UXDOM_BUF_SIZE];
    char IP[IP_STR_LEN];

    marshalAreq(data, IPaddr, HWaddr);
    struct sockaddr_un suArpAddr;

    int iSock = Socket(AF_LOCAL, SOCK_STREAM, 0);
    bzero(&suArpAddr, sizeof(suArpAddr));
    suArpAddr.sun_family = AF_LOCAL;
    strcpy(suArpAddr.sun_path, ARP_SUN_PATH);
    Connect(iSock, (SA*)&suArpAddr, sizeof(suArpAddr));

    inet_ntop(AF_INET, &((struct sockaddr_in*)IPaddr)->sin_addr, IP, IP_STR_LEN);
    prtln("areq() called, targetIP: %s", IP);
    write(iSock, data, sizeof(data));
    read(iSock, data, sizeof(data));
    
    unmarshalAreq(IP, HWaddr, data);
    char mac[MAC_STR_LEN];
    sprtMac(mac, HWaddr->sll_addr);
    prtln("Received Response:");
    prtln("    Ethernet Addr: %s", mac);
    prtln("    Interface Index: %d", HWaddr->sll_ifindex);
    prtln("    Hard Type: %u\n", HWaddr->sll_hatype);
    inet_pton(AF_INET, IP, &((struct sockaddr_in*)IPaddr)->sin_addr);
    return 0;
}
