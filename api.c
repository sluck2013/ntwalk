#include "api.h"
#include "constants.h"
#include "utility.h"

int areq(struct sockaddr* IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr) {
    prtln("==== in AREQ ==== ");
    prtln("index:%d", HWaddr->sll_ifindex);
    unsigned char sendData[IP_STR_LEN + HWADDR_SIZE + 1];
    marshalAreq(sendData, IPaddr, HWaddr);

    struct sockaddr_un suArpAddr;

    int iSock = Socket(AF_LOCAL, SOCK_STREAM, 0);
    bzero(&suArpAddr, sizeof(suArpAddr));
    suArpAddr.sun_family = AF_LOCAL;
    strcpy(suArpAddr.sun_path, ARP_SUN_PATH);
    Connect(iSock, (SA*)&suArpAddr, sizeof(suArpAddr));
    write(iSock, sendData, sizeof(sendData));
    return 0;
}
