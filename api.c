#include "api.h"
#include "constants.h"

int areq(struct sockaddr* IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr) {
    char sendData[IP_LEN];
    marshalIPAddr(sendData, IPaddr);

    struct sockaddr_un suArpAddr;

    int iSock = Socket(AF_LOCAL, SOCK_STREAM, 0);
    bzero(&suArpAddr, sizeof(suArpAddr));
    suArpAddr.sun_family = AF_LOCAL;
    strcpy(suArpAddr.sun_path, ARP_SUN_PATH);
    Connect(iSock, (SA*)&suArpAddr, sizeof(suArpAddr));
    write(iSock, sendData, IP_LEN);
    return 0;
}
