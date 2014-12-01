#ifndef COMMON_H
#define COMMON_H

#include "unp.h"

typedef struct hwaddr {
    int sll_ifindex;
    unsigned short sll_hatype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
} Hwaddr;

void marshalAreq(unsigned char* dest, const struct sockaddr* IPaddr, const Hwaddr *hwAddr);
void unmarshalAreq(char *IP, Hwaddr *hwAddr, const unsigned char *src);

#endif
