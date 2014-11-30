#ifndef COMMON_H
#define COMMON_H

#include "unp.h"

typedef struct hwaddr {
    int sll_ifindex;
    unsigned short sll_hatype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
} Hwaddr;

void marshalIPAddr(char* dest, const struct sockaddr* IPaddr);
void unmarshalIPAddr(SA* IPaddr, const char* src);

#endif
