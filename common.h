#ifndef COMMON_H
#define COMMON_H

typedef struct hwaddr {
    int sll_ifindex;
    unsigned short sll_hatype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
} Hwaddr;

#endif
