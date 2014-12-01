#include "common.h"
#include <string.h>
#include "constants.h"

void marshalAreq(unsigned char* dest, const struct sockaddr* IPaddr, const Hwaddr *hwAddr) {
    inet_ntop(AF_INET, &((struct sockaddr_in*)IPaddr)->sin_addr, dest, IP_STR_LEN);
    memcpy((void*)dest + IP_STR_LEN, (void*)&hwAddr->sll_ifindex, 4);
    memcpy((void*)dest + IP_STR_LEN + 4, (void*)&hwAddr->sll_hatype, 2);
    memcpy((void*)dest + IP_STR_LEN + 6, (void*)&hwAddr->sll_halen, 1);
    memcpy((void*)dest + IP_STR_LEN + 7, (void*)hwAddr->sll_addr, 8);
}

void unmarshalAreq(char* IP, Hwaddr *hwAddr, const unsigned char* src) {
    memcpy((void*)IP, (void*)src, IP_STR_LEN);
    memcpy((void*)&hwAddr->sll_ifindex, (void*)src + IP_STR_LEN, 4);
    memcpy((void*)&hwAddr->sll_hatype, (void*)src + IP_STR_LEN + 4, 2);
    memcpy((void*)&hwAddr->sll_halen, (void*)src + IP_STR_LEN + 6, 1);
    memcpy((void*)&hwAddr->sll_addr, (void*)src + IP_STR_LEN + 7, 8);
}


