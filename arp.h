#ifndef ARP_H
#define ARP_H

#include "constants.h"

/*
 * This structs stores local mapping from IP to Mac address
 */
typedef struct LocalMapping {
    char IP[IP_LEN];
    char mac[MAC_LEN];
    struct LocalMapping* next;
} LocalMap;

LocalMap* getLocalMap();
void prtLocalMap(const LocalMap* localMap);

#endif
