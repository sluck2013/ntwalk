#include "arp.h"
#include "lib/hw_addrs.h"
#include "unp.h"
#include "utility.h"
#include <stdlib.h>
#include <string.h>

int main() {
    LocalMap *localMap = getLocalMap();
    prtLocalMap(localMap);
    return 0;
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
        if (strcmp(hwaPtr->if_name, "eth0") == 0) {
            mapPtr = malloc(sizeof(LocalMap));
            struct sockaddr *sa = hwaPtr->ip_addr;
            char *addr = Sock_ntop_host(sa, sizeof(*sa));
            strcpy(mapPtr->IP, addr);
            memcpy(mapPtr->mac, hwaPtr->if_haddr, MAC_LEN);
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
 * print <IP, HW addr> entries in LocalMap structure
 * @param localMap pointer to LocalMap struct to be printed
 */
void prtLocalMap(const LocalMap* localMap) {
    prtln("===== Local <IP addr, HW addr> found for eth0 BEGIN =====");
    const LocalMap *lmPtr = localMap;
    while (lmPtr != NULL) {
        char mac[MAC_STR_LEN];
        sprtMac(mac, lmPtr->mac);
        prtln("    <%s, %s>", lmPtr->IP, mac);
        lmPtr = lmPtr->next;
    }
    prtln("====== Local <IP addr, HW addr> found for eth0 END ======");
}
