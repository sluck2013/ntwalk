#include "common.h"
#include <string.h>
#include "constants.h"

void marshalIPAddr(char* dest, const struct sockaddr* IPaddr) {
    inet_ntop(AF_INET, &((struct sockaddr_in*)IPaddr)->sin_addr, dest, IP_LEN);
}

void unmarshalIPAddr(struct sockaddr* IPaddr, const char* src) {
    inet_pton(AF_INET, src, &((struct sockaddr_in*)IPaddr)->sin_addr);
}
