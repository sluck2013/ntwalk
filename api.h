#ifndef API_H
#define API_H
#include "unp.h"
#include "common.h"

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr);
#endif
