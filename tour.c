#include "tour.h"
#include "unp.h"
#include "api.h"
#include "common.h"

int main(int argc, char** argv) {
    struct sockaddr_in IP;
    char src[] = "192.168.1.103";
    inet_pton(AF_INET, src, &IP.sin_addr);
    struct hwaddr HWaddr;
    HWaddr.sll_ifindex = 1;
    HWaddr.sll_hatype = 2;
    HWaddr.sll_halen = 3;
    strcpy(HWaddr.sll_addr, "1234");
    areq((SA*)&IP, sizeof(IP) + sizeof(HWaddr), &HWaddr);
    return 0;
}
