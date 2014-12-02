#include "tour.h"
#include "unp.h"
#include "api.h"
#include "common.h"
#include "constants.h"
#include "utility.h"

int main(int argc, char** argv) {
    struct sockaddr_in IP;
    char src[] = "130.245.156.22";
    inet_pton(AF_INET, src, &IP.sin_addr);
    struct hwaddr HWaddr;
    HWaddr.sll_ifindex = 1;
    HWaddr.sll_hatype = 2;
    HWaddr.sll_halen = 3;
    strcpy(HWaddr.sll_addr, "1234");
    areq((SA*)&IP, sizeof(IP), &HWaddr);
    char res[MAC_STR_LEN];
    sprtMac(res, HWaddr.sll_addr);
    printf("eth:%s\n", res);
    return 0;
}
