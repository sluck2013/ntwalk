#include "tour.h"
#include "unp.h"
#include "api.h"
#include "common.h"

int main(int argc, char** argv) {
    struct sockaddr_in IP;
    char src[] = "192.168.1.103";
    inet_pton(AF_INET, src, &IP.sin_addr);
    struct hwaddr HWaddr;
    areq((SA*)&IP, sizeof(IP), &HWaddr);
    return 0;
}
