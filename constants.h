#ifndef CONSTANTS_H
#define CONSTANTS_H

#define DEBUG

#define IP_LEN (4)
#define IP_STR_LEN (16)  //length of IP in dec-dotted format
#define MAC_STR_LEN (18) //length of string storing mac in readable format
#define HWADDR_SIZE (15)
#define UXDOM_BUF_SIZE IP_STR_LEN+HWADDR_SIZE+1
#define ARP_SUN_PATH "/tmp/arp109399621"
#define ARP_ETH_PROT (10939)
#define ARP_MAN_ID (10939)
#define AREQ_TIMEOUT (3);

#define ERR_ARP_CREATE_RAW_SOCK "Cannot create PF_PACKET socket!"
#define ERR_ARP_CREATE_DOM_SOCK "Cannot create Unix domain socket!"
#define ERR_ARP_ACCEPT "Accepting failed on domain socket!"
#define ERR_SEND_ARP_REQ "Sending ARP request to vms"

#endif
