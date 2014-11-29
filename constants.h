#ifndef CONSTANTS_H
#define CONSTANTS_H

#define DEBUG

#define IP_LEN (16)  //length of IP in dec-dotted format
#define MAC_LEN (6)  //length of mac address
#define MAC_STR_LEN (18) //length of string storing mac in readable format
#define ARP_SUN_PATH "/tmp/arp109399621"
#define ARP_ETH_PROT (10939)

#define ERR_ARP_CREATE_RAW_SOCK "Cannot create PF_PACKET socket!"
#define ERR_ARP_CREATE_DOM_SOCK "Cannot create Unix domain socket!"

#endif
