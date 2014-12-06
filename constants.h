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
#define AREQ_TIMEOUT (10)
#define IPPROTO_RT (126)
#define IPID_RT (10939)
#define IPID_ICMP (9621)
#define RT_PACKET_SIZE (1500)
#define TOUR_MCAST_IP "230.245.147.245"
#define TOUR_MCAST_PORT (10939)

#define ERR_ARP_CREATE_RAW_SOCK "Cannot create PF_PACKET socket!"
#define ERR_ARP_CREATE_DOM_SOCK "Cannot create Unix domain socket!"
#define ERR_ARP_ACCEPT "Accepting failed on domain socket!"
#define ERR_SEND_ARP_REQ "Sending ARP request to vms"
#define ERR_TOUR_HOSTS_EXCEED "Too many hosts to traverse!"
#define ERR_CREATE_RT "Socket rt was not created!"
#define ERR_CREATE_UDP "UDP Socket was not created!"
#define ERR_CREATE_ICMP "ICMP socket was not created!"
#define ERR_CREATE_PG "Socket pg was not created!"
#define ERR_JOIN_MCAST "Cannot join multicast group!"

#endif
