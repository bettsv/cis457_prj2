#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <netinet/ether.h> //ether_ntoa
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#define MAC_ANY "00:00:00:00:00:00"
#define MAC_BCAST "FF:FF:FF:FF:FF:FF"

char data_msg[200];

struct arphdr
{
  unsigned short int arp_hrd; /* Format of hardware address.  */
  unsigned short int arp_pro; /* Format of protocol address.  */
  unsigned char arp_hln;      /* Length of hardware address.  */
  unsigned char arp_pln;      /* Length of protocol address.  */
  unsigned short int arp_op;  /* ARP opcode (command).  */
};
struct ether_arp
{
  struct arphdr ea_hdr;       /* fixed-size header */
  u_int8_t arp_sha[ETH_ALEN]; /* sender hardware address */
  u_int8_t arp_spa[4];        /* sender protocol address */
  u_int8_t arp_tha[ETH_ALEN]; /* target hardware address */
  u_int8_t arp_tpa[4];        /* target protocol address */
};

struct icmp
{
  u_int8_t type;      //#bit 0-7
  u_int8_t code;      //#bit 8-15
  u_int16_t checksum; //#bit 16-31
  u_int16_t id;       //#bit 32-47
  u_int16_t snum;     //#bit 48-63
  char opt[8];        // #bit 64-127
};

struct ipv4
{
  u_int8_t versionHeader; // the first 4 bits are version, latter 4 are internet header
  // tos has first 3 bits as precedence, 1 as delay, 1 as throughput, 1 is reliability, 2 as reserved
  u_int8_t tos;     // type of service
  u_int16_t length; // total length
  u_int16_t id;
  // flags has first bit reserved, second bit don't fragment, 3rd bit more fragments
  u_int16_t flagFragment; // flags are first 3 bits, offset remaining 11
  u_int8_t ttl;           // time to live
  u_int8_t protocol;
  u_int16_t checksum;
  u_int32_t sourceAddr;
  u_int32_t destAddr;
  char options[8]; //
  char data[8];    // 64 bits
};
struct ifmap
{
  unsigned long mem_start;
  unsigned long mem_end;
  unsigned short base_addr;
  unsigned char irq;
  unsigned char dma;
  unsigned char port;
};
struct ifreq
{
#define IFHWADDRLEN 6
#define IFNAMSIZ IF_NAMESIZE

  char ifr_name[IFNAMSIZ]; /* Interface name */
  union
  {
    struct sockaddr ifr_addr;
    struct sockaddr ifr_dstaddr;
    struct sockaddr ifr_broadaddr;
    struct sockaddr ifr_netmask;
    struct sockaddr ifr_hwaddr;
    short ifr_flags;
    int ifr_ifindex;
    int ifr_metric;
    int ifr_mtu;
    struct ifmap ifr_map;
    char ifr_slave[IFNAMSIZ];
    char ifr_newname[IFNAMSIZ];
    char *ifr_data;
  };
};
  u_int8_t temp_src_ip[4]; 
  u_int8_t temp_dst_ip[4];

int main()
{
  int iNetType;
  char chMAC[6];

  struct ifreq ifr;
  int sock;
  char *ifname = NULL;

  if (!iNetType)
  {
    ifname = "eth0"; /* Ethernet */
  }
  else
  {
    ifname = "wlan0"; /* Wifi */
  }
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  strcpy(ifr.ifr_name, ifname);
  ifr.ifr_addr.sa_family = AF_INET;
  ioctl(sock, SIOCGIFHWADDR, &ifr);
  memcpy(chMAC, ifr.ifr_hwaddr.sa_data, 6);
  close(sock);
/*
-------------------------------------------------------------------------------------------------
struct ifreq ifr;
size_t if_name_len=strlen(if_name);
if (if_name_len<sizeof(ifr.ifr_name)) {
    memcpy(ifr.ifr_name,if_name,if_name_len);
    ifr.ifr_name[if_name_len]=0;
} else {
    die("interface name is too long");
}

int fd=socket(AF_UNIX,SOCK_DGRAM,0);
if (fd==-1) {
    die("%s",strerror(errno));
}

if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
    int temp_errno=errno;
    close(fd);
    die("%s",strerror(temp_errno));
}
close(fd);

if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
    die("not an Ethernet interface");
}vv

const unsigned char* mac=(unsigned char*)ifr.ifr_hwaddr.sa_data;
printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
-------------------------------------------------------------------------------------------------
*/









  int packet_socket;
  /* get list of interface addresses. This is a linked list. Next pointer is in ifa_next,
  interface name is in ifa_name, address is in ifa_addr. You will have multiple entries
  in the list with the same name, if the same interface has multiple addresses. This is
  common since most interfaces will have a MAC, IPv4, and IPv6 address. Yovu can use the
  names to match up which IPv4 address goes with which MAC address.*/
  struct ifaddrs *ifaddr, *tmp;
  if (getifaddrs(&ifaddr) == -1)
  {
    perror("getifaddrs");
    return 1;
  }
  // have the list, loop over the list
  for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
  {
    /* Check if this is a packet address, there will be one per interface.  There are IPv4
    and IPv6 as well, but we don't care about those for the purpose of enumerating interfaces.
    We can use the AF_INET addresses in this list for example to get a list of our own IP addresses*/
    if (tmp->ifa_addr->sa_family == AF_PACKET)
    {
      printf("Interface: %s\n", tmp->ifa_name);
      // create a packet socket on interface r?-eth1
      if (!strncmp(&(tmp->ifa_name[3]), "eth1", 4))
      {
        printf("Creating Socket on interface %s\n", tmp->ifa_name);
        /* create a packet socket AF_PACKET makes it a packet socket SOCK_RAW makes it so we get the
        entire packet could also use SOCK_DGRAM to cut off link layer header ETH_P_ALL indicates we
        want all (upper layer) protocols we could specify just a specific one*/
        packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (packet_socket < 0)
        {
          perror("socket");
          return 2;
        }
        /* Bind the socket to the address, so we only get packets received on this specific interface.
        For packet sockets, the address structure is a struct sockaddr_ll (see the man page for "packet"),
        but of course bind takes a struct sockaddr. Here, we can use the sockaddr we got from getifaddrs
        (which we could convert to sockaddr_ll if we needed to)*/
        if (bind(packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1)
        {
          perror("bind");
        }
      }
    }
  }
  /*loop and receive packets. We are only looking at one interface, for the project you will probably want
   to look at more (to do so, a good way is to have one socket per interface and use select to see which
   ones have data)*/
  printf("Ready to receive now\n");
  while (1)
  {
    char buf[1500];
    struct sockaddr_ll recvaddr;
    struct sockaddr_ll listenaddr;
    listenaddr.sll_family = AF_PACKET;
    listenaddr.sll_protocol = htons(ETH_P_ALL);
    listenaddr.sll_ifindex = if_nametoindex("hi eth0");
    unsigned int recvaddrlen = sizeof(struct sockaddr_ll);
    /* we can use recv, since the addresses are in the packet, but we use recvfrom because it gives us
    an easy way to determine if this packet is incoming or outgoing (when using ETH_P_ALL, we see packets
    in both directions. Only outgoing can be seen when using a packet socket with some specific protocol) */
    int n = recvfrom(packet_socket, buf, 1500, 0, (struct sockaddr *)&recvaddr, &recvaddrlen);
    /*ignore outgoing packets (we can't disable some from being sent by the OS automatically, for example
    ICMP port unreachable messages, so we will just ignore them here)*/
    if (recvaddr.sll_pkttype == PACKET_OUTGOING)
      continue;
    // start processing all others
    //  buf came from the socket
    struct ether_header e_h;
    struct iphdr ip_h;
    struct icmp icmp_h;
    // printf("The size of eh is [%lu] bytes.\n",sizeof(eh));
    //  Copy the first 14 bytes from the buf and give it to the ethernet header
    memcpy(&e_h, buf, sizeof(e_h));

    char nn[] = "address";
    // IF we have an incoming ICMP echo request/reply
    if (ntohs(e_h.ether_type) == 0x800)
    {
      // u_int8_t type;      //#bit 0-7
      // u_int8_t code;      //#bit 8-15
      // u_int16_t checksum; //#bit 16-31
      // u_int16_t id;       //#bit 32-47
      // u_int16_t snum;     //#bit 48-63
      // char opt[8];        // #bit 64-127

      // Parse a request from h1
      printf("Type: 0x%03x\n", ntohs(e_h.ether_type));

      
      // /*[Eth header][IP header][ICMP header]*/

      // // Eth header (type,source mac, dest mac)
      // printf("Type: 0x%03x\n", ntohs(e_h.ether_type));
      // printf("ICMP type\n");
      // printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
      // printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
      // // printf("Got a %d byte packet\n", n);

      // // IP header -> If the protocol header in the IP header = 1 this means we have an ICMP request/reply
      // memcpy(&ip_h, &buf[sizeof(e_h)], sizeof(ip_h));
      // printf("IP Protocol: %d\n", ip_h.protocol);

      // ICMP header (type, code, checksum, identifier, sequence number, optional data)
      // http://www.tcpipguide.com/free/t_ICMPv4EchoRequestandEchoReplyMessages-2.htm
      // Offset the buffer data by the size of the ethernet and ip headers
      memcpy(&icmp_h, &buf[sizeof(e_h) + sizeof(ip_h)], sizeof(icmp_h));
      if (icmp_h.type == 0)
      {
        printf("ICMP Reply\n");
        // There is no need to respond to the reply
      }
      else if (icmp_h.type == 8)
      {
        printf("ICMP Request\n");
        // Respond to the echo request by forwarding its mac address to who requested it.
        // Swap the info in the ethernet header so we arrive at the requester
        // IP protocol will still be type 1
        // Switch the ICMP type from 8 to zero
        // Place the targets mac address in the data header
        // Send it via the socket to the requester that can then decode byte stream/datagram
      }
      // The ICMP header provides a place for optional data beginning at bit 65 and/or at 8 bytes into the ICMP frame
      memcpy(&data_msg, &buf[sizeof(e_h) + sizeof(ip_h) + 8], sizeof(data_msg));
      printf("Data message: %s\n", data_msg);
    }

    // If we have an incoming ARP request/response
    else if (ntohs(e_h.ether_type) == 0x806)
    {

      //[Eth header][ARP header]
      // ARP frame needs source Hardware type, length, protocol type and IP length
      // IP/MAC and target IP/MAC
      printf("ARP Type\n");

      // struct arphdr arp_h;
      struct ether_arp full_arp_h;
      
      /* FIXED DATA */
      full_arp_h.ea_hdr.arp_hrd = 1;                     //#bit 0-15   /* Format of hardware address.  unsigned short int*/
      full_arp_h.ea_hdr.arp_pro = ntohs(e_h.ether_type); //#bit 16-31     /* Format of protocol address.  unsigned short int*/
      full_arp_h.ea_hdr.arp_hln = 6;                     //#bit 32-47   /* Length of hardware address.  unsigned char*/
      full_arp_h.ea_hdr.arp_pln = 4;                     //#bit 48-55   /* Length of protocol address.  unsigned char*/
      
      //full_arp_h.ea_hdr.arp_op == 1                      //#bit 56-71 /* Protocol Address Length */
      
      //Offset buf by the size of the eth header and populate the arp struct based off the remaining data that buf has
      memcpy(&full_arp_h, &buf[sizeof(e_h)], sizeof(full_arp_h));
      
      
      if(full_arp_h.ea_hdr.arp_op == 1)
      {
        printf("ARP Request");
        // Create the ARP reply
        // Recycle the ethernet header by updating the source and destination header, the type can stay as 0x806
        e_h.ether_type = e_h.ether_type;
        memcpy(&e_h.ether_dhost,e_h.ether_shost,sizeof(e_h.ether_shost));
        memcpy(&e_h.ether_shost,chMAC,sizeof(e_h.ether_shost));

        /* Recycle the ARP header by updating the source and destination mac/ip, opcode needs = 2 for request, the type can stay as 0x806, 
          hardware type, hardware address
        */
        /* FIXED DATA */
        full_arp_h.ea_hdr.arp_hrd = 1;                     //#bit 0-15   /* Format of hardware address.  unsigned short int*/
        full_arp_h.ea_hdr.arp_pro = ntohs(e_h.ether_type); //#bit 16-31     /* Format of protocol address.  unsigned short int*/
        full_arp_h.ea_hdr.arp_hln = 6;                     //#bit 32-47   /* Length of hardware address.  unsigned char*/
        full_arp_h.ea_hdr.arp_pln = 4;                     //#bit 48-55   /* Length of protocol address.  unsigned char*/

        // = //mac of r1 (we dont currently know)
        full_arp_h.ea_hdr.arp_op = 2; 

        //Only for assigning new values before sending on the socket
        memcpy(&full_arp_h.arp_sha,&e_h.ether_shost,sizeof(full_arp_h.arp_sha)); /* sender hardware address */
        memcpy(&full_arp_h.arp_tha,&e_h.ether_dhost,sizeof(full_arp_h.arp_tha)); /* target hardware address */

        /* sender protocol address --  -- use a temp variable to protect the data */
        memcpy(&temp_src_ip,&full_arp_h.arp_spa,sizeof(temp_src_ip)); //use a temp variable to protect the data
        memcpy(&temp_dst_ip,&full_arp_h.arp_tpa,sizeof(temp_dst_ip)); //use a temp variable to protect the data

        memcpy(&full_arp_h.arp_spa[4],&temp_dst_ip,sizeof(temp_dst_ip)); //Take the ip of the source from the arp header and replace it with the destination ip
        memcpy(&full_arp_h.arp_tpa[4],&temp_src_ip,sizeof(temp_src_ip)); //Take the ip of the destination from the arp header and replace it with the source ip

      }


      printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
      printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
      printf("Type: 0x%03x\n", ntohs(e_h.ether_type));
      printf("Got a %d byte packet\n", n);
      printf("IP Protocol: %d\n", ip_h.protocol);
    }
    sleep(3);

    // what else to do is up to you, you can send packets with send, just like we used for TCP sockets (or you can use sendto, but it is not necessary, since the headers, including all addresses, need to be in the buffer you are sending)
  }
  // free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);
  // exit
  return 0;
}
