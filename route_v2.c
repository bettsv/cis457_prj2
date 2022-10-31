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

#define MAC_ANY "00:00:00:00:00:00"
#define MAC_BCAST "FF:FF:FF:FF:FF:FF"

char data_msg[200];

struct mac_ip{
	char src_mac[INET6_ADDRSTRLEN];
	char src_ip[INET6_ADDRSTRLEN];
	char dst_mac[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
};
struct my_icmp
{
  short int icmp_type;
};

int main()
{
  int packet_socket;
  /* get list of interface addresses. This is a linked list. Next pointer is in ifa_next, 
  interface name is in ifa_name, address is in ifa_addr. You will have multiple entries 
  in the list with the same name, if the same interface has multiple addresses. This is 
  common since most interfaces will have a MAC, IPv4, and IPv6 address. You can use the 
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
      /*[Eth header][IP header][ICMP header]*/

      // Eth header (type,source mac, dest mac)
      printf("Type: 0x%03x\n", ntohs(e_h.ether_type));
      printf("ICMP type\n");
      printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
      printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
      //printf("Got a %d byte packet\n", n);

      // IP header -> If the protocol header in the IP header = 1 this means we have an ICMP request/reply
      memcpy(&ip_h, &buf[sizeof(e_h)], sizeof(ip_h));
      printf("IP Protocol: %d\n", ip_h.protocol);

      // ICMP header (type, code, checksum, identifier, sequence number, optional data)
      // http://www.tcpipguide.com/free/t_ICMPv4EchoRequestandEchoReplyMessages-2.htm
      // Offset the buffer data by the size of the ethernet and ip headers
      memcpy(&icmp_h, &buf[sizeof(e_h) + sizeof(ip_h)], sizeof(icmp_h));
      if (icmp_h.icmp_type == 0)
      {
        printf("ICMP Reply\n");
        //There is no need to respond to the reply
      }
      else if (icmp_h.icmp_type == 8)
      {
        printf("ICMP Request\n");
        //Respond to the echo request by forwarding its mac address to who requested it.
        //Swap the info in the ethernet header so we arrive at the requester
        //IP protocol will still be type 1
        //Switch the ICMP type from 8 to zero
        //Place the targets mac address in the data header
        //Send it via the socket to the requester that can then decode byte stream/datagram        
      }
      // The ICMP header provides a place for optional data beginning at bit 65 and/or at 8 bytes into the ICMP frame
      memcpy(&data_msg, &buf[sizeof(e_h) + sizeof(ip_h) + 8], sizeof(data_msg));
      printf("Data message: %s\n", data_msg);
    }
     
    // If we have an incoming ARP request/response
    else if(ntohs(e_h.ether_type) == 0x806)
    {

      //[Eth header][ARP header]
      // ARP frame needs source Hardware type, length, protocol type and IP length
      // IP/MAC and target IP/MAC
      printf("ARP Type\n");

      // struct arphdr arp_h;
      struct ether_arp full_arp_h;


      full_arp_h.ea_hdr.arp_hrd = 1; /* Format of hardware address.  unsigned short int*/
      full_arp_h.ea_hdr.arp_hln = 6;          /* Length of hardware address.  unsigned char*/
      full_arp_h.ea_hdr.arp_pro = ntohs(e_h.ether_type);     /* Format of protocol address.  unsigned short int*/
      full_arp_h.ea_hdr.arp_pln = 4;          /* Length of protocol address.  unsigned char*/
      full_arp_h.ea_hdr.arp_op = ; // Can be 1 for ARP request and 2 for ARP reply
      // // e_h.ether_shost;
      // // ip_h.daddr;
      // // e_h.ether_dhost;
      // // ip_h.daddr; 

      // // Struct is used to hold source/destination ip/mac
      // struct mac_ip arp;
      // memcpy(&arp.src_mac,&e_h.ether_shost,sizeof(arp.src_mac));	// Setting the source mac
      // memcpy(&arp.src_ip, &ip_h.daddr,sizeof(arp.src_ip));	// Setting the source ip 
      // memcpy(&arp.dst_mac,&e_h.ether_dhost,sizeof(arp.dst_mac));	// Setting the destination mac
      // memcpy(&arp.dst_ip,&ip_h.daddr,sizeof(arp.dst_ip));	// Setting the destination ip

      // arp_h.__ar_sha[ETH_ALEN] = e_h.ether_dhost; /* Sender hardware address.  unsigned char*/
      // arp_h.__ar_sip[4];        /* Sender IP address.  unsigned char*/
      // arp_h.__ar_tha[ETH_ALEN]; /* Target hardware address.  unsigned char*/
      // arp_h.__ar_tip[4];        /* Target IP address.  unsigned char*/
      
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
