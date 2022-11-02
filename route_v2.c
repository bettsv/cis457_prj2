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
#include <byteswap.h>
#include <netdb.h>
#define _GNU_SOURCE /* To get defns of NI_MAXSERV and NI_MAXHOST */

#define MAC_ANY "00:00:00:00:00:00"
#define MAC_BCAST "FF:FF:FF:FF:FF:FF"

char data_msg[200];
u_int8_t temp_src_ip[4];
u_int8_t temp_dst_ip[4];
u_int8_t  temp_ether_dhost[ETH_ALEN];        /* destination eth addr        */
u_int8_t  temp_ether_shost[ETH_ALEN];        /* source ether addr        */
int i = 1;
int main()
{
  int packet_socket;
  /* get list of interface addresses. This is a linked list. Next pointer is in ifa_next,
  interface name is in ifa_name, address is in ifa_addr. You will have multiple entries
  in the list with the same name, if the same interface has multiple addresses. This is
  common since most interfaces will have a MAC, IPv4, and IPv6 address. You can use the
  names to match up which IPv4 address goes with which MAC address.*/
  struct ifaddrs *ifaddr, *tmp;
  int family, s;
  char host[NI_MAXHOST];
  if (getifaddrs(&ifaddr) == -1)
  {
    perror("getifaddrs");
    return 1;
  }

  struct ifreq ifr;
  struct ifconf ifc;
  char buf[1024];
  int success = 0;

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock == -1)
  { /* handle error*/
  };

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
  { /* handle error */
  }

  struct ifreq *it = ifc.ifc_req;
  const struct ifreq *const end = it + (ifc.ifc_len / sizeof(struct ifreq));

  for (; it != end; ++it)
  {
    strcpy(ifr.ifr_name, it->ifr_name);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
    {
      if (!(ifr.ifr_flags & IFF_LOOPBACK))
      { // don't count loopback
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
        {
          success = 1;
          break;
        }
      }
    }
    else
    { /* handle error */
    }
  }

  unsigned char chMAC[6];

  if (success)
    memcpy(chMAC, ifr.ifr_hwaddr.sa_data, 6);
  // printf("mac[%s]\n",ether_ntoa((struct ether_addr *)&chMAC));
  //  printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
  //  mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);

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

    //IF we have an incoming ICMP echo request/reply
    if (ntohs(e_h.ether_type) == 0x800)
    {
  

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

      struct ether_arp full_arp_h;

      memcpy(&full_arp_h, &buf[sizeof(e_h)], sizeof(full_arp_h)); // Store byte 14 - 41 in the full arp struct

      if (__bswap_16(full_arp_h.ea_hdr.ar_op) == 1)
      {
        printf("Sending the ARP Request\n");
        printf("Ethernet Header\n");
        printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
        printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
        printf("Type: 0x%03x\n",e_h.ether_type);
        
        printf("Full ARP Header\n");
        printf("Hardware Type: \n");
        printf("Protocol Type: \n");
        printf("Hardware Address Length: \n");
        printf("Protocol Address Length: \n");
        printf("Sender Hardware Address: \n");
        printf("Sender Protocol Address: \n");
        printf("Target Hardware Address: ,\n");
        printf("Target Protocol Address: ,\n");


        memcpy(&e_h.ether_dhost, e_h.ether_shost, sizeof(e_h.ether_shost));
        printf("chMAC before: %s\n", ether_ntoa((struct ether_addr *)&chMAC));
        memcpy(&e_h.ether_shost, chMAC, sizeof(e_h.ether_shost));
        printf("chMAC After %s\n", ether_ntoa((struct ether_addr *)&chMAC));
        printf("new destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
        printf("new source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
        printf("IP Protocol: %d\n", __bswap_16(full_arp_h.ea_hdr.ar_op));

        // Only for assigning new values before sending on the socket
        memcpy(&full_arp_h.arp_sha, &e_h.ether_shost, sizeof(full_arp_h.arp_sha)); /* sender hardware address */
        memcpy(&full_arp_h.arp_tha, &e_h.ether_dhost, sizeof(full_arp_h.arp_tha)); /* target hardware address */


        // Update the ethernet header to point to who requested it
        memcpy(&temp_ether_dhost,&e_h.ether_dhost,sizeof(temp_ether_dhost));
        memcpy(&temp_ether_shost,&e_h.ether_shost,sizeof(temp_ether_dhost));
        memcpy(&e_h.ether_shost,&temp_ether_dhost,sizeof(temp_ether_dhost));
        memcpy(&e_h.ether_dhost,&temp_ether_shost,sizeof(temp_ether_dhost));


        /* sender protocol address --  -- use a temp variable to protect the data */
        memcpy(&temp_src_ip, &full_arp_h.arp_spa, sizeof(temp_src_ip)); // use a temp variable to protect the data
        memcpy(&temp_dst_ip, &full_arp_h.arp_tpa, sizeof(temp_dst_ip)); // use a temp variable to protect the data

        memcpy(&full_arp_h.arp_spa, &temp_dst_ip, sizeof(temp_dst_ip)); // Take the ip of the source from the arp header and replace it with the destination ip
        memcpy(&full_arp_h.arp_tpa, &temp_src_ip, sizeof(temp_src_ip)); // Take the ip of the destination from the arp header and replace it with the source ip
        //full_arp_h.ea_hdr.ar_op = 2;
        full_arp_h.ea_hdr.ar_op = __bswap_16(2);
        //memcpy(&full_arp_h.ea_hdr.ar_op,2,sizeof(int));

        printf("\nSending the ARP reply\n");
        printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
        printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
        printf("Type: 0x%03x\n", ntohs(e_h.ether_type));
        printf("Got a %d byte packet\n", n);
        printf("IP Protocol: %d\n", __bswap_16(full_arp_h.ea_hdr.ar_op));
        
        memcpy(&buf, &e_h, sizeof(e_h)); // Store byte 14 - 41 in the full arp struct
        memcpy(&buf[sizeof(e_h)],&full_arp_h,sizeof(full_arp_h));
        int n = sendto(packet_socket, buf, 42, 0, (struct sockaddr *)&recvaddr, sizeof(recvaddr));
        printf("SENT %d\n", i++);
      }
    }
    sleep(2);

    // what else to do is up to you, you can send packets with send, just like we used for TCP sockets (or you can use sendto, but it is not necessary, since the headers, including all addresses, need to be in the buffer you are sending)
  }
  // free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);
  // exit
  return 0;
}
