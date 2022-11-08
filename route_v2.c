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

// For Ethernet Header
u_int8_t temp_ether_dhost[ETH_ALEN]; /* destination eth addr        */
u_int8_t temp_ether_shost[ETH_ALEN]; /* source ether addr        */

// For IP Header
u_int8_t temp_ip_dhost[4]; /* destination eth addr        */
u_int8_t temp_ip_shost[4]; /* source ether addr        */
u_int8_t temp_src_ip[4];
u_int8_t temp_dst_ip[4];

int i = 1;
int j = 1;
int main()
{
  /** Beginning of cited code **/
  /*
  Credit goes to: https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
  */

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
  /** End of cited code **/

  uint8_t chMAC[6];

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
    struct icmphdr icmp_h;
    // printf("The size of eh is [%lu] bytes.\n",sizeof(eh));
    //  Copy the first 14 bytes from the buf and give it to the ethernet header
    memcpy(&e_h, buf, sizeof(e_h));

    printf("Type: 0x%03x\n", ntohs(e_h.ether_type));

    /** IF we have an incoming ICMP echo request/reply **/
    if (ntohs(e_h.ether_type) == 0x800)
    {
      //sleep(2);
      printf("********************Received ICMP Request********************\n");
      /*[Eth header][IP header][ICMP header]*/
      printf("Ethernet Header\n");
      printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
      printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
      printf("Type: 0x%03x\n", ntohs(e_h.ether_type));

      // Parse the the buffer after the Ethernet Header and place the data into the ip_h structure
      printf("------------IP Header------------\n");
      memcpy(&ip_h, &buf[14], sizeof(ip_h));
      printf("Type of service: %d\n", ip_h.tos);
      printf("Total Length: %d\n", ip_h.tot_len);
      printf("Identification: %d\n", ip_h.id);
      //printf("Fragment Offset: %d\n", ip_h.frag_off);
      printf("Time To Live: %d\n", ip_h.ttl);
      printf("Protocol: %d\n", ip_h.protocol);         // Potentially needs to be converted to little endian
      printf("Header Checksum: %d\n", ip_h.check);     // Will possible change
      
      printf("Source Address: %s\n", inet_ntoa(*(struct in_addr *)&ip_h.saddr));      // Will possible change
      printf("Destination Address: %s\n", inet_ntoa(*(struct in_addr *)&ip_h.daddr)); // Will possible change

      printf("------------ICMP Header------------\n");
      printf("Type of service: %d\n", icmp_h.type); /* message type */
      printf("Code: %d\n", icmp_h.code);            /* type sub-code */
      printf("Check sum: %d\n", icmp_h.checksum);
      printf("Id: %d\n", icmp_h.un.echo.id);
      printf("Sequence: %d\n", icmp_h.un.echo.sequence);

      // IP header -> If the ip_h.protocol == 1 this means we have an ICMP request/reply
      if (ip_h.protocol == 1)
      {
        
        // Offset the buffer data by the size of the ethernet and ip headers
        memcpy(&icmp_h, &buf[sizeof(e_h) + sizeof(ip_h)], sizeof(icmp_h));

        /** IF we have an incoming ICMP echo request/reply **/
        if (icmp_h.type == 0)
        {
          printf("ICMP Reply\n");
          // There is no need to respond. For part 1 a router will not receive a ICMP reply
        }
        else if (icmp_h.type == 8)
        {
          printf("ICMP Request\n");
          /**** Update the new Ethernet Header ****/

          // use a temp variable to protect the data
          memcpy(&temp_ether_dhost, &e_h.ether_dhost, sizeof(temp_ether_dhost));
          memcpy(&temp_ether_shost, &e_h.ether_shost, sizeof(temp_ether_dhost));
          


          // Grabs the hosts mac address from chMAC and stores it into e_h.ether_shost for the Ethernet Header
          memcpy(&e_h.ether_shost, &chMAC, sizeof(e_h.ether_shost)); // Replaces all zeros with the mac

          // Updating the ethernet header
          // memcpy(&e_h.ether_shost,&temp_ether_dhost,sizeof(temp_ether_dhost));
          memcpy(&e_h.ether_dhost, &temp_ether_shost, sizeof(temp_ether_dhost));
          // Type does not net to be changed, must be 0x806 for ARP

          // Type does not net to be changed, must be 0x800 for ICMP

          /**** Update new IP Header  ****/
          // ip addresses
          //  use a temp variable to protect the data
          memcpy(&temp_src_ip, &ip_h.saddr, sizeof(temp_src_ip)); // use a temp variable to protect the data
          memcpy(&temp_dst_ip, &ip_h.daddr, sizeof(temp_dst_ip)); // use a temp variable to protect the data
          
          
          // IP for source and destination swapped
          memcpy(&ip_h.saddr, &temp_dst_ip, sizeof(temp_dst_ip)); // Take the ip of the source from the arp header and replace it with the destination ip
          memcpy(&ip_h.daddr, &temp_src_ip, sizeof(temp_src_ip)); // Take the ip of the destination from the arp header and replace it with the source ip

        
          // Protocol of 1 means we are working with ICMP
          ip_h.protocol = 1;

          // Header checksum
          //sleep(2);
          printf("********************Sent ICMP Reply********************\n");
          icmp_h.type = 0;
          printf("------------Ethernet Header------------\n");
          printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
          printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
          printf("Type: 0x%03x\n", ntohs(e_h.ether_type));

          printf("------------IP Header------------\n");
          printf("Type of service: %d\n", ip_h.tos);
          printf("Total Length: %d\n", ntohs(ip_h.tot_len));
          printf("Identification: %d\n", ip_h.id);
          printf("Fragment Offset: %d\n", ip_h.frag_off);
          printf("Time To Live: %d\n", ip_h.ttl);
          printf("Protocol: %d\n", ip_h.protocol);         // Potentially needs to be converted to little endian
          printf("Header Checksum: %d\n", ip_h.check);     // Will possible change
          printf("Source Address: %s\n", inet_ntoa(*(struct in_addr *)&ip_h.saddr));      // Will possible change
          printf("Destination Address: %s\n", inet_ntoa(*(struct in_addr *)&ip_h.daddr)); // Will possible change

          printf("------------ICMP Header------------\n");
          printf("Type of service: %d\n", icmp_h.type); /* message type */
          printf("Code: %d\n", icmp_h.code);            /* type sub-code */
          printf("Check sum: %d\n", icmp_h.checksum);
          printf("Id: %d\n", icmp_h.un.echo.id);
          printf("Sequence: %d\n", icmp_h.un.echo.sequence);

          char data[1500];
          // Grab the 1500 bytes that are after the ICMP header and store it in data
          //memcpy(&data, &buf[sizeof(e_h) + sizeof(ip_h)+ sizeof(icmp_h)], sizeof(data));
          // Setting the new Ethernet header and ARP header
          memcpy(&buf, &e_h, sizeof(e_h)); // Store byte 14 - 41 in the full arp struct
          memcpy(&buf[sizeof(e_h)], &ip_h, sizeof(ip_h));
          memcpy(&buf[sizeof(e_h) + sizeof(ip_h)], &icmp_h, sizeof(icmp_h));

          //memcpy(&buf[sizeof(e_h) + sizeof(ip_h)+ sizeof(icmp_h)], &data, sizeof(data));

          // Send the num data on via the socket
          int n = sendto(packet_socket, buf, sizeof(e_h) + sizeof(ip_h) + sizeof(icmp_h), 0, (struct sockaddr *)&recvaddr, sizeof(recvaddr));
          printf("SENT ICMP %d\n", i++);
        }
      }
    }

    /** If we have an incoming ARP request/response **/
    else if (ntohs(e_h.ether_type) == 0x806)
    {

      //[Eth header][ARP header]
      // ARP frame needs source Hardware type, length, protocol type and IP length
      // IP/MAC and target IP/MAC
      printf("ARP Type\n");

      struct ether_arp full_arp_h;
      // Parse the the buffer after the Ethernet Header and place the data into the full_arp_h structure
      memcpy(&full_arp_h, &buf[sizeof(e_h)], sizeof(full_arp_h)); // Store byte 14 - 41 in the full arp struct

      //if (ntoh(full_arp_h.ea_hdr.ar_op) == 1)
      if (ntohs(full_arp_h.ea_hdr.ar_op) == 1)
      {
        //sleep(2);
        printf("********************Received the ARP Request********************\n");
        printf("------------Ethernet Header------------\n");
        printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
        printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
        printf("Type: 0x%03x\n", ntohs(e_h.ether_type));

        
        printf("------------Full ARP Header------------\n");
        printf("Hardware Type: %d\n", full_arp_h.ea_hdr.ar_hrd);                                       // unsigned short
        printf("Protocol Type: %d\n", ntohs(full_arp_h.ea_hdr.ar_pro));                           // unsigned short
        printf("Hardware Address Length: %d\n", full_arp_h.ea_hdr.ar_hln);                             // unsigned char
        printf("Protocol Address Length: %d\n", full_arp_h.ea_hdr.ar_pln);                             // unsigned char
        printf("Sender Hardware Address: %s\n", ether_ntoa((struct ether_addr *)&full_arp_h.arp_sha)); // u_int8_t
        printf("Sender Protocol Address: %s\n",inet_ntoa(*(struct in_addr *)&full_arp_h.arp_spa)); // u_int8_t
        printf("Target Hardware Address: %s\n", ether_ntoa((struct ether_addr *)&full_arp_h.arp_tha)); // u_int8_t
        printf("Target Protocol Address: %s\n", inet_ntoa(*(struct in_addr *)&full_arp_h.arp_tpa)); // u_int8_t
        memcpy(&full_arp_h.arp_sha, &e_h.ether_shost, sizeof(full_arp_h.arp_sha)); /* sender hardware address */
        memcpy(&full_arp_h.arp_tha, &e_h.ether_dhost, sizeof(full_arp_h.arp_tha)); /* target hardware address */

        /**** Update the new Ethernet Header ****/

        // use a temp variable to protect the data
        memcpy(&temp_ether_dhost, &e_h.ether_dhost, sizeof(temp_ether_dhost));
        memcpy(&temp_ether_shost, &e_h.ether_shost, sizeof(temp_ether_dhost));

        // Grabs the hosts mac address from chMAC and stores it into e_h.ether_shost for the Ethernet Header
        memcpy(&e_h.ether_shost, &chMAC, sizeof(e_h.ether_shost)); // Replaces all zeros with the mac

        // Updating the ethernet header
        // memcpy(&e_h.ether_shost,&temp_ether_dhost,sizeof(temp_ether_dhost));
        memcpy(&e_h.ether_dhost, &temp_ether_shost, sizeof(temp_ether_dhost));
        // Type does not net to be changed, must be 0x806 for ARP

        /**** Update new full_arp_h ip addresses ****/
        // use a temp variable to protect the data
        memcpy(&temp_src_ip, &full_arp_h.arp_spa, sizeof(temp_src_ip)); // use a temp variable to protect the data
        memcpy(&temp_dst_ip, &full_arp_h.arp_tpa, sizeof(temp_dst_ip)); // use a temp variable to protect the data

        // IP for source and destination swapped
        memcpy(&full_arp_h.arp_spa, &temp_dst_ip, sizeof(temp_dst_ip)); // Take the ip of the source from the arp header and replace it with the destination ip
        memcpy(&full_arp_h.arp_tpa, &temp_src_ip, sizeof(temp_src_ip)); // Take the ip of the destination from the arp header and replace it with the source ip

        /* fix me Update new IP within full_arp_h mac addresses */

        // Grabs the hosts mac address from chMAC and stores it into e_h.ether_shost for the IP Header
        // memcpy(&temp_ip_dhost, &chMAC, sizeof(temp_ip_dhost));

        // // use a temp variable to protect the data
        // memcpy(&temp_ip_shost,&full_arp_h.arp_sha,sizeof(temp_ip_dhost));        /* source ether addr        */
        // memcpy(&temp_ip_dhost,&full_arp_h.arp_tha, sizeof(temp_ip_dhost));        /* destination eth addr        */

        // // MAC for source and destination swapped
        // memcpy(&full_arp_h.arp_tha,&temp_ether_shost,sizeof(temp_ip_shost));        /* source ether addr        */
        // //memcpy(&full_arp_h.arp_sha,&temp_ip_dhost,sizeof(temp_ip_dhost));        /* destination eth addr        */
        // memcpy(&full_arp_h.arp_sha, &chMAC, sizeof(full_arp_h.arp_sha)); //Replaces all zeros with the mac

        // The opcode was updated to be 2 in big endian format
        full_arp_h.ea_hdr.ar_op = ntohs(2);

        memcpy(&full_arp_h.arp_sha, &chMAC, sizeof(chMAC));
        memcpy(&full_arp_h.arp_tha, &temp_ether_shost, sizeof(chMAC));

        //sleep(2);
        // Hardware type for source and dest plus protocol for source and dest do not need to be changed.
        printf("\n********************Sending the ARP reply********************\n");
        printf("------------Ethernet Header------------\n");
        printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_dhost));
        printf("Source: %s\n", ether_ntoa((struct ether_addr *)&e_h.ether_shost));
        printf("Type: 0x%03x\n", ntohs(e_h.ether_type));

        printf("------------Full ARP Header------------\n");
        printf("Hardware Type: %d\n", full_arp_h.ea_hdr.ar_hrd);                                       // unsigned short
        printf("Protocol Type: %d\n", full_arp_h.ea_hdr.ar_pro);                                       // unsigned short
        printf("Hardware Address Length: %c\n", full_arp_h.ea_hdr.ar_hln);                             // unsigned char
        printf("Protocol Address Length: %c\n", full_arp_h.ea_hdr.ar_pln);                             // unsigned char
        printf("Sender Hardware Address: %s\n", ether_ntoa((struct ether_addr *)&full_arp_h.arp_sha)); // u_int8_t
        printf("Sender Protocol Address: %s\n",inet_ntoa(*(struct in_addr *)&full_arp_h.arp_spa)); // u_int8_t
        printf("Target Hardware Address: %s\n", ether_ntoa((struct ether_addr *)&full_arp_h.arp_tha)); // u_int8_t
        printf("Target Protocol Address: %s\n", inet_ntoa(*(struct in_addr *)&full_arp_h.arp_tpa)); // u_int8_t


        printf("Got a %d byte packet\n", n);
        printf("IP Protocol: %d\n", ntohs(full_arp_h.ea_hdr.ar_op));

        // Setting the new Ethernet header and ARP header
        memcpy(&buf, &e_h, sizeof(e_h)); // Store byte 14 - 41 in the full arp struct
        memcpy(&buf[sizeof(e_h)], &full_arp_h, sizeof(full_arp_h));

        // Send the num data on via the socket
        int n = sendto(packet_socket, buf, sizeof(e_h) + sizeof(full_arp_h), 0, (struct sockaddr *)&recvaddr, sizeof(recvaddr));
        printf("SENT ARP %d\n", j++);
      }
    }

    // what else to do is up to you, you can send packets with send, just like we used for TCP sockets (or you can use sendto, but it is not necessary, since the headers, including all addresses, need to be in the buffer you are sending)
  }
  // free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);
  // exit
  return 0;
}
