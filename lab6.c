#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

int main(int argc, char **argv)
{
  int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  struct sockaddr_ll addr;
  struct sockaddr_ll listenaddr;
  listenaddr.sll_family = AF_PACKET;
  listenaddr.sll_protocol = htons(ETH_P_ALL);
  listenaddr.sll_ifindex = if_nametoindex("hi eth0");
  bind(sockfd, (struct sockaddr *)&listenaddr, sizeof(listenaddr));
  while (1)
  {
    int len = sizeof(addr);
    char buf[5000];
    int n = recvfrom(sockfd, buf, 5000, 0, (struct sockaddr *)&addr, &len);
    if (addr.sll_pkttype != PACKET_OUTGOING)
    {
      printf("Got a packet\n");
      struct ether_header eh;
      memcpy(& eh, buf, 14);
      printf("Destination: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_dhost));
      printf("Source: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_shost));
      printf("Type: 0x%03x\n", ntohs(eh.ether_type));
      
      char n[] = "address";
      if (ntohs(eh.ether_type) == 0x800)
      {

      	struct iphdr ih;
      	memcpy(&ih, buf, 20);
      	printf("IP destination: %s\n", ether_ntoa((struct ether_addr *)&ih.daddr));
      	printf("IP source: %s\n", ether_ntoa((struct ether_addr *)&ih.saddr));
      }
      printf("-------------------\n");
    }
  }
}
