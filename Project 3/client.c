#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  char *ip;
  short port;

  if( argc == 3 ) {
    ip = argv[1];
    port = atoi(argv[2]);
   }
   else {
    printf("usage: ./client  <ip> <port>\n");
    return 0;
   }

  struct sockaddr_in serveraddr;
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(port);
  serveraddr.sin_addr.s_addr = inet_addr(ip);

  int n = connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
  if (n < 0)
  {
    printf("There was a problem connecting\n");
    return 1;
  }

  printf("Enter a message: ");
  char line[5000];
  fgets(line, 5000, stdin);
  send(sockfd, line, strlen(line) + 1, 0);

  close(sockfd);
  return 0;
}
