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

  printf("Enter an IP Address: ");
  char ip[5000];
  scanf("%s", ip);
  printf("Enter a port: ");
  short port;
  scanf("%hd%*c", &port);

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
  recv(sockfd, line, 5000, 0);
  printf("Got from server: %s", line);

  close(sockfd);
  return 0;
}
