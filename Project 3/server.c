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

  fd_set sockets;
  FD_ZERO(&sockets);
  FD_SET(sockfd, &sockets);

  short port;

  if( argc == 2 ) {
    port = atoi(argv[1]);
   }
   else {
    printf("usage: ./client <port>\n");
    return 0;
   }


  struct sockaddr_in serveraddr, clientaddr;
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(port);
  serveraddr.sin_addr.s_addr = INADDR_ANY;

  int n = bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
  listen(sockfd, 10);

  while (1)
  {
    fd_set tmpset = sockets;
    int r = select(FD_SETSIZE, &tmpset, NULL, NULL, NULL);
    if (FD_ISSET(sockfd, &tmpset))
    {

      socklen_t len = sizeof(struct sockaddr_in);
      int clientsocket = accept(sockfd, (struct socckaddr *)&clientaddr, &len);
      FD_SET(clientsocket, &sockets);
    }
    for (int i = 0; i < FD_SETSIZE; i++)
    {
      if (FD_ISSET(i, &tmpset) && i != sockfd)
      {
        char line[5000];
        char test[5000] = "adios";
        recv(i, line, 5000, 0);
        printf("Got from client #%d: %s\n", i, line);


        if (send(i, line, sizeof(line), 0) == -1)
        {
          printf("Error in sending file.");
          return (0);
        }
        FD_CLR(i, &sockets);
        close(i);
      }
    }
  }
}