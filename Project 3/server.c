#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  fd_set sockets;
  FD_ZERO(&sockets);
  FD_SET(sockfd, &sockets);

  printf("Enter a port: ");
  short port;
  scanf("%hd%*c", &port);

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
        int n = recv(i, line, 5000, 0);
        printf("Got from client: %s", line);
        line[strlen(line) - 1] = '\0';

        // READ FILE
        char *fname = line;
        FILE *fp = fopen(fname, "rb");
        if (fp == NULL)
        {
          printf("Error in reading file.");
          return (0);
        }

        // SEND FILE
        char data[1025] = {0};
        while (1)
        {
          data[0] = 0;
          n = fread(&data[1], 1024, 1, fp);
          if (n == 0)
          {
            break;
          }

          if (send(i, data, sizeof(data), 0) == -1)
          {
            printf("Error in sending file.");
            return (0);
          }
          bzero(data, 1025);
        }
        data[0] = 1;
        if (send(i, data, sizeof(data), 0) == -1)
        {
          printf("Error in sending file.");
          return (0);
        }
        printf("File Transfer done.\n");
        FD_CLR(i, &sockets);
        close(i);
      }
    }
  }
}