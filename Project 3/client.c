#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

char *get_filename_ext(const char *filename)
{
  char *dot = strrchr(filename, '.');
  if (!dot || dot == filename)
    return "";
  return dot;
}

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

  printf("Enter filename: ");
  char line[5000];
  fgets(line, 5000, stdin);
  send(sockfd, line, strlen(line) + 1, 0);

  // create new file
  char *ext = get_filename_ext(line);
  char *output = "output";
  char *fname;
  fname = malloc(strlen(output) + 4 + 1);
  strcpy(fname, output);
  strcat(fname, ext);
  fname[strlen(fname) - 1] = '\0';

  // WRITE FILE
  char buffer[1025];
  FILE *fp = fopen(fname, "wb");

  char errfile[5000] = "File not found.";
  int packet_count = 1;
  while (1)
  {
    recv(sockfd, buffer, 1025, 0);

    if (strcmp(buffer, "file not found") == 0)
    {
      printf("File doesn't exists.");
      break;
    }
    if (buffer[0] == 1)
    {
      break;
    }
    packet_count++;
    fwrite(&buffer[1], 1024, 1, fp);
    bzero(buffer, 1025);
  }
  int count = 0;
  for (int i = 0; i < 1024; i++)
  {
    if (buffer[i] == 0)
    {
      break;
    }
    count++;
  }
  fwrite(&buffer[1], count - 1, 1, fp);

  close(sockfd);
  return 0;
}
