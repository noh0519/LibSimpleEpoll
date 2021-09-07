/*

test_clnt.cpp

*/

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAXBUF 128

int servsock = -1;
int end = 0;

void *fn_recv(void *p) {
  char buf[MAXBUF];
  int readn;

  while (!end) {
    memset(buf, 0, MAXBUF);
    readn = read(servsock, buf, MAXBUF);
    if (readn <= 0) {
      end = 1;
      printf("disconnected..\n");
      break;
    }
    printf("%s\n", buf);
  }

  return NULL;
}

int main(int argc, char **argv) {
  pthread_t tid;
  struct sockaddr_in servaddr;
  char buf[MAXBUF];
  int readn;

  servsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (servsock == -1) {
    printf("failed to create socket\n");
    return -1;
  }

  // connect
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  servaddr.sin_port = htons(12345);

  if (connect(servsock, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
    printf("failed to connect\n");
    return -1;
  }

  if (pthread_create(&tid, NULL, fn_recv, NULL) != 0) {
    printf("failed to create recv thread\n");
    close(servsock);
    return -1;
  }

  while (1) {
    // write / read
    memset(buf, 0, MAXBUF);
    readn = read(0, buf, MAXBUF);
    if (readn <= 0) {
      printf("read error\n");
      break;
    }
    if (strncmp(buf, "quit", 4) == 0) {
      break;
    }

    buf[readn - 1] = 0;
    if (write(servsock, buf, strlen(buf)) <= 0) {
      printf("write error\n");
      break;
    }
  }

  end = 1;
  pthread_join(tid, NULL);
  close(servsock);

  return 0;
}