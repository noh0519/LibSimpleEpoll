#include <arpa/inet.h>
#include <iostream>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define BUFF_SIZE 1024
#define EPOLL_SIZE 1024

int g_step = 0;

int main(int argc, char **argv) {
  // socket variable
  int client_socket = -1;
  struct sockaddr_in server_addr;

  char buff_recv[4096];
  char buff_send[4096];
  // ~socket variable

  // epoll variables
  int epoll_fd = -1;
  struct epoll_event client_event;
  struct epoll_event *events;
  // ~epoll variables

  client_socket = socket(PF_INET, SOCK_STREAM, 0);
  if (client_socket == -1) {
    printf("socket create fail\n");
    exit(1);
  }

  memset(&server_addr, 0x00, sizeof(sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(4000);
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
    printf("socket connect fail\n");
    exit(1);
  }

  /* epoll create */
  if ((epoll_fd = epoll_create1(0)) == -1) {
    printf("epoll create fail\n");
    exit(1);
  }

  /**/
  client_event.events = EPOLLIN | EPOLLOUT;
  client_event.data.fd = client_socket;
  epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &client_event);

  /* alloc event */
  events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EPOLL_SIZE);

  /* first send*/
  memset(buff_send, 0x00, 4096);
  snprintf(buff_send, 4096, "%s", "start step 0");
  send(client_socket, buff_send, 4096, 0);

  while (1) {
    int event_count = epoll_wait(epoll_fd, events, EPOLL_SIZE, -1);

    if (event_count == -1) {
      printf("epoll wait fail\n");
      exit(1);
    }

    for (int i = 0; i < event_count; i++) {
      int who = events[i].data.fd;
      uint32_t what = events[i].events;

      if (who == client_socket) {
        if (what & EPOLLIN) {
          memset(buff_recv, 0x00, 4096);
          recv(who, buff_recv, 4096, 0);
          if (!strcmp("start step 1", buff_recv)) {
            printf("step 1 get\n");
            g_step = 2;
          } else if (!strcmp("start step 3", buff_recv)) {
            printf("step 3 get\n");
            g_step = 4;
          } else if (!strcmp("start step 5", buff_recv)) {
            printf("step 5 get\n");
            g_step = 6;
          }
        } else if (what & EPOLLOUT) {
          memset(buff_send, 0x00, 4096);
          if (g_step == 2) {
            snprintf(buff_send, 4096, "%s", "start step 2");
            send(who, buff_send, 4096, 0);
            g_step = 3;
          } else if (g_step == 4) {
            snprintf(buff_send, 4096, "%s", "start step 4");
            send(who, buff_send, 4096, 0);
            g_step = 5;
          } else if (g_step == 6) {
            printf("login completed\n");
            struct epoll_event event;
            event.events = EPOLLIN;
            event.data.fd = who;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, who, &event);
          }
        }
      }
    }
  }

  return 0;
}