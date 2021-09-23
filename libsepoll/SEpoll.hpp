#include "def_hdr.hpp"
#include <arpa/inet.h>
#include <memory>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

template <typename T1, typename T2, class T3, class T4> //
class SEpoll {
public:
  SEpoll(SEPOLL_TYPE type, uint32_t epoll_size, uint32_t buff_size, uint16_t port) {
    m_epoll_size = epoll_size;
    m_buff_size = buff_size;
    m_port = port;

    buff_rcv = (char *)malloc(sizeof(char) * m_buff_size);
    buff_snd = (char *)malloc(sizeof(char) * m_buff_size);
  }
  ~SEpoll() {}

  SEPOLL_RESULT init() {
    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
      printf("socket 생성 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
      printf("bind 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    if (listen(server_socket, 5) == -1) {
      printf("listen 모드 설정 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll create */
    if ((epoll_fd = epoll_create1(0)) == -1) {
      printf("server epoll 생성 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll ctl add server socket */
    // server_event.events = EPOLLIN | EPOLLRDHUP;
    server_event.events = EPOLLIN;
    server_event.data.fd = server_socket;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &server_event);

    /* alloc events */
    events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * m_epoll_size);
  }

  void run() {}

private:
  T1 recv_obj;
  T2 send_obj;
  T3 recv_func;
  T4 send_func;

  SEPOLL_TYPE m_type = SEPOLL_TYPE::ACCEPT;
  uint32_t m_epoll_size = 1024;
  uint32_t m_buff_size = 2048;
  uint16_t m_port = 4000;

  // socket variables
  int server_socket;
  struct sockaddr_in server_addr;

  char *buff_rcv;
  char *buff_snd;
  // ~socket variables

  // epoll variables
  int epoll_fd = -1;
  struct epoll_event server_event;
  struct epoll_event *events;
  // ~epoll variables

protected:
};

#if 0
template <typename T1, typename T2, class T3, class T4> //
class SEpoll {
public:
  SEpoll(uint32_t epoll_size, uint32_t buff_size, uint16_t port) {
    m_epoll_size = epoll_size;
    m_buff_size = buff_size;
    m_port = port;

    buff_rcv = (char *)malloc(sizeof(char) * m_buff_size);
    buff_snd = (char *)malloc(sizeof(char) * m_buff_size);
  }
  ~SEpoll() {}

  SEPOLL_RESULT init() {
    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
      printf("socket 생성 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
      printf("bind 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    if (listen(server_socket, 5) == -1) {
      printf("listen 모드 설정 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll create */
    if ((epoll_fd = epoll_create1(0)) == -1) {
      printf("server epoll 생성 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll ctl add server socket */
    server_event.events = EPOLLIN | EPOLLRDHUP;
    server_event.data.fd = server_socket;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &server_event);

    /* alloc events */
    events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * m_epoll_size);
  }

  void run() {}

private:
  T1 recv_obj;
  T2 send_obj;
  T3 recv_func;
  T4 send_func;

  uint32_t m_epoll_size = 1024;
  uint32_t m_buff_size = 2048;
  uint16_t m_port = 4000;

  // socket variables
  int server_socket;
  struct sockaddr_in server_addr;

  char *buff_rcv;
  char *buff_snd;
  // ~socket variables

  // epoll variables
  int epoll_fd = -1;
  struct epoll_event server_event;
  struct epoll_event *events;
  // ~epoll variables

protected:
};
#endif