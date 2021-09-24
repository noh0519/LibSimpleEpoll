#include "def_hdr.hpp"
#include <arpa/inet.h>
#include <functional>
#include <memory>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unordered_map>
#include <vector>

class SEpollFDFunc {
public:
  SEpollFDFunc() {}
  ~SEpollFDFunc() {}

  void setReadFunc(std::function<void(int fd, short what, void *arg)> read_func, void *arg = NULL,
                   uint32_t what = EPOLLIN | EPOLLRDHUP | EPOLLERR) {
    m_read_func = read_func;
    m_read_arg = arg;
    m_read_what = what;
  }
  void unsetReadFunc() {
    m_read_func = NULL;
    m_read_arg = NULL;
    m_read_what = 0;
  };
  bool isReadWhat(uint32_t what) { return what & m_read_what ? true : false; }
  void executeReadFunc(int fd, short what) {
    if (m_read_func) {
      m_read_func(fd, what, m_read_arg);
    }
  }

  void setWriteFunc(std::function<void(int fd, short what, void *arg)> write_func, void *arg = NULL, uint32_t what = EPOLLOUT) {
    m_write_func = write_func;
    m_write_arg = arg;
    m_write_what = what;
  }
  void unsetWriteFunc() {
    m_write_func = NULL;
    m_write_arg = NULL;
    m_write_what = 0;
  };
  bool isWriteWhat(uint32_t what) { return what & m_write_what ? true : false; }
  void executeWriteFunc(int fd, short what) {
    if (m_write_func) {
      m_write_func(fd, what, m_write_arg);
    }
  }

  uint32_t getWhat() { return m_read_what | m_write_what; }

private:
  std::function<void(int fd, short what, void *arg)> m_read_func = NULL;
  void *m_read_arg = NULL;
  uint32_t m_read_what = 0;

  std::function<void(int fd, short what, void *arg)> m_write_func = NULL;
  void *m_write_arg = NULL;
  uint32_t m_write_what = 0;
};

template <class FDType, class FDSetFunc, class FDGetFunc> class SEpoll {
public:
private:
  // std::mutext m_fds_mutex;

  FDSetFunc m_fd_set_func;
  FDGetFunc m_fd_get_func;

  std::shared_ptr<std::vector<FDType>> m_fds = std::make_shared<std::vector<FDType>>();
  std::unordered_map<int, SEpollFDFunc> m_fds_funcs;

  SEPOLL_TYPE m_type = SEPOLL_TYPE::ACCEPT;

  uint32_t m_epoll_size = 1024;
  uint32_t m_buff_size = 2048;
  uint16_t m_port = 4000;
  std::string m_ip = "";

  uint32_t m_init_read_what = 0;
  std::function<void(int, short, void *arg)> m_init_read_func = NULL;
  void *m_init_read_arg = NULL;

  uint32_t m_init_write_what = 0;
  std::function<void(int, short, void *arg)> m_init_write_func = NULL;
  void *m_init_write_arg = NULL;

  // socket variables
  int server_socket = -1;
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
public:
  SEpoll(FDSetFunc fd_set_func, FDGetFunc fd_get_func) {
    m_fd_set_func = fd_set_func;
    m_fd_get_func = fd_get_func;
  }
  ~SEpoll() {}

  SEPOLL_RESULT init(SEPOLL_TYPE type, uint32_t epoll_size, uint32_t buff_size, uint16_t port, std::string ip) {
    m_type = type;

    m_epoll_size = epoll_size;
    m_buff_size = buff_size;
    m_port = port;
    m_ip = ip;

    buff_rcv = (char *)malloc(sizeof(char) * m_buff_size);
    buff_snd = (char *)malloc(sizeof(char) * m_buff_size);

    if (m_type == SEPOLL_TYPE::ACCEPT) {
      return initAccept();
    } else { // SEPOLL_TYPE::CONNECT
      return initConnect();
    }
  }

  std::shared_ptr<std::vector<FDType>> getObjVectorPtr() { return m_fds; }

  void setInitReadFunc(std::function<void(int, short, void *)> func, void *arg = NULL, uint32_t what = EPOLLIN | EPOLLRDHUP | EPOLLERR) {
    m_init_read_func = func;
    m_init_read_arg = arg;
    m_init_read_what = what;
  }
  void setReadFunc(int fd, std::function<void(int, short, void *)> func, void *arg = NULL,
                   uint32_t what = EPOLLIN | EPOLLRDHUP | EPOLLERR) {
    m_fds_funcs[fd].setReadFunc(func, arg, what);
    refreshEvent(fd);
  }
  void unsetReadFunc(int fd) {
    m_fds_funcs[fd].unsetReadFunc();
    refreshEvent(fd);
  }

  void setInitWriteFunc(std::function<void(int, short, void *)> func, void *arg = NULL, uint32_t what = EPOLLOUT) {
    m_init_write_func = func;
    m_init_write_arg = arg;
    m_init_write_what = what;
  }
  void setWriteFunc(int fd, std::function<void(int, short, void *)> func, void *arg = NULL, uint32_t what = EPOLLOUT) {
    m_fds_funcs[fd].setWriteFunc(func, arg, what);
    refreshEvent(fd);
  }
  void unsetWriteFunc(int fd) {
    m_fds_funcs[fd].unsetWriteFunc();
    refreshEvent(fd);
  }

  void refreshEvent(int fd) {
    struct epoll_event event;
    event.events = m_fds_funcs[fd].getWhat();
    event.data.fd = fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
  }

  void run() {
    while (1) {
      int event_count = epoll_wait(epoll_fd, events, m_epoll_size, -1);

      if (event_count == -1) {
        printf("실패\n");
        continue;
      }

      for (int i = 0; i < event_count; i++) {
        int who = events[i].data.fd;
        uint32_t what = events[i].events;
        if (m_type == SEPOLL_TYPE::ACCEPT) { // SEPOLL_TYPE::ACCEPT
          runAccept(who, what);
        } else { // SEPOLL_TYPE::CONNECT
        }
      } // ~for (int i = 0; i < event_count; i++)
    }   // ~while (1)
  }

private:
  SEPOLL_RESULT initAccept() {
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

    return SEPOLL_RESULT::SUCCESS;
  }

  SEPOLL_RESULT initConnect() { return SEPOLL_RESULT::SUCCESS; }

  void runAccept(int who, uint32_t what) {
    if (who == server_socket) { // Server Socket Event
      if (what & EPOLLIN) {
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_addr_size;

        client_addr_size = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);

        /* set fds */
        m_fds->push_back(m_fd_set_func(client_socket));

        struct epoll_event client_event;
        client_event.events = 0;
        if (m_init_read_func) {
          client_event.events |= m_init_read_what;
          m_fds_funcs[client_socket].setReadFunc(m_init_read_func, m_init_read_arg, m_init_read_what);
        }
        if (m_init_write_func) {
          client_event.events |= m_init_write_what;
          m_fds_funcs[client_socket].setWriteFunc(m_init_write_func, m_init_write_arg, m_init_write_what);
        }
        client_event.data.fd = client_socket;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &client_event);
      }
    } else { // Client Socket Event
      if (m_fds_funcs[who].isReadWhat(what)) {
        m_fds_funcs[who].executeReadFunc(who, what);
      } else if (m_fds_funcs[who].isWriteWhat(what)) {
        m_fds_funcs[who].executeWriteFunc(who, what);
      }
    }
  }

  void runConnect(int who, uint32_t what) {}

  FDType getFDTypeByFD(int fd) {
    for (auto a : m_fds) {
      if (m_fd_get_func(a) == fd) {
        return a;
      }
    }
    return NULL;
  };
};