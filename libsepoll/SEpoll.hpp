#ifndef _SEPOLL_HPP_
#define _SEPOLL_HPP_

#include "def_hdr.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

// using EventType = std::pair<int, uint32_t>;
using EventType = uint32_t;

class SEpollFDFunc {
public:
private:
  int m_fd = -1;

  std::recursive_mutex m_mutex_what;
  std::recursive_mutex m_mutex_read;
  std::recursive_mutex m_mutex_write;
  std::thread m_thr;
  bool m_run_thr = true;
  uint32_t m_what = 0;

  std::function<void(int fd, short what, void *arg)> m_read_func = NULL;
  void *m_read_arg = NULL;
  uint32_t m_read_what = 0;

  std::function<void(int fd, short what, void *arg)> m_write_func = NULL;
  void *m_write_arg = NULL;
  uint32_t m_write_what = 0;

public:
  SEpollFDFunc(int fd) {
    m_fd = fd;
    m_run_thr = true;
    m_thr = std::thread(&SEpollFDFunc::run, this);
  }
  ~SEpollFDFunc() {
    m_run_thr = false;
    if (m_thr.joinable()) {
      m_thr.join();
    }
  }

  void orEvent(uint32_t what) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_what);
    m_what |= what;
  }

  void setEvent(uint32_t what) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_what);
    m_what = what;
  }

  uint32_t getEvent() {
    std::lock_guard<std::recursive_mutex> g(m_mutex_what);
    return m_what;
  }

  void setReadFunc(std::function<void(int fd, short what, void *arg)> read_func, void *arg = NULL, uint32_t what = EPOLLIN) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_read);
    m_read_func = read_func;
    m_read_arg = arg;
    m_read_what = what;
    m_read_what |= EPOLLRDHUP | EPOLLHUP | EPOLLERR; // necessary event
  }
  void unsetReadFunc() {
    std::lock_guard<std::recursive_mutex> g(m_mutex_read);
    m_read_func = NULL;
    m_read_arg = NULL;
    m_read_what = 0;
  };
  bool isReadWhat(uint32_t what) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_read);
    return what & m_read_what ? true : false;
  }
  void executeReadFunc(short what) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_read);
    if (m_read_func) {
      m_read_func(m_fd, what, m_read_arg);
    }
  }

  void setWriteFunc(std::function<void(int fd, short what, void *arg)> write_func, void *arg = NULL, uint32_t what = EPOLLOUT) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_write);
    m_write_func = write_func;
    m_write_arg = arg;
    m_write_what = what;
  }
  void unsetWriteFunc() {
    std::lock_guard<std::recursive_mutex> g(m_mutex_write);
    m_write_func = NULL;
    m_write_arg = NULL;
    m_write_what = 0;
  };
  bool isWriteWhat(uint32_t what) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_write);
    return what & m_write_what ? true : false;
  }
  void executeWriteFunc(short what) {
    std::lock_guard<std::recursive_mutex> g(m_mutex_write);
    if (m_write_func) {
      m_write_func(m_fd, what, m_write_arg);
    }
  }

  uint32_t getWhat() { //
    return m_read_what | m_write_what;
  }

private:
  void run() {
    char pname[128] = {0};
    snprintf(pname, 128, "SEpollFDFunc %d", m_fd);
    pthread_setname_np(pthread_self(), pname);
    while (m_run_thr) {
      uint32_t what = getEvent();
      if (what != 0) {
        if (isReadWhat(what)) {
          executeReadFunc(what);
        }
        if (isWriteWhat(what)) {
          executeWriteFunc(what);
        }
        setEvent(0);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
};

template <class FDType> class SEpoll {
public:
private:
  // std::recursive_mutext m_fds_mutex;

  std::function<void(FDType &, int)> m_fd_set_func;
  std::function<int(FDType)> m_fd_get_func;

  std::shared_ptr<std::vector<std::shared_ptr<FDType>>> m_fds;
  std::unordered_map<int, std::shared_ptr<SEpollFDFunc>> m_fds_funcs;

  SEPOLL_TYPE m_type = SEPOLL_TYPE::ACCEPT;

  uint32_t m_epoll_size = 1024;
  uint16_t m_port = 4000;
  std::string m_ip = "";

  uint32_t m_init_read_what = 0;
  std::function<void(int, short, void *arg)> m_init_read_func = NULL;

  uint32_t m_init_write_what = 0;
  std::function<void(int, short, void *arg)> m_init_write_func = NULL;

  // socket variables
  int m_sock_fd = -1;
  struct sockaddr_in m_sock_addr;
  // ~socket variables

  // epoll variables
  int m_epoll_fd = -1;
  struct epoll_event m_event;
  struct epoll_event *m_events;
  // ~epoll variables

protected:
public:
  SEpoll(std::function<void(FDType &, int)> fd_set_func, std::function<int(FDType)> fd_get_func,
         std::shared_ptr<std::vector<std::shared_ptr<FDType>>> fds, SEPOLL_TYPE type, std::string ip, uint16_t port) {
    m_fd_set_func = fd_set_func;
    m_fd_get_func = fd_get_func;
    m_fds = fds;

    m_epoll_size = fds->size() + 1;

    m_type = type;
    m_port = port;
    m_ip = ip;

    SEPOLL_RESULT ret = SEPOLL_RESULT::SUCCESS;
    if (m_type == SEPOLL_TYPE::ACCEPT) {
      ret = initAccept();
    } else { // SEPOLL_TYPE::CONNECT
      ret = initConnect();
    }

    if (ret == SEPOLL_RESULT::FAIL) {
      printf("SEpoll Init Failed\n");
    }
  }

  void setInitReadFunc(std::function<void(int, short, void *)> func, uint32_t what = EPOLLIN) {
    m_init_read_func = func;
    m_init_read_what = what;
  }
  void setReadFunc(int fd, std::function<void(int, short, void *)> func, void *arg = NULL, uint32_t what = EPOLLIN) {
    m_fds_funcs[fd]->setReadFunc(func, arg, what);
    refreshEvent(fd);
  }
  void unsetReadFunc(int fd) {
    m_fds_funcs[fd]->unsetReadFunc();
    refreshEvent(fd);
  }

  void setInitWriteFunc(std::function<void(int, short, void *)> func, uint32_t what = EPOLLOUT) {
    m_init_write_func = func;
    m_init_write_what = what;
  }
  void setWriteFunc(int fd, std::function<void(int, short, void *)> func, void *arg = NULL, uint32_t what = EPOLLOUT) {
    m_fds_funcs[fd]->setWriteFunc(func, arg, what);
    refreshEvent(fd);
  }
  void unsetWriteFunc(int fd) {
    m_fds_funcs[fd]->unsetWriteFunc();
    refreshEvent(fd);
  }

  void removeEvent(int fd) { //
    epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
  }

  void refreshEvent(int fd) {
    struct epoll_event event;
    event.events = m_fds_funcs[fd]->getWhat();
    event.data.fd = fd;
    epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event);
  }

  void run() {
    pthread_setname_np(pthread_self(), "SEpoll");
    while (1) {
      if (m_type == SEPOLL_TYPE::ACCEPT) { // SEPOLL_TYPE::ACCEPT
        runAccept();
      } else { // SEPOLL_TYPE::CONNECT
        runConnect();
      }
    } // ~while (1)
  }

private:
  SEPOLL_RESULT initAccept() {
    m_sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (m_sock_fd == -1) {
      printf("socket create fail\n");
      return SEPOLL_RESULT::FAIL;
    }

    int optval = 1;
    setsockopt(m_sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&m_sock_addr, 0, sizeof(m_sock_addr));
    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(m_port);
    m_sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(m_sock_fd, (struct sockaddr *)&m_sock_addr, sizeof(m_sock_addr)) == -1) {
      printf("bind fail\n");
      return SEPOLL_RESULT::FAIL;
    }

    if (listen(m_sock_fd, 5) == -1) {
      printf("listen fail\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll create */
    if ((m_epoll_fd = epoll_create1(0)) == -1) {
      printf("server epoll create fail\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll ctl add socket */
    m_event.events = EPOLLIN;
    m_event.data.fd = m_sock_fd;
    epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_sock_fd, &m_event);

    /* alloc m_events */
    m_events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * m_epoll_size);

    return SEPOLL_RESULT::SUCCESS;
  }

  SEPOLL_RESULT initConnect() {
    /* epoll create */
    if ((m_epoll_fd = epoll_create1(0)) == -1) {
      printf("epoll create fail\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* alloc event */
    m_events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * m_epoll_size);

    return SEPOLL_RESULT::SUCCESS;
  }

  void runAccept() {
    int event_count = epoll_wait(m_epoll_fd, m_events, m_epoll_size, -1);

    if (event_count == -1) {
      printf("epoll wait fail\n");
    }

    for (int i = 0; i < event_count; i++) {
      int who = m_events[i].data.fd;
      uint32_t what = m_events[i].events;

      if (who == m_sock_fd) { // m_sock_fd event
        if (what & EPOLLIN) {
          int connect_socket;
          struct sockaddr_in connect_addr;
          socklen_t connect_addr_size;

          connect_addr_size = sizeof(connect_addr);
          connect_socket = accept(m_sock_fd, (struct sockaddr *)&connect_addr, &connect_addr_size);

          /* set fds */
          auto find_shrfdt = std::find_if(m_fds->begin(), m_fds->end(),
                                          [fgf = m_fd_get_func](std::shared_ptr<FDType> fdt) -> bool { return fgf(*fdt) == -1; });
          if (find_shrfdt == m_fds->end()) {
            close(connect_socket);
            continue;
          } else {
            // set fd
            m_fd_set_func(**find_shrfdt, connect_socket);
          }

          /* set fds_func */
          if (m_fds_funcs.find(connect_socket) == m_fds_funcs.end()) {
            m_fds_funcs.insert(std::make_pair(connect_socket, std::make_shared<SEpollFDFunc>(connect_socket)));
          }
          struct epoll_event client_event;
          client_event.events = 0;
          if (m_init_read_func) {
            client_event.events |= m_init_read_what;
            m_fds_funcs[connect_socket]->setReadFunc(m_init_read_func, static_cast<void *>(find_shrfdt->get()), m_init_read_what);
          }
          if (m_init_write_func) {
            client_event.events |= m_init_write_what;
            m_fds_funcs[connect_socket]->setWriteFunc(m_init_write_func, static_cast<void *>(find_shrfdt->get()), m_init_write_what);
          }
          client_event.data.fd = connect_socket;
          epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, connect_socket, &client_event);
        }
      } else { // connected sock event
        m_fds_funcs[who]->orEvent(what);
        if ((what & EPOLLRDHUP) || (what & EPOLLHUP) || (what & EPOLLERR)) { // necessary event : disconnection, error
          // printf("!!!EPOLLRDHUP || EPOLLHUP || EPOLLERR!!!\n");
          removeFD(who);
        }
      }
    }
  }

  void runConnect() {
    // fds sock connect thread
    // epoll wait & process
#if 0
    /* connect */
    if (m_sock_addr == -1) {
      if (connect(m_sock_fd, (struct sockaddr *)&m_sock_addr, sizeof(m_sock_addr)) == -1) {
        printf("socket connect fail\n");
        return;
      } else {
        /* epoll ctl add socket */
        m_event.events = EPOLLIN;
        m_event.data.fd = m_sock_fd;
        epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_sock_fd, &m_event);
      }
    }

    int event_count = epoll_wait(m_epoll_fd, m_events, m_epoll_size, -1);

    if (event_count == -1) {
      printf("실패\n");
    }

    for (int i = 0; i < event_count; i++) {
      int who = m_events[i].data.fd;
      uint32_t what = m_events[i].events;
    }
#endif
  }

  void removeFD(int fd) {
    close(fd);
    epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    auto find_shrfdt = std::find_if(m_fds->begin(), m_fds->end(),
                                    [fgf = m_fd_get_func, fd](std::shared_ptr<FDType> fdt) -> bool { return fgf(*fdt) == fd; });
    if (find_shrfdt != m_fds->end()) {
      m_fd_set_func(**find_shrfdt, -1);
    }
    m_fds_funcs.erase(fd);
  }

  FDType getFDTypeByFD(int fd) {
    for (auto a : m_fds) {
      if (m_fd_get_func(*a) == fd) {
        return *a;
      }
    }
    return NULL;
  };
};

#endif /* _SEPOLL_HPP_ */