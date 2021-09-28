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

  std::mutex m_mutex;
  std::thread m_thr;
  bool m_run_thr = true;
  std::list<EventType> m_eventtypes;

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

  void pushEvent(uint32_t what) {
    std::lock_guard<std::mutex> g(m_mutex);
    m_eventtypes.push_back(what);
  }

  void setReadFunc(std::function<void(int fd, short what, void *arg)> read_func, void *arg = NULL, uint32_t what = EPOLLIN) {
    m_read_func = read_func;
    m_read_arg = arg;
    m_read_what = what;
    m_read_what |= EPOLLRDHUP | EPOLLHUP | EPOLLERR; // necessary event
  }
  void unsetReadFunc() {
    m_read_func = NULL;
    m_read_arg = NULL;
    m_read_what = 0;
  };
  bool isReadWhat(uint32_t what) { return what & m_read_what ? true : false; }
  void executeReadFunc(short what) {
    if (m_read_func) {
      m_read_func(m_fd, what, m_read_arg);
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
  void executeWriteFunc(short what) {
    if (m_write_func) {
      m_write_func(m_fd, what, m_write_arg);
    }
  }

  uint32_t getWhat() { return m_read_what | m_write_what; }

private:
  void run() {
    while (m_run_thr) {
      while (!m_eventtypes.empty()) {
        uint32_t what = m_eventtypes.front();
        m_eventtypes.pop_front();
        if (isReadWhat(what)) {
          executeReadFunc(what);
        }
        if (isWriteWhat(what)) {
          executeWriteFunc(what);
        }
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
};

template <class FDType, class FDSetFunc, class FDGetFunc> class SEpoll {
public:
private:
  // std::mutext m_fds_mutex;

  typedef std::shared_ptr<FDType> ShrFDType;
  FDSetFunc m_fd_set_func;
  FDGetFunc m_fd_get_func;

  std::shared_ptr<std::vector<ShrFDType>> m_fds = std::make_shared<std::vector<ShrFDType>>();
  std::unordered_map<int, std::shared_ptr<SEpollFDFunc>> m_fds_funcs;

  SEPOLL_TYPE m_type = SEPOLL_TYPE::ACCEPT;

  uint32_t m_epoll_size = 1024;
  uint32_t m_buff_size = 2048;
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

    if (m_type == SEPOLL_TYPE::ACCEPT) {
      return initAccept();
    } else { // SEPOLL_TYPE::CONNECT
      return initConnect();
    }
  }

  void getObjVectorPtr(std::shared_ptr<std::vector<ShrFDType>> &fds) { fds = m_fds; }

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

  void refreshEvent(int fd) {
    struct epoll_event event;
    event.events = m_fds_funcs[fd]->getWhat();
    event.data.fd = fd;
    epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event);
  }

  void run() {
    while (1) {
      int event_count = epoll_wait(m_epoll_fd, m_events, m_epoll_size, -1);

      if (event_count == -1) {
        printf("실패\n");
        continue;
      }

      for (int i = 0; i < event_count; i++) {
        int who = m_events[i].data.fd;
        uint32_t what = m_events[i].events;
        if (m_type == SEPOLL_TYPE::ACCEPT) { // SEPOLL_TYPE::ACCEPT
          runAccept(who, what);
        } else { // SEPOLL_TYPE::CONNECT
        }
      } // ~for (int i = 0; i < event_count; i++)
    }   // ~while (1)
  }

private:
  SEPOLL_RESULT initAccept() {
    m_sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (m_sock_fd == -1) {
      printf("socket 생성 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    int optval = 1;
    setsockopt(m_sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&m_sock_addr, 0, sizeof(m_sock_addr));
    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(m_port);
    m_sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(m_sock_fd, (struct sockaddr *)&m_sock_addr, sizeof(m_sock_addr)) == -1) {
      printf("bind 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    if (listen(m_sock_fd, 5) == -1) {
      printf("listen 모드 설정 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll create */
    if ((m_epoll_fd = epoll_create1(0)) == -1) {
      printf("server epoll 생성 실패\n");
      return SEPOLL_RESULT::FAIL;
    }

    /* epoll ctl add server socket */
    // m_event.events = EPOLLIN | EPOLLRDHUP;
    m_event.events = EPOLLIN;
    m_event.data.fd = m_sock_fd;
    epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_sock_fd, &m_event);

    /* alloc m_events */
    m_events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * m_epoll_size);

    return SEPOLL_RESULT::SUCCESS;
  }

  SEPOLL_RESULT initConnect() { return SEPOLL_RESULT::SUCCESS; }

  void runAccept(int who, uint32_t what) {
    if (who == m_sock_fd) { // Server Socket Event
      if (what & EPOLLIN) {
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_addr_size;

        client_addr_size = sizeof(client_addr);
        client_socket = accept(m_sock_fd, (struct sockaddr *)&client_addr, &client_addr_size);

        /* set fds */
        // FDType set_fdt = m_fd_set_func(client_socket);
        ShrFDType set_shrfdt = std::make_shared<FDType>(m_fd_set_func(client_socket));
        m_fds->push_back(set_shrfdt);

        /* set fds_func */
        if (m_fds_funcs.find(client_socket) == m_fds_funcs.end()) {
          // m_fds_funcs.insert(std::make_pair(client_socket, new SEpollFDFunc(client_socket)));
          m_fds_funcs.insert(std::make_pair(client_socket, std::make_shared<SEpollFDFunc>(client_socket)));
        }
        struct epoll_event client_event;
        client_event.events = 0;
        if (m_init_read_func) {
          client_event.events |= m_init_read_what;
          m_fds_funcs[client_socket]->setReadFunc(m_init_read_func, static_cast<void *>(set_shrfdt.get()), m_init_read_what);
        }
        if (m_init_write_func) {
          client_event.events |= m_init_write_what;
          m_fds_funcs[client_socket]->setWriteFunc(m_init_write_func, static_cast<void *>(set_shrfdt.get()), m_init_write_what);
        }
        client_event.data.fd = client_socket;
        epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, client_socket, &client_event);
      }
    } else { // Client Socket Event
      m_fds_funcs[who]->pushEvent(what);
      if ((what & EPOLLRDHUP) || (what & EPOLLHUP) || (what & EPOLLERR)) { // necessary event : disconnection, error
        // printf("!!!EPOLLRDHUP || EPOLLHUP || EPOLLERR!!!\n");
        removeFD(who);
      }
    }
  }

  void runConnect(int who, uint32_t what) {}

  void removeFD(int fd) {
    close(fd);
    epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    auto remove_if_func = [fgf = m_fd_get_func, fd](std::shared_ptr<FDType> fdt) -> bool {
      if (fgf(*fdt) == fd) {
        return true;
      } else {
        return false;
      }
    };
    m_fds->erase(remove_if(m_fds->begin(), m_fds->end(), remove_if_func), m_fds->end());
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