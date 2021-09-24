#include "SEpoll.hpp"
#include <stdio.h>
#include <thread>

class MyFDClass {
public:
  MyFDClass() {}
  MyFDClass(int fd) { m_fd = fd; }

  void setFD(int fd) { m_fd = fd; }
  int getFD() { return m_fd; }

  int getStep() { return m_step; }

  // void loginReadCallback(int fd, short what, void *arg) { static_cast<MyFDClass *>(arg)->loginReadFunc(fd, what); }
  void loginReadFunc(int fd, short what) {
    if (what | EPOLLIN) {
      memset(buff_recv, 0x00, 4096);
      // int ref = recv(fd, buff_recv, 4096, 0);
      recv(fd, buff_recv, 4096, 0);
      if (!strcmp("start step 1", buff_recv)) {
        m_step = 1;
      } else if (!strcmp("start step 2", buff_recv)) {
        m_step = 2;
      } else if (!strcmp("start step 3", buff_recv)) {
        m_step = 3;
      }
    }
  }
  // void loginWriteCallback(int fd, short what, void *arg) { static_cast<MyFDClass *>(arg)->loginWriteFunc(fd, what); }
  void loginWriteFunc(int fd, short what) {
    if (what | EPOLLOUT) {
      memset(buff_send, 0x00, 4096);
      if (m_step == 1) {
        snprintf(buff_send, 4096, "%s", "end step 1");
        send(fd, buff_send, 4096, 0);
      } else if (m_step == 2) {
        snprintf(buff_send, 4096, "%s", "end step 2");
        send(fd, buff_send, 4096, 0);
      } else if (m_step == 3) {
        snprintf(buff_send, 4096, "%s", "end step 3");
        send(fd, buff_send, 4096, 0);
      }
    }
  }

private:
  int m_fd = -1;

  int m_step = 0; // 0 : init, 1 ~ 3 : step

  char buff_recv[4096] = {0};
  char buff_send[4096] = {0};
};

typedef std::function<MyFDClass(int)> FDSetFunc;
auto lamFDSetFunc = [](int fd) -> MyFDClass {
  MyFDClass mfc(fd);
  return mfc;
};
typedef std::function<int(MyFDClass)> FDGetFunc;
auto lamFDGetFunc = [](MyFDClass mfc) -> int { return mfc.getFD(); };

std::shared_ptr<std::vector<std::shared_ptr<MyFDClass>>> mfcs;

int main(int argc, char **argv) {
  printf("Start Server\n");

  SEpoll<MyFDClass, FDSetFunc, FDGetFunc> mysepoll(lamFDSetFunc, lamFDGetFunc);
  mysepoll.getObjVectorPtr(mfcs);
  mysepoll.init(SEPOLL_TYPE::ACCEPT, 1024, 4096, 4000, "127.0.0.1");
  mysepoll.setInitReadFunc([](int fd, short what, void *arg) -> void { static_cast<MyFDClass *>(arg)->loginReadFunc(fd, what); },
                           EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
  // mysepoll.setInitWriteFunc(^MyFDClass);

  std::thread tsepoll(&SEpoll<MyFDClass, FDSetFunc, FDGetFunc>::run, &mysepoll);
  tsepoll.detach();

  while (1) {
    // printf("client count %lu\n", mfcs->size());
    for (auto a : *mfcs) {
      if (a->getStep() == 3) {
        printf("find step 3 (%d)\n", a->getFD());
      }
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  printf("End Server\n");

  return 0;
}