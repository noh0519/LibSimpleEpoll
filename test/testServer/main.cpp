#include "SEpoll.hpp"
#include <stdio.h>
#include <thread>

class MyFDClass {
public:
  MyFDClass() {}
  MyFDClass(int fd) { m_fd = fd; }

  void setFD(int fd) { m_fd = fd; }
  int getFD() { return m_fd; }

  void setStep(int step) { m_step = step; }
  int getStep() { return m_step; }

  void loginReadFunc(int fd, short what) {
    if (what & EPOLLIN) {
      memset(buff_recv, 0x00, 4096);
      // int ref = recv(fd, buff_recv, 4096, 0);
      recv(fd, buff_recv, 4096, 0);
      if (!strcmp("start step 0", buff_recv)) {
        printf("step 0 get\n");
        setStep(1);
      } else if (!strcmp("start step 2", buff_recv)) {
        printf("step 2 get\n");
        setStep(3);
      } else if (!strcmp("start step 4", buff_recv)) {
        printf("step 4 get\n");
        setStep(5);
      }
    }
  }

  void loginWriteFunc(int fd, short what) {
    if (what & EPOLLOUT) {
      memset(buff_send, 0x00, 4096);
      if (m_step == 1) {
        snprintf(buff_send, 4096, "%s", "start step 1");
        send(fd, buff_send, 4096, 0);
        setStep(2);
      } else if (m_step == 3) {
        snprintf(buff_send, 4096, "%s", "start step 3");
        send(fd, buff_send, 4096, 0);
        setStep(4);
      } else if (m_step == 5) {
        snprintf(buff_send, 4096, "%s", "start step 5");
        send(fd, buff_send, 4096, 0);
        setStep(6);
        printf("login completed\n");
      }
    }
  }

  void runReadFunc(int fd, short what) {
    if (what & EPOLLIN) {
      memset(buff_recv, 0x00, 4096);
      recv(fd, buff_recv, 4096, 0);
      // printf("get data(%d) : %s\n", fd, buff_recv);
    }
  }

private:
  int m_fd = -1;

  int m_step = 0; // 0 : init, 1 ~ 3 : login step, 4 : running

  char buff_recv[4096] = {0};
  char buff_send[4096] = {0};
};

auto lamFDSetFunc = [](MyFDClass mfc, int fd) -> void { mfc.setFD(fd); };
auto lamFDGetFunc = [](MyFDClass mfc) -> int { return mfc.getFD(); };

int main(int argc, char **argv) {
  printf("Start Server\n");
  std::shared_ptr<std::vector<std::shared_ptr<MyFDClass>>> mfcs = std::make_shared<std::vector<std::shared_ptr<MyFDClass>>>();
  std::shared_ptr<MyFDClass> mfc1 = std::make_shared<MyFDClass>();
  mfcs->push_back(mfc1);

  // TODO: set mfcs element

  SEpoll<MyFDClass> mysepoll(lamFDSetFunc, lamFDGetFunc, mfcs);
  mysepoll.init(SEPOLL_TYPE::ACCEPT, "127.0.0.1", 4000);
  mysepoll.setInitReadFunc([](int fd, short what, void *arg) -> void { static_cast<MyFDClass *>(arg)->loginReadFunc(fd, what); },
                           EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
  mysepoll.setInitWriteFunc([](int fd, short what, void *arg) -> void { static_cast<MyFDClass *>(arg)->loginWriteFunc(fd, what); },
                            EPOLLOUT);

  std::thread tsepoll(&SEpoll<MyFDClass>::run, &mysepoll);
  tsepoll.detach();

  int loop_cnt = 0;

  while (1) {
    for (auto a : *mfcs) {
      if (a->getStep() == 6) {
        printf("find step 6 (%d)\n", a->getFD());
        a->setStep(4);
        mysepoll.setReadFunc(
            a->getFD(), [](int fd, short what, void *arg) -> void { static_cast<MyFDClass *>(arg)->runReadFunc(fd, what); }, a.get(),
            EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
        mysepoll.unsetWriteFunc(a->getFD());
      }
    }

    loop_cnt++;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  printf("End Server\n");

  return 0;
}