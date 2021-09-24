#include "SEpoll.hpp"
#include <stdio.h>

class MyFDClass {
public:
  MyFDClass() {}
  MyFDClass(int fd) { m_fd = fd; }
  void setFD(int fd) { m_fd = fd; }
  int getFD() { return m_fd; }

private:
  int m_fd = 0;
};

typedef std::function<MyFDClass(int)> FDSetFunc;
auto lamFDSetFunc = [](int fd) -> MyFDClass {
  MyFDClass mfc(fd);
  return mfc;
};
typedef std::function<int(MyFDClass)> FDGetFunc;
auto lamFDGetFunc = [](MyFDClass mfc) -> int { return mfc.getFD(); };

int main(int argc, char **argv) {
  printf("Start Server\n");

  SEpoll<MyFDClass, FDSetFunc, FDGetFunc> mysepoll(lamFDSetFunc, lamFDGetFunc);
  mysepoll.init(SEPOLL_TYPE::ACCEPT, 1024, 4096, 4000, "127.0.0.1");

  printf("End Server\n");

  return 0;
}