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

auto __FDSetFunc = [](int fd) -> MyFDClass {
  MyFDClass mfc(fd);
  return mfc;
};
auto __FDGetFunc = [](MyFDClass mfc) -> int { return mfc.getFD(); };

typedef std::function<MyFDClass(int)> FDSetFunc;
typedef std::function<int(MyFDClass)> FDGetFunc;

int main(int argc, char **argv) {
  printf("Start Server\n");

  SEpoll<MyFDClass, FDSetFunc, FDGetFunc> mysepoll(SEPOLL_TYPE::ACCEPT, 1024, 4096, 4000, "127.0.0.1");
  // SEpoll<MyFDClass, int, char> mysepoll(SEPOLL_TYPE::ACCEPT, 1024, 4096, 4000, "127.0.0.1");

  printf("End Server\n");

  return 0;
}