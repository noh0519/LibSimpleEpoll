#include "pol_collector.hpp"
#include <fmt/format.h>
#include <thread>

PolCollector::PolCollector() {}

PolCollector::~PolCollector() {}

void PolCollector::run() {
  pthread_setname_np(pthread_self(), "PolCOllector");

  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void PolCollector::setSEpollRef(std::shared_ptr<SEpoll<SocketManager>> sepoll_ref) { //
  _sepoll_ref = sepoll_ref;
}

void PolCollector::setTotalSockMansRef(std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> total_sockmans_ref) { //
  _total_sockmans_ref = total_sockmans_ref;
}

void PolCollector::setSockMan(std::shared_ptr<SocketManager> sockman) { //
  _sockmans.push_back(sockman);
  _sepoll_ref->setReadFunc(
      sockman->getSock(), [](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->configReadFunc(fd, what); },
      sockman.get(), EPOLLIN);
}