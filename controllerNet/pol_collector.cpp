#include "pol_collector.hpp"
#include <thread>

PolCollector::PolCollector() {}

PolCollector::~PolCollector() {}

void PolCollector::run() {
  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

void PolCollector::setSockMan(std::shared_ptr<SocketManager> sockman) { m_sockmans.push_back(sockman); }