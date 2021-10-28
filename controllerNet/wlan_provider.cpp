#include "wlan_provider.hpp"
#include <thread>

WlanProvider::WlanProvider() {}

WlanProvider::~WlanProvider() {}

void WlanProvider::run() {
  while (true) {

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

void WlanProvider::setSockMan(std::shared_ptr<SocketManager> sockman) { m_sockmans.push_back(sockman); }