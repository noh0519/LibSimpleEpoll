#include "SEpoll.hpp"
#include "aria.hpp"
#include "pol_collector.hpp"
#include "sha1v2.hpp"
#include "socketmanager.hpp"
#include "wlan_provider.hpp"
#include <fmt/format.h>
#include <iostream>

// using namespace chkchk;
// using namespace nlohmann;

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
#if 0
  auto sensor_data = ap_client_data();
  std::cout << sensor_data.dump(4) << std::endl;
#endif
#if 1
  // set sensor vector
  std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> sockmans = std::make_shared<std::vector<std::shared_ptr<SocketManager>>>();
  std::shared_ptr<SocketManager> sockman1 = std::make_shared<SocketManager>("Secui00@!");
  (*sockmans).push_back(sockman1);
  std::shared_ptr<SocketManager> sockman2 = std::make_shared<SocketManager>("Secui00@!");
  (*sockmans).push_back(sockman2);
  // ~set sensor vector

  // start threads
  std::shared_ptr<WlanProvider> wp = std::make_shared<WlanProvider>();
  std::thread t_wp(&WlanProvider::run, wp);
  t_wp.detach();
  std::shared_ptr<PolCollector> pc = std::make_shared<PolCollector>();
  std::thread t_pc(&PolCollector::run, pc);
  t_pc.detach();
  // ~start threads

  // ref wp, pc
  sockman1->setWlanProvider(wp);
  sockman1->setPolCollector(pc);
  sockman2->setWlanProvider(wp);
  sockman2->setPolCollector(pc);
  // ~ref wp, pc

  // set SEpoll
  auto lamb_setFunc = [](SocketManager &sockman, int sock) -> void {
    if (sock == -1) {
      sockman.setState(ConnectionState::INIT);
    } else if (sockman.getSock() == -1 && sock > 0) {
      sockman.setState(ConnectionState::VERIFY_MAC);
    }
    sockman.setSock(sock);
  };
  auto lamb_getFunc = [](SocketManager sockman) -> int { //
    return sockman.getSock();
  };
  std::shared_ptr<SEpoll<SocketManager>> mysepoll =
      std::make_shared<SEpoll<SocketManager>>(lamb_setFunc, lamb_getFunc, sockmans, SEPOLL_TYPE::ACCEPT, "192.168.246.35", 19895);
  mysepoll->setInitReadFunc([](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->loginReadFunc(fd, what); },
                            EPOLLIN);

  wp->setSEpollRef(mysepoll);
  wp->setTotalSockMansRef(sockmans);
  pc->setSEpollRef(mysepoll);
  pc->setTotalSockMansRef(sockmans);

  std::thread t_sepoll(&SEpoll<SocketManager>::run, mysepoll);
  t_sepoll.detach();
  // ~set SEpoll

  // wait all obj set
  while (true) {
    for (auto it = sockmans->begin(); it != sockmans->end(); /**/) {
      if (static_cast<int>((*it)->getMode()) == static_cast<int>(ConnectionMode::DATA)) {
        mysepoll->unsetReadFunc((*it)->getSock());
        wp->setSockMan(*it);
        it = sockmans->erase(it);
      } else if (static_cast<int>((*it)->getMode()) == static_cast<int>(ConnectionMode::CONFIG)) {
        mysepoll->unsetReadFunc((*it)->getSock());
        pc->setSockMan(*it);
        it = sockmans->erase(it);
      } else {
        it++;
      }
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  // ~wait all obj set
#endif

  return 0;
}