#include "SEpoll.hpp"
#include "socketmanager.hpp"
#include <iostream>
#include <smartmq.hpp>

using namespace chkchk;
using namespace nlohmann;

template <typename... _String_> //
static bool check_key(json &j, _String_... args) {
  for (auto &a : {args...}) {
    auto v = j.value(a, json());
    if (v.is_null()) {
      return false;
    }
  }
  return true;
}

#if 0
static void test_check_key() {
  json j;
  j["a"] = 1;
  j["b"] = "2";

  cout << check_key(j, "a") << endl;
  cout << check_key(j, "b") << endl;
  cout << check_key(j, "c") << endl;
  cout << check_key(j, "a", "b") << endl;
  cout << check_key(j, "a", "b", "c") << endl;
}
#endif

/// AP 정보 조회
static json get_aps() {
  SmartMQ smq("get", "ipc:///tmp/ap_get.uds");
  json aps;
  aps["1"] = "{}"_json; // 2GHz
  aps["2"] = "{}"_json; // 5GHz

  auto res = smq.getall([&](json &&j) { //
    if (!check_key(j, "band", "bssid")) {
      assert("missing key: band + bssid");
      return;
    }
    auto band = std::to_string(j["band"].get<uint8_t>());
    auto bssid = j["bssid"].get<std::string>();
    aps[band][bssid] = j;
  });
  return aps;
}

/// AP-단말 세션 정보 조회
static json get_ap_client() {
  SmartMQ smq("get", "ipc:///tmp/ap_client_get.uds");
  json ap_client;

  auto res = smq.getall([&](json &&j) { //
    if (!check_key(j, "band", "bssid", "clients")) {
      assert("missing key: band + bssid + clients");
      return;
    }
    ap_client.push_back(j);
  });
  return ap_client;
}

/// 단말 정보 조회
static json get_clients() {
  SmartMQ smq("get", "ipc:///tmp/client_get.uds");
  json clients;

  auto res = smq.getall([&](json &&j) { //
    if (!check_key(j, "client")) {
      assert("missing key: client");
      return;
    }
    auto client = j["client"].get<std::string>();
    clients[client] = j;
  });
  return clients;
}

/// AP-단말 정보 + 세션 정보를 하나의 json으로 취합
static json ap_client_data() {
  auto ap_client_db = get_ap_client(); // ap-client session 정보
  auto ap_db = get_aps();              // ap 정보
  auto client_db = get_clients();      // 단말 정보

  for (auto &item : ap_client_db.items()) {
    auto &ac = item.value();
    auto band = std::to_string(ac["band"].get<uint8_t>());
    auto bssid = ac["bssid"].get<std::string>();
    auto &clients = ac["clients"];

    auto ap_info = ap_db[band].value(bssid, json());
    if (!ap_info.is_null()) {
      //
      // AP 정보 업데이트
      //
      ac.update(ap_info);
    }
    if (!clients.is_null()) {
      for (auto &item : clients.items()) {
        auto &client = item.value();
        auto client_info = client_db.value(client, json());
        if (!client_info.is_null()) {
          //
          // 단말 정보 업데이트
          //
          client = client_info;
        } else {
          client = json{{"client", client}};
        }
      }
    }
  }

  return ap_client_db;
}

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
  std::shared_ptr<SocketManager> wlancollector_sensor = std::make_shared<SocketManager>("Secui00@!");
  (*sockmans).push_back(wlancollector_sensor);
  std::shared_ptr<SocketManager> polprovider_sensor = std::make_shared<SocketManager>("Secui00@!");
  (*sockmans).push_back(polprovider_sensor);

  // set SEpoll
  auto lamb_setFunc = [](SocketManager &sm, int sock) -> void {
    if (sock == -1) {
      sm.setState(ConnectionState::INIT);
    } else if (sm.getSock() == -1 && sock > 0) {
      sm.setState(ConnectionState::VERIFY_MAC);
    }
    sm.setSock(sock);
  };
  auto lamb_getFunc = [](SocketManager sm) -> int { return sm.getSock(); };
  SEpoll<SocketManager> mysepoll(lamb_setFunc, lamb_getFunc, sockmans);
  mysepoll.init(SEPOLL_TYPE::ACCEPT, "192.168.246.35", 19895);
  mysepoll.setInitReadFunc([](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->loginReadFunc(fd, what); },
                           EPOLLIN);
  // mysepoll.setInitWriteFunc([](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->loginWriteFunc(fd, what); },
  //                           EPOLLOUT);

  std::thread tsepoll(&SEpoll<SocketManager>::run, &mysepoll);
  tsepoll.detach();
  // ~set SEpoll

  // wait all obj set
  printf("start connection loop\n");
  std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> sockmans_data =
      std::make_shared<std::vector<std::shared_ptr<SocketManager>>>();
  std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> sockmans_config =
      std::make_shared<std::vector<std::shared_ptr<SocketManager>>>();
  while (true) {
    for (auto it = sockmans->begin(); it != sockmans->end(); /**/) {
      if (static_cast<int>((*it)->getMode()) == static_cast<int>(ConnectionMode::DATA)) {
        mysepoll.unsetReadFunc((*it)->getSock());
        sockmans_data->push_back(*it);
        it = sockmans->erase(it);
      } else if (static_cast<int>((*it)->getMode()) == static_cast<int>(ConnectionMode::CONFIG)) {
        sockmans_config->push_back(*it);
        it = sockmans->erase(it);
      } else {
        it++;
      }
    }

    if (sockmans->size() == 0) {
      break;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  // ~wait all obj set

  // send session data
  printf("start data loop\n");
  while (true) {
    auto sensor_data = ap_client_data();
    // std::cout << sensor_data.dump(4) << std::endl;
    if (sensor_data.is_null()) {
      printf("sensor db empty\n");
      continue;
    }
    for (auto a : *sockmans_data) {
      a->pushSessionData(sensor_data);
      mysepoll.setWriteFunc(
          a->getSock(), [](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->dataWriteFunc(fd, what); }, a.get(),
          EPOLLOUT | EPOLLONESHOT);
    }
  }
  // ~send session data
#endif
}

/// sensor_data output example
/*
[
   {
        "auth": 3,
        "band": 1,
        "bssid": "00:0f:00:b0:3d:da",
        "channel_width": 1,
        "cipher": 4,
        "frame_channel": 6,
        "mimo": 0,
        "mode": 1,
        "pmf": false,
        "protocol": 13,
        "radiotap_channel": 6,
        "rssi": -75,
        "ssid": "GNET_BB_CP440_B03DDA",
        "ssid_broadcast": true,
        "wps": true,
        "clients": [
            {
                "client": "02:00:00:00:00:00",
                "rssi": -78
            },
            {
                "client": "02:fe:dd:24:dc:9b",
                "rssi": -73
            }
        ]
    },
    ....
]
*/