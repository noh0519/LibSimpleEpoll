#include "wlan_provider.hpp"
#include <fmt/format.h>
#include <smart_io.hpp>
#include <thread>

template <typename... _String_> //
static bool check_key(nlohmann::json &j, _String_... args) {
  for (auto &a : {args...}) {
    auto v = j.value(a, nlohmann::json());
    if (v.is_null()) {
      return false;
    }
  }
  return true;
}

#if 0
static void test_check_key() {
  nlohmann::json j;
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
static nlohmann::json get_aps() {
  SmartIO io("get", "ipc:///tmp/ap_get.uds");
  nlohmann::json aps;
  aps["1"] = "{}"_json; // 2GHz
  aps["2"] = "{}"_json; // 5GHz

  auto res = io.getall([&](nlohmann::json &j) { //
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
static nlohmann::json get_ap_client() {
  SmartIO io("get", "ipc:///tmp/ap_client_get.uds");
  nlohmann::json ap_client;

  auto res = io.getall([&](nlohmann::json &j) { //
    if (!check_key(j, "band", "bssid", "clients")) {
      assert("missing key: band + bssid + clients");
      return;
    }
    ap_client.push_back(j);
  });
  return ap_client;
}

/// 단말 정보 조회
static nlohmann::json get_clients() {
  SmartIO io("get", "ipc:///tmp/client_get.uds");
  nlohmann::json clients;

  auto res = io.getall([&](nlohmann::json &j) { //
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
static nlohmann::json ap_client_data() {
  auto ap_client_db = get_ap_client(); // ap-client session 정보
  auto ap_db = get_aps();              // ap 정보
  auto client_db = get_clients();      // 단말 정보

  for (auto &item : ap_client_db.items()) {
    auto &ac = item.value();
    auto band = std::to_string(ac["band"].get<uint8_t>());
    auto bssid = ac["bssid"].get<std::string>();
    auto &clients = ac["clients"];

    auto ap_info = ap_db[band].value(bssid, nlohmann::json());
    if (!ap_info.is_null()) {
      //
      // AP 정보 업데이트
      //
      ac.update(ap_info);
    }
    if (!clients.is_null()) {
      for (auto &item : clients.items()) {
        auto &client = item.value();
        auto client_info = client_db.value(client, nlohmann::json());
        if (!client_info.is_null()) {
          //
          // 단말 정보 업데이트
          //
          client = client_info;
        } else {
          client = nlohmann::json{{"client", client}};
        }
      }
    }
  }

  return ap_client_db;
}

WlanProvider::WlanProvider() {}

WlanProvider::~WlanProvider() {}

void WlanProvider::run() {
  uint32_t loop_cnt = 1;
  while (true) {
    // Scheduler Job
    if (loop_cnt % 5 == 0) {
      checkSessionData();
    }
    // ~Scheduler Job

    loop_cnt++;
    if (loop_cnt > 400000000) {
      loop_cnt = 0;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void WlanProvider::setSEpollRef(std::shared_ptr<SEpoll<SocketManager>> sepoll_ref) { //
  _sepoll_ref = sepoll_ref;
}

void WlanProvider::setTotalSockMansRef(std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> total_sockmans_ref) { //
  _total_sockmans_ref = total_sockmans_ref;
}

void WlanProvider::setSockMan(std::shared_ptr<SocketManager> sockman) { //
  _sockmans.push_back(sockman);
}

void WlanProvider::checkSessionData() {
  auto sensor_data = ap_client_data();
  // std::cout << sensor_data.dump(4) << std::endl;
  if (sensor_data.is_null()) {
    fmt::print("sensor db empty\n");
    return;
  }
  for (auto a : _sockmans) {
    a->pushSessionData(sensor_data);
    _sepoll_ref->setWriteFunc(
        a->getSock(), [](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->dataWriteFunc(fd, what); }, a.get(),
        EPOLLOUT | EPOLLONESHOT);
  }
}

void WlanProvider::sendHash(uint8_t *data, uint16_t length, SetConfigList setcfg) {
  std::vector<uint8_t> v;
  v.insert(v.begin(), data, data + length);
  for (auto a : _sockmans) {
    a->pushHashData(setcfg, v);
    _sepoll_ref->setWriteFunc(
        a->getSock(), [](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->dataWriteFunc(fd, what); }, a.get(),
        EPOLLOUT | EPOLLONESHOT);
  }
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