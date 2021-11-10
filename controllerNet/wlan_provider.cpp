#include "wlan_provider.hpp"
#include <fmt/format.h>
#include <thread>

WlanProvider::WlanProvider() {}

WlanProvider::~WlanProvider() {}

void WlanProvider::run() {
  pthread_setname_np(pthread_self(), "WlanProvider");

  uint32_t loop_cnt = 1;
  while (true) {
    // Scheduler Job
    if (loop_cnt % 5 == 0) {
      pushSendSignalType(SendSignalType::SESSIONS);
    }
    // ~Scheduler Job

    checkSendSignalType();

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

void WlanProvider::pushSendSignalType(SendSignalType sst) { //
  auto search = std::find(_send_signal_types.begin(), _send_signal_types.end(), sst);
  if (search == _send_signal_types.end()) {
    _send_signal_types.push_back(sst);
  }
}

void WlanProvider::checkSendSignalType() {
  if (!_send_signal_types.empty()) {
    std::list<SendSignalType> temp_send_signal_types;
    temp_send_signal_types.assign(_send_signal_types.begin(), _send_signal_types.end());
    for (auto a : _sockmans) {
      for (auto s : temp_send_signal_types) {
        a->pushSendSignalType(s);
      }
      _sepoll_ref->setWriteFunc(
          a->getSock(), [](int fd, short what, void *arg) -> void { static_cast<SocketManager *>(arg)->dataWriteFunc(fd, what); }, a.get(),
          EPOLLOUT | EPOLLONESHOT);
    }
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