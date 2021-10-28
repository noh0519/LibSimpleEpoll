#include "socketmanager.hpp"
#include "mac_util.hpp"
#include "sys/socket.h"
#include <fmt/format.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

SocketManager::SocketManager(const char *sharedkey) { _sharedkey = sharedkey; }

SocketManager::~SocketManager() {}

bool SocketManager::isConnected() { return false; }

int SocketManager::getSock() { return _sock; };

void SocketManager::setSock(int sock) { _sock = sock; }

ConnectionState SocketManager::getState() { return _state; };

void SocketManager::setState(ConnectionState state) { _state = state; }

ConnectionMode SocketManager::getMode() { return _mode; };

void SocketManager::loginReadFunc(int fd, short what) {
  if (what & EPOLLIN) {
    Packet p;
    auto decrypted = recvData(p);

    if (!decrypted) {
      // TODO: 연결 끊김 처리
      return;
    }

    if (_state == ConnectionState::VERIFY_MAC) {
      auto nonce = (*decrypted).getNonce();
      if (nonce) {
        calcControllerAuthCode(*nonce);
      } else {
        fmt::print("No Nonce\n");
        _state = ConnectionState::INIT;
        return;
      }
      sendLoginChallenge();
      _state = ConnectionState::LOGIN_REQUEST_CHALLENGE;
    } else if (_state == ConnectionState::LOGIN_REQUEST_CHALLENGE) {
      auto auth_code = (*decrypted).getAuthCode();
      if (!auth_code.empty()) {
        if (!memcmp(_s_auth, auth_code.data(), sizeof(_s_auth))) {
          _state = ConnectionState::LOGIN_SUCCESS;
          sendLoginSuccess();
          fmt::print("Login Success ({})\n", _sock);
        } else {
          fmt::print("Failed verify auth code\n");
          (*decrypted).print();
        }
      } else {
        fmt::print("No auth code\n");
        (*decrypted).print();
        _state = ConnectionState::INIT;
        return;
      }
    } else if (_state == ConnectionState::LOGIN_SUCCESS) {
      auto sensor_id = (*decrypted).getSensorID();
      if (sensor_id) {
        fmt::print("get sensor_id: {} ({})\n", *sensor_id, _sock);
        _sensor_id = *sensor_id;
        _state = ConnectionState::SET_SENSOR_ID;
      } else {
        fmt::print("not find sensor_id");
        (*decrypted).print();
        _state = ConnectionState::INIT;
        return;
      }
    } else if (_state == ConnectionState::SET_SENSOR_ID) {
      _mode = *(*decrypted).getMode();
      fmt::print("get mode : {} ({})\n", _mode, _sock);
      if (_mode == ConnectionMode::DATA) {
        _state = ConnectionState::REQUEST_DATA;
      } else if (_mode == ConnectionMode::CONFIG) {
        _state = ConnectionState::SET_CONFIG;
      }
    }
  }
}

void SocketManager::dataWriteFunc(int fd, short what) {
  if (what | EPOLLOUT) {
    while (!_sessions.empty()) {
      auto session = _sessions.front();
      _sessions.pop_front();
      sendSessionData(session);
    }
  }
}

void SocketManager::configReadFunc(int fd, short what) {
  if (what | EPOLLIN) {
  }
}

void SocketManager::pushSessionData(nlohmann::json sessions) { //
  if (sessions.is_null()) {
    return;
  }
  _sessions.push_back(sessions);
}

tl::optional<Packet> SocketManager::recvData(Packet &p) {
  int ret = 0;
  int flags = 0;
  uint32_t size = 0;

  uint8_t buf[8192] = {0x00};

  /* get header data */
  // fmt::print("start header receive ({})\n", _sock);
  memset(buf, 0x00, 8192);
  do {
    ret = recv(_sock, buf + size, sizeof(Header) - size, flags);
    if (ret < 0) {
      fmt::print("receive < 0 ! ({})\n", _sock);
      return tl::nullopt;
    } else if (ret == 0) {
      fmt::print("receive == 0 ! ({})\n", _sock);
      return tl::nullopt;
    }
    size += ret;
  } while (size != sizeof(Header));
  p.insert(buf, size);

  /* get body, tlv data */
  // fmt::print("start body receive ({})\n", _sock);
  size = 0;
  memset(buf, 0x00, 8192);
  uint32_t header_length = p.getHeaderLength();
  do {
    ret = recv(_sock, buf + size, header_length - size, flags);
    if (ret < 0) {
      return tl::nullopt;
      fmt::print("receive < 0 !! ({})\n", _sock);
    } else if (ret == 0) {
      fmt::print("receive == 0 !! ({})\n", _sock);
      return tl::nullopt;
    }
    size += ret;
  } while (size != header_length);
  p.insert(buf, size);

  // fmt::print("end packet receive (%d)\n", _sock);

  auto decrypted = p.decrypt(_sharedkey);
  if (!decrypted) {
    fmt::print("Err decrypt\n");
    _state = ConnectionState::INIT;
    return tl::nullopt;
  }

#if 0
  if (!Packet::verifySeqence(*decrypted, se->recv_seq_)) {
    _state = ConnectionState::INIT;
    return tl::nullopt;
  }
#endif

  if (!Packet::verifyPacketHeaderLength(*decrypted)) {
    fmt::print("Err verifyPacketHeaderLength\n");
    _state = ConnectionState::INIT;
    return tl::nullopt;
  }

  return decrypted;
}

void SocketManager::sendData(Packet &p) {
  // fmt::print("sendData start ({}) ({})\n", p.size(), _sock);
  send(_sock, p.data(), p.size(), 0);
  // int ret = send(_sock, p.data(), p.size(), 0);
  // fmt::print("sendData end ({}) ({})\n", ret, _sock);
}

void SocketManager::calcControllerAuthCode(const uint32_t &nonce) {
  std::vector<uint8_t> n;
  std::vector<uint8_t> k;

  std::string nonce_str = std::to_string(nonce);
  n.insert(n.end(), nonce_str.c_str(), nonce_str.c_str() + nonce_str.size());
  k.insert(k.end(), _sharedkey.begin(), _sharedkey.end());

  MD5 md5;
  auto ret = md5.hmac_md5(n, k);

  memcpy(_c_auth, ret.data(), sizeof(_c_auth));
}

void SocketManager::calcSensorAuthCode(const uint32_t &nonce) {
  std::vector<uint8_t> n;
  std::vector<uint8_t> k;

  std::string nonce_str = std::to_string(nonce);
  n.insert(n.end(), nonce_str.c_str(), nonce_str.c_str() + nonce_str.size());
  k.insert(k.end(), _sharedkey.begin(), _sharedkey.end());

  MD5 md5;
  auto ret = md5.hmac_md5(n, k);

  memcpy(_s_auth, ret.data(), sizeof(_s_auth));
}

void SocketManager::sendLoginChallenge() {
  uint32_t seed = time(NULL);
  uint32_t nonce = static_cast<uint32_t>(rand_r(&seed));

  calcSensorAuthCode(nonce);

  Packet p;

  p.makeLoginResponseTLV(LoginValue::AUTH, MD5::HASH_SIZE, _c_auth);
  nonce = htonl(nonce);
  p.makeLoginResponseTLV(LoginValue::NONCE, sizeof(nonce), reinterpret_cast<uint8_t *>(&nonce));
  p.makeLoginResponseBody(LoginResponse::CHALLENGE);
  p.makeLoginResponseBodyHeader();
  p.makeHeader(_send_seq++);

  p.encrypt(_sharedkey);

  sendData(p);
}

void SocketManager::sendLoginSuccess() {
  Packet p;

  p.makeLoginResponseBody(LoginResponse::OK);
  p.makeLoginResponseBodyHeader();
  p.makeHeader(_send_seq++);

  p.encrypt(_sharedkey);

  sendData(p);
}

void SocketManager::sendSessionData(nlohmann::json session) {
  for (auto a : session) {
    // send ap
    AP ap = getAPFromJson(a);
    sendSessionAPData(ap);
    // ~send ap

    // send clients
    auto j_clients = a.value("clients", nlohmann::json());
    if (j_clients.is_null()) {
      continue;
    }
    for (auto c : j_clients) {
      Client client = getClientFromJson(c, ap.bssid_, ap.channel_);
      sendSessionClientData(client);
    }
    // ~send clients
  }
}

void SocketManager::sendSessionAPData(AP ap) {
  Packet p;

  p.makeSensorID(_sensor_id);
  p.makeAPData(ap);
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(_send_seq++);

  p.encrypt(_sharedkey);

  sendData(p);
}

void SocketManager::sendSessionAPsData(std::vector<AP> aps) {
  Packet p;

  p.makeSensorID(_sensor_id);
  for (auto ap : aps) {
    p.makeAPData(ap);
  }
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(_send_seq++);

  p.encrypt(_sharedkey);

  sendData(p);
}

void SocketManager::sendSessionClientData(Client client) {
  Packet p;

  p.makeSensorID(_sensor_id);
  p.makeClientData(client);
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(_send_seq++);

  p.encrypt(_sharedkey);

  sendData(p);
}

void SocketManager::sendSessionClientsData(std::vector<Client> clients) {
  Packet p;

  p.makeSensorID(_sensor_id);
  for (auto client : clients) {
    p.makeClientData(client);
  }
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(_send_seq++);

  p.encrypt(_sharedkey);

  sendData(p);
}

void SocketManager::sendSensorInfo() {
  Packet p;

  p.makeSensorID(_sensor_id);
  // p.makeSensorMAC(si.mac);
  // p.makeSensorIP(si.ip);
  // p.makeSensorVersion(si.version);
  // p.makeSensorRevision(si.revision);
  // p.makeSensorModel(si.model);

  p.makeDataResponseBody(DataResponse::SENSOR_STATUS_DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(_send_seq++);

  p.encrypt(_sharedkey);

  sendData(p);
}

AP SocketManager::getAPFromJson(nlohmann::json j) {
  AP ap;
  ap.bssid_ = static_cast<uint64_t>(j.value("band", 0)) << (8 * 6);
  ap.bssid_ += mac::string_to_mac(j.value("bssid", "00:00:00:00:00:00"));
  ap.ssid_ = j.value("ssid", "");
  ap.channel_ = static_cast<uint8_t>(j.value("frame_channel", 0));
  ap.rssi_ = static_cast<int8_t>(j.value("rssi", -90));
  ap.cipher_ = static_cast<uint8_t>(j.value("cipher", 0));
  ap.auth_ = static_cast<uint8_t>(j.value("auth", 0));
  ap.ssid_broadcast_ = static_cast<bool>(j.value("ssid_broadcast", false));
  ap.channel_width_ = static_cast<uint8_t>(j.value("channel_width", 0));
  ap.wps_ = static_cast<bool>(j.value("wps", false));
  ap.pmf_ = static_cast<bool>(j.value("pmf", false));
  ap.media_ = 1;
  ap.net_type_ = 1;
  ap.signature_[32] = {0};
  ap.mgnt_count_ = 0;
  ap.ctrl_count_ = 0;
  ap.data_count_ = 0;
  ap.wds_peer_ = 0;
  ap.support_rate_[16] = {0};
  ap.mcs_ = 0;
  ap.support_mimo_ = 0;
  ap.highest_rate_ = 0;
  ap.spatial_stream_ = 0;
  ap.guard_interval_ = 0;
  ap.last_dt_ = 0;
  ap.probe_dt_ = 0;
  return ap;
}

Client SocketManager::getClientFromJson(nlohmann::json j, uint64_t bssid, uint8_t channel) {
  Client client;
  client.client_mac_ = mac::string_to_mac(j.value("client", "00:00:00:00:00:00"));
  client.rssi_ = static_cast<int8_t>(j.value("rssi", -90));
  client.bssid_ = bssid;
  client.channel_ = channel;
  client.eap_id_[64] = {0};
  client.data_rate_ = 0;
  client.noise_ = -90;
  client.mimo_ = 0;
  client.signature_[32] = {0};
  client.signature5_[32] = {0};
  client.data_size_ = 0;
  client.mgnt_count_ = 0;
  client.ctrl_count_ = 0;
  client.data_count_ = 0;
  client.auth_count_ = 0;
  client.last_dt_ = 0;
  client.probe_dt_ = 0;
  return client;
}