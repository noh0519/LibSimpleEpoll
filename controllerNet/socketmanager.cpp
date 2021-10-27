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
    recvData(p);

    auto decrypted = Packet::decrypt(p, _sharedkey);
    if (!decrypted) {
      fmt::print("Err decrypt\n");
      _state = ConnectionState::INIT;
      return;
    }

#if 0
  if (!Packet::verifySeqence(*decrypted, se->recv_seq_)) {
    _state = ConnectionState::INIT;
    return;
  }
#endif

    if (!Packet::verifyPacketHeaderLength(*decrypted)) {
      fmt::print("Err verifyPacketHeaderLength\n");
      _state = ConnectionState::INIT;
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
        // TODO: Need Set Event (Data Mode)
        _state = ConnectionState::REQUEST_DATA;
      } else if (_mode == ConnectionMode::CONFIG) {
        // TODO: Need Set Event (Config Mode)
        _state = ConnectionState::SET_CONFIG;
      }
    }
  }
}

void SocketManager::loginWriteFunc(int fd, short what) {}

void SocketManager::dataWriteFunc(int fd, short what) {
  if (what | EPOLLOUT) {
    while (!_sessions.empty()) {
      auto session = _sessions.front();
      _sessions.pop_front();
      sendSessionData(session);
    }
  }
}

void SocketManager::pushSessionData(nlohmann::json sessions) { //
  if (sessions.is_null()) {
    return;
  }
  _sessions.push_back(sessions);
}

uint32_t SocketManager::getHeaderLength(std::vector<uint8_t> vec) {
  Header *h = reinterpret_cast<Header *>(&vec[0]);
  return ntohs((*h).length);
}

void SocketManager::recvData(Packet &p) {
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
      return;
    } else if (ret == 0) {
      fmt::print("receive == 0 ! ({})\n", _sock);
      return;
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
      return;
      fmt::print("receive < 0 !! ({})\n", _sock);
    } else if (ret == 0) {
      fmt::print("receive == 0 !! ({})\n", _sock);
      return;
    }
    size += ret;
  } while (size != header_length);
  p.insert(buf, size);

  // fmt::print("end packet receive (%d)\n", _sock);
}

void SocketManager::sendData(Packet &p) {
  // fmt::print("sendData start ({}) ({})\n", p.size(), _sock);
  send(_sock, p.data(), p.size(), 0);
  // int ret = send(_sock, p.data(), p.size(), 0);
  // fmt::print("sendData end ({}) ({})\n", ret, _sock);
}

bool SocketManager::verifyPacketHeaderLength(std::vector<uint8_t> vec) {
  if (getHeaderLength(vec) == vec.size() - sizeof(Header)) {
    return true;
  } else {
    return false;
  }
}

tl::optional<uint32_t> SocketManager::getNonce(std::vector<uint8_t> vec) {
  uint32_t *nonce;
  int32_t body_pos = sizeof(Header) + sizeof(Bodyheader);
  TLV *body = reinterpret_cast<TLV *>(&vec[body_pos]);
  uint16_t length = 0;

  if (static_cast<LoginRequest>((*body).type) != LoginRequest::START) {
    fmt::print("Not body type challenge : {}\n", (*body).type);
    return tl::nullopt;
  }
  while (true) {
    TLV *tlv = reinterpret_cast<TLV *>(&vec[body_pos + sizeof(*body) + length]);

    if (static_cast<LoginValue>((*tlv).type) == LoginValue::NONCE) {
      int data_pos = body_pos + sizeof(*body) + length + 3;
      nonce = reinterpret_cast<uint32_t *>(&vec[data_pos]);
      auto n = ntohl(*nonce);
      return tl::make_optional<uint32_t>(n);
    }

    length += 3 + ntohs((*tlv).length);
    if (length >= ntohs((*body).length)) {
      break;
    }
  }
  return tl::nullopt;
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

  auto p = Packet::makeLoginResponseChallenge(_c_auth, nonce, _send_seq++, _sharedkey);
  if (p) {
    sendData(*p);
  }
}

void SocketManager::sendLoginSuccess() {
  auto p = Packet::makeLoginSuccess(_send_seq++, _sharedkey);
  if (p) {
    sendData(*p);
  }
}

void SocketManager::sendSessionData(nlohmann::json session) {
  for (auto a : session) {
    // send ap
    AP ap;
    ap.bssid_ = static_cast<uint64_t>(a.value("band", 0)) << (8 * 6);
    ap.bssid_ += mac::string_to_mac(a.value("bssid", "00:00:00:00:00:00"));
    ap.ssid_ = a.value("ssid", "");
    ap.channel_ = static_cast<uint8_t>(a.value("frame_channel", 0));
    ap.rssi_ = static_cast<int8_t>(a.value("rssi", -90));
    ap.cipher_ = static_cast<uint8_t>(a.value("cipher", 0));
    ap.auth_ = static_cast<uint8_t>(a.value("auth", 0));
    ap.ssid_broadcast_ = static_cast<bool>(a.value("ssid_broadcast", false));
    ap.channel_width_ = static_cast<uint8_t>(a.value("channel_width", 0));
    ap.wps_ = static_cast<bool>(a.value("wps", false));
    ap.pmf_ = static_cast<bool>(a.value("pmf", false));
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

    auto p_ap = Packet::makeSessionAP(ap, _sensor_id, _send_seq++, _sharedkey);
    if (p_ap) {
      sendData(*p_ap);
    }
    // ~send ap

    // send clients
    auto j_clients = a.value("clients", nlohmann::json());
    if (j_clients.is_null()) {
      continue;
    }
    for (auto c : j_clients) {
      Client client;
      client.client_mac_ = mac::string_to_mac(c.value("client", "00:00:00:00:00:00"));
      client.rssi_ = static_cast<int8_t>(c.value("rssi", -90));
      client.bssid_ = ap.bssid_;
      client.channel_ = ap.channel_;
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

      auto p_client = Packet::makeSessionClient(client, _sensor_id, _send_seq++, _sharedkey);
      if (p_client) {
        sendData(*p_client);
      }
    }
    // ~send clients
  }
}