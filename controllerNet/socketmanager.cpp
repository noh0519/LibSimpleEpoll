#include "socketmanager.hpp"
#include "sys/socket.h"
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

SocketManager::SocketManager(const char *sharedkey) { _sharedkey = sharedkey; }

bool SocketManager::isConnected() { return false; }

int SocketManager::getSock() { return _sock; };

void SocketManager::setSock(int sock) { _sock = sock; }

void SocketManager::setState(ConnectionState state) { _state = state; }

void SocketManager::loginReadFunc(int fd, short what) {
  Packet p;
  recvData(p);

  auto decrypted = Packet::decrypt(p, _sharedkey);
  if (!decrypted) {
#ifdef TMI
    fmt::print("Err decrypt\n");
#endif
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
#ifdef TMI
    fmt::print("Err verifyPacketHeaderLength\n");
#endif
    _state = ConnectionState::INIT;
    return;
  }

  if (_state == ConnectionState::VERIFY_MAC) {
    auto nonce = (*decrypted).getNonce();
    if (nonce) {
      calcControllerAuthCode(*nonce);
    } else {
#ifdef TMI
      fmt::print("No Nonce\n");
#endif
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
        // fmt::print("Login Success\n");
      } else {
#ifdef TMI
        fmt::print("Failed verify auth code\n");
#endif
        (*decrypted).print();
      }
    } else {
#ifdef TMI
      fmt::print("No auth code\n");
#endif
      (*decrypted).print();
      _state = ConnectionState::INIT;
      return;
    }
  } else if (_state == ConnectionState::LOGIN_SUCCESS) {
    auto sensor_id = (*decrypted).getSensorID();
    if (sensor_id) {
      // fmt::print("get sensor_id: {}\n", *sensor_id);
      _sensor_id = *sensor_id;
      _state = ConnectionState::SET_SENSOR_ID;
    } else {
#ifdef TMI
      fmt::print("NO sensor_id\n");
#endif
      (*decrypted).print();
      _state = ConnectionState::INIT;
      return;
    }
  } else if (_state == ConnectionState::SET_SENSOR_ID) {
    _mode = *(*decrypted).getMode();
    // fmt::print("bev_: {:p} - get mode: {}\n", fmt::ptr(se->bev_), _mode);
    if (_mode == ConnectionMode::DATA) {
      // TODO: Need Set Event (Data Mode)
      _state = ConnectionState::REQUEST_DATA;
    } else if (_mode == ConnectionMode::CONFIG) {
      // TODO: Need Set Event (Config Mode)
      _state = ConnectionState::SET_CONFIG;
    }
  }
}

void SocketManager::loginWriteFunc(int fd, short what) {}

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
  // printf("start header receive (%d)\n", _sock);
  memset(buf, 0x00, 8192);
  do {
    ret = recv(_sock, buf + size, sizeof(Header) - size, flags);
    if (ret < 0) {
      return;
    } else if (ret == 0) {
      return;
    }
    size += ret;
  } while (size != sizeof(Header));
  p.insert(buf, size);

  /* get body, tlv data */
  // printf("start body receive (%d)\n", _sock);
  size = 0;
  memset(buf, 0x00, 8192);
  uint32_t header_length = p.getHeaderLength();
  do {
    ret = recv(_sock, buf + size, header_length - size, flags);
    size += ret;
  } while (size != header_length);
  p.insert(buf, size);

  // printf("end packet receive (%d)\n", _sock);
}

void SocketManager::sendData(Packet &p) { send(_sock, p.data(), p.data() + p.size(), 0); }

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
    // fmt::print("Not body type challenge : {}\n", (*body).type);
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