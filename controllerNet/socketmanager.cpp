#include "socketmanager.hpp"
#include "mac_util.hpp"
#include "sys/socket.h"
#include "var_util.hpp"
#include <fmt/format.h>
#include <iomanip>
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

void SocketManager::setWlanProvider(std::shared_ptr<WlanProvider> wp) { _wp = wp; }

void SocketManager::setPolCollector(std::shared_ptr<PolCollector> pc) { _pc = pc; }

void SocketManager::loginReadFunc(int fd, short what) {
  if (what & EPOLLIN) {
    auto decrypted = recvData();

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
    sendHashData();
    sendSessionData();
  }
}

void SocketManager::configReadFunc(int fd, short what) {
  if (what | EPOLLIN) {
    auto recvpacket = recvData();
    if (!recvpacket) {
      return;
    }
    // recvpacket->print();
    switch (static_cast<SetConfig>(recvpacket->getBodyType())) {
    case SetConfig::LIST_SINGLE:
    case SetConfig::LIST_START:
    case SetConfig::LIST_CONTINUE:
    case SetConfig::LIST_FINISH:
      recvConfigData(*recvpacket);
      break;
    case SetConfig::FIRMWARE:
      break;
    default:
      break;
    }
  }
}

void SocketManager::recvConfigData(Packet p) {
  uint16_t pos = sizeof(HEADER) + sizeof(BODYHEADER) + sizeof(TLV);
  size_t total_size = p.size();

  while (pos < total_size) {
    TLV *tlv = reinterpret_cast<TLV *>(&p.data()[pos]);
    SetConfigList tlv_type = static_cast<SetConfigList>(tlv->type);
    uint16_t tlv_len = ntohs(tlv->length);
    uint8_t *tlv_val = static_cast<uint8_t *>(&p.data()[pos + sizeof(TLV)]);

    switch (tlv_type) {
    case SetConfigList::AUTH_AP:
    case SetConfigList::AUTH_CLIENT:
    case SetConfigList::GUEST_AP:
    case SetConfigList::GUEST_CLIENT:
    case SetConfigList::EXTERNAL_AP:
    case SetConfigList::EXTERNAL_CLIENT:
    case SetConfigList::EXCEPT_AP:
    case SetConfigList::EXCEPT_CLIENT:
    case SetConfigList::ROGUE_AP:
    case SetConfigList::ROGUE_CLIENT:
      setWhiteList(tlv_val, tlv_len, tlv_type);
      break;
    case SetConfigList::POLICY:
      setThreatPolicy(tlv_val, tlv_len);
      break;
    case SetConfigList::BLOCK:
      break;
    case SetConfigList::ADMIN_BLOCK:
      break;
    case SetConfigList::SENSOR_SETTING:
      break;
    case SetConfigList::AUTH_AP_HASH:
    case SetConfigList::AUTH_CLIENT_HASH:
    case SetConfigList::GUEST_AP_HASH:
    case SetConfigList::GUEST_CLIENT_HASH:
    case SetConfigList::EXTERNAL_AP_HASH:
    case SetConfigList::EXTERNAL_CLIENT_HASH:
    case SetConfigList::EXCEPT_AP_HASH:
    case SetConfigList::EXCEPT_CLIENT_HASH:
    case SetConfigList::ROGUE_AP_HASH:
    case SetConfigList::ROGUE_CLIENT_HASH:
    case SetConfigList::POLICY_HASH:
    case SetConfigList::BLOCK_HASH:
    case SetConfigList::ADMIN_BLOCK_HASH:
    case SetConfigList::SENSOR_SETTING_HASH:
      setHash(tlv_val, tlv_len, tlv_type);
      flushConfigData(tlv_type);
      break;
    case SetConfigList::TIMESYNC:
      setTimeSync(tlv_val, tlv_len);
      break;
    case SetConfigList::GENERAL_CONFIG:
      setGeneralConfig(tlv_val, tlv_len);
      break;
    default:
      break;
    }

    pos += sizeof(TLV) + tlv_len;
  }
}

void SocketManager::setWhiteList(uint8_t *data, uint16_t length, SetConfigList setcfg) {
  uint16_t offset = 0;
  std::string mac_str = "";

  while (offset < length) {
    mac_str = mac::pointer_to_mac(data + offset);
    switch (setcfg) {
    case SetConfigList::AUTH_AP:
      _auth_aps[mac_str.c_str()] = "";
      break;
    case SetConfigList::AUTH_CLIENT:
      _auth_clients[mac_str.c_str()] = "";
      break;
    case SetConfigList::GUEST_AP:
      _guest_aps[mac_str.c_str()] = "";
      break;
    case SetConfigList::GUEST_CLIENT:
      _guest_clients[mac_str.c_str()] = "";
      break;
    case SetConfigList::EXTERNAL_AP:
      _external_aps[mac_str.c_str()] = "";
      break;
    case SetConfigList::EXTERNAL_CLIENT:
      _external_clients[mac_str.c_str()] = "";
      break;
    case SetConfigList::EXCEPT_AP:
      _except_aps[mac_str.c_str()] = "";
      break;
    case SetConfigList::EXCEPT_CLIENT:
      _except_clients[mac_str.c_str()] = "";
      break;
    case SetConfigList::ROGUE_AP:
      _rogue_aps[mac_str.c_str()] = "";
      break;
    case SetConfigList::ROGUE_CLIENT:
      _rogue_clients[mac_str.c_str()] = "";
      break;
    default:
      break;
    }

    offset += 6;
  }
}

void SocketManager::setThreatPolicy(uint8_t *data, uint16_t length) {
  uint16_t offset = 0;

  while (offset < length) {
    nlohmann::json policy;

    uint16_t pol_code = 0;
    memcpy(&pol_code, data + offset, sizeof(uint16_t));
    pol_code = htons(pol_code);
    offset += sizeof(uint16_t);
    policy["pol_code"] = pol_code;

    uint8_t pol_use = *(data + offset);
    offset += sizeof(uint8_t);
    policy["pol_use"] = pol_use;

    uint8_t auto_blk = *(data + offset);
    offset += sizeof(uint8_t);
    policy["auto_blk"] = auto_blk;

    int8_t rss = *(data + offset);
    offset += sizeof(int8_t);
    policy["rss"] = rss;

    uint8_t except_ext_ap = *(data + offset);
    offset += sizeof(uint8_t);
    policy["except_ext_ap"] = except_ext_ap;

    uint16_t threshold = 0;
    memcpy(&threshold, data + offset, sizeof(uint16_t));
    threshold = htons(threshold);
    offset += sizeof(uint16_t);
    policy["threshold"] = threshold;

    std::string pol_name = getThreatPolicyName(pol_code);
    _threat_policy[pol_name] = policy;
  }
}

void SocketManager::setTimeSync(uint8_t *data, uint16_t length) {}

void SocketManager::setGeneralConfig(uint8_t *data, uint16_t length) {}

void SocketManager::setHash(uint8_t *data, uint16_t length, SetConfigList setcfg) {
  switch (setcfg) {
  case SetConfigList::AUTH_AP_HASH:
    _auth_aps_hash.clear();
    _auth_aps_hash.insert(_auth_aps_hash.begin(), data, data + length);
    break;
  case SetConfigList::AUTH_CLIENT_HASH:
    _auth_clients_hash.clear();
    _auth_clients_hash.insert(_auth_clients_hash.begin(), data, data + length);
    break;
  case SetConfigList::GUEST_AP_HASH:
    _guest_aps_hash.clear();
    _guest_aps_hash.insert(_guest_aps_hash.begin(), data, data + length);
    break;
  case SetConfigList::GUEST_CLIENT_HASH:
    _guest_clients_hash.clear();
    _guest_clients_hash.insert(_guest_clients_hash.begin(), data, data + length);
    break;
  case SetConfigList::EXTERNAL_AP_HASH:
    _external_aps_hash.clear();
    _external_aps_hash.insert(_external_aps_hash.begin(), data, data + length);
    break;
  case SetConfigList::EXTERNAL_CLIENT_HASH:
    _external_clients_hash.clear();
    _external_clients_hash.insert(_external_clients_hash.begin(), data, data + length);
    break;
  case SetConfigList::EXCEPT_AP_HASH:
    _except_aps_hash.clear();
    _except_aps_hash.insert(_except_aps_hash.begin(), data, data + length);
    break;
  case SetConfigList::EXCEPT_CLIENT_HASH:
    _except_clients_hash.clear();
    _except_clients_hash.insert(_except_clients_hash.begin(), data, data + length);
    break;
  case SetConfigList::ROGUE_AP_HASH:
    _rogue_aps_hash.clear();
    _rogue_aps_hash.insert(_rogue_aps_hash.begin(), data, data + length);
    break;
  case SetConfigList::ROGUE_CLIENT_HASH:
    _rogue_clients_hash.clear();
    _rogue_clients_hash.insert(_rogue_clients_hash.begin(), data, data + length);
    break;
  case SetConfigList::POLICY_HASH:
    _threat_policy_hash.clear();
    _threat_policy_hash.insert(_threat_policy_hash.begin(), data, data + length);
    break;
  case SetConfigList::BLOCK_HASH:
    _block_hash.clear();
    _block_hash.insert(_block_hash.begin(), data, data + length);
    break;
  case SetConfigList::ADMIN_BLOCK_HASH:
    _admin_block_hash.clear();
    _admin_block_hash.insert(_admin_block_hash.begin(), data, data + length);
    break;
  case SetConfigList::SENSOR_SETTING_HASH:
    _sensor_setting_hash.clear();
    _sensor_setting_hash.insert(_sensor_setting_hash.begin(), data, data + length);
    break;
  default:
    break;
  }
  _wp->sendHash(data, length, setcfg);
}

std::string SocketManager::getThreatPolicyName(uint16_t pol_code) {
  std::string pol_name = "";
  switch (pol_code) {
  case 1:
    pol_name = "misconfig_ap";
    break;
  case 2:
    pol_name = "rogue_ap";
    break;
  case 3:
    pol_name = "unauth_ap";
    break;
  case 4:
    pol_name = "soft_ap";
    break;
  case 5:
    pol_name = "mobile_router";
    break;
  case 6:
    pol_name = "mobile_hotspot";
    break;
  case 7:
    pol_name = "wds";
    break;
  case 8:
    pol_name = "wps";
    break;
  case 257:
    pol_name = "rogue_cli_auth_ap";
    break;
  case 258:
    pol_name = "rogue_cli_guest_ap";
    break;
  case 259:
    pol_name = "rogue_cli_unauth_ap";
    break;
  case 273:
    pol_name = "auth_cli_unauth_ap";
    break;
  case 274:
    pol_name = "auth_cli_guest_ap";
    break;
  case 275:
    pol_name = "auth_cli_ext_ap";
    break;
  case 276:
    pol_name = "violation_auth_cli_auth_ap";
    break;
  case 289:
    pol_name = "unauth_cli_auth_ap";
    break;
  case 290:
    pol_name = "unauth_cli_guest_ap";
    break;
  case 291:
    pol_name = "unauth_cli_unauth_ap";
    break;
  case 292:
    pol_name = "unauth_cli_ext_ap";
    break;
  case 305:
    pol_name = "guest_cli_auth_ap";
    break;
  case 306:
    pol_name = "guest_cli_unauth_ap";
    break;
  case 321:
    pol_name = "ext_cli_auth_ap";
    break;
  case 322:
    pol_name = "ext_cli_guest_ap";
    break;
  case 323:
    pol_name = "ext_cli_unauth_ap";
    break;
  case 513:
    pol_name = "adhoc_auth_cli";
    break;
  case 514:
    pol_name = "adhoc_unauth_cli";
    break;
  case 515:
    pol_name = "adhoc_rogue_cli";
    break;
  case 516:
    pol_name = "adhoc_guest_cli";
    break;
  case 529:
    pol_name = "direct_auth_cli";
    break;
  case 530:
    pol_name = "direct_unauth_cli";
    break;
  case 531:
    pol_name = "direct_rogue_cli";
    break;
  case 532:
    pol_name = "direct_guest_cli";
    break;
  case 769:
    pol_name = "anti_ap_spoof";
    break;
  case 770:
    pol_name = "anti_cli_spoof";
    break;
  case 771:
    pol_name = "anti_evil_twin_ap";
    break;
  case 1025:
    pol_name = "rf_interference";
    break;
  case 1026:
    pol_name = "wep_crack";
    break;
  case 1040:
    pol_name = "flood";
    break;
  case 1041:
    pol_name = "flood_assoc";
    break;
  case 1042:
    pol_name = "flood_disassoc";
    break;
  case 1043:
    pol_name = "flood_disassoc_b";
    break;
  case 1044:
    pol_name = "flood_auth";
    break;
  case 1045:
    pol_name = "flood_deauth";
    break;
  case 1046:
    pol_name = "flood_deauth_b";
    break;
  case 1047:
    pol_name = "flood_probe_req";
    break;
  case 1048:
    pol_name = "flood_rts";
    break;
  case 1049:
    pol_name = "flood_cts";
    break;
  case 1050:
    pol_name = "flood_eapol_start";
    break;
  case 1051:
    pol_name = "flood_eapol_logoff";
    break;
  case 1052:
    pol_name = "flood_pspoll";
    break;
  case 1056:
    pol_name = "malformed";
    break;
  case 1057:
    pol_name = "malformed_ie_len";
    break;
  case 1058:
    pol_name = "malformed_ie_dup";
    break;
  case 1059:
    pol_name = "malformed_ie_redundant";
    break;
  case 1060:
    pol_name = "malformed_abnormal_bss";
    break;
  case 1061:
    pol_name = "malformed_assoc_req";
    break;
  case 1062:
    pol_name = "malformed_ht_ie";
    break;
  case 1063:
    pol_name = "malformed_deauth_code";
    break;
  case 1064:
    pol_name = "malformed_disassoc_code";
    break;
  case 1065:
    pol_name = "malformed_nul_probe_req";
    break;
  case 1066:
    pol_name = "malformed_too_long_ssid";
    break;
  case 1067:
    pol_name = "malformed_src_mac";
    break;
  case 1068:
    pol_name = "malformed_overflow_eapol_key";
    break;
  case 1069:
    pol_name = "malformed_fata_jack";
    break;
  default:
    break;
  }

  return pol_name;
}

void SocketManager::flushConfigData(SetConfigList setcfg) {
  switch (setcfg) {
  case SetConfigList::AUTH_AP_HASH:
    // std::cout << _auth_aps.dump(4) << std::endl;
    _auth_aps.clear();
    break;
  case SetConfigList::AUTH_CLIENT_HASH:
    _auth_clients.clear();
    break;
  case SetConfigList::GUEST_AP_HASH:
    _guest_aps.clear();
    break;
  case SetConfigList::GUEST_CLIENT_HASH:
    _guest_clients.clear();
    break;
  case SetConfigList::EXTERNAL_AP_HASH:
    _external_aps.clear();
    break;
  case SetConfigList::EXTERNAL_CLIENT_HASH:
    _external_clients.clear();
    break;
  case SetConfigList::EXCEPT_AP_HASH:
    _except_aps.clear();
    break;
  case SetConfigList::EXCEPT_CLIENT_HASH:
    _except_clients.clear();
    break;
  case SetConfigList::ROGUE_AP_HASH:
    _rogue_aps.clear();
    break;
  case SetConfigList::ROGUE_CLIENT_HASH:
    _rogue_clients.clear();
    break;
  case SetConfigList::POLICY_HASH:
    // std::cout << _threat_policy.dump(4) << std::endl;
    _threat_policy.clear();
    break;
  case SetConfigList::BLOCK_HASH:
    _block.clear();
    break;
  case SetConfigList::ADMIN_BLOCK_HASH:
    _admin_block.clear();
    break;
  case SetConfigList::SENSOR_SETTING_HASH:
    _sensor_setting.clear();
    break;
  default:
    break;
  }
}

void SocketManager::pushHashData(SetConfigList setcfg, std::vector<uint8_t> v) { //
  _hashs.push_back(std::make_pair(setcfg, v));
}

void SocketManager::pushSessionData(nlohmann::json sessions) { //
  if (sessions.is_null()) {
    return;
  }
  _sessions.push_back(sessions);
}

tl::optional<Packet> SocketManager::recvData() {
  Packet p;

  int ret = 0;
  int flags = 0;
  uint32_t size = 0;

  uint8_t buf[8192] = {0x00};

  /* get header data */
  // fmt::print("start header receive ({})\n", _sock);
  memset(buf, 0x00, 8192);
  do {
    ret = recv(_sock, buf + size, sizeof(HEADER) - size, flags);
    if (ret < 0) {
      fmt::print("receive < 0 ! ({})\n", _sock);
      return tl::nullopt;
    } else if (ret == 0) {
      fmt::print("receive == 0 ! ({})\n", _sock);
      return tl::nullopt;
    }
    size += ret;
  } while (size != sizeof(HEADER));
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

  if (!verifyPacketHeaderLength(*decrypted)) {
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

bool SocketManager::verifyPacket(Packet p) {
#if 0
  // debug log
  auto verifySeq = [&recv_seq = recv_seq_, this](Packet p) {
    bool success = verifyPacketSeq(p, recv_seq);
    // debug log
    return success ? unit_(p) : nullopt;
  };
  auto verifyHeaderLength = [this](Packet p) {
    bool success = verifyPacketHeaderLength(p);
    // debug log
    return success ? unit_(p) : nullopt;
  };
  auto verifyHash = [this](Packet p) {
    bool success = verifyPacketHash(p);
    // debug log
    return success ? unit_(p) : nullopt;
  };
  auto verifyBodyHeaderType = [state = state_, this](Packet p) {
    bool success = verifyPacketBodyHeaderType(p, state);
    // debug log
    return success ? unit_(p) : nullopt;
  };
  auto verifyBodyHeaderLength = [this](Packet p) {
    bool success = verifyPacketBodyHeaderLength(p);
    // debug log
    return success ? unit_(p) : nullopt;
  };

  auto result = p | verifySeq | verifyHeaderLength | verifyHash | verifyBodyHeaderType | verifyBodyHeaderLength;

  // debug log

  return (result) ? true : false;
#endif
  return true;
}

bool SocketManager::verifyPacketSeq(Packet p, uint16_t &recv_seq) {
  uint16_t seq = p.getSeq();
  // debug log
  if (recv_seq == 65535)
    recv_seq = 0;
  if (recv_seq == 0) {
    recv_seq = seq;
    return true;
  } else if (recv_seq < seq) {
    recv_seq = seq;
    return true;
  }
  return false;
}

bool SocketManager::verifyPacketHeaderLength(Packet p) {
  if (p.getHeaderLength() == p.size() - sizeof(HEADER)) {
    return true;
  }

  // error log
  return false;
}

bool SocketManager::verifyPacketHash(Packet p) {
  p = p;
  return true;
}

bool SocketManager::verifyPacketBodyHeaderType(Packet p, ConnectionState state) {
  if (state == ConnectionState::LOGIN_REQUEST_START)
    return p.getBodyHeaderType() == Messages::S2C_LOGIN_RESPONSE;
  if (state == ConnectionState::LOGIN_REQUEST_CHALLENGE)
    return p.getBodyHeaderType() == Messages::S2C_LOGIN_RESPONSE;
  if (state == ConnectionState::REQUEST_DATA)
    return p.getBodyHeaderType() == Messages::S2C_DATA_RESPONSE;
  return false;
}

bool SocketManager::verifyPacketBodyHeaderLength(Packet p) {
  if (p.getBodyHeaderLength() == p.size() - sizeof(HEADER) - sizeof(BODYHEADER))
    return true;
  return false;
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

void SocketManager::sendHashData() {
  while (!_hashs.empty()) {
    auto hash = _hashs.front();
    _hashs.pop_front();

    Packet p;

    p.makeHashSensorID(_sensor_id);
    p.makeHashData(hash.first, hash.second);
    p.makeDataResponseBody(DataResponse::SENSOR_HASH);
    p.makeDataResponseBodyHeader();
    p.makeHeader(_send_seq++);

    p.encrypt(_sharedkey);

    sendData(p);
  }
}

void SocketManager::sendSessionData() {
  while (!_sessions.empty()) {
    auto session = _sessions.front();
    _sessions.pop_front();
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