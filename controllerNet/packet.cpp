#include "packet.hpp"

#include <arpa/inet.h>
// #include <fmt/format.h>
#include <string.h>

#include "enums.hpp"
#include "mac_util.hpp"
#include "md5.hpp"
#include "sha256.hpp"

Packet::Packet(){};

Packet::~Packet(){};

void Packet::insert(uint8_t *buf, size_t len) { d_.insert(d_.end(), buf, buf + len); }

uint16_t Packet::getSeq() {
  Header *h = reinterpret_cast<Header *>(&d_[0]);
  uint16_t seq;
  memcpy(&seq, &(*h).seq, sizeof(seq));
  seq = ntohs(seq);
  return seq;
}

uint16_t Packet::getHeaderLength() {
  Header *h = reinterpret_cast<Header *>(&d_[0]);
  uint16_t length = ntohs((*h).length);
  return length;
}

uint16_t Packet::getBodyHeaderLength() {
  Bodyheader *b = reinterpret_cast<Bodyheader *>(&d_[sizeof(Header)]);
  return ntohs((*b).length);
}

Messages Packet::getBodyHeaderType() {
  Bodyheader *b = reinterpret_cast<Bodyheader *>(&d_[sizeof(Header)]);
  return (*b).type;
}

std::vector<uint8_t> Packet::getAuthCode() {
  std::vector<uint8_t> auth_code;
  int32_t body_pos = sizeof(Header) + sizeof(Bodyheader);
  TLV *body = reinterpret_cast<TLV *>(&d_[body_pos]);
  uint16_t length = 0;

  if (static_cast<LoginRequest>((*body).type) != LoginRequest::CHALLENGE) {
    // fmt::print("Not body type challenge : {}\n", static_cast<int>((*body).type));
    printf("Not body type challenge : %d\n", static_cast<int>((*body).type));
    return auth_code;
  }
  while (true) {
    LOGIN_REQUEST_TLV *tlv = reinterpret_cast<LOGIN_REQUEST_TLV *>(&d_[body_pos + sizeof(*body) + length]);

    if ((*tlv).type == LoginValue::AUTH) {
      int data_pos = body_pos + sizeof(*body) + length + 3;
      auth_code.insert(auth_code.end(), &d_[data_pos], &d_[data_pos + ntohs((*tlv).length)]);
      return auth_code;
    }

    length = ntohs((*tlv).length);
    if (length >= ntohs((*body).length)) {
      break;
    }
  }
  return auth_code;
}

tl::optional<uint32_t> Packet::getNonce() {
  uint32_t *nonce;
  int32_t body_pos = sizeof(Header) + sizeof(Bodyheader);
  TLV *body = reinterpret_cast<TLV *>(&d_[body_pos]);
  uint16_t length = 0;

  if (static_cast<LoginRequest>((*body).type) != LoginRequest::START) {
    // fmt::print("Not body type challenge : {}\n", (*body).type);
    return tl::nullopt;
  }
  while (true) {
    TLV *tlv = reinterpret_cast<TLV *>(&d_[body_pos + sizeof(*body) + length]);

    if (static_cast<LoginValue>((*tlv).type) == LoginValue::NONCE) {
      int data_pos = body_pos + sizeof(*body) + length + 3;
      nonce = reinterpret_cast<uint32_t *>(&d_[data_pos]);
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

tl::optional<uint32_t> Packet::getSensorID() {
  uint32_t *sensor_id;
  int32_t body_pos = sizeof(Header) + sizeof(Bodyheader);
  TLV *body = reinterpret_cast<TLV *>(&d_[body_pos]);
  uint16_t length = 0;

  if (static_cast<SetConfig>((*body).type) != SetConfig::SENSOR_ID) {
    // fmt::print("Not body type set_sensor_id : {}\n", (*body).type);
    return tl::nullopt;
  }
  while (true) {
    TLV *tlv = reinterpret_cast<TLV *>(&d_[body_pos + sizeof(*body) + length]);

    if (static_cast<SetSensorIDValue>((*tlv).type) == SetSensorIDValue::SENSOR_ID) {
      int data_pos = body_pos + sizeof(*body) + length + 3;
      sensor_id = reinterpret_cast<uint32_t *>(&d_[data_pos]);
      auto s = ntohl(*sensor_id);
      return tl::make_optional<uint32_t>(s);
    }

    length += 3 + ntohs((*tlv).length);
    if (length >= ntohs((*body).length)) {
      break;
    }
  }
  return tl::nullopt;
}

tl::optional<ConnectionMode> Packet::getMode() {
  if (getBodyHeaderType() == Messages::C2S_DATA_REQUEST)
    return tl::make_optional(ConnectionMode::DATA);
  if (getBodyHeaderType() == Messages::C2S_SET_CONFIG)
    return tl::make_optional(ConnectionMode::CONFIG);
  return tl::nullopt;
}

size_t Packet::size() { return d_.size(); }
uint8_t *Packet::data() { return d_.data(); }

tl::optional<Packet> Packet::encrypt(Packet &p, const std::string &shared_key) {
  Packet enc_packet;
  enc_packet.insert(p.data(), p.size());
  return tl::make_optional(enc_packet);
}

tl::optional<Packet> Packet::decrypt(Packet &p, const std::string &shared_key) {
  Packet decrypt_packet;
  decrypt_packet.insert(p.data(), p.size());

  return tl::make_optional(decrypt_packet);
}

bool Packet::verifySeqence(Packet &p, uint16_t &prev_seq) {
  uint16_t seq = p.getSeq();
  if (prev_seq == 65535)
    prev_seq = 0;
  if (prev_seq == 0) {
    prev_seq = seq;
    return true;
  } else if (prev_seq < seq) {
    prev_seq = seq;
    return true;
  }
  return false;
}

bool Packet::verifyPacketHeaderLength(Packet p) {
  if (p.getHeaderLength() == p.size() - sizeof(Header)) {
    return true;
  }
  //   fmt::print("===> verifyHeaderLength failed - header_len: {} != data_len: {} - sizeof(header): {}", p.getHeaderLength(), p.size(),
  //              sizeof(Header));
  return false;
}

bool Packet::verifyPacketHash(Packet p) { return true; }

bool Packet::verifyPacketBodyHeaderType(Packet p, ConnectionState state) {
  if (state == ConnectionState::LOGIN_REQUEST_START)
    return p.getBodyHeaderType() == Messages::S2C_LOGIN_RESPONSE;
  if (state == ConnectionState::LOGIN_REQUEST_CHALLENGE)
    return p.getBodyHeaderType() == Messages::S2C_LOGIN_RESPONSE;
  if (state == ConnectionState::REQUEST_DATA)
    return p.getBodyHeaderType() == Messages::S2C_DATA_RESPONSE;
  return false;
}

bool Packet::verifyPacketBodyHeaderLength(Packet p) {
  if (p.getBodyHeaderLength() == p.size() - sizeof(Header) - sizeof(Bodyheader))
    return true;
  return false;
}

bool Packet::verifyAuth(Packet p) {
  // vector<uint8_t> auth_code = p.getAuthCode();
  // tl::optional<uint32_t> nonce  = p.getNonce();
  // if (nonce) {
  // }
  //
  // return true;
}

void Packet::makeSensorID(const uint32_t &sensor_id) {
  auto s_id = htonl(sensor_id);
  auto length = htons(static_cast<uint16_t>(sizeof(sensor_id)));

  d_.insert(d_.end(), static_cast<uint8_t>(DataValue::SENSOR_ID));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&s_id), reinterpret_cast<uint8_t *>(&s_id) + sizeof(s_id));
}

void Packet::makeSensorMAC(const uint64_t &mac) {
  auto s_mac = mac::mac_to_byte(mac);
  auto length = htons(static_cast<uint16_t>(s_mac.size()));

  d_.insert(d_.end(), static_cast<uint8_t>(SensorStatusDataValue::MAC_ADDRESS));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), s_mac.begin(), s_mac.end());
}

void Packet::makeSensorIP(const std::string &ip) {
  auto length = htons(static_cast<uint16_t>(ip.size()));

  d_.insert(d_.end(), static_cast<uint8_t>(SensorStatusDataValue::IP_ADDRESS));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), ip.begin(), ip.end());
}

void Packet::makeSensorVersion(const std::string &ver) {
  auto length = htons(static_cast<uint16_t>(ver.size()));

  d_.insert(d_.end(), static_cast<uint8_t>(SensorStatusDataValue::SENSOR_VERSION));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), ver.begin(), ver.end());
}

void Packet::makeSensorRevision(const uint32_t &rev) {
  auto s_rev = htonl(rev);
  auto length = htons(static_cast<uint16_t>(sizeof(rev)));

  d_.insert(d_.end(), static_cast<uint8_t>(SensorStatusDataValue::SENSOR_REVISION));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&s_rev), reinterpret_cast<uint8_t *>(&s_rev) + sizeof(s_rev));
}

void Packet::makeSensorModel(const uint8_t &model) {
  auto length = htons(static_cast<uint16_t>(sizeof(model)));

  d_.insert(d_.end(), static_cast<uint8_t>(SensorStatusDataValue::SENSOR_MODEL));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), model);
}

tl::optional<Packet> Packet::makeSessionAPData(const int &index, const uint32_t &sensor_id, const uint16_t &send_seq,
                                               const std::string shared_key) {
  Packet p;

  p.makeSensorID(sensor_id);
  // TODO:
  //   for (int i = index; i < index + Global::once_aps_; i++) {
  //     p.makeAPData(*(Global::aps_[i % Global::aps_.size()]));
  //   }
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(send_seq);

  return Packet::encrypt(p, shared_key);
}

tl::optional<Packet> Packet::makeSessionAPs(std::vector<APPtr> aps, const uint32_t &sensor_id, const uint16_t &send_seq,
                                            const std::string shared_key) {
  Packet p;

  p.makeSensorID(sensor_id);
  for (auto ap : aps) {
    p.makeAPData(*ap);
  }
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(send_seq);

  return Packet::encrypt(p, shared_key);
}

tl::optional<Packet> Packet::makeSessionClientData(const int &index, const uint32_t &sensor_id, const uint16_t &send_seq,
                                                   const std::string shared_key) {
  Packet p;

  p.makeSensorID(sensor_id);
  // TODO:
  //   for (int i = index; i < index + Global::once_clients_; i++) {
  //     p.makeClientData((*Global::clients_[i % Global::clients_.size()]));
  //   }
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(send_seq);

  return Packet::encrypt(p, shared_key);
}

tl::optional<Packet> Packet::makeSessionClients(std::vector<ClientPtr> clients, const uint32_t &sensor_id, const uint16_t &send_seq,
                                                const std::string shared_key) {
  Packet p;

  p.makeSensorID(sensor_id);
  for (auto client : clients) {
    p.makeClientData(*client);
  }
  p.makeDataResponseBody(DataResponse::DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(send_seq);

  return Packet::encrypt(p, shared_key);
}

tl::optional<Packet> Packet::makeSensorInfo(const uint32_t &sensor_id, const SensorInfo &si, const uint16_t &send_seq,
                                            const std::string shared_key) {
  Packet p;

  p.makeSensorID(sensor_id);
  p.makeSensorMAC(si.mac);
  p.makeSensorIP(si.ip);
  p.makeSensorVersion(si.version);
  p.makeSensorRevision(si.revision);
  p.makeSensorModel(si.model);

  p.makeDataResponseBody(DataResponse::SENSOR_STATUS_DATA);
  p.makeDataResponseBodyHeader();
  p.makeHeader(send_seq);

  return Packet::encrypt(p, shared_key);
}

void Packet::makeAPData(const AP &ap) {
  Packet p;

  std::vector<uint8_t> band_bssid = ap.getAPDataBSSID();
  p.makeAPDataTLV(APData::BSSID, band_bssid.size(), band_bssid.data());

  std::vector<uint8_t> ssid = ap.getAPDataSSID();
  p.makeAPDataTLV(APData::SSID, ssid.size(), ssid.data());

  std::vector<uint8_t> channel = ap.getAPDataChannel();
  p.makeAPDataTLV(APData::CHANNEL, channel.size(), channel.data());

  std::vector<uint8_t> rssi = ap.getAPDataRSSI();
  p.makeAPDataTLV(APData::RSSI, rssi.size(), rssi.data());

  std::vector<uint8_t> cipher = ap.getAPDataCipher();
  p.makeAPDataTLV(APData::CIPHER, cipher.size(), cipher.data());

  std::vector<uint8_t> protocol = ap.getAPDataProtocol();
  p.makeAPDataTLV(APData::PROTOCOL, protocol.size(), protocol.data());

  std::vector<uint8_t> auth = ap.getAPDataAuth();
  p.makeAPDataTLV(APData::AUTH, auth.size(), auth.data());

  std::vector<uint8_t> mode = ap.getAPDataMode();
  p.makeAPDataTLV(APData::MODE, mode.size(), mode.data());

  std::vector<uint8_t> signature = ap.getAPDataSignature();
  p.makeAPDataTLV(APData::SIGNATURE, signature.size(), signature.data());

  std::vector<uint8_t> ssid_b = ap.getAPDataSSIDBroadcast();
  p.makeAPDataTLV(APData::SSID_BROADCAST, ssid_b.size(), ssid_b.data());

  std::vector<uint8_t> m_cnt = ap.getAPDataMgntCnt();
  p.makeAPDataTLV(APData::MNGFRM_CNT, m_cnt.size(), m_cnt.data());

  std::vector<uint8_t> c_cnt = ap.getAPDataCtrlCnt();
  p.makeAPDataTLV(APData::CTRLFRM_CNT, c_cnt.size(), c_cnt.data());

  std::vector<uint8_t> wds_peer = ap.getAPDataWDSPeer();
  p.makeAPDataTLV(APData::WDS_AP, wds_peer.size(), wds_peer.data());

  std::vector<uint8_t> data_rate = ap.getAPDataDataRate();
  p.makeAPDataTLV(APData::DATA_RATE, data_rate.size(), data_rate.data());

  std::vector<uint8_t> mcs = ap.getAPDataMCS();
  p.makeAPDataTLV(APData::MCS, mcs.size(), mcs.data());

  std::vector<uint8_t> channel_width = ap.getAPDataChannelWidth();
  p.makeAPDataTLV(APData::CHANNEL_WIDTH, channel_width.size(), channel_width.data());

  std::vector<uint8_t> mimo = ap.getAPDataMimo();
  p.makeAPDataTLV(APData::MIMO, mimo.size(), mimo.data());

  std::vector<uint8_t> highest_rate = ap.getAPDataHighestRate();
  p.makeAPDataTLV(APData::HIGHEST_RATE, highest_rate.size(), highest_rate.data());

  std::vector<uint8_t> ss = ap.getAPDataSpatialStream();
  p.makeAPDataTLV(APData::SPATIAL_STREAM, ss.size(), ss.data());

  std::vector<uint8_t> gi = ap.getAPDataGuardInterval();
  p.makeAPDataTLV(APData::GUARD_INTERVAL, gi.size(), gi.data());

  std::vector<uint8_t> wps = ap.getAPDataWPS();
  p.makeAPDataTLV(APData::WPS, wps.size(), wps.data());

  std::vector<uint8_t> pmf = ap.getAPDataPMF();
  p.makeAPDataTLV(APData::PMF, pmf.size(), pmf.data());

  std::vector<uint8_t> last_dt = ap.getAPDataLastDT();
  p.makeAPDataTLV(APData::LAST_DT, last_dt.size(), last_dt.data());

  std::vector<uint8_t> probe_dt = ap.getAPDataProbeDT();
  p.makeAPDataTLV(APData::PROBE_DT, probe_dt.size(), probe_dt.data());

  uint16_t length = htons((uint16_t)p.d_.size());
  d_.insert(d_.end(), static_cast<uint8_t>(DataValue::APS));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), p.d_.begin(), p.d_.end());
}

void Packet::makeClientData(const Client &client) {
  Packet p;

  std::vector<uint8_t> band_bssid = client.getClientDataBSSID();
  p.makeClientDataTLV(ClientData::BSSID, band_bssid.size(), band_bssid.data());

  std::vector<uint8_t> client_mac = client.getClientDataClientMAC();
  p.makeClientDataTLV(ClientData::CLIENT_MAC, client_mac.size(), client_mac.data());

  std::vector<uint8_t> eap_id = client.getClientDataEAPID();
  p.makeClientDataTLV(ClientData::EAP_ID, eap_id.size(), eap_id.data());

  std::vector<uint8_t> data_rate = client.getClientDataDataRate();
  p.makeClientDataTLV(ClientData::DATA_RATE, data_rate.size(), data_rate.data());

  std::vector<uint8_t> noise = client.getClientDataNoise();
  p.makeClientDataTLV(ClientData::SN, noise.size(), noise.data());

  std::vector<uint8_t> rssi = client.getClientDataRSSI();
  p.makeClientDataTLV(ClientData::RSSI, rssi.size(), rssi.data());

  std::vector<uint8_t> mimo = client.getClientDataMimo();
  p.makeClientDataTLV(ClientData::MIMO, mimo.size(), mimo.data());

  std::vector<uint8_t> sig = client.getClientDataSignature();
  p.makeClientDataTLV(ClientData::SIGNATURE, sig.size(), sig.data());

  std::vector<uint8_t> sig5 = client.getClientDataSignature5();
  p.makeClientDataTLV(ClientData::SIGNATURE_5, sig5.size(), sig5.data());

  std::vector<uint8_t> data_size = client.getClientDataDataSize();
  p.makeClientDataTLV(ClientData::DATA_SIZE, data_size.size(), data_size.data());

  std::vector<uint8_t> m_cnt = client.getClientDataMgntCnt();
  p.makeClientDataTLV(ClientData::MNGFRM_CNT, m_cnt.size(), m_cnt.data());

  std::vector<uint8_t> c_cnt = client.getClientDataCtrlCnt();
  p.makeClientDataTLV(ClientData::CTRLFRM_CNT, c_cnt.size(), c_cnt.data());

  std::vector<uint8_t> d_cnt = client.getClientDataDataCnt();
  p.makeClientDataTLV(ClientData::DATAFRM_CNT, d_cnt.size(), d_cnt.data());

  std::vector<uint8_t> a_cnt = client.getClientDataAuthCnt();
  p.makeClientDataTLV(ClientData::AUTH_COUNT, a_cnt.size(), a_cnt.data());

  std::vector<uint8_t> last_dt = client.getClientDataLastDT();
  p.makeClientDataTLV(ClientData::LAST_DT, last_dt.size(), last_dt.data());

  std::vector<uint8_t> probe_dt = client.getClientDataProbeDT();
  p.makeClientDataTLV(ClientData::PROBE_DT, probe_dt.size(), probe_dt.data());

  uint16_t length = htons((uint16_t)p.d_.size());
  d_.insert(d_.end(), static_cast<uint8_t>(DataValue::CLIENTS));
  d_.insert(d_.end(), reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  d_.insert(d_.end(), p.d_.begin(), p.d_.end());
}

void Packet::makeAPDataTLV(APData type, uint16_t len, const uint8_t *data) {
  uint8_t length[2];
  length[0] = len >> 8;
  length[1] = len;

  d_.insert(d_.end(), static_cast<uint8_t>(type));
  d_.insert(d_.end(), length, length + 2);
  d_.insert(d_.end(), data, data + len);
}

void Packet::makeClientDataTLV(ClientData type, uint16_t len, const uint8_t *data) {
  uint8_t length[2];
  length[0] = len >> 8;
  length[1] = len;

  d_.insert(d_.end(), static_cast<uint8_t>(type));
  d_.insert(d_.end(), length, length + 2);
  d_.insert(d_.end(), data, data + len);
}

void Packet::makeLoginResponseTLV(LoginValue type, uint16_t len, const uint8_t *data) {
  uint8_t length[2];
  length[0] = len >> 8;
  length[1] = len;

  d_.insert(d_.end(), static_cast<uint8_t>(type));
  d_.insert(d_.end(), length, length + 2);
  d_.insert(d_.end(), data, data + len);
}

void Packet::makeLoginResponseBody(LoginResponse type) {
  uint16_t length = htons(d_.size());

  auto type_pos = d_.begin();
  d_.insert(type_pos, static_cast<uint8_t>(type));

  auto length_pos = d_.begin() + sizeof(type);
  d_.insert(length_pos, reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
}

void Packet::makeLoginResponseBodyHeader() {
  Bodyheader b;

  b.type = Messages::S2C_LOGIN_RESPONSE;
  b.product = Product::SENSOR;
  b.length = htons(d_.size());
  b.res1 = 0;
  b.res2 = 0;

  d_.insert(d_.begin(), reinterpret_cast<uint8_t *>(&b), reinterpret_cast<uint8_t *>(&b) + sizeof(b));
}

void Packet::makeDataResponseBody(DataResponse type) {
  uint16_t length = htons(d_.size());

  auto type_pos = d_.begin();
  d_.insert(type_pos, static_cast<uint8_t>(type));

  auto length_pos = d_.begin() + sizeof(type);
  d_.insert(length_pos, reinterpret_cast<uint8_t *>(&length), reinterpret_cast<uint8_t *>(&length) + sizeof(length));
}

void Packet::makeDataResponseBodyHeader() {
  Bodyheader b;

  b.type = Messages::S2C_DATA_RESPONSE;
  b.product = Product::SENSOR;
  b.length = htons(d_.size());
  b.res1 = 0;
  b.res2 = 0;

  d_.insert(d_.begin(), reinterpret_cast<uint8_t *>(&b), reinterpret_cast<uint8_t *>(&b) + sizeof(b));
}

void Packet::makeHeader(uint16_t send_seq) {
  Flags flags;
  flags.cipher = 0;
  flags.fragment = 0;
  flags.reserved = 0;

  Header h;
  h.version = 0;
  h.seq = htons(send_seq);
  h.flags = flags;
  h.offset = 0;
  h.nonce = 0;
  h.subtype = Protocol::SWMP;
  h.res = 0;
  h.length = htons(d_.size());

  d_.insert(d_.begin(), reinterpret_cast<uint8_t *>(&h), reinterpret_cast<uint8_t *>(&h) + sizeof(h));
}

tl::optional<Packet> Packet::makeLoginResponseChallenge(const uint8_t *auth_code, const uint32_t &nonce, const uint16_t &send_seq,
                                                        const std::string shared_key) {
  Packet p;

  p.makeLoginResponseTLV(LoginValue::AUTH, MD5::HASH_SIZE, auth_code);
  uint32_t n = htonl(nonce);
  p.makeLoginResponseTLV(LoginValue::NONCE, sizeof(n), reinterpret_cast<uint8_t *>(&n));
  p.makeLoginResponseBody(LoginResponse::CHALLENGE);
  p.makeLoginResponseBodyHeader();
  p.makeHeader(send_seq);

  return Packet::encrypt(p, shared_key);
}

tl::optional<Packet> Packet::makeLoginSuccess(const uint16_t &send_seq, const std::string shared_key) {
  Packet p;

  p.makeLoginResponseBody(LoginResponse::OK);
  p.makeLoginResponseBodyHeader();
  p.makeHeader(send_seq);

  return Packet::encrypt(p, shared_key);
}

void Packet::print() {
#if 0
  Header *h = reinterpret_cast<Header *>(&d_[0]);

  fmt::print("+ Header --------------\n");
  fmt::print("| version: {:02x}\n", (*h).version);
  fmt::print("| seq    : {:04x}\n", ntohs((*h).seq));
  fmt::print("| flags  : {:02x} {:02x} {:04x}\n", static_cast<uint8_t>((*h).flags.cipher), static_cast<uint8_t>((*h).flags.fragment),
             static_cast<uint8_t>((*h).flags.reserved));
  fmt::print("| offset : {:02x}\n", (*h).offset);
  fmt::print("| option : {:02x}\n", (*h).option);
  fmt::print("| nonce  : {:04x}\n", ntohs((*h).nonce));
  fmt::print("| subtype: {:02x}\n", static_cast<uint8_t>((*h).subtype));
  fmt::print("| res    : {:02x}\n", (*h).res);
  fmt::print("| length : {:04x}\n", ntohs((*h).length));

  Bodyheader *b = reinterpret_cast<Bodyheader *>(&d_[sizeof(*h)]);

  fmt::print("+ Bodyheader ----------\n");
  fmt::print("| type   : {:02x}\n", static_cast<uint8_t>((*b).type));
  fmt::print("| product: {:02x}\n", static_cast<uint8_t>((*b).product));
  fmt::print("| length : {:04x}\n", ntohs((*b).length));
  fmt::print("| res1   : {:02x}\n", (*b).res1);
  fmt::print("| res2   : {:02x}\n", (*b).res2);
  fmt::print("+----------------------\n");

#if 0
  TLV *tlv = reinterpret_cast<TLV *>(&d_[sizeof(*h) + sizeof(*b)]);

  cm_logd("+ BODY ----------------");
  cm_logd("| type   : %02x", (*tlv).type);
  cm_logd("| length : %04x", ntohs((*tlv).length));
  cm_logd("+----------------------");
#endif
#endif
}