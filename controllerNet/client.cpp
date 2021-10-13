#include "client.hpp"
#include "mac_util.hpp"
#include <arpa/inet.h>
// #include <fmt/format.h>

Client::Client() {}

Client::~Client() {}

std::vector<uint8_t> Client::getClientDataBSSID() const {
  std::vector<uint8_t> band_bssid;
  band_bssid.push_back(channel_ < 14 ? 1 : 2);
  std::vector<uint8_t> mac_byte = mac::mac_to_byte(bssid_);
  band_bssid.insert(band_bssid.end(), mac_byte.begin(), mac_byte.end());
  return band_bssid;
}

std::vector<uint8_t> Client::getClientDataClientMAC() const {
  std::vector<uint8_t> client_mac = mac::mac_to_byte(client_mac_);
  return client_mac;
}

std::vector<uint8_t> Client::getClientDataEAPID() const {
  std::vector<uint8_t> eap_id;
  eap_id.insert(eap_id.end(), eap_id_, eap_id_ + 32);
  return eap_id;
}

std::vector<uint8_t> Client::getClientDataDataRate() const {
  std::vector<uint8_t> data_rate;
  data_rate.insert(data_rate.end(), &data_rate_, &data_rate_ + sizeof(data_rate_));
  return data_rate;
}

std::vector<uint8_t> Client::getClientDataNoise() const {
  std::vector<uint8_t> sn;
  sn.insert(sn.end(), &noise_, &noise_ + sizeof(noise_));
  return sn;
}

std::vector<uint8_t> Client::getClientDataRSSI() const {
  std::vector<uint8_t> rssi;
  int8_t rrssi = -90;
  rssi.insert(rssi.end(), &rrssi, &rrssi + sizeof(rrssi));
  return rssi;
}

std::vector<uint8_t> Client::getClientDataMimo() const {
  std::vector<uint8_t> mimo;
  mimo.insert(mimo.end(), &mimo_, &mimo_ + sizeof(mimo_));
  return mimo;
}

std::vector<uint8_t> Client::getClientDataSignature() const {
  std::vector<uint8_t> signature;
  signature.insert(signature.end(), signature_, signature_ + sizeof(signature_));
  return signature;
}

std::vector<uint8_t> Client::getClientDataSignature5() const {
  std::vector<uint8_t> signature;
  signature.insert(signature.end(), signature5_, signature5_ + sizeof(signature5_));
  return signature;
}

std::vector<uint8_t> Client::getClientDataDataSize() const {
  std::vector<uint8_t> data_size;
  data_size.insert(data_size.end(), &data_size_, &data_size_ + sizeof(data_size_));
  return data_size;
}

std::vector<uint8_t> Client::getClientDataMgntCnt() const {
  std::vector<uint8_t> mgnt_cnt;
  auto c = htonl(mgnt_count_);
  mgnt_cnt.insert(mgnt_cnt.end(), &c, &c + sizeof(c));
  return mgnt_cnt;
}

std::vector<uint8_t> Client::getClientDataCtrlCnt() const {
  std::vector<uint8_t> ctrl_cnt;
  auto c = htonl(ctrl_count_);
  ctrl_cnt.insert(ctrl_cnt.end(), &c, &c + sizeof(c));
  return ctrl_cnt;
}

std::vector<uint8_t> Client::getClientDataDataCnt() const {
  std::vector<uint8_t> data_cnt;
  auto c = htonl(data_count_);
  data_cnt.insert(data_cnt.end(), &c, &c + sizeof(c));
  return data_cnt;
}

std::vector<uint8_t> Client::getClientDataAuthCnt() const {
  std::vector<uint8_t> auth_cnt;
  auto c = htonl(auth_count_);
  auth_cnt.insert(auth_cnt.end(), &c, &c + sizeof(c));
  return auth_cnt;
}

std::vector<uint8_t> Client::getClientDataLastDT() const {
  std::vector<uint8_t> last_dt;
  last_dt.insert(last_dt.end(), &last_dt_, &last_dt_ + sizeof(last_dt_));
  return last_dt;
}

std::vector<uint8_t> Client::getClientDataProbeDT() const {
  std::vector<uint8_t> probe_dt;
  probe_dt.insert(probe_dt.end(), &probe_dt_, &probe_dt_ + sizeof(probe_dt_));
  return probe_dt;
}
