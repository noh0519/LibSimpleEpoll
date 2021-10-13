#include "ap.hpp"
#include "mac_util.hpp"
#include <arpa/inet.h>
// #include <fmt/format.h>

AP::AP() {}

AP::~AP() {}

std::vector<uint8_t> AP::getAPDataBSSID() const {
  std::vector<uint8_t> band_bssid;
  band_bssid.push_back(channel_ < 14 ? 1 : 2);
  std::vector<uint8_t> mac_byte = mac::mac_to_byte(bssid_);
  band_bssid.insert(band_bssid.end(), mac_byte.begin(), mac_byte.end());
  return band_bssid;
}

std::vector<uint8_t> AP::getAPDataSSID() const {
  std::vector<uint8_t> ssid;
  ssid.insert(ssid.end(), ssid_.begin(), ssid_.end());
  return ssid;
}

std::vector<uint8_t> AP::getAPDataChannel() const {
  std::vector<uint8_t> channel;
  channel.insert(channel.end(), channel_);
  return channel;
}

std::vector<uint8_t> AP::getAPDataRSSI() const {
  std::vector<uint8_t> rssi;
  int8_t rrssi = -90;
  rssi.insert(rssi.end(), &rrssi, &rrssi + sizeof(rrssi));
  return rssi;
}

std::vector<uint8_t> AP::getAPDataCipher() const {
  std::vector<uint8_t> cipher;
  cipher.insert(cipher.end(), &cipher_, &cipher_ + sizeof(cipher_));
  return cipher;
}

std::vector<uint8_t> AP::getAPDataProtocol() const {
  std::vector<uint8_t> protocol;
  protocol.insert(protocol.end(), &media_, &media_ + sizeof(media_));
  return protocol;
}

std::vector<uint8_t> AP::getAPDataAuth() const {
  std::vector<uint8_t> auth;
  auth.insert(auth.end(), &auth_, &auth_ + sizeof(auth_));
  return auth;
}

std::vector<uint8_t> AP::getAPDataMode() const {
  std::vector<uint8_t> mode;
  mode.insert(mode.end(), &net_type_, &net_type_ + sizeof(net_type_));
  return mode;
}

std::vector<uint8_t> AP::getAPDataSignature() const {
  std::vector<uint8_t> signature;
  signature.insert(signature.end(), signature_, signature_ + sizeof(signature_));
  return signature;
}

std::vector<uint8_t> AP::getAPDataSSIDBroadcast() const {
  std::vector<uint8_t> b;
  b.insert(b.end(), &ssid_broadcast_, &ssid_broadcast_ + sizeof(ssid_broadcast_));
  return b;
}

std::vector<uint8_t> AP::getAPDataMgntCnt() const {
  std::vector<uint8_t> mgnt_cnt;
  auto c = htonl(mgnt_count_);
  mgnt_cnt.insert(mgnt_cnt.end(), &c, &c + sizeof(c));
  return mgnt_cnt;
}

std::vector<uint8_t> AP::getAPDataCtrlCnt() const {
  std::vector<uint8_t> ctrl_cnt;
  auto c = htonl(ctrl_count_);
  ctrl_cnt.insert(ctrl_cnt.end(), &c, &c + sizeof(c));
  return ctrl_cnt;
}

std::vector<uint8_t> AP::getAPDataDataCnt() const {
  std::vector<uint8_t> data_cnt;
  auto c = htonl(data_count_);
  data_cnt.insert(data_cnt.end(), &c, &c + sizeof(c));
  return data_cnt;
}

std::vector<uint8_t> AP::getAPDataWDSPeer() const {
  std::vector<uint8_t> band_bssid;
  band_bssid.push_back(channel_ < 14 ? 1 : 2);
  std::vector<uint8_t> mac_byte = mac::mac_to_byte(wds_peer_);
  band_bssid.insert(band_bssid.end(), mac_byte.begin(), mac_byte.end());
  return band_bssid;
}

std::vector<uint8_t> AP::getAPDataDataRate() const {
  std::vector<uint8_t> data_rate;
  data_rate.insert(data_rate.end(), support_rate_, support_rate_ + 8);
  return data_rate;
}

std::vector<uint8_t> AP::getAPDataMCS() const {
  std::vector<uint8_t> mcs;
  mcs.insert(mcs.end(), &mcs_, &mcs_ + sizeof(mcs_));
  return mcs;
}

std::vector<uint8_t> AP::getAPDataChannelWidth() const {
  std::vector<uint8_t> cw;
  cw.insert(cw.end(), &channel_width_, &channel_width_ + sizeof(channel_width_));
  return cw;
}

std::vector<uint8_t> AP::getAPDataMimo() const {
  std::vector<uint8_t> mimo;
  mimo.insert(mimo.end(), &support_mimo_, &support_mimo_ + sizeof(support_mimo_));
  return mimo;
}

std::vector<uint8_t> AP::getAPDataHighestRate() const {
  std::vector<uint8_t> highest_rate;
  highest_rate.insert(highest_rate.end(), &highest_rate_, &highest_rate_ + sizeof(highest_rate_));
  return highest_rate;
}

std::vector<uint8_t> AP::getAPDataSpatialStream() const {
  std::vector<uint8_t> ss;
  ss.insert(ss.end(), &spatial_stream_, &spatial_stream_ + sizeof(spatial_stream_));
  return ss;
}

std::vector<uint8_t> AP::getAPDataGuardInterval() const {
  std::vector<uint8_t> gi;
  gi.insert(gi.end(), &guard_interval_, &guard_interval_ + sizeof(guard_interval_));
  return gi;
}

std::vector<uint8_t> AP::getAPDataWPS() const {
  std::vector<uint8_t> wps;
  wps.insert(wps.end(), &wps_, &wps_ + sizeof(wps_));
  return wps;
}

std::vector<uint8_t> AP::getAPDataPMF() const {
  std::vector<uint8_t> pmf;
  pmf.insert(pmf.end(), &pmf_, &pmf_ + sizeof(pmf_));
  return pmf;
}

std::vector<uint8_t> AP::getAPDataLastDT() const {
  std::vector<uint8_t> last_dt;
  last_dt.insert(last_dt.end(), &last_dt_, &last_dt_ + sizeof(last_dt_));
  return last_dt;
}

std::vector<uint8_t> AP::getAPDataProbeDT() const {
  std::vector<uint8_t> probe_dt;
  probe_dt.insert(probe_dt.end(), &probe_dt_, &probe_dt_ + sizeof(probe_dt_));
  return probe_dt;
}