#ifndef _WIPS_STRESS_AP_HPP_
#define _WIPS_STRESS_AP_HPP_

#include <memory>
#include <string>
#include <vector>
#include "channel.hpp"

class Client;

class AP {
public:
  uint64_t bssid_ = 0;
  std::string ssid_ = "";
  uint8_t channel_ = 0;
  int8_t rssi_ = -90;
  uint8_t cipher_ = 4;
  uint8_t media_ = 1;
  uint8_t auth_ = 3;
  uint8_t net_type_ = 1;
  uint8_t signature_[32] = {0};
  bool ssid_broadcast_ = true;
  uint32_t mgnt_count_ = 0;
  uint32_t ctrl_count_ = 0;
  uint32_t data_count_ = 0;
  uint64_t wds_peer_ = 0;
  uint8_t support_rate_[16] = {0};
  uint32_t mcs_ = 0;
  uint8_t channel_width_ = 0;
  uint8_t support_mimo_ = 0;
  uint32_t highest_rate_ = 0;
  uint8_t spatial_stream_ = 0;
  uint8_t guard_interval_ = 0;
  bool wps_ = 1;
  bool pmf_ = 1;

  uint8_t last_dt_ = 0;
  uint8_t probe_dt_ = 0;

  std::vector<std::weak_ptr<Client>> clients_;

  AP();
  ~AP();

  std::vector<uint8_t> getAPDataBSSID() const;
  std::vector<uint8_t> getAPDataSSID() const;
  std::vector<uint8_t> getAPDataChannel() const;
  std::vector<uint8_t> getAPDataRSSI() const;
  std::vector<uint8_t> getAPDataCipher() const;
  std::vector<uint8_t> getAPDataProtocol() const;
  std::vector<uint8_t> getAPDataAuth() const;
  std::vector<uint8_t> getAPDataMode() const;
  std::vector<uint8_t> getAPDataSignature() const;
  std::vector<uint8_t> getAPDataSSIDBroadcast() const;
  std::vector<uint8_t> getAPDataMgntCnt() const;
  std::vector<uint8_t> getAPDataCtrlCnt() const;
  std::vector<uint8_t> getAPDataDataCnt() const;
  std::vector<uint8_t> getAPDataWDSPeer() const;
  std::vector<uint8_t> getAPDataDataRate() const;
  std::vector<uint8_t> getAPDataMCS() const;
  std::vector<uint8_t> getAPDataChannelWidth() const;
  std::vector<uint8_t> getAPDataMimo() const;
  std::vector<uint8_t> getAPDataHighestRate() const;
  std::vector<uint8_t> getAPDataSpatialStream() const;
  std::vector<uint8_t> getAPDataGuardInterval() const;
  std::vector<uint8_t> getAPDataWPS() const;
  std::vector<uint8_t> getAPDataPMF() const;
  std::vector<uint8_t> getAPDataLastDT() const;
  std::vector<uint8_t> getAPDataProbeDT() const;
};

#endif /* _WIPS_STRESS_AP_HPP_ */