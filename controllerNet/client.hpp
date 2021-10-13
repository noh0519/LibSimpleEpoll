#ifndef _WIPS_STRESS_CLIENT_HPP_
#define _WIPS_STRESS_CLIENT_HPP_

#include "ap.hpp"
#include <memory>
#include <stdint.h>
#include <vector>

class Client {
public:
  uint64_t client_mac_ = 0;
  uint64_t bssid_ = 0;
  uint64_t channel_ = 0;
  char eap_id_[64] = {0};
  uint32_t data_rate_ = 0;
  int8_t noise_ = -90;
  int8_t rssi_ = -90;
  uint8_t mimo_ = 0;
  uint8_t signature_[32] = {0};
  uint8_t signature5_[32] = {0};
  uint8_t data_size_ = 0;
  uint32_t mgnt_count_ = 0;
  uint32_t ctrl_count_ = 0;
  uint32_t data_count_ = 0;
  uint32_t auth_count_ = 0;
  uint8_t last_dt_ = 0;
  uint8_t probe_dt_ = 0;

  std::weak_ptr<AP> ap_;

  Client();
  ~Client();

  std::vector<uint8_t> getClientDataBSSID() const;
  std::vector<uint8_t> getClientDataClientMAC() const;
  std::vector<uint8_t> getClientDataEAPID() const;
  std::vector<uint8_t> getClientDataDataRate() const;
  std::vector<uint8_t> getClientDataNoise() const;
  std::vector<uint8_t> getClientDataRSSI() const;
  std::vector<uint8_t> getClientDataMimo() const;
  std::vector<uint8_t> getClientDataSignature() const;
  std::vector<uint8_t> getClientDataSignature5() const;
  std::vector<uint8_t> getClientDataDataSize() const;
  std::vector<uint8_t> getClientDataMgntCnt() const;
  std::vector<uint8_t> getClientDataCtrlCnt() const;
  std::vector<uint8_t> getClientDataDataCnt() const;
  std::vector<uint8_t> getClientDataAuthCnt() const;
  std::vector<uint8_t> getClientDataLastDT() const;
  std::vector<uint8_t> getClientDataProbeDT() const;
};

#endif /* _WIPS_STRESS_CLIENT_HPP_ */