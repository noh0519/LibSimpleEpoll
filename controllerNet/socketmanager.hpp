#ifndef _SOCKETMANAGER_HPP_
#define _SOCKETMANAGER_HPP_

#include "md5.hpp"
#include "optional.hpp"
#include "packet.hpp"
#include <list>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/epoll.h>
#include <thread>
#include <vector>

class SocketManager {
public:
private:
  int _sock = -1;

  uint32_t _sensor_id = 0;
  std::string _sharedkey = "";
  ConnectionState _state = ConnectionState::INIT;
  ConnectionMode _mode = ConnectionMode::UNKNOWN;

  uint16_t _recv_seq = 0;
  uint16_t _send_seq = 0;
  uint8_t _s_auth[16] = {0};
  uint8_t _c_auth[16] = {0};

  /* recv data storage */
  nlohmann::json _auth_aps;
  nlohmann::json _auth_clients;
  nlohmann::json _guest_aps;
  nlohmann::json _guest_clients;
  nlohmann::json _external_aps;
  nlohmann::json _external_clients;
  nlohmann::json _except_aps;
  nlohmann::json _except_clients;
  nlohmann::json _rogue_aps;
  nlohmann::json _rogue_clients;
  nlohmann::json _threat_policy;
  nlohmann::json _block;
  nlohmann::json _admin_block;
  nlohmann::json _sensor_setting;

  std::vector<uint8_t> _auth_clients_hash;
  std::vector<uint8_t> _auth_aps_hash;
  std::vector<uint8_t> _guest_aps_hash;
  std::vector<uint8_t> _guest_clients_hash;
  std::vector<uint8_t> _external_aps_hash;
  std::vector<uint8_t> _external_clients_hash;
  std::vector<uint8_t> _except_aps_hash;
  std::vector<uint8_t> _except_clients_hash;
  std::vector<uint8_t> _rogue_aps_hash;
  std::vector<uint8_t> _rogue_clients_hash;
  std::vector<uint8_t> _threat_policy_hash;
  std::vector<uint8_t> _block_hash;
  std::vector<uint8_t> _admin_block_hash;
  std::vector<uint8_t> _sensor_setting_hash;
  /* ~recv data storage */

  std::list<nlohmann::json> _sessions;

public:
  SocketManager(const char *sharedkey);
  ~SocketManager();

  bool isConnected();

  int getSock();
  void setSock(int sock);

  ConnectionState getState();
  void setState(ConnectionState state);

  ConnectionMode getMode();

  void loginReadFunc(int fd, short what);
  void dataWriteFunc(int fd, short what);
  void configReadFunc(int fd, short what);

  void pushSessionData(nlohmann::json sessions);

private:
  void recvConfigData(Packet p);

  void setWhiteList(uint8_t *data, uint16_t length, SetConfigList setcfg);
  void setThreatPolicy(uint8_t *data, uint16_t length);
  void setTimeSync(uint8_t *data, uint16_t length);
  void setGeneralConfig(uint8_t *data, uint16_t length);
  void setHash(uint8_t *data, uint16_t length, SetConfigList setcfg);

  std::string getThreatPolicyName(uint16_t pol_code);

  void flushConfigData(SetConfigList setcfg);

  tl::optional<Packet> recvData();
  void sendData(Packet &p);

  void calcControllerAuthCode(const uint32_t &nonce);
  void calcSensorAuthCode(const uint32_t &nonce);

  /* verify packet */
  bool verifyPacket(Packet p);
  bool verifyPacketSeq(Packet p, uint16_t &recv_seq);
  bool verifyPacketHeaderLength(Packet p);
  bool verifyPacketHash(Packet p);
  bool verifyPacketBodyHeaderType(Packet p, ConnectionState state);
  bool verifyPacketBodyHeaderLength(Packet p);

  void sendLoginChallenge();
  void sendLoginSuccess();
  void sendSessionData(nlohmann::json session);
  void sendSessionAPData(AP ap);
  void sendSessionAPsData(std::vector<AP> aps);
  void sendSessionClientData(Client client);
  void sendSessionClientsData(std::vector<Client> clients);
  void sendSensorInfo();

  AP getAPFromJson(nlohmann::json j);
  Client getClientFromJson(nlohmann::json j, uint64_t bssid, uint8_t channel);
};

#endif /* _SOCKETMANAGER_HPP_ */