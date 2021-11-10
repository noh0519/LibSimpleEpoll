#ifndef _SOCKETMANAGER_HPP_
#define _SOCKETMANAGER_HPP_

#include "md5.hpp"
#include "optional.hpp"
#include "packet.hpp"
#include "pol_collector.hpp"
#include "publicmemory.hpp"
#include "wlan_provider.hpp"
#include <list>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/epoll.h>
#include <thread>
#include <utility>
#include <vector>

class WlanProvider;
class PolCollector;

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

  std::shared_ptr<WlanProvider> _wp;
  std::shared_ptr<PolCollector> _pc;

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
  /* ~recv data storage */

  std::list<SendSignalType> _send_signal_types;

public:
  SocketManager(const char *sharedkey);
  ~SocketManager();

  bool isConnected();

  int getSock();
  void setSock(int sock);

  ConnectionState getState();
  void setState(ConnectionState state);

  ConnectionMode getMode();

  void setWlanProvider(std::shared_ptr<WlanProvider> wp);
  void setPolCollector(std::shared_ptr<PolCollector> pc);

  void loginReadFunc(int fd, short what);
  void dataWriteFunc(int fd, short what);
  void configReadFunc(int fd, short what);

  void pushSendSignalType(SendSignalType sst);

private:
  void recvConfigData(Packet p);
  void checkSendSignalType();

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

  void sendHashData(std::vector<SendSignalType> signals);
  void sendSessionData();

  void sendSessionAPData(AP ap);
  void sendSessionAPsData(std::vector<AP> aps);
  void sendSessionClientData(Client client);
  void sendSessionClientsData(std::vector<Client> clients);
  void sendSensorInfo();

  AP getAPFromJson(nlohmann::json j);
  Client getClientFromJson(nlohmann::json j, uint64_t bssid, uint8_t channel);
};

#endif /* _SOCKETMANAGER_HPP_ */