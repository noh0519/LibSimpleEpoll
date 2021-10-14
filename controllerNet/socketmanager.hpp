#ifndef _SOCKETMANAGER_HPP_
#define _SOCKETMANAGER_HPP_

#include "md5.hpp"
#include "packet.hpp"
#include "optional.hpp"
#include <string>
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

public:
  SocketManager(const char *sharedkey);

  bool isConnected();

  int getSock();
  void setSock(int sock);

  void setState(ConnectionState state);

  void loginReadFunc(int fd, short what);
  void loginWriteFunc(int fd, short what);

private:
  uint32_t getHeaderLength(std::vector<uint8_t> vec);

  void recvData(Packet &p);
  void sendData(Packet &p);
  bool verifyPacketHeaderLength(std::vector<uint8_t> vec);
  tl::optional<uint32_t> getNonce(std::vector<uint8_t> vec);
  void calcControllerAuthCode(const uint32_t &nonce);
  void calcSensorAuthCode(const uint32_t &nonce);
  void sendLoginChallenge();
  void sendLoginSuccess();
};

#endif /* _SOCKETMANAGER_HPP_ */