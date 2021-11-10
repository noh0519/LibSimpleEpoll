#ifndef _WLAN_PROVIDER_HPP_
#define _WLAN_PROVIDER_HPP_

#include "SEpoll.hpp"
#include "socketmanager.hpp"
#include <memory>
#include <nlohmann/json.hpp>
#include <stdint.h>
#include <string>
#include <vector>

class SocketManager;

class WlanProvider {
public:
private:
  std::shared_ptr<SEpoll<SocketManager>> _sepoll_ref;
  std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> _total_sockmans_ref;
  std::vector<std::shared_ptr<SocketManager>> _sockmans;

  std::list<SendSignalType> _send_signal_types;

protected:
public:
  WlanProvider();
  ~WlanProvider();

  void run();

  void setSEpollRef(std::shared_ptr<SEpoll<SocketManager>> sepoll_ref);
  void setTotalSockMansRef(std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> total_sockmans_ref);
  void setSockMan(std::shared_ptr<SocketManager> sockman);

  void pushSendSignalType(SendSignalType sst);

private:
  void checkSendSignalType();

protected:
};

#endif /* _WLAN_PROVIDER_HPP_ */