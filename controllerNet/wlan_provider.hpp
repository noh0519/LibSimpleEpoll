#ifndef _WLAN_PROVIDER_HPP_
#define _WLAN_PROVIDER_HPP_

#include "socketmanager.hpp"
#include <memory>
#include <vector>

class WlanProvider {
public:
private:
  std::vector<std::shared_ptr<SocketManager>> m_sockmans;

protected:
public:
  WlanProvider();
  ~WlanProvider();

  void run();

  void setSockMan(std::shared_ptr<SocketManager> sockman);

private:
protected:
};

#endif /* _WLAN_PROVIDER_HPP_ */