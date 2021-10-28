#ifndef _POL_COLLECTOR_HPP_
#define _POL_COLLECTOR_HPP_

#include "SEpoll.hpp"
#include "socketmanager.hpp"
#include <memory>
#include <nlohmann/json.hpp>
#include <stdint.h>
#include <string>
#include <vector>

class PolCollector {
public:
private:
  std::shared_ptr<SEpoll<SocketManager>> _sepoll_ref;
  std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> _total_sockmans_ref;
  std::vector<std::shared_ptr<SocketManager>> _sockmans;

protected:
public:
  PolCollector();
  ~PolCollector();

  void run();

  void setSEpollRef(std::shared_ptr<SEpoll<SocketManager>> sepoll_ref);
  void setTotalSockMansRef(std::shared_ptr<std::vector<std::shared_ptr<SocketManager>>> total_sockmans_ref);
  void setSockMan(std::shared_ptr<SocketManager> sockman);

private:
protected:
};

#endif /* _POL_COLLECTOR_HPP_ */