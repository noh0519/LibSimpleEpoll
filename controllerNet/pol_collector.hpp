#ifndef _POL_COLLECTOR_HPP_
#define _POL_COLLECTOR_HPP_

#include "socketmanager.hpp"
#include <memory>
#include <vector>

class PolCollector {
public:
private:
  std::vector<std::shared_ptr<SocketManager>> m_sockmans;

protected:
public:
  PolCollector();
  ~PolCollector();

  void run();

  void setSockMan(std::shared_ptr<SocketManager> sockman);

private:
protected:
};

#endif /* _POL_COLLECTOR_HPP_ */