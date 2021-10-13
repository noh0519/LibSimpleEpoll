#ifndef _WIPS_STRESS_MAC_UTIL_HPP_
#define _WIPS_STRESS_MAC_UTIL_HPP_

#include <string>
#include <vector>

// #include <fmt/format.h>

namespace mac {

static uint64_t string_to_mac(const std::string &mac_str) {
  unsigned char a[6];
  int last = -1;
  int rc = sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n", a + 0, a + 1, a + 2, a + 3, a + 4, a + 5, &last);
  if (rc != 6 || mac_str.size() != last)
    throw std::runtime_error("invalid mac address format " + mac_str);
  return uint64_t(a[0]) << 40 | uint64_t(a[1]) << 32 | (uint32_t(a[2]) << 24 | uint32_t(a[3]) << 16 | uint32_t(a[4]) << 8 | uint32_t(a[5]));
}

static std::vector<uint8_t> mac_to_byte(const uint64_t &mac) {
  std::vector<uint8_t> ret;
  int8_t i;

  for (i = 5; i >= 0; i--) {
    ret.push_back((uint8_t)(mac >> (__CHAR_BIT__ * i)));
  }
  return ret;
}

} // namespace mac

#endif /* _WIPS_STRESS_MAC_UTIL_HPP_ */