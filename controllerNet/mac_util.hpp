#ifndef _MAC_UTIL_HPP_
#define _MAC_UTIL_HPP_

#include <ifaddrs.h>
#include <iomanip>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>

// #include <fmt/format.h>

class mac {
public:
  static uint64_t string_to_mac(const std::string &mac_str) {
    unsigned char a[6];
    int last = -1;
    int rc = sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n", a + 0, a + 1, a + 2, a + 3, a + 4, a + 5, &last);
    if (rc != 6 || mac_str.size() != (size_t)last)
      throw std::runtime_error("invalid mac address format " + mac_str);
    return uint64_t(a[0]) << 40 | uint64_t(a[1]) << 32 |
           (uint32_t(a[2]) << 24 | uint32_t(a[3]) << 16 | uint32_t(a[4]) << 8 | uint32_t(a[5]));
  }

  static std::vector<uint8_t> mac_to_byte(const uint64_t &mac) {
    std::vector<uint8_t> ret;
    int8_t i;

    for (i = 5; i >= 0; i--) {
      ret.push_back((uint8_t)(mac >> (__CHAR_BIT__ * i)));
    }
    return ret;
  }

  static std::string pointer_to_mac(const uint8_t *ptr) {
    /*
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << *(ptr)             //
       << ":" << std::setfill('0') << std::setw(2) << std::hex << *(ptr + 1)  //
       << ":" << std::setfill('0') << std::setw(2) << std::hex << *(ptr + 2)  //
       << ":" << std::setfill('0') << std::setw(2) << std::hex << *(ptr + 3)  //
       << ":" << std::setfill('0') << std::setw(2) << std::hex << *(ptr + 4)  //
       << ":" << std::setfill('0') << std::setw(2) << std::hex << *(ptr + 5); //
    std::string str = ss.str();
    */
    char carray[18] = {0};
    snprintf(carray, 18, "%02x:%02x:%02x:%02x:%02x:%02x", *(ptr), *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4), *(ptr + 5));
    std::string str = carray;
    return str;
  }

  static uint64_t get_interface_mac(const char *ifc) {
    uint64_t retval = 0;

    /// get interface addresses
    struct ifaddrs *interface_addrs = NULL;
    if (getifaddrs(&interface_addrs) == -1 || !interface_addrs) {
      return 1;
    }

    int32_t sd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
      /// free memory allocated by getifaddrs
      freeifaddrs(interface_addrs);
      return 1;
    }

    /// get MAC address for each interface
    for (struct ifaddrs *ifa = interface_addrs; ifa != NULL; ifa = ifa->ifa_next) {
      /// print MAC address
      if (ifa->ifa_data != 0 && !strncmp(ifa->ifa_name, ifc, strlen(ifc))) {
        struct ifreq req;
        strcpy(req.ifr_name, ifa->ifa_name);
        if (ioctl(sd, SIOCGIFHWADDR, &req) != -1) {
          uint8_t *mac = (uint8_t *)req.ifr_ifru.ifru_hwaddr.sa_data;
          printf("%s:MAC[%02X:%02X:%02X:%02X:%02X:%02X]\n", ifa->ifa_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
          retval += mac[0];
          retval = retval << 8;
          retval += mac[1];
          retval = retval << 8;
          retval += mac[2];
          retval = retval << 8;
          retval += mac[3];
          retval = retval << 8;
          retval += mac[4];
          retval = retval << 8;
          retval += mac[5];
          printf("uint64_t : %lu\n", retval);
        }
      }
    }

    /// close socket
    close(sd);

    /// free memory allocated by getifaddrs
    freeifaddrs(interface_addrs);

    return retval;
  }
};

#endif /* _MAC_UTIL_HPP_ */