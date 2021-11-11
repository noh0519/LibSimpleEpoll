#ifndef _VAR_UTIL_HPP_
#define _VAR_UTIL_HPP_

#include <sstream>
#include <stdint.h>
#include <string>
#include <vector>

class var {
public:
  static std::string base64_encode(const std::string &s) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, ix = 0, leng = s.length();
    std::stringstream q;

    for (i = 0, ix = leng - leng % 3; i < ix; i += 3) {
      q << base64_chars[(s[i] & 0xfc) >> 2];
      q << base64_chars[((s[i] & 0x03) << 4) + ((s[i + 1] & 0xf0) >> 4)];
      q << base64_chars[((s[i + 1] & 0x0f) << 2) + ((s[i + 2] & 0xc0) >> 6)];
      q << base64_chars[s[i + 2] & 0x3f];
    }
    if (ix < leng) {
      q << base64_chars[(s[ix] & 0xfc) >> 2];
      q << base64_chars[((s[ix] & 0x03) << 4) + (ix + 1 < leng ? (s[ix + 1] & 0xf0) >> 4 : 0)];
      q << (ix + 1 < leng ? base64_chars[((s[ix + 1] & 0x0f) << 2)] : '=');
      q << '=';
    }
    return q.str();
  }

  static std::string base64_encode(std::vector<uint8_t> &v) {
    std::string str;
    str.assign(v.begin(), v.end());
    return var::base64_encode(str);
  }

  static std::string base64_decode(const std::string &s) {
    static char base64_reverse[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
    size_t i = 0, ix = 0, leng = s.length();
    std::stringstream q;
    if ((leng % 4) == 0) {
      leng = s[leng - 1] == '=' ? leng - 1 : leng;
      leng = s[leng - 1] == '=' ? leng - 1 : leng;

      for (i = 0, ix = leng - (leng % 4); i < ix; i += 4) {
        q << (char)((base64_reverse[(unsigned char)s[i]] << 2) +
                    ((base64_reverse[(unsigned char)s[i + 1]] & 0x30) >> 4));
        q << (char)(((base64_reverse[(unsigned char)s[i + 1]] & 0xf) << 4) +
                    ((base64_reverse[(unsigned char)s[i + 2]] & 0x3c) >> 2));
        q << (char)(((base64_reverse[(unsigned char)s[i + 2]] & 0x3) << 6) + base64_reverse[(unsigned char)s[i + 3]]);
      }
      if (ix < leng) {
        q << (char)((base64_reverse[(unsigned char)s[ix]] << 2) +
                    (ix + 1 < leng ? (base64_reverse[(unsigned char)s[ix + 1]] & 0x30) >> 4 : 0));
        q << (char)(ix + 1 < leng ? ((base64_reverse[(unsigned char)s[ix + 1]] & 0xf) << 4) +
                                        (ix + 2 < leng ? (base64_reverse[(unsigned char)s[ix + 2]] & 0x3c) >> 2 : 0)
                                  : '\0');
        q << (char)(ix + 2 < leng ? (base64_reverse[(unsigned char)s[ix + 2]] & 0x3) << 6 : '\0');
      }
    }
    return q.str();
  }

  static std::string base64_decode(std::vector<uint8_t> &v) {
    std::string str;
    str.assign(v.begin(), v.end());
    return var::base64_decode(str);
  }
};

#endif /* _VAR_UTIL_HPP_ */