#ifndef _WIPS_STRESS_PACKET_HPP_
#define _WIPS_STRESS_PACKET_HPP_

#include "ap.hpp"
#include "client.hpp"
#include "optional.hpp"
#include "protocol.hpp"
#include "sha1.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

class Client;

using APPtr = std::shared_ptr<AP>;
using ClientPtr = std::shared_ptr<Client>;

typedef struct _flags {
  uint8_t cipher : 1;
  uint8_t fragment : 1;
  uint8_t reserved : 6;
} __attribute__((packed)) FLAGS;

typedef struct _header {
  uint8_t version;
  uint16_t seq;
  FLAGS flags;
  uint8_t offset;
  uint8_t option;
  uint16_t nonce;
  Protocol subtype;
  uint8_t res;
  uint16_t length;
} __attribute__((packed)) HEADER;

typedef struct _bodyheader {
  Messages type;
  Product product;
  uint16_t length;
  uint8_t res1;
  uint8_t res2;
} __attribute__((packed)) BODYHEADER;

typedef struct _tlv {
  uint8_t type;
  uint16_t length;
} __attribute__((packed)) TLV;

typedef struct _login_request_tlv {
  LoginValue type;
  uint16_t length;
} __attribute__((packed)) LOGIN_REQUEST_TLV;

struct SensorInfo {
  uint64_t mac = 0;
  std::string ip = "";
  std::string version = "";
  uint32_t revision = 0;
  uint8_t model = 0;
};

class Packet {
private:
  std::vector<uint8_t> _data;

public:
  Packet();
  ~Packet();

  void insert(uint8_t *buf, size_t len);

  size_t size();
  uint8_t *data();

  uint16_t getSeq();
  uint16_t getHeaderLength();
  Messages getBodyHeaderType();
  uint16_t getBodyHeaderLength();
  uint8_t getBodyType();
  std::vector<uint8_t> getAuthCode();
  tl::optional<uint32_t> getNonce();
  tl::optional<uint32_t> getSensorID();
  tl::optional<ConnectionMode> getMode();

  void encrypt(const std::string &shared_key);
  tl::optional<Packet> decrypt(const std::string &shared_key);

  void makeSensorID(const uint32_t &sensor_id);
  void makeSensorMAC(const uint64_t &mac);
  void makeSensorIP(const std::string &ip);
  void makeSensorVersion(const std::string &ver);
  void makeSensorRevision(const uint32_t &rev);
  void makeSensorModel(const uint8_t &model);

  void makeHashSensorID(const uint32_t &sensor_id);
  void makeHashData(SetConfigList setcfg, std::vector<uint8_t> v);

  void makeAPData(const AP &ap);
  void makeClientData(const Client &client);
  void makeAPDataTLV(APData type, uint16_t len, const uint8_t *data);
  void makeClientDataTLV(ClientData type, uint16_t len, const uint8_t *data);

  void makeLoginResponseTLV(LoginValue type, uint16_t len, const uint8_t *data);
  void makeLoginResponseBody(LoginResponse type);
  void makeLoginResponseBodyHeader();
  void makeDataResponseBody(DataResponse type);
  void makeDataResponseBodyHeader();
  void makeHeader(uint16_t send_seq);

  void print();
};

#endif /* _WIPS_STRESS_PACKET_HPP_ */
