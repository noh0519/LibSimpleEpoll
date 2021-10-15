#ifndef _WIPS_STRESS_PACKET_HPP_
#define _WIPS_STRESS_PACKET_HPP_

#include "ap.hpp"
#include "client.hpp"
#include "enums.hpp"
#include "optional.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

class Client;

using APPtr = std::shared_ptr<AP>;
using ClientPtr = std::shared_ptr<Client>;

struct Flags {
  uint8_t cipher : 1;
  uint8_t fragment : 1;
  uint8_t reserved : 6;
} __attribute__((packed));

struct Header {
  uint8_t version;
  uint16_t seq;
  Flags flags;
  uint8_t offset;
  uint8_t option;
  uint16_t nonce;
  Protocol subtype;
  uint8_t res;
  uint16_t length;
} __attribute__((packed));

struct Bodyheader {
  Messages type;
  Product product;
  uint16_t length;
  uint8_t res1;
  uint8_t res2;
} __attribute__((packed));

struct TLV {
  uint8_t type;
  uint16_t length;
} __attribute__((packed));

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
  std::vector<uint8_t> d_;

  uint16_t getSeq();
  uint16_t getBodyHeaderLength();
  Messages getBodyHeaderType();

public:
  Packet();
  ~Packet();

  void insert(uint8_t *buf, size_t len);

  size_t size();
  uint8_t *data();

  uint16_t getHeaderLength();
  std::vector<uint8_t> getAuthCode();
  tl::optional<uint32_t> getNonce();
  tl::optional<uint32_t> getSensorID();
  tl::optional<ConnectionMode> getMode();

  static tl::optional<Packet> encrypt(Packet &p, const std::string &shared_key);
  static tl::optional<Packet> decrypt(Packet &p, const std::string &shared_key);

  static bool verifySeqence(Packet &p, uint16_t &prev_seq);
  static bool verifyPacketHeaderLength(Packet p);
  static bool verifyPacketHash(Packet p);
  static bool verifyPacketBodyHeaderType(Packet p, ConnectionState state);
  static bool verifyPacketBodyHeaderLength(Packet p);
  static bool verifyAuth(Packet p);

  void makeSensorID(const uint32_t &sensor_id);
  void makeSensorMAC(const uint64_t &mac);
  void makeSensorIP(const std::string &ip);
  void makeSensorVersion(const std::string &ver);
  void makeSensorRevision(const uint32_t &rev);
  void makeSensorModel(const uint8_t &model);

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

  static tl::optional<Packet> makeLoginResponseChallenge(const uint8_t *auth_code, const uint32_t &nonce, const uint16_t &send_seq,
                                                         const std::string shared_key);
  static tl::optional<Packet> makeLoginSuccess(const uint16_t &send_seq, const std::string shared_key);
  static tl::optional<Packet> makeSessionAPData(const int &index, const uint32_t &sensor_id, const uint16_t &send_seq,
                                                const std::string shared_key);
  static tl::optional<Packet> makeSessionAPs(std::vector<APPtr> aps, const uint32_t &sensor_id, const uint16_t &send_seq,
                                             const std::string shared_key);
  static tl::optional<Packet> makeSessionAP(AP ap, const uint32_t &sensor_id, const uint16_t &send_seq, const std::string shared_key);
  static tl::optional<Packet> makeSessionClientData(const int &index, const uint32_t &sensor_id, const uint16_t &send_seq,
                                                    const std::string shared_key);
  static tl::optional<Packet> makeSessionClients(std::vector<ClientPtr> clients, const uint32_t &sensor_id, const uint16_t &send_seq,
                                                 const std::string shared_key);
  static tl::optional<Packet> makeSessionClient(Client client, const uint32_t &sensor_id, const uint16_t &send_seq,
                                                const std::string shared_key);
  static tl::optional<Packet> makeSensorInfo(const uint32_t &sensor_id, const SensorInfo &si, const uint16_t &send_seq,
                                             const std::string shared_key);

  void print();
};

#endif /* _WIPS_STRESS_PACKET_HPP_ */
