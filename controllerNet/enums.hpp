#ifndef _WIPS_STRESS_ENUMS_HPP_
#define _WIPS_STRESS_ENUMS_HPP_

#include <stdint.h>

enum class Protocol : uint8_t {
  USNP = 0x01,
  UFDP = 0x02,
  SWMP = 0x03,
};

enum class Product : uint8_t {
  SENSOR = 0x01,
  PROBER = 0x02,
  SERVER = 0x03,
  UI = 0x04,
};

enum class Messages : uint8_t {
  C2S_LOGIN_REQUEST = 0x01,
  S2C_LOGIN_RESPONSE = 0x02,
  C2S_DATA_REQUEST = 0x03,
  S2C_DATA_RESPONSE = 0x04,
  C2S_SET_CONFIG = 0x05,
};

enum class ConnectionState : uint8_t {
  INIT = 0x01,
  LOGIN_REQUEST_START = 0x02,
  LOGIN_REQUEST_CHALLENGE = 0x03,
  LOGIN_SUCCESS = 0x04,
  SET_SENSOR_ID = 0x05,
  CONNECTION_COMPLETE = 0x06,
  REQUEST_DATA = 0x07,
  SET_CONFIG = 0x08,
  WAIT_MAC = 0x09,
  VERIFY_MAC = 0x0a,
};

enum class LoginRequest : uint8_t { START = 0x01, CHALLENGE = 0x03, NOK = 0xff };

enum class LoginResponse : uint8_t {
  OK = 0x01,
  CHALLENGE = 0x02,
  NOK = 0xff,
};

enum class DataResponse : uint8_t {
  DATA = 0x01,
  EVENT = 0x02,
  SENSOR_HASH = 0x03,
  SENSOR_STATUS_DATA = 0x04,
};

enum class LoginValue : uint8_t {
  NONCE = 0x01,
  AUTH = 0x02,
};

enum class SetConfig : uint8_t {
  HASH = 0x01,
  LIST_SINGLE = 0x02,
  LIST_START = 0x03,
  LIST_CONTINUE = 0x04,
  LIST_FINISH = 0x05,
  FIRMWARE = 0x06,
  SENSOR_ID = 0x07,
  THREAT_POLICY = 0x08,
};

enum class SetSensorIDValue : uint8_t {
  SENSOR_ID = 0x01,
};

enum class DataValue : uint8_t {
  SENSOR_ID = 0x01,
  APS = 0x10,
  CLIENTS = 0x11,
};

enum class APData : uint8_t {
  BSSID = 0x02,
  SSID = 0x03,
  CHANNEL = 0x04,
  RSSI = 0x05,
  CIPHER = 0x06,
  PROTOCOL = 0x07,
  AUTH = 0x08,
  MODE = 0x09,
  SIGNATURE = 0x0a,
  SSID_BROADCAST = 0x0b,
  MNGFRM_CNT = 0x0c,
  CTRLFRM_CNT = 0x0d,
  DATAFRM_CNT = 0x0e,
  WDS_AP = 0x10,
  DATA_RATE = 0x11,
  MCS = 0x12,
  CHANNEL_WIDTH = 0x13,
  MIMO = 0x14,
  HIGHEST_RATE = 0x15,
  SPATIAL_STREAM = 0x16,
  GUARD_INTERVAL = 0x17,
  WPS = 0x18,
  PMF = 0x19,

  LAST_DT = 0x20,
  PROBE_DT = 0x21,
};

enum class ClientData : uint8_t {
  BSSID = 0x02,
  CLIENT_MAC = 0x04,
  EAP_ID = 0x05,
  DATA_RATE = 0x06,
  SN = 0x07,
  RSSI = 0x08,
  SIGNATURE = 0x09,
  DATA_SIZE = 0x0a,
  MNGFRM_CNT = 0x0b,
  CTRLFRM_CNT = 0x0c,
  DATAFRM_CNT = 0x0d,
  AUTH_COUNT = 0x0e,
  SIGNATURE_5 = 0x0f,
  MIMO = 0x10,

  LAST_DT = 0x11,
  PROBE_DT = 0x12,
};

enum class SensorStatusDataValue : uint8_t {
  SENSOR_ID = 0x01,
  IP_ADDRESS = 0x03,
  PORT_NUMBER = 0x04,
  MAC_ADDRESS = 0x05,
  BLOCK_MEM_USAGE = 0x0a,
  RAM_MEM_USAGE = 0x0c,
  ARP_DATA = 0x0d,
  SENSOR_MODEL = 0x10,
  SENSOR_VERSION = 0x12,
  CPU_TEMP = 0x13,
  CPU_USAGE = 0x14,
  SENSOR_REVISION = 0x15,
  SENSOR_INTEGRITY = 0x18,
  SENSOR_INTEGRITY_DETAIL = 0x19,
  SENSOR_LOG = 0x1a,
};

enum class ConnectionMode : uint8_t {
  UNKNOWN = 0x00,
  DATA = 0x01,
  CONFIG = 0x02,
};

#endif /* _WIPS_STRESS_ENUMS_HPP_ */
