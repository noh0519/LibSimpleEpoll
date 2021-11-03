#ifndef _PUBLICMEMORY_HPP_
#define _PUBLICMEMORY_HPP_

#include <nlohmann/json.hpp>
#include <stdint.h>
#include <vector>

namespace PublicMemory {
nlohmann::json _auth_aps;
std::vector<uint8_t> _auth_aps_hash;
nlohmann::json _auth_clients;
std::vector<uint8_t> _auth_clients_hash;
nlohmann::json _guest_aps;
std::vector<uint8_t> _guest_aps_hash;
nlohmann::json _guest_clients;
std::vector<uint8_t> _guest_clients_hash;
nlohmann::json _external_aps;
std::vector<uint8_t> _external_aps_hash;
nlohmann::json _external_clients;
std::vector<uint8_t> _external_clients_hash;
nlohmann::json _except_aps;
std::vector<uint8_t> _except_aps_hash;
nlohmann::json _except_clients;
std::vector<uint8_t> _except_clients_hash;
nlohmann::json _rogue_aps;
std::vector<uint8_t> _rogue_aps_hash;
nlohmann::json _rogue_clients;
std::vector<uint8_t> _rogue_clients_hash;

nlohmann::json _threat_policy;
std::vector<uint8_t> _threat_policy_hash;

nlohmann::json _block;
std::vector<uint8_t> _block_hash;

nlohmann::json _admin_block;
std::vector<uint8_t> _admin_block_hash;

nlohmann::json _sensor_setting;
std::vector<uint8_t> _sensor_setting_hash;
} // namespace PublicMemory

#endif /* _PUBLICMEMORY_HPP_ */