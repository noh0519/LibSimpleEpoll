#ifndef _PUBLICMEMORY_HPP_
#define _PUBLICMEMORY_HPP_

#include "lockedvector.hpp"

namespace PublicMemory {
static std::shared_ptr<LockedVector<uint8_t>> _auth_aps_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _auth_clients_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _guest_aps_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _guest_clients_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _external_aps_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _external_clients_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _except_aps_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _except_clients_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _rogue_aps_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _rogue_clients_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _threat_policy_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _block_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _admin_block_hash = std::make_shared<LockedVector<uint8_t>>();
static std::shared_ptr<LockedVector<uint8_t>> _sensor_setting_hash = std::make_shared<LockedVector<uint8_t>>();
} // namespace PublicMemory
#endif /* _PUBLICMEMORY_HPP_ */