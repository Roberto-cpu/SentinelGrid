/*
 * @file agent_key_registry.cpp
 * @brief Implementation of the AgentKeyRegistry class for managing agent credentials in a secure manner.
 * 
 * This file contains the implementation of the AgentKeyRegistry class, which is responsible for securely storing and managing agent credentials, 
 * including agent IDs and their associated keys. 
 * The class provides methods for registering new keys and retrieving existing credentials based on key IDs.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <security/agent_key_registry.hpp>

namespace sentinelgrid::engine::security {

	AgentKeyRegistry::~AgentKeyRegistry() noexcept {
		for (auto& [keyId, credential] : credentials_) {
			static_cast<void>(keyId);
			SecureZeroMemory(credential.key.data(), credential.key.size());
		}
	}

	bool AgentKeyRegistry::registerKey(std::uint32_t keyId, std::uint32_t agentId, const AgentKey& key) {
		const auto [iterator, inserted] = credentials_.emplace(
			keyId,
			StoredCredentials{
				.agent_id = agentId,
				.key = key
			}
		);
		
		static_cast<void>(iterator);
		return inserted;
	}

	std::optional<AgentCredentialView> AgentKeyRegistry::findCredential(std::uint32_t keyId) const noexcept {
		const auto iterator = credentials_.find(keyId);

		if (iterator == credentials_.end())
			return std::nullopt;

		const auto& credential = iterator->second;
		return AgentCredentialView{
			.agent_id = credential.agent_id,
			.key = std::span<const std::uint8_t>{ credential.key }
		};
	}
}