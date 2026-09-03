#pragma once

/**
 * @file agent_key_registry.hpp
 * @brief This header file defines the interface for managing agent keys in a registry.
 *
 * The AgentKeyRegistry class provides functionality for registering, finding, and managing agent keys.
 * 
 * @note The implementation of the AgentKeyRegistry class is expected to be provided in a corresponding source file (e.g., agent_key_registry.cpp).
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>

namespace sentinelgrid::engine::security {

	inline constexpr std::size_t AgentKeySize{ 32U };

	using AgentKey = std::array<std::uint8_t, AgentKeySize>;

	/**
	 * @brief A view of an agent's credential information.
	 */
	struct AgentCredentialView {
		std::uint32_t agent_id;
		std::span<const std::uint8_t> key;
	};

	/**
	 * @class AgentKeyRegistry
	 * @brief A registry for managing agent keys.
	 *
	 * The AgentKeyRegistry class provides functionality for registering, finding, and managing agent keys.
	 */
	class AgentKeyRegistry final {
		
		public:
			
			/**
			 * @brief Constructs a new AgentKeyRegistry object.
			 */
			AgentKeyRegistry() = default;
			
			/**
			 * @brief Destroys the AgentKeyRegistry object and securely clears stored keys.
			 */
			~AgentKeyRegistry() noexcept;

			/**
			 * @brief Deleted copy constructor to prevent copying of AgentKeyRegistry instances.
			 */
			AgentKeyRegistry(const AgentKeyRegistry&) = delete;
			
			/**
			 * @brief Deleted copy assignment operator to prevent copying of AgentKeyRegistry instances.
			 */
			AgentKeyRegistry& operator=(const AgentKeyRegistry&) = delete;

			/**
			 * @brief Deleted move constructor to prevent moving of AgentKeyRegistry instances.
			 */
			AgentKeyRegistry(AgentKeyRegistry&&) = delete;
			
			/**
			 * @brief Deleted move assignment operator to prevent moving of AgentKeyRegistry instances.
			 */
			AgentKeyRegistry& operator=(AgentKeyRegistry&&) = delete;
	
			/**
			 * @brief Registers a new agent key in the registry.
			 * @param keyId The unique identifier for the key.
			 * @param agentId The unique identifier for the agent.
			 * @param key The agent key to be registered.
			 * @return true if the key was successfully registered, false if the keyId already exists.
			 */
			[[nodiscard]]
			bool registerKey(std::uint32_t keyId, std::uint32_t agentId, const AgentKey& key);

			/**
			 * @brief Finds the credential information for a given keyId.
			 * @param keyId The unique identifier for the key.
			 * @return An optional containing the AgentCredentialView if found, or std::nullopt if not found.
			 */
			[[nodiscard]]
			std::optional<AgentCredentialView> findCredential(std::uint32_t keyId) const noexcept;

		private:
			/**
			 * @brief A structure to hold stored credentials, including agent ID and key.
			 */
			struct StoredCredentials {
				std::uint32_t agent_id;
				AgentKey key;
			};

			std::unordered_map<std::uint32_t, StoredCredentials> credentials_;
	};
}