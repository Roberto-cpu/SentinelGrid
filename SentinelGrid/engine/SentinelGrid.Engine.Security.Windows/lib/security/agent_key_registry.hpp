#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>

namespace sentinelgrid::engine::security {

	inline constexpr std::size_t AgentKeySize{ 32U };

	using AgentKey = std::array<std::uint8_t, AgentKeySize>;

	struct AgentCredentialView {
		std::uint32_t agent_id;
		std::span<const std::uint8_t> key;
	};

	class AgentKeyRegistry final {
		
		public:
			AgentKeyRegistry() = default;
			~AgentKeyRegistry() noexcept;

			AgentKeyRegistry(const AgentKeyRegistry&) = delete;
			AgentKeyRegistry& operator=(const AgentKeyRegistry&) = delete;

			AgentKeyRegistry(AgentKeyRegistry&&) = delete;
			AgentKeyRegistry& operator=(AgentKeyRegistry&&) = delete;
	
			[[nodiscard]]
			bool registerKey(std::uint32_t keyId, std::uint32_t agentId, const AgentKey& key);

			[[nodiscard]]
			std::optional<AgentCredentialView> findCredential(std::uint32_t keyId) const noexcept;

		private:
			struct StoredCredentials {
				std::uint32_t agent_id;
				AgentKey key;
			};

			std::unordered_map<std::uint32_t, StoredCredentials> credentials_;
	};
}