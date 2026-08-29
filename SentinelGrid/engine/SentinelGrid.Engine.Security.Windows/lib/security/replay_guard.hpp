#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace sentinelgrid::engine::security {

	enum class ReplayDecision {
		accepted,
		invalid_sequence,
		duplicate,
		stale
	};

	class ReplayGuard final {
		public:
			ReplayGuard() = default;

			ReplayGuard(const ReplayGuard&) = delete;
			ReplayGuard& operator=(const ReplayGuard&) = delete;

			[[nodiscard]]
			ReplayDecision checkAndRecord(std::uint32_t agentId, std::uint64_t sequenceNumber);

		private:
			std::mutex mutex_;
			std::unordered_map<std::uint32_t, std::uint64_t> lastSequenceByAgent_;
	};
}