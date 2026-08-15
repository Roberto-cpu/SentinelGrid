#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <unordered_map>

#include <codecs/security_event.hpp>
#include <alerts/security_alerts.hpp>

namespace sentinelgrid::engine {

	class FailedLoginRule final {
		public:
			explicit FailedLoginRule(std::size_t threshold);

			[[nodiscard]]
			std::optional<SecurityAlert> evaluate(const SecurityEvent& event);

			void reset(std::uint32_t agent_id);

		private:
			std::size_t threshold_;
			std::unordered_map<std::uint32_t, std::size_t> failureCounts_;
	};
}