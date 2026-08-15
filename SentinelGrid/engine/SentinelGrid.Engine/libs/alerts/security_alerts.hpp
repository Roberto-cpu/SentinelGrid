#pragma once

#include <cstddef>
#include <cstdint>

namespace sentinelgrid::engine {

	enum class AlertType : std::uint32_t {
		repeated_login_failure = 1
	};

	enum class AlertSeverity : std::uint32_t {
		low = 1,
		medium = 2,
		high = 3,
		critical = 4
	};

	struct SecurityAlert {
		AlertType type;
		AlertSeverity severity;

		std::uint32_t agent_id;
		std::uint64_t triggering_sequence;
		std::uint32_t failure_count;
	};
}