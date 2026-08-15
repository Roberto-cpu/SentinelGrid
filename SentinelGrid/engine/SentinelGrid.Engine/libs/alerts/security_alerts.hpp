#pragma once

#include <cstddef>
#include <cstdint>

namespace sentinelgrid::engine {

	enum class AlertType {
		repeated_login_failure
	};

	enum class AlertSeverity {
		low,
		medium,
		high,
		critical
	};

	struct SecurityAlert {
		AlertType type;
		AlertSeverity severity;

		std::uint32_t agent_id;
		std::uint64_t triggering_sequence;
		std::uint32_t failure_count;
	};
}