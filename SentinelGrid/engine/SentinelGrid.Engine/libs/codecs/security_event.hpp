#pragma once

#include <cstdint>

namespace sentinelgrid::engine {

	enum class EventType : std::uint32_t {
		heartbeat = 1,
		login_failed = 2,
		service_stop = 3
	};

	struct SecurityEvent {
		std::uint32_t agent_id{};
		std::uint64_t sequence_number{};
		EventType type{};
	};
}