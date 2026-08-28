#pragma once

#include <cstddef>
#include <span>

#include <codecs/security_event.hpp>
#include <concurrency/bounded_blocking_queue.hpp>
#include <network/unique_socket.hpp>

namespace sentinelgrid::engine::app {
	using EventQueue = concurrency::BoundedBlockingQueue<SecurityEvent>;

	enum class SessionStatus {
		cleanDisconnect,
		truncatedPacket,
		socketError,
		decodingError,
		queueClosed
	};

	struct SessionResult {
		SessionStatus sessionStatus{};
		std::size_t eventsReceived{};
		int socketErrorCode{};
	};

	[[nodiscard]]
	SessionResult runSessionAgent(
		network::UniqueSocket client, 
		EventQueue& eventQueue,
		const sentinelgrid::engine::security::AgentKeyRegistry& keyRegistry
	);
}
