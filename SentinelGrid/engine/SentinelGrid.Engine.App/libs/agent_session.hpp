#pragma once

#include <cstddef>
#include <span>

#include <codecs/security_event.hpp>
#include <concurrency/bounded_blocking_queue.hpp>
#include <network/unique_socket.hpp>
#include <security/agent_key_registry.hpp>
#include <security/replay_guard.hpp>

namespace sentinelgrid::engine::app {
	using EventQueue = concurrency::BoundedBlockingQueue<SecurityEvent>;

	enum class SessionStatus {
		cleanDisconnect,
		truncatedPacket,
		socketError,
		decodingError,
		queueClosed,
		replayRejected
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
		const security::AgentKeyRegistry& keyRegistry,
		security::ReplayGuard& replayGuard
	);
}
