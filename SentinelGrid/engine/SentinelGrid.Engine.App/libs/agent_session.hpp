#pragma once

/**
 * @file agent_session.hpp
 * @brief This header file defines the interface for running an agent session, which handles communication with a connected client.
 *
 * The functions declared in this file allow for running an agent session, processing incoming data, and managing security events.
 *
 * @note The implementation of these functions is expected to be provided in a corresponding source file (e.g., agent_session.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstddef>
#include <span>

#include <codecs/security_event.hpp>
#include <concurrency/bounded_blocking_queue.hpp>
#include <network/unique_socket.hpp>
#include <security/agent_key_registry.hpp>
#include <security/replay_guard.hpp>

namespace sentinelgrid::engine::app {
	using EventQueue = concurrency::BoundedBlockingQueue<SecurityEvent>;

	/**
	 * @brief Enumeration representing the status of an agent session.
	 */
	enum class SessionStatus {
		cleanDisconnect,
		truncatedPacket,
		socketError,
		decodingError,
		queueClosed,
		replayRejected
	};

	/**
	 * @brief Structure representing the result of an agent session.
	 */
	struct SessionResult {
		SessionStatus sessionStatus{};
		std::size_t eventsReceived{};
		int socketErrorCode{};
	};

	/**
	 * @brief Runs an agent session, handling communication with a connected client.
	 *
	 * This function manages the lifecycle of an agent session, including receiving packets from the client,
	 * decoding them, checking for replay attacks, and pushing valid events into the event queue.
	 *
	 * @param client The unique socket representing the connected client.
	 * @param eventQueue The queue to which valid security events will be pushed.
	 * @param keyRegistry The registry containing agent keys for authentication.
	 * @param replayGuard The guard responsible for preventing replay attacks.
	 * @return A SessionResult structure containing the status of the session, number of events received, and any socket error code.
	 */
	[[nodiscard]]
	SessionResult runSessionAgent(
		network::UniqueSocket client, 
		EventQueue& eventQueue,
		const security::AgentKeyRegistry& keyRegistry,
		security::ReplayGuard& replayGuard
	);
}
