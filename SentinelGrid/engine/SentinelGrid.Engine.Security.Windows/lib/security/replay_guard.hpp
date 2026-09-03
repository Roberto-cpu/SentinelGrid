#pragma once

/**
 * @file replay_guard.hpp
 * @brief This file contains the declaration of the ReplayGuard class, which is responsible for preventing replay attacks by tracking sequence numbers for agents.
 *
 * The ReplayGuard class provides functionality to check and record sequence numbers for agents, 
 * ensuring that messages are processed in order and preventing duplicates or stale messages.
 *
 * @note The implementation of the ReplayGuard class is expected to be provided in a corresponding source file (e.g., replay_guard.cpp).
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace sentinelgrid::engine::security {

	/**
	 * @brief: This enumeration defines the possible decisions made by the ReplayGuard when checking sequence numbers.
	 */
	enum class ReplayDecision {
		accepted,
		invalid_sequence,
		duplicate,
		stale
	};

	/**
	 * @class ReplayGuard
	 * @brief: The ReplayGuard class is responsible for preventing replay attacks by tracking sequence numbers for agents.
	 *
	 * The ReplayGuard class provides functionality to check and record sequence numbers for agents,
	 * ensuring that messages are processed in order and preventing duplicates or stale messages.
	 */
	class ReplayGuard final {
		public:
			/**
			 * @brief: Constructs a new ReplayGuard object.
			 */
			ReplayGuard() = default;

			/**
			 * @brief: Deleted copy constructor to prevent copying of ReplayGuard instances.
			 */
			ReplayGuard(const ReplayGuard&) = delete;
			
			/**
			 * @brief: Deleted copy assignment operator to prevent copying of ReplayGuard instances.
			 */
			ReplayGuard& operator=(const ReplayGuard&) = delete;

			/**
			 * @brief: Checks the provided sequence number for the specified agent and records it if valid.
			 * @param agentId: The unique identifier of the agent.
			 * @param sequenceNumber: The sequence number to check and record.
			 * @return A ReplayDecision indicating whether the sequence number is accepted, invalid, duplicate, or stale.
			 */
			[[nodiscard]]
			ReplayDecision checkAndRecord(std::uint32_t agentId, std::uint64_t sequenceNumber);

		private:
			std::mutex mutex_;
			std::unordered_map<std::uint32_t, std::uint64_t> lastSequenceByAgent_;
	};
}