/**
 * @file replay_guard.cpp
 * @brief Implementation of the ReplayGuard class for preventing replay attacks.
 *
 * This file contains the implementation of the ReplayGuard class, which is responsible for checking and recording sequence numbers 
 * associated with agents to prevent replay attacks. 
 * The class maintains a mapping of agent IDs to their last recorded sequence numbers and provides thread-safe access to this data.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>
#include <mutex>
#include <unordered_map>

#include <security/replay_guard.hpp>

namespace sentinelgrid::engine::security {

	ReplayDecision ReplayGuard::checkAndRecord(std::uint32_t agentId, std::uint64_t sequenceNumber) {

		if (sequenceNumber <= 0)
			return ReplayDecision::invalid_sequence;


		std::scoped_lock{ mutex_ };
		const auto [iterator, inserted] = lastSequenceByAgent_.try_emplace(agentId, sequenceNumber);

		if (inserted)
			return ReplayDecision::accepted;

		const std::uint64_t lastSequence = iterator->second;
		
		if (sequenceNumber == lastSequenceByAgent_[agentId])
			return ReplayDecision::duplicate;
		
		if (sequenceNumber < lastSequenceByAgent_[agentId])
			return ReplayDecision::stale;

		iterator->second = sequenceNumber;
		return ReplayDecision::accepted;
	}
}