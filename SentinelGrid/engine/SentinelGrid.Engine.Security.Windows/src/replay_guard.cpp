#include <cstdint>
#include <mutex>

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