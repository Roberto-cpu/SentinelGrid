#include <cstddef>
#include <stdexcept>

#include <rules/failed_login_rule.hpp>
#include <codecs/security_event.hpp>

namespace sentinelgrid::engine {

	FailedLoginRule::FailedLoginRule(std::size_t threshold) : threshold_{ threshold } {
		if (threshold == 0)
			throw std::invalid_argument{"Max attempts cannot be zero!\n"};
	}

	std::optional<SecurityAlert> FailedLoginRule::evaluate(const SecurityEvent& event) {
		
		if (event.type == EventType::service_stop) {
			reset(event.agent_id);
		}
		else if (event.type == EventType::login_failed) {
			failureCounts_[event.agent_id]++;

			if (failureCounts_[event.agent_id] == threshold_) {
				SecurityAlert securityAlert{
					AlertType::repeated_login_failure,
					AlertSeverity::high,
					event.agent_id,
					event.sequence_number,
					failureCounts_[event.agent_id]
				};

				failureCounts_[event.agent_id] = 0;
				return securityAlert;
			}
		}

		return std::nullopt;
	}

	void FailedLoginRule::reset(std::uint32_t agent_id) {
		failureCounts_.erase(agent_id);
	}
}