#pragma once

/**
 * @file failed_login_rule.hpp
 * @brief This header file defines the FailedLoginRule class for evaluating failed login attempts.
 *
 * The FailedLoginRule class provides functionality to evaluate security events related to failed login attempts
 * and generate security alerts when a specified threshold is exceeded.
 *
 * @note The implementation of the FailedLoginRule class is expected to be provided in a corresponding source file (e.g., failed_login_rule.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>
#include <cstddef>
#include <optional>
#include <unordered_map>

#include <codecs/security_event.hpp>
#include <alerts/security_alerts.hpp>

namespace sentinelgrid::engine {

	/**
	 * @class FailedLoginRule
	 * @brief A rule for evaluating failed login attempts and generating security alerts.
	 *
	 * The FailedLoginRule class evaluates security events related to failed login attempts and generates
	 * security alerts when the number of failed attempts exceeds a specified threshold.
	 */
	class FailedLoginRule final {
		public:
			
			/**
			 * @brief Constructs a new FailedLoginRule object with the specified threshold.
			 * @param threshold The number of failed login attempts required to trigger an alert.
			 */
			explicit FailedLoginRule(std::size_t threshold);

			/**
			 * @brief Evaluates a security event and determines if it triggers a security alert.
			 * @param event The security event to evaluate.
			 * @return An optional containing a SecurityAlert if the threshold is exceeded, or std::nullopt otherwise.
			 */
			[[nodiscard]]
			std::optional<SecurityAlert> evaluate(const SecurityEvent& event);

			/**
			 * @brief Resets the failure count for a specific agent ID.
			 * @param agent_id The agent ID for which to reset the failure count.
			 */
			[[nodiscard]]
			void reset(std::uint32_t agent_id);

		private:
			std::size_t threshold_;
			std::unordered_map<std::uint32_t, std::size_t> failureCounts_;
	};
}