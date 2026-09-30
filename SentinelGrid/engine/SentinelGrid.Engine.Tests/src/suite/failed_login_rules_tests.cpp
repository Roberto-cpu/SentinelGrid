/*
 * @file failed_login_rules_tests.cpp
 * @brief Implementation of failed login rules test runner.
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */
#include <iostream>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>

#include <codecs/security_event.hpp>
#include <rules/failed_login_rule.hpp>

#include <tests/test_framework.hpp>
#include <tests/suites/failed_login_rules_tests.hpp>

namespace sentinelgrid::engine::tests::rules {

	namespace {
		/**
		 * @brief: Tests the initialization of a login rule with zero allowed attempts.
		 */
		static void testLoginRuleZeroAttempts() {
			std::cout << "[+] Zero login attempts allowed...\n";

			bool exceptionThrown = false;

			try {
				FailedLoginRule rule{ 0 };
			}
			catch (std::invalid_argument&) {
				exceptionThrown = true;
			}

			EXPECT_TRUE(exceptionThrown);
		}

		/**
		 * @brief: Tests the alert behavior on the third login attempt failure.
		 */
		static void testAlertOnThirdFailure() {
			std::cout << "[+] Alert on third failure...\n";

			FailedLoginRule rule{ 3 };

			std::size_t i = 1;
			while (i < 4) {
				SecurityEvent event{
					1U,
					(unsigned long)(i),
					EventType::login_failed
				};

				if (i < 3)
					EXPECT_TRUE(rule.evaluate(event) == std::nullopt);
				else {
					auto alert = rule.evaluate(event);
					EXPECT_TRUE(alert->severity == AlertSeverity::high);
					EXPECT_TRUE(alert->type == AlertType::repeated_login_failure);
				}
				i++;
			}
		}

		/**
		 * @brief: Tests the agent isolation behavior.
		 */
		static void testAgentIsolation() {
			std::cout << "[+] Agent isolation...\n";

			FailedLoginRule rule{ 3 };

			SecurityEvent event1{
				1U,
				1ULL,
				EventType::login_failed
			};

			SecurityEvent event2{
				1U,
				2ULL,
				EventType::login_failed
			};

			SecurityEvent event3{
				2U,
				1ULL,
				EventType::login_failed
			};

			SecurityEvent event4{
				2U,
				2ULL,
				EventType::login_failed
			};

			SecurityEvent event5{
				1U,
				3ULL,
				EventType::login_failed
			};

			EXPECT_TRUE(rule.evaluate(event1) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event2) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event3) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event4) == std::nullopt);

			auto alert = rule.evaluate(event5);
			EXPECT_TRUE(alert->severity == AlertSeverity::high);
			EXPECT_TRUE(alert->agent_id == 1U);
		}

		/**
		 * @brief: Tests the behavior of ignoring heartbeat events.
		 */
		static void testIgnoreHeartbeat() {
			std::cout << "[+] \"Heartbeat\" event is ignored...\n";

			FailedLoginRule rule{ 3 };

			SecurityEvent event1{
				1U,
				1ULL,
				EventType::login_failed
			};

			SecurityEvent event2{
				1U,
				2ULL,
				EventType::heartbeat
			};

			SecurityEvent event3{
				1U,
				3ULL,
				EventType::login_failed
			};

			SecurityEvent event4{
				1U,
				4ULL,
				EventType::login_failed
			};

			EXPECT_TRUE(rule.evaluate(event1) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event2) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event3) == std::nullopt);

			auto alert = rule.evaluate(event4);
			EXPECT_TRUE(alert->severity == AlertSeverity::high);
		}

		/**
		 * @brief: Tests the behavior of a service stop event resetting the failure counter.
		 */
		static void testServiceStopReset() {
			std::cout << "[+] \"Service Stop\" event resets counter...\n";

			FailedLoginRule rule{ 3 };

			SecurityEvent event1{
				1U,
				1ULL,
				EventType::login_failed
			};

			SecurityEvent event2{
				1U,
				2ULL,
				EventType::service_stop
			};

			SecurityEvent event3{
				1U,
				3ULL,
				EventType::login_failed
			};

			SecurityEvent event4{
				1U,
				4ULL,
				EventType::login_failed
			};

			SecurityEvent event5{
				1U,
				5ULL,
				EventType::login_failed
			};

			EXPECT_TRUE(rule.evaluate(event1) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event2) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event3) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event4) == std::nullopt);

			auto alert = rule.evaluate(event5);
			EXPECT_TRUE(alert->severity == AlertSeverity::high);
		}

		/**
		 * @brief: Tests the behavior of an alert resetting the failure counter.
		 */
		static void testAlertResetsCounter() {
			std::cout << "[+] Counter reset after alert...\n";

			FailedLoginRule rule{ 3 };

			SecurityEvent event1{
				1U,
				1ULL,
				EventType::login_failed
			};

			SecurityEvent event2{
				1U,
				2ULL,
				EventType::login_failed
			};

			SecurityEvent event3{
				1U,
				3ULL,
				EventType::login_failed
			};

			SecurityEvent event4{
				1U,
				4ULL,
				EventType::login_failed
			};

			SecurityEvent event5{
				1U,
				5ULL,
				EventType::login_failed
			};

			SecurityEvent event6{
				1U,
				6ULL,
				EventType::login_failed
			};

			EXPECT_TRUE(rule.evaluate(event1) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event2) == std::nullopt);

			auto alert = rule.evaluate(event3);
			EXPECT_TRUE(alert->severity == AlertSeverity::high);

			EXPECT_TRUE(rule.evaluate(event4) == std::nullopt);
			EXPECT_TRUE(rule.evaluate(event5) == std::nullopt);

			alert = rule.evaluate(event6);
			EXPECT_TRUE(alert->severity == AlertSeverity::high);
		}
	}

	void runTests() {
		std::cout << "\n[Suite] Failed Login Rules Tests...\n";

		testLoginRuleZeroAttempts();
		testAlertOnThirdFailure();
		testAgentIsolation();
		testIgnoreHeartbeat();
		testServiceStopReset();
		testAlertResetsCounter();
	}
}