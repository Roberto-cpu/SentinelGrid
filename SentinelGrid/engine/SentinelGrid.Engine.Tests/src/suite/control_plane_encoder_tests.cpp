/*
 * @file test_framework.cpp
 * @brief Implementation of control plane encoder test runner
 *
 * This file contains the implementation of the test runner containing the control plan encoder
 * tests
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>

#include <codecs/security_event.hpp>
#include <protocol/control_plane_encoder.hpp>

#include <tests/test_framework.hpp>
#include <tests/suites/control_plane_encoder_tests.hpp>

namespace sentinelgrid::engine::tests::encoder {
	
	namespace {
		/**
		 * @brief: Creates a test security event.
		 */
		static SecurityEvent createSecurityEvent() {
			return{
				.agent_id = 101U,
				.sequence_number = 3ULL,
				.type = EventType::login_failed
			};
		}

		/**
		 * @brief: Creates a test security alert.
		 */
		static SecurityAlert createSecurityAlert() {
			return{
				.type = AlertType::repeated_login_failure,
				.severity = AlertSeverity::high,
				.agent_id = 101U,
				.triggering_sequence = 3ULL,
				.failure_count = 3U
			};
		}

		/**
		 * @brief: Tests the encoding of control plane events.
		 */
		static void testControlPlaneEventEncoding() {
			std::cout << "[+] Security Event Encoding...\n";

			const SecurityEvent event{ createSecurityEvent() };

			std::array<std::uint8_t, protocol::EventPacketSize> output{};
			protocol::EncodeResult result{ protocol::encodeControlPlaneMessage(event, output) };

			EXPECT_TRUE(result.is_success());
			EXPECT_TRUE(result.byte_written == 28);

			constexpr std::array<std::uint8_t, protocol::EventPacketSize> expectedBytes{
				0x53, 0x47, 0x52, 0x44, // SGRD
				0x00, 0x01,             // Version
				0x00, 0x01,             // SecurityEvent
				0x00, 0x00, 0x00, 0x10, // Payload size 16

				0x00, 0x00, 0x00, 0x65, // Agent 101

				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x03, // Sequence 3

				0x00, 0x00, 0x00, 0x02  // LoginFailed	
			};

			EXPECT_TRUE(output == expectedBytes);
		}

		/**
		 * @brief: Tests the encoding of control plane alerts.
		 */
		static void testControlPlaneAlertEncoding() {
			std::cout << "[+] Security Alert Encoding...\n";

			const SecurityAlert alert{ createSecurityAlert() };

			std::array<std::uint8_t, protocol::AlertPacketSize> output{};
			protocol::EncodeResult result{ protocol::encodeControlPlaneMessage(alert, output) };

			EXPECT_TRUE(result.is_success());
			EXPECT_TRUE(result.byte_written == 36);

			constexpr std::array<std::uint8_t, protocol::AlertPacketSize> expectedBytes{
				0x53, 0x47, 0x52, 0x44, // SGRD
				0x00, 0x01,             // Version
				0x00, 0x02,             // SecurityAlert
				0x00, 0x00, 0x00, 0x18, // Payload size 24

				0x00, 0x00, 0x00, 0x01, // RepeatedLoginFailures
				0x00, 0x00, 0x00, 0x03, // High
				0x00, 0x00, 0x00, 0x65, // Agent 101

				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x03, // Triggering sequence 3

				0x00, 0x00, 0x00, 0x03  // Failure count 3	
			};

			EXPECT_TRUE(output == expectedBytes);
		}

		/**
		 * @brief: Tests the behavior when the output buffer is too small.
		 */
		static void testOutputTooSmall() {

			std::cout << "[+] Output too small...\n";

			const SecurityEvent event{ createSecurityEvent() };
			const SecurityAlert alert{ createSecurityAlert() };

			std::array<std::uint8_t, protocol::EventPacketSize - 1> outputEvent{};
			protocol::EncodeResult resultEvent{ protocol::encodeControlPlaneMessage(event, outputEvent) };

			std::array<std::uint8_t, protocol::AlertPacketSize - 1> outputAlert{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, outputAlert) };

			EXPECT_TRUE(resultEvent.error == protocol::EncodeError::output_too_small);
			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::output_too_small);
		}

		/**
		 * @brief: Tests the behavior when the agent ID is zero.
		 */
		static void testAgentIdZero() {

			std::cout << "[+] Agent ID zero...\n";

			SecurityEvent event{ createSecurityEvent() };
			event.agent_id = 0U;

			SecurityAlert alert{ createSecurityAlert() };
			alert.agent_id = 0U;

			std::array<std::uint8_t, protocol::EventPacketSize> outputEvent{};
			protocol::EncodeResult resultEvent{ protocol::encodeControlPlaneMessage(event, outputEvent) };

			std::array<std::uint8_t, protocol::AlertPacketSize> outputAlert{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, outputAlert) };

			EXPECT_TRUE(resultEvent.error == protocol::EncodeError::invalid_agent_id);
			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_agent_id);
		}

		/**
		 * @brief: Tests the behavior with an invalid event type.
		 */
		static void testInvalidEventType() {

			std::cout << "[+] Invalid event type...\n";

			SecurityEvent event{ createSecurityEvent() };
			event.type = static_cast<EventType>(99);

			std::array<std::uint8_t, protocol::EventPacketSize> output{};
			protocol::EncodeResult resultEvent{ protocol::encodeControlPlaneMessage(event, output) };

			EXPECT_TRUE(resultEvent.error == protocol::EncodeError::invalid_event_type);
		}

		/**
		 * @brief: Tests the behavior with an invalid alert type.
		 */
		static void testInvalidAlertType() {

			std::cout << "[+] Invalid alert type...\n";

			SecurityAlert alert{ createSecurityAlert() };
			alert.type = static_cast<AlertType>(99);

			std::array<std::uint8_t, protocol::AlertPacketSize> output{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, output) };

			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_alert_type);
		}

		/**
		 * @brief: Tests the behavior with an invalid alert severity.
		 */
		static void testInvalidAlertSeverity() {

			std::cout << "[+] Invalid alert severity...\n";

			SecurityAlert alert{ createSecurityAlert() };
			alert.severity = static_cast<AlertSeverity>(0);

			std::array<std::uint8_t, protocol::AlertPacketSize> output{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, output) };

			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_severity);
		}

		/**
		 * @brief: Tests the behavior with an invalid failures count.
		 */
		static void testInvalidFailuresCount() {

			std::cout << "[+] Invalid failures count...\n";

			SecurityAlert alert{ createSecurityAlert() };
			alert.failure_count = 0;

			std::array<std::uint8_t, protocol::AlertPacketSize> outputAlert0{};
			protocol::EncodeResult resultAlert0{ protocol::encodeControlPlaneMessage(alert, outputAlert0) };

			EXPECT_TRUE(resultAlert0.error == protocol::EncodeError::invalid_failure_count);

			alert.failure_count = UINT32_MAX + 1;

			std::array<std::uint8_t, protocol::AlertPacketSize> outputAlert{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, outputAlert) };

			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_failure_count);
		}
	}

	void runTests() {
		std::cout << "\n[Suite] Control Plane Encoder Tests...\n";

		testControlPlaneEventEncoding();
		testControlPlaneAlertEncoding();
		testOutputTooSmall();
		testAgentIdZero();
		testInvalidEventType();
		testInvalidAlertType();
		testInvalidAlertSeverity();
		testInvalidFailuresCount();
	}
}