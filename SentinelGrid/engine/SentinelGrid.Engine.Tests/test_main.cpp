#include <cstdint>
#include <cstdio>
#include <iostream>
#include <variant>
#include <array>
#include <optional>
#include <thread>
#include <future>
#include <chrono>
#include <type_traits>
#include <string>

#include <codecs/packet_decoder.hpp>
#include <concurrency/bounded_blocking_queue.hpp>
#include <rules/failed_login_rule.hpp>
#include <codecs/security_event.hpp>
#include <protocol/control_plane_encoder.hpp>
#include <security/hmac_sha256_verifier.hpp>
#include <security/agent_key_registry.hpp>

static int testCount = 0;
static int failCount = 0;

#define EXPECT_TRUE(condition)				\
	do {									\
		testCount++;						\
		if (!(condition)) {					\
			failCount++;					\
			printf(							\
				"[FAIL] Line %d: %s\n",		\
				__LINE__,					\
				#condition					\
			);								\
		}									\
	} while(0)								\

namespace sentinelgrid::engine::tests {

	namespace decoding {

		static void expectedDecodeError(std::span<const std::uint8_t> packet, DecodeError expectedError) {
			const auto result = decodeEventPacket(packet);

			EXPECT_TRUE(std::holds_alternative<DecodeError>(result));

			if (const auto* error = std::get_if<DecodeError>(&result))
				EXPECT_TRUE(*error == expectedError);
		}

		static std::array<std::uint8_t, EventPacketSize> getBytesPacket() {
			return {
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x01,
				0x00, 0x10,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x01
			};
		}

		static void testPacketDecoder() {
			std::cout << "[Test][Decoder] packet correctly decode...\n";
			
			const auto heartbeatPacket = getBytesPacket();

			const auto result = decodeEventPacket(heartbeatPacket);
			EXPECT_TRUE(std::holds_alternative<SecurityEvent>(result));

			if (std::holds_alternative<SecurityEvent>(result)) {
				const auto& event = std::get<SecurityEvent>(result);

				EXPECT_TRUE(event.agent_id == 1U);
				EXPECT_TRUE(event.sequence_number == 1ULL);
				EXPECT_TRUE(event.type == EventType::heartbeat);
			}
		}

		static void testTruncatedPacket() {
			std::cout << "[Test][Decoder] truncated packets...\n";

			const auto eventPacket = getBytesPacket();
			for (size_t i = 0; i < EventPacketSize; ++i) {
				expectedDecodeError(std::span{ eventPacket.data(), i }, DecodeError::packetTooSmall);
			}
		}

		static void testInvalidHeaders() {
			std::cout << "[Test][Decoder] invalid headers...\n";

			const auto validPacket = getBytesPacket();

			auto invalidMagic = validPacket;
			invalidMagic[0] ^= 0x10;
			expectedDecodeError(invalidMagic, DecodeError::invalidMagic);

			auto invalidVersion = validPacket;
			invalidVersion[4] = 0x00;
			invalidVersion[5] = 0x02;
			expectedDecodeError(invalidVersion, DecodeError::unsupportedVersion);

			auto invalidPacketLength = validPacket;
			invalidPacketLength[6] = 0x00;
			invalidPacketLength[7] = 0x0F;
			expectedDecodeError(invalidPacketLength, DecodeError::invalidPayloadLength);

			auto invalidPacketType = validPacket;
			invalidPacketType[20] = 0x00;
			invalidPacketType[21] = 0x00;
			invalidPacketType[22] = 0x00;
			invalidPacketType[23] = 0x63;
			expectedDecodeError(invalidPacketType, DecodeError::invalidEventType);
		}
	}

	namespace queue {
		static void testFIFORoundTrip() {
			std::cout << "[Test][Queue] FIFO queue round-trip...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 3 };

			EXPECT_TRUE(queue.push(10));
			EXPECT_TRUE(queue.push(20));
			EXPECT_TRUE(queue.push(30));


			EXPECT_TRUE(queue.pop() == 10);
			EXPECT_TRUE(queue.pop() == 20);
			EXPECT_TRUE(queue.pop() == 30);
		}

		static void testZeroCapacityDetection() {
			std::cout << "[Test][Queue] Zero Capacity initialization...\n";

			bool exceptionThrown = false;

			try {
				concurrency::BoundedBlockingQueue<int> queue{ 0 };
			}
			catch (const std::invalid_argument&) {
				exceptionThrown = true;
			}

			EXPECT_TRUE(exceptionThrown);
		}

		static void testPushAfterClose() {
			std::cout << "[Test][Queue] push after closing queue...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };
			queue.close();

			EXPECT_TRUE(!queue.push(10));
		}

		static void testDrainAfterClose() {
			std::cout << "[Test][Queue] drain after close...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 10 };

			EXPECT_TRUE(queue.push(10));
			EXPECT_TRUE(queue.push(20));

			queue.close();
			EXPECT_TRUE(queue.pop() == 10);
			EXPECT_TRUE(queue.pop() == 20);
			EXPECT_TRUE(queue.pop() == std::nullopt);
		}

		static void testBlockedConsumer() {
			std::cout << "[Test][Queue] blocked consumer...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };

			std::promise<void> startedPromise;
			const auto startedFuture = startedPromise.get_future();

			std::promise<std::optional<int>> resultPromise;
			const auto resultFuture = resultPromise.get_future();

			std::jthread consumer{
				[&queue, &startedPromise, &resultPromise]() {
					startedPromise.set_value();
					resultPromise.set_value(queue.pop()); // Blocks the consumer until the a value is pushed into the queue
				}
			};

			startedFuture.wait(); // ensures that the consumer thread has started

			// checks that the consumer waits because the queue is empty
			EXPECT_TRUE(resultFuture.wait_for(std::chrono::microseconds{ 50 }) == std::future_status::timeout);
			EXPECT_TRUE(queue.push(42));

			const auto status = resultFuture.wait_for(std::chrono::milliseconds{ 1 });
			EXPECT_TRUE(status == std::future_status::ready);

			if (status == std::future_status::ready) {
				const auto result = resultFuture._Get_value();
				EXPECT_TRUE(result.has_value());

				if (result.has_value()) {
					EXPECT_TRUE(result.value() == 42);
				}
			}
		}

		static void testWakesAblockedConsumer() {
			std::cout << "[Test][Queue] close wakes a blocked consumer...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };

			std::promise<void> startedPromise;
			const auto startedFuture = startedPromise.get_future();

			std::promise<std::optional<int>> resultPromise;
			const auto resultFuture = resultPromise.get_future();

			std::jthread consumer{
				[&queue, &startedPromise, &resultPromise]() {
					startedPromise.set_value();
					resultPromise.set_value(queue.pop()); // Blocks the consumer until the a value is pushed into the queue
				}
			};

			startedFuture.wait(); // ensures that the consumer thread has started

			// checks that the consumer waits because the queue is empty
			EXPECT_TRUE(resultFuture.wait_for(std::chrono::microseconds{ 50 }) == std::future_status::timeout);

			queue.close();

			const auto status = resultFuture.wait_for(std::chrono::milliseconds{ 1 });
			EXPECT_TRUE(status == std::future_status::ready);

			if (status == std::future_status::ready) {
				const auto result = resultFuture._Get_value();
				EXPECT_TRUE(!result.has_value());
			}
		}

		static void testFullQueueBlock() {
			std::cout << "[Test][Queue] blocked producer...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };
			EXPECT_TRUE(queue.push(10));

			std::promise<void> startPromise;
			auto startFuture = startPromise.get_future();

			std::promise<std::optional<int>> pushPromise;
			auto pushFuture = pushPromise.get_future();

			std::jthread consumer{
				[&queue, &startPromise, &pushPromise]() {
					startPromise.set_value();
					pushPromise.set_value(queue.push(20));
				}
			};

			startFuture.wait();
			EXPECT_TRUE(pushFuture.wait_for(std::chrono::microseconds{ 50 }) == std::future_status::timeout);

			EXPECT_TRUE(queue.size() == 1);

			const auto first = queue.pop();

			EXPECT_TRUE(first.has_value());

			if (first.has_value()) {
				EXPECT_TRUE(*first == 10);
			}

			const auto status = pushFuture.wait_for(std::chrono::milliseconds{ 1 });
			EXPECT_TRUE(status == std::future_status::ready);

			if (status == std::future_status::ready)
				EXPECT_TRUE(pushFuture.get());

			const auto second = queue.pop();

			EXPECT_TRUE(second.has_value());

			if (second.has_value())
				EXPECT_TRUE(*second == 20);

			queue.close();
		}
	}

	namespace rules {
		static void testLoginRuleZeroAttempts() {
			std::cout << "[Test][Login-Rules] zero login attempts allowed...\n";

			bool exceptionThrown = false;

			try {
				FailedLoginRule rule{ 0 };
			}
			catch (std::invalid_argument&) {
				exceptionThrown = true;
			}

			EXPECT_TRUE(exceptionThrown);
		}

		static void testAlertOnThirdFailure() {
			std::cout << "[Test][Login-Rules] alert on third failure...\n";

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

		static void testAgentIsolation() {
			std::cout << "[Test][Login-Rules] agent isolation...\n";

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

		static void testIgnoreHeartbeat() {
			std::cout << "[Test][Login-Rules] \"Heartbeat\" event is ignored...\n";

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

		static void testServiceStopReset() {
			std::cout << "[Test][Login-Rules] \"Service Stop\" event resets counter...\n";

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

		static void testAlertResetsCounter() {
			std::cout << "[Test][Login-Rules] counter reset after alert...\n";

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

	namespace encoding {
		static SecurityEvent createSecurityEvent() {
			return{
				.agent_id = 101U,
				.sequence_number = 3ULL,
				.type = EventType::login_failed
			};
		}

		static SecurityAlert createSecurityAlert() {
			return{
				.type = AlertType::repeated_login_failure,
				.severity = AlertSeverity::high,
				.agent_id = 101U,
				.triggering_sequence = 3ULL,
				.failure_count = 3U
			};
		}

		static void testControlPlaneEventEncoding() {
			std::cout << "[Test][Encoding] Security Event Encoding...\n";

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

		static void testControlPlaneAlertEncoding() {
			std::cout << "[Test][Encoding] Security Alert Encoding...\n";

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

		static void testOutputTooSmall() {

			std::cout << "[Test][Encoding] output too small...\n";

			const SecurityEvent event{ createSecurityEvent() };
			const SecurityAlert alert{ createSecurityAlert() };

			std::array<std::uint8_t, protocol::EventPacketSize - 1> outputEvent{};
			protocol::EncodeResult resultEvent{ protocol::encodeControlPlaneMessage(event, outputEvent) };

			std::array<std::uint8_t, protocol::AlertPacketSize - 1> outputAlert{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, outputAlert) };

			EXPECT_TRUE(resultEvent.error == protocol::EncodeError::output_too_small);
			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::output_too_small);
		}

		static void testAgentIdZero() {

			std::cout << "[Test][Encoding] agent ID zero...\n";

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

		static void testInvalidEventType() {

			std::cout << "[Test][Encoding] invalid event type...\n";

			SecurityEvent event{ createSecurityEvent() };
			event.type = static_cast<EventType>(99);

			std::array<std::uint8_t, protocol::EventPacketSize> output{};
			protocol::EncodeResult resultEvent{ protocol::encodeControlPlaneMessage(event, output) };

			EXPECT_TRUE(resultEvent.error == protocol::EncodeError::invalid_event_type);
		}

		static void testInvalidAlertType() {

			std::cout << "[Test][Encoding] invalid alert type...\n";

			SecurityAlert alert{ createSecurityAlert() };
			alert.type = static_cast<AlertType>(99);

			std::array<std::uint8_t, protocol::AlertPacketSize> output{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, output) };

			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_alert_type);
		}

		static void testInvalidAlertSeverity() {

			std::cout << "[Test][Encoding] invalid alert severity...\n";

			SecurityAlert alert{ createSecurityAlert() };
			alert.severity = static_cast<AlertSeverity>(0);

			std::array<std::uint8_t, protocol::AlertPacketSize> output{};
			protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, output) };

			EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_severity);
		}

		static void testInvalidFailuresCount() {

			std::cout << "[Test][Encoding] invalid failures count...\n";

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

	namespace secure::encoding {
		static void testValidSecureHmacEncoding() {
			std::cout << "[Test][HMAC-SHA256] valid inputs...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const SecurityEvent* event = std::get_if<SecurityEvent>(&authDecodeRes);

			EXPECT_TRUE(event != nullptr);

			if (event == nullptr)
				return;

			EXPECT_TRUE(event->agent_id == 1U);
			EXPECT_TRUE(event->sequence_number == 1UL);
			EXPECT_TRUE(event->type == EventType::service_stop);
		}

		static void testSecureHmacEncoding_ModifiedAgentId() {
			std::cout << "[Test][HMAC-SHA256] modified agent ID...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x00,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}

		static void testSecureHmacEncoding_ModifiedSequenceNumber() {
			std::cout << "[Test][HMAC-SHA256] modified sequence number...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}

		static void testSecureHmacEncoding_ModifiedEventType() {
			std::cout << "[Test][HMAC-SHA256] modified event type...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x99,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}

		static void testSecureHmacEncoding_ModifiedKeyId() {
			std::cout << "[Test][HMAC-SHA256] modified key ID...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x00,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		static void testSecureHmacEncoding_ModifiedHMAC() {
			std::cout << "[Test][HMAC-SHA256] modified HMAC...\n";
			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0x00
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}

		static void testSecureHmacEncoding_WrongKey() {
			std::cout << "[Test][HMAC-SHA256] wrong key...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x00
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}

		static void testSecureHmacEncoding_TruncatedHMAC() {
			std::cout << "[Test][HMAC-SHA256] truncated HMAC...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}

		static void testSecureHmacEncoding_EmptyKey() {
			std::cout << "[Test][HMAC-SHA256] empty key...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}

		static void testSecureHmacEncoding_TamperedPacket() {
			std::cout << "[Test][HMAC-SHA256] tampered packet...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			auto tamperedPacket = packet;
			tamperedPacket[PacketHeaderSize] = static_cast<std::uint8_t>(tamperedPacket[PacketHeaderSize] ^ 0x01U);

			security::AgentKeyRegistry keyRegistry;
			auto registered = keyRegistry.registerKey(keyId, 1U, key);

			if (!registered) return;

			const auto authDecodeRes = decodeAuthenticatedEventPacket(tamperedPacket, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&authDecodeRes);

			EXPECT_TRUE(*err == DecodeError::cryptographicFailure);
		}
	}

	namespace registry::key {
		static void testKeyRegistrationSuccess() {
			std::cout << "[Test][Key-Registry] new key registration...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered = keyRegistry.registerKey(keyId, 1U, key);

			EXPECT_TRUE(registered);
		}

		static void testKeyRegistrationTwice() {
			std::cout << "[Test][Key-Registry] register two times the same key ID...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<std::uint8_t, 32> key2{
				0x00, 0x01, 0x02, 0x00,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered1 = keyRegistry.registerKey(keyId, 1U, key1);
			bool registered2 = keyRegistry.registerKey(keyId, 2U, key2);

			EXPECT_TRUE(registered1 && !registered2);
		}

		static void testFindExistentKey() {
			std::cout << "[Test][Key-Registry] find existent key...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;
			
			bool registered = keyRegistry.registerKey(keyId, 1U, key);
			EXPECT_TRUE(registered);

			const auto foundKey = keyRegistry.findCredential(keyId);
			EXPECT_TRUE(foundKey.has_value() && std::ranges::equal(foundKey.value().key, key));
		}

		static void testFindNotExistentKey() {
			std::cout << "[Test][Key-Registry] find not existent key...\n";

			security::AgentKeyRegistry keyRegistry;
			const auto foundKey = keyRegistry.findCredential(1U);

			EXPECT_TRUE(!foundKey.has_value());
		}

		static void testFindForTwoDifferentKeys() {
			std::cout << "[Test][Key-Registry] find for key ID returns only the associated key...\n";

			constexpr std::uint32_t keyId1 = 1U;
			constexpr std::uint32_t keyId2 = 2U;

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<std::uint8_t, 32> key2{
				0x00, 0x01, 0x02, 0x00,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered1 = keyRegistry.registerKey(keyId1, 1U, key1);
			bool registered2 = keyRegistry.registerKey(keyId2, 2U, key2);

			EXPECT_TRUE(registered1 && registered2);

			const auto foundKey1 = keyRegistry.findCredential(keyId1);
			const auto foundKey2 = keyRegistry.findCredential(keyId2);

			EXPECT_TRUE(foundKey1.has_value() && std::ranges::equal(foundKey1.value().key, key1));
			EXPECT_TRUE(foundKey2.has_value() && std::ranges::equal(foundKey2.value().key, key2));
		}

		static void testDecodePacketWithAnotherKey() {
			std::cout << "[Test][Key-Registry] cannot decode a packet with another packet's key...\n";

			constexpr std::uint32_t keyId1 = 2U;

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered1 = keyRegistry.registerKey(keyId1, 1U, key1);
			EXPECT_TRUE(registered1);

			const auto foundKey1 = keyRegistry.findCredential(keyId1);
			EXPECT_TRUE(foundKey1.has_value() && std::ranges::equal(foundKey1.value().key, key1));

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		static void testMatchingKeyAndAgent() {
			std::cout << "[Test][Key-Registry] matching key ID and agent ID...\n";

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(1U, 1U, key);
			EXPECT_TRUE(registered);

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto *securityEvent = std::get_if<SecurityEvent>(&result);

			EXPECT_TRUE(securityEvent->agent_id == 1U);
		}

		static void testUnknownKeyID() {
			std::cout << "[Test][Key-Registry] unknown key ID...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(2U, 1U, key1);
			EXPECT_TRUE(registered);

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		static void testHmacForAnotherAgent() {
			std::cout << "[Test][Key-Registry] valid HMAC claiming another agent ID...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(1U, 2U, key1);
			EXPECT_TRUE(registered);

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		static void testAgentImpersonification() {
			std::cout << "[Test][Key-Registry] agent 2 cannot impersonate agent 1 ...\n";

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};
			
			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> impersonedPacket{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x02,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				0x65, 0xCE, 0x14, 0xB8,
				0x76, 0xA8, 0x9B, 0xEE,
				0xD7, 0x68, 0x32, 0x01,
				0xC5, 0x79, 0xE0, 0x29,
				0x85, 0x8E, 0x2C, 0x9E,
				0xBA, 0x52, 0x78, 0xCE,
				0x1B, 0x05, 0x53, 0x20,
				0x43, 0xA1, 0x5D, 0xA8
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(1U, 1U, key);
			EXPECT_TRUE(registered);

			if (!registered) return;

			const std::span<const std::uint8_t> packetView{ impersonedPacket };
			
			const auto verificationRes = security::verifyHmacSha256(
				key,
				packetView.first(security::authenticatedDataSize),
				packetView.subspan(HmacSha256Offset, security::hmacSha256Size)
			);

			EXPECT_TRUE(verificationRes == security::HmacVerificationResult::valid);

			if (verificationRes != security::HmacVerificationResult::valid) return;

			const auto result = decodeAuthenticatedEventPacket(impersonedPacket, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		static void testDuplicatedKeyID() {
			std::cout << "[Test][Key-Registry] reject duplicated key ID...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered1 = keyRegistry.registerKey(2U, 1U, key1);
			bool registered2 = keyRegistry.registerKey(2U, 2U, key1);
			EXPECT_TRUE(registered1 && !registered2);
		}

		static void testOneAgentWithTwoKeyIDs() {
			std::cout << "[Test][Key-Registry] an agent can have multiple key IDs...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered1 = keyRegistry.registerKey(1U, 1U, key1);
			bool registered2 = keyRegistry.registerKey(2U, 1U, key1);
			EXPECT_TRUE(registered1 && registered2);
		}

		static void testCredentialsLookupReturnesStoredKeysView() {
			std::cout << "[Test][Key-Registry] credential lookup returns stored key view...\n";

			constexpr std::uint32_t keyId{ 1U };
			constexpr std::uint32_t agentId{ 42U };

			const security::AgentKey key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(keyId, agentId, key);
			EXPECT_TRUE(registered);

			if (!registered) return;

			const auto firstLookup = keyRegistry.findCredential(keyId);
			EXPECT_TRUE(firstLookup.has_value());

			if (!firstLookup.has_value()) return;

			EXPECT_TRUE(firstLookup->agent_id == agentId);
			EXPECT_TRUE(firstLookup->key.size() == key.size());
			EXPECT_TRUE(std::ranges::equal(firstLookup->key, key));

			EXPECT_TRUE(firstLookup->key.data() != key.data());

			const auto secondLookup = keyRegistry.findCredential(keyId);
			EXPECT_TRUE(secondLookup.has_value());

			if (!secondLookup.has_value()) return;

			EXPECT_TRUE(firstLookup->key.data() == secondLookup->key.data());
			EXPECT_TRUE(std::ranges::equal(secondLookup->key, key));
		}
	}
}

int main(void) {
	std::cout << "Start SentinelGrid Engine Unit Tests.\n\n\n";

	std::cout << "Running Server packet management tests...\n\n";

	sentinelgrid::engine::tests::decoding::testPacketDecoder();
	sentinelgrid::engine::tests::decoding::testTruncatedPacket();
	sentinelgrid::engine::tests::decoding::testInvalidHeaders();

	std::cout << "\nRunning events queue management tests...\n\n";

	sentinelgrid::engine::tests::queue::testFIFORoundTrip();
	sentinelgrid::engine::tests::queue::testZeroCapacityDetection();
	sentinelgrid::engine::tests::queue::testPushAfterClose();
	sentinelgrid::engine::tests::queue::testDrainAfterClose();
	sentinelgrid::engine::tests::queue::testBlockedConsumer();
	sentinelgrid::engine::tests::queue::testWakesAblockedConsumer();
	sentinelgrid::engine::tests::queue::testFullQueueBlock();

	std::cout << "\nRunning login attempts rules management tests...\n\n";

	sentinelgrid::engine::tests::rules::testLoginRuleZeroAttempts();
	sentinelgrid::engine::tests::rules::testAlertOnThirdFailure();
	sentinelgrid::engine::tests::rules::testAgentIsolation();
	sentinelgrid::engine::tests::rules::testIgnoreHeartbeat();
	sentinelgrid::engine::tests::rules::testServiceStopReset();
	sentinelgrid::engine::tests::rules::testAlertResetsCounter();

	std::cout << "\nRunning encoding tests...\n\n";

	sentinelgrid::engine::tests::encoding::testControlPlaneEventEncoding();
	sentinelgrid::engine::tests::encoding::testControlPlaneAlertEncoding();
	sentinelgrid::engine::tests::encoding::testOutputTooSmall();
	sentinelgrid::engine::tests::encoding::testAgentIdZero();
	sentinelgrid::engine::tests::encoding::testInvalidEventType();
	sentinelgrid::engine::tests::encoding::testInvalidAlertType();
	sentinelgrid::engine::tests::encoding::testInvalidAlertSeverity();
	sentinelgrid::engine::tests::encoding::testInvalidFailuresCount();

	std::cout << "\nRunning secure encoding tests...\n\n";

	sentinelgrid::engine::tests::secure::encoding::testValidSecureHmacEncoding();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_ModifiedAgentId();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_ModifiedSequenceNumber();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_ModifiedEventType();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_ModifiedKeyId();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_ModifiedHMAC();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_WrongKey();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_TruncatedHMAC();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_EmptyKey();
	sentinelgrid::engine::tests::secure::encoding::testSecureHmacEncoding_TamperedPacket();

	std::cout << "\nRunning key registry tests...\n\n";

	sentinelgrid::engine::tests::registry::key::testKeyRegistrationSuccess();
	sentinelgrid::engine::tests::registry::key::testKeyRegistrationTwice();
	sentinelgrid::engine::tests::registry::key::testFindExistentKey();
	sentinelgrid::engine::tests::registry::key::testFindNotExistentKey();
	sentinelgrid::engine::tests::registry::key::testFindForTwoDifferentKeys();
	sentinelgrid::engine::tests::registry::key::testDecodePacketWithAnotherKey();
	sentinelgrid::engine::tests::registry::key::testMatchingKeyAndAgent();
	sentinelgrid::engine::tests::registry::key::testUnknownKeyID();
	sentinelgrid::engine::tests::registry::key::testAgentImpersonification();
	sentinelgrid::engine::tests::registry::key::testHmacForAnotherAgent();
	sentinelgrid::engine::tests::registry::key::testDuplicatedKeyID();
	sentinelgrid::engine::tests::registry::key::testOneAgentWithTwoKeyIDs();
	sentinelgrid::engine::tests::registry::key::testCredentialsLookupReturnesStoredKeysView();

	std::cout << "\nTests Completed: " << testCount << " checks, " << failCount << " failures.\n";
		
	if (failCount == 0) {
		std::cout << "[PASS] All tests passed.\n";
		return EXIT_SUCCESS;
	}

	std::cout << "[FAIL] Some tests failed.\n";
	return EXIT_FAILURE;
}