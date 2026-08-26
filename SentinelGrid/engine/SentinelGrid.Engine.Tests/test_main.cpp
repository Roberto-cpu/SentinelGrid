#include <cstdint>
#include <cstdio>
#include <iostream>
#include <variant>
#include <array>
#include <optional>
#include <thread>
#include <future>
#include <chrono>

#include <codecs/packet_decoder.hpp>
#include <concurrency/bounded_blocking_queue.hpp>
#include <rules/failed_login_rule.hpp>
#include <codecs/security_event.hpp>
#include <protocol/control_plane_encoder.hpp>
#include <hmac_sha256_verifier.hpp>

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

namespace sentinelgrid::engine {

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
		std::cout << "Testing packet decoder...\n";

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
		std::cout << "Testing truncated packets...\n";

		const auto eventPacket = getBytesPacket();
		for (size_t i = 0; i < EventPacketSize; ++i) {
			expectedDecodeError(std::span{ eventPacket.data(), i }, DecodeError::packetTooSmall);
		}
	}

	static void testInvalidHeaders() {
		std::cout << "Testing invalid headers...\n";

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

	static void testFIFORoundTrip() {
		std::cout << "Test FIFO queue round-trip...\n";

		concurrency::BoundedBlockingQueue<int> queue{ 3 };

		EXPECT_TRUE(queue.push(10));
		EXPECT_TRUE(queue.push(20));
		EXPECT_TRUE(queue.push(30));

		
		EXPECT_TRUE(queue.pop() == 10);
		EXPECT_TRUE(queue.pop() == 20);
		EXPECT_TRUE(queue.pop() == 30);
	}

	static void testZeroCapacityDetection() {
		std::cout << "Test Zero Capacity initialization...\n";

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
		std::cout << "Testing push after closing queue...\n";

		concurrency::BoundedBlockingQueue<int> queue{ 1 };
		queue.close();

		EXPECT_TRUE(!queue.push(10));
	}

	static void testDrainAfterClose() {
		std::cout << "Test drain after close...\n";

		concurrency::BoundedBlockingQueue<int> queue{ 10 };

		EXPECT_TRUE(queue.push(10));
		EXPECT_TRUE(queue.push(20));

		queue.close();
		EXPECT_TRUE(queue.pop() == 10);
		EXPECT_TRUE(queue.pop() == 20);
		EXPECT_TRUE(queue.pop() == std::nullopt);
	}

	static void testBlockedConsumer() {
		std::cout << "Test blocked consumer...\n";
		 
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
		std::cout << "Test close wakes a blocked consumer...\n";

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
		std::cout << "Test blocked producer...\n";

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

	static void testLoginRuleZeroAttempts() {
		std::cout << "Test zero login attempts allowed...\n";

		bool exceptionThrown = false;

		try {
			FailedLoginRule rule{ 0 };
		}
		catch(std::invalid_argument&) {
			exceptionThrown = true;
		}

		EXPECT_TRUE(exceptionThrown);
	}

	static void testAlertOnThirdFailure() {
		std::cout << "Test alert on third failure...\n";

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
		std::cout << "Test agent isolation...\n";

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
		std::cout << "Test \"Heartbeat\" event is ignored...\n";

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
		std::cout << "Test \"Service Stop\" event resets counter...\n";

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
		std::cout << "Test counter reset after alert...\n";

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
		std::cout << "Test Security Event Encoding...\n";

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
		std::cout << "Test Security Alert Encoding...\n";

		const SecurityAlert alert{ createSecurityAlert()};

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
		
		std::cout << "Test Output Too Small...\n";

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

		std::cout << "Test Agent ID Zero...\n";

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

		std::cout << "Test Invalid Event Type...\n";

		SecurityEvent event{ createSecurityEvent() };
		event.type = static_cast<EventType>(99);
		
		std::array<std::uint8_t, protocol::EventPacketSize> output{};
		protocol::EncodeResult resultEvent{ protocol::encodeControlPlaneMessage(event, output) };

		EXPECT_TRUE(resultEvent.error == protocol::EncodeError::invalid_event_type);
	}

	static void testInvalidAlertType() {

		std::cout << "Test Invalid Alert Type...\n";

		SecurityAlert alert{ createSecurityAlert() };
		alert.type = static_cast<AlertType>(99);

		std::array<std::uint8_t, protocol::AlertPacketSize> output{};
		protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, output) };

		EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_alert_type);
	}

	static void testInvalidAlertSeverity() {

		std::cout << "Test Invalid Alert Severity...\n";

		SecurityAlert alert{ createSecurityAlert() };
		alert.severity = static_cast<AlertSeverity>(0);

		std::array<std::uint8_t, protocol::AlertPacketSize> output{};
		protocol::EncodeResult resultAlert{ protocol::encodeControlPlaneMessage(alert, output) };

		EXPECT_TRUE(resultAlert.error == protocol::EncodeError::invalid_severity);
	}

	static void testInvalidFailuresCount() {

		std::cout << "Test Invalid Failures Count...\n";

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

	static void testValidSecureHmacEncoding() {
		std::cout << "Test Secure Encoding with Valid Inputs...\n";

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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const SecurityEvent* event = std::get_if<SecurityEvent>(&authDecodeRes);

		EXPECT_TRUE(event != nullptr);

		if (event == nullptr)
			return;

		EXPECT_TRUE(event->agent_id == 1U);
		EXPECT_TRUE(event->sequence_number == 1UL);
		EXPECT_TRUE(event->type == EventType::service_stop);
	}

	static void testSecureHmacEncoding_ModifiedAgentId() {
		std::cout << "Test Secure Encoding with Modified Agent ID...\n";

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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}

	static void testSecureHmacEncoding_ModifiedSequenceNumber() {
		std::cout << "Test Secure Encoding with Modified Sequence Number...\n";

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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}

	static void testSecureHmacEncoding_ModifiedEventType() {
		std::cout << "Test Secure Encoding with Modified Event Type...\n";

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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}

	static void testSecureHmacEncoding_ModifiedKeyId() {
		std::cout << "Test Secure Encoding with Modified Key ID...\n";
		
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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}

	static void testSecureHmacEncoding_ModifiedHMAC() {
		std::cout << "Test Secure Encoding with Modified HMAC...\n";
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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}

	static void testSecureHmacEncoding_WrongKey() {
		std::cout << "Test Secure Encoding with Wrong Key...\n";

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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}

	static void testSecureHmacEncoding_TruncatedHMAC() {
		std::cout << "Test Secure Encoding with Truncated HMAC...\n";

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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}

	static void testSecureHmacEncoding_EmptyKey() {
		std::cout << "Test Secure Encoding with Empty Key...\n";

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

		const auto authDecodeRes = decodeAuthenticatedEventPacket(packet, keyId, key);
		const auto* err = std::get_if<DecodeError>(&authDecodeRes);

		EXPECT_TRUE(*err == DecodeError::authenticationFailed);
	}
}

int main(void) {
	std::cout << "Start SentinelGrid Engine Unit Tests.\n\n\n";

	std::cout << "Running Server packet management tests...\n\n";

	sentinelgrid::engine::testPacketDecoder();
	sentinelgrid::engine::testTruncatedPacket();
	sentinelgrid::engine::testInvalidHeaders();

	std::cout << "\nRunning events queue management tests...\n\n";

	sentinelgrid::engine::testFIFORoundTrip();
	sentinelgrid::engine::testZeroCapacityDetection();
	sentinelgrid::engine::testPushAfterClose();
	sentinelgrid::engine::testDrainAfterClose();
	sentinelgrid::engine::testBlockedConsumer();
	sentinelgrid::engine::testWakesAblockedConsumer();
	sentinelgrid::engine::testFullQueueBlock();

	std::cout << "\nRunning login attempts rules management tests...\n\n";

	sentinelgrid::engine::testLoginRuleZeroAttempts();
	sentinelgrid::engine::testAlertOnThirdFailure();
	sentinelgrid::engine::testAgentIsolation();
	sentinelgrid::engine::testIgnoreHeartbeat();
	sentinelgrid::engine::testServiceStopReset();
	sentinelgrid::engine::testAlertResetsCounter();

	std::cout << "\nRunning encoding tests...\n\n";

	sentinelgrid::engine::testControlPlaneEventEncoding();
	sentinelgrid::engine::testControlPlaneAlertEncoding();
	sentinelgrid::engine::testOutputTooSmall();
	sentinelgrid::engine::testAgentIdZero();
	sentinelgrid::engine::testInvalidEventType();
	sentinelgrid::engine::testInvalidAlertType();
	sentinelgrid::engine::testInvalidAlertSeverity();
	sentinelgrid::engine::testInvalidFailuresCount();

	std::cout << "\nRunning secure encoding tests...\n\n";

	sentinelgrid::engine::testValidSecureHmacEncoding();
	sentinelgrid::engine::testSecureHmacEncoding_ModifiedAgentId();
	sentinelgrid::engine::testSecureHmacEncoding_ModifiedSequenceNumber();
	sentinelgrid::engine::testSecureHmacEncoding_ModifiedEventType();
	sentinelgrid::engine::testSecureHmacEncoding_ModifiedKeyId();
	sentinelgrid::engine::testSecureHmacEncoding_ModifiedHMAC();
	sentinelgrid::engine::testSecureHmacEncoding_WrongKey();
	sentinelgrid::engine::testSecureHmacEncoding_TruncatedHMAC();
	sentinelgrid::engine::testSecureHmacEncoding_EmptyKey();

	std::cout << "\nTests Completed: " << testCount << " checks, " << failCount << " failures.\n";
		
	if (failCount == 0) {
		std::cout << "[PASS] All tests passed.\n";
		return EXIT_SUCCESS;
	}

	std::cout << "[FAIL] Some tests failed.\n";
	return EXIT_FAILURE;
}