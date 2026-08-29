#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <cstdlib>
#include <iostream>
#include <array>
#include <thread>
#include <variant>
#include <cstddef>
#include <atomic>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>

#include <network/winsock_runtime.hpp>
#include <network/tcp_server.hpp>
#include <network/unique_socket.hpp>
#include <network/socket_io.hpp>
#include <codecs/packet_decoder.hpp>
#include <concurrency/bounded_blocking_queue.hpp>
#include <agent_session.hpp>
#include <rules/failed_login_rule.hpp>
#include <network/tcp_client.hpp>
#include <protocol/control_plane_encoder.hpp>
#include <security/agent_key_registry.hpp>
#include <security/replay_guard.hpp>

int main() {
	using namespace sentinelgrid::engine;

	using network::WinsockRuntime;
	using network::UniqueSocket;
	using network::TcpServer;
	using network::TcpClient;
	using EventQueue = concurrency::BoundedBlockingQueue<SecurityEvent>;


	security::AgentKeyRegistry keyRegistry;
	security::ReplayGuard replayGuard;

	security::AgentKey agentOneKey{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B,
		0x1C, 0x1D, 0x1E, 0x1F
	};

	security::AgentKey agentTwoKey{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B,
		0x1C, 0x1D, 0x1E, 0x1F
	};

	if (!keyRegistry.registerKey(1U, 1U, agentOneKey)) {
		std::cerr << "Unable to register agent key.\n";
		return EXIT_FAILURE;
	}
	
	if (!keyRegistry.registerKey(1U, 2U, agentTwoKey)) {
		std::cerr << "Unable to register agent key.\n";
		return EXIT_FAILURE;
	}

	SecureZeroMemory(agentOneKey.data(), agentOneKey.size());
	SecureZeroMemory(agentTwoKey.data(), agentTwoKey.size());

	std::cout << "SentinelGrid Engine start.\n\n";

	static_assert(!std::is_copy_constructible_v<UniqueSocket>);
	static_assert(!std::is_copy_assignable_v<UniqueSocket>);

	static_assert(std::is_move_constructible_v<UniqueSocket>);
	static_assert(std::is_move_assignable_v<UniqueSocket>);
	
	constexpr std::size_t AgentCount{ 2 };

	WinsockRuntime winsock;

	if (!winsock.isReady()) {
		std::cerr << "WinSock initialization failed.\n Errcode: " 
			<< winsock.errorCode() << "\n";
		return EXIT_FAILURE;
	}

	std::cout << "WinSock successfully initialized.\n";
	
	TcpServer server;

	if (!server.start(5050U)) {
		std::cerr << "Unable to start the server TCP on port 5050.\n";
		return EXIT_FAILURE;
	}

	std::cout << "SentinelGrid TCP server listening on: 127.0.0.1:5050.\n";
	std::cout << "Waiting for Agent connection...\n";

	TcpClient client;

	if (!client.connect("127.0.0.1", 6060U)) {
		std::cerr << "Unable to connect to the server on port 6060.\n";
		return EXIT_FAILURE;
	}

	std::cout << "Client connected on 127.0.0.1:6060.\n";


	std::atomic_bool publicationFailed{ false };
	std::vector<app::SessionResult> sessionResults(AgentCount);
	std::vector<std::jthread> sessionWorkers;
	sessionWorkers.reserve(AgentCount);

	FailedLoginRule loginRule{ 3 };
	EventQueue eventQueue{ 4 };

	std::size_t processedEvents{ 0 };
	std::size_t totalEvents{ 0 };

	std::jthread processor{
		[&eventQueue,&client, &loginRule, &processedEvents, &publicationFailed]() {

			while (auto event = eventQueue.pop()) {

				if (!event.has_value())
					break;

				std::cout << "Sending event: Agent=" << event->agent_id
					<< ", Sequence=" << event->sequence_number
					<< ", Type=" << eventTypeToString(event->type)
					<< "\n";

				std::array<std::uint8_t, protocol::EventPacketSize> eventFrame{};
				const auto eventEncodeResult = protocol::encodeControlPlaneMessage(*event, eventFrame);
				
				if (!eventEncodeResult.is_success()) {
					std::cerr << "Unable to encode the event.\n";
					publicationFailed = true;
					eventQueue.close();
					break;
				}

				const auto eventSendResult = network::sendAll(
					client.socket(), 
					std::span<const std::uint8_t>{
						eventFrame.data(), 
						eventEncodeResult.byte_written
					}
				);

				if (!eventSendResult.isSuccess()) {
					std::cerr << "Unable to publish the event.\n"
						<< "Sent bytes: " << eventSendResult.sentBytes
						<< ", Error: " << eventSendResult.errorCode << "\n";
					publicationFailed = true;
					eventQueue.close();
					break;
				}

				const auto loginAlert = loginRule.evaluate(*event);
				if (loginAlert.has_value()) {
					std::cout << "Sending alert: Type=" << alertTypeToString(loginAlert->type)
						<< ", Severity=" << alertSeverityToString(loginAlert->severity)
						<< ", Agent=" << loginAlert->agent_id
						<< ", Sequence=" << loginAlert->triggering_sequence
						<< " , Failures=" << loginAlert->failure_count
						<< "\n";

					std::array<std::uint8_t, protocol::AlertPacketSize> alertFrame{};
					const auto alertEncodeResult = protocol::encodeControlPlaneMessage(*loginAlert, alertFrame);

					if (!alertEncodeResult.is_success()) {
						std::cerr << "Unable to encode alert.\n";
						publicationFailed = true;
						eventQueue.close();
						break;
					}

					const auto alertSedResult = network::sendAll(
						client.socket(),
						std::span<const std::uint8_t> {
							alertFrame.data(),
							alertEncodeResult.byte_written
						}
					);

					if (!alertSedResult.isSuccess()) {
						std::cerr << "Unable to publish the alert.\n";
						publicationFailed = true;
						eventQueue.close();
						break;
					}

				}

				processedEvents++;
			}

			std::cout << "Event processor stopped.\n";
		}
	};

	for (std::size_t i = 0; i < AgentCount; ++i) {
		auto client = server.acceptClient();
		
		if (!client.isValid()) {
			std::cerr << "Unable to accept Agent \"" << (i + 1) << "\" connection.\n";
			break;
		}

		std::cout << "Opened session for agent \"" << (i + 1) << "\".\n";

		sessionWorkers.emplace_back(
			[client = std::move(client), &eventQueue, &sessionResults, i, &keyRegistry, &replayGuard]() mutable {
					sessionResults[i] = app::runSessionAgent(std::move(client), eventQueue, keyRegistry, replayGuard);
				}
			);
	}

	for (auto& worker : sessionWorkers) {
		if (worker.joinable())
			worker.join();
	}

	eventQueue.close();

	if (processor.joinable())
		processor.join();

	for (const auto& result : sessionResults) {
		totalEvents += result.eventsReceived;
	}

	server.stop();

	if (server.isRunning()) {
		std::cerr << "Server did not stop correctly.\n";
		return EXIT_FAILURE;
	}

	std::cout << "Server stopped.\n";
	std::cout << "Processed Events: " << processedEvents << "/" << totalEvents << ".\n";

	return  EXIT_SUCCESS;
}