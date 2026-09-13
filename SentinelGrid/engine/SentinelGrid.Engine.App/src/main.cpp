/*
 * @file main.cpp
 * @brief This file contains the main entry point for the SentinelGrid Engine application.
 *
 * This application is responsible for managing agent sessions and handling security events.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

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
#include <string>

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
#include <security/windows_credential_store.hpp>

 /**
  * @brief Structure representing the configuration for an agent's credentials.
  */
struct AgentCredentialConfiguration {
	std::uint32_t keyId;
	std::uint32_t agentId;
	std::wstring  target;
};

int main() {

	std::cout << "[+] SentinelGrid Engine start.\n\n";

	using namespace sentinelgrid::engine;

	using network::WinsockRuntime;
	using network::UniqueSocket;
	using network::TcpServer;
	using network::TcpClient;
	using EventQueue = concurrency::BoundedBlockingQueue<SecurityEvent>;

	const std::array<AgentCredentialConfiguration, 2> agentCredentials{
		AgentCredentialConfiguration{ 1U, 1U, L"SentinelGrid/Agent/1" },
		AgentCredentialConfiguration{ 2U, 2U, L"SentinelGrid/Agent/2" }
	};

	const std::size_t agentCount = agentCredentials.size();

	security::AgentKeyRegistry keyRegistry;
	security::ReplayGuard replayGuard;

	for (const auto& configuration : agentCredentials) {
		security::AgentKey loadedKey{};
		const auto loadResult = security::loadAgentKey(configuration.target, loadedKey);

		if (!loadResult.isSuccess()) {
			security::secureErase(loadedKey);

			std::cerr << "[-] Unable to load credential for agent " << configuration.agentId << ".\n"
				<< "Status: " << static_cast<int>(loadResult.status)
				<< ", WinErr: " << loadResult.nativeErrorCode << "\n";

			return EXIT_FAILURE;
		}

		const bool registered = keyRegistry.registerKey(configuration.keyId, configuration.agentId, loadedKey);
		security::secureErase(loadedKey);

		if (!registered) {
			std::cerr << "[-] Duplicated key ID while configuring agent " << configuration.agentId << ".\n";

			return EXIT_FAILURE;
		}
	}

	static_assert(!std::is_copy_constructible_v<UniqueSocket>);
	static_assert(!std::is_copy_assignable_v<UniqueSocket>);

	static_assert(std::is_move_constructible_v<UniqueSocket>);
	static_assert(std::is_move_assignable_v<UniqueSocket>);
	
	WinsockRuntime winsock;

	if (!winsock.isReady()) {
		std::cerr << "[-] WinSock initialization failed.\n Errcode: " 
			<< winsock.errorCode() << "\n";
		return EXIT_FAILURE;
	}

	std::cout << "[+] WinSock successfully initialized.\n";
	
	TcpServer server;

	if (!server.start(5050U)) {
		std::cerr << "[-] Unable to start the server TCP on port 5050.\n";
		return EXIT_FAILURE;
	}

	std::cout << "[+] SentinelGrid TCP server listening on: 127.0.0.1:5050.\n";
	std::cout << "[*] Waiting for Agent connection...\n";

	TcpClient controlPlaneClient;

	if (!controlPlaneClient.connect("127.0.0.1", 6060U)) {
		std::cerr << "[-] Unable to connect to the server on port 6060.\n";
		return EXIT_FAILURE;
	}

	std::cout << "[+] Client connected on 127.0.0.1:6060.\n";


	std::atomic_bool publicationFailed{ false };
	std::vector<app::SessionResult> sessionResults(agentCount);
	std::vector<std::jthread> sessionWorkers;
	sessionWorkers.reserve(agentCount);

	FailedLoginRule loginRule{ 3 };
	EventQueue eventQueue{ 4 };

	std::size_t processedEvents{ 0 };
	std::size_t totalEvents{ 0 };

	std::jthread processor{
		[&eventQueue,&controlPlaneClient, &loginRule, &processedEvents, &publicationFailed]() {

			while (auto event = eventQueue.pop()) {

				if (!event.has_value())
					break;

				std::cout << "[*] Sending event: Agent=" << event->agent_id
					<< ", Sequence=" << event->sequence_number
					<< ", Type=" << eventTypeToString(event->type)
					<< "\n";

				std::array<std::uint8_t, protocol::EventPacketSize> eventFrame{};
				const auto eventEncodeResult = protocol::encodeControlPlaneMessage(*event, eventFrame);
				
				if (!eventEncodeResult.is_success()) {
					std::cerr << "[-] Unable to encode the event.\n";
					publicationFailed = true;
					eventQueue.close();
					break;
				}

				const auto eventSendResult = network::sendAll(
					controlPlaneClient.socket(),
					std::span<const std::uint8_t>{
						eventFrame.data(), 
						eventEncodeResult.byte_written
					}
				);

				if (!eventSendResult.isSuccess()) {
					std::cerr << "[-] Unable to publish the event.\n"
						<< "Sent bytes: " << eventSendResult.sentBytes
						<< ", Error: " << eventSendResult.errorCode << "\n";
					publicationFailed = true;
					eventQueue.close();
					break;
				}

				if (publicationFailed.load()) {
					std::cerr << "[-] Control-Plane publication failed.\n";
					return EXIT_FAILURE;
				}

				const auto loginAlert = loginRule.evaluate(*event);
				if (loginAlert.has_value()) {
					std::cout << "[*] Sending alert: Type=" << alertTypeToString(loginAlert->type)
						<< ", Severity=" << alertSeverityToString(loginAlert->severity)
						<< ", Agent=" << loginAlert->agent_id
						<< ", Sequence=" << loginAlert->triggering_sequence
						<< " , Failures=" << loginAlert->failure_count
						<< "\n";

					std::array<std::uint8_t, protocol::AlertPacketSize> alertFrame{};
					const auto alertEncodeResult = protocol::encodeControlPlaneMessage(*loginAlert, alertFrame);

					if (!alertEncodeResult.is_success()) {
						std::cerr << "[-] Unable to encode alert.\n";
						publicationFailed = true;
						eventQueue.close();
						break;
					}

					const auto alertSedResult = network::sendAll(
						controlPlaneClient.socket(),
						std::span<const std::uint8_t> {
							alertFrame.data(),
							alertEncodeResult.byte_written
						}
					);

					if (!alertSedResult.isSuccess()) {
						std::cerr << "[-] Unable to publish the alert.\n";
						publicationFailed = true;
						eventQueue.close();
						break;
					}

				}

				processedEvents++;
			}

			std::cout << "[+] Event processor stopped.\n";
		}
	};

	for (std::size_t i = 0; i < agentCount; ++i) {
		auto agentSocket = server.acceptClient();
		
		if (!agentSocket.isValid()) {
			std::cerr << "[-] Unable to accept Agent \"" << (i + 1) << "\" connection.\n";
			break;
		}

		std::cout << "[*] Opened session for agent \"" << (i + 1) << "\".\n";

		sessionWorkers.emplace_back(
			[agentSocket = std::move(agentSocket), &eventQueue, &sessionResults, i, &keyRegistry, &replayGuard]() mutable {
					sessionResults[i] = app::runSessionAgent(std::move(agentSocket), eventQueue, keyRegistry, replayGuard);
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
		std::cerr << "[-] Server did not stop correctly.\n";
		return EXIT_FAILURE;
	}

	std::cout << "[+] Server stopped.\n";
	std::cout << "[*] Processed Events: " << processedEvents << "/" << totalEvents << ".\n";

	return  EXIT_SUCCESS;
}