#include <cstdlib>
#include <iostream>
#include <array>
#include <thread>
#include <variant>
#include <cstddef>
#include <vector>

#include <network/winsock_runtime.hpp>
#include <network/tcp_server.hpp>
#include <network/unique_socket.hpp>
#include <network/socket_io.hpp>
#include <codecs/packet_decoder.hpp>
#include <concurrency/bounded_blocking_queue.hpp>
#include <agent_session.hpp>
#include <rules/failed_login_rule.hpp>

int main() {
	using namespace sentinelgrid::engine;

	using network::WinsockRuntime;
	using network::UniqueSocket;
	using network::TcpServer;
	using EventQueue = concurrency::BoundedBlockingQueue<SecurityEvent>;


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

	std::vector<app::SessionResult> sessionResults(AgentCount);
	std::vector<std::jthread> sessionWorkers;
	sessionWorkers.reserve(AgentCount);

	EventQueue eventQueue{ 4 };
	std::size_t processedEvents{ 0 };
	std::size_t totalEvents{ 0 };

	std::jthread processor{
		[&eventQueue, &processedEvents]() {
			FailedLoginRule loginRule{ 3 };

			while (true) {
				auto event = eventQueue.pop();

				if (!event.has_value())
					break;

				processedEvents++;

				const auto loginAlert = loginRule.evaluate(*event);

				if (loginAlert.has_value())
					std::cout << "[ALERT] Agent " << loginAlert->agent_id
					<< " generated " << loginAlert->failure_count
					<< " failed login alerts. Trigger sequence: "
					<< loginAlert->triggering_sequence << "\n";
				else
					std::cout << "Agent ID: " << event->agent_id
					<< ", Sequence Number: " << event->sequence_number
					<< ", Event Type: " << sentinelgrid::engine::eventTypeToString(event->type) << "\n";
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
			[client = std::move(client), &eventQueue, &sessionResults, i]() mutable {
					sessionResults[i] = app::runSessionAgent(std::move(client), eventQueue);
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