#include <cstdlib>
#include <iostream>

#include <network/winsock_runtime.hpp>
#include <network/tcp_server.hpp>
#include <network/unique_socket.hpp>

int main() {
	using sentinelgrid::engine::network::WinsockRuntime;
	using sentinelgrid::engine::network::UniqueSocket;
	using sentinelgrid::engine::network::TcpServer;


	std::cout << "SentinelGrid Engine start.\n\n";

	static_assert(!std::is_copy_constructible_v<UniqueSocket>);
	static_assert(!std::is_copy_assignable_v<UniqueSocket>);

	static_assert(std::is_move_constructible_v<UniqueSocket>);
	static_assert(std::is_move_assignable_v<UniqueSocket>);
	
	WinsockRuntime winsock;

	if (!winsock.isReady()) {
		std::cerr << "WinSock initialization failed.\n Errcode: " 
			<< winsock.errorCode() << "\n";
		return EXIT_FAILURE;
	}

	UniqueSocket first{ ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };

	if (!first.isValid()) {
		std::cerr << "Socket \"first\" creation failed.\n";
		return EXIT_FAILURE;
	}

	UniqueSocket second{ std::move(first) };

	if (first.isValid() || !second.isValid()) {
		std::cerr << "Socket ownership transfer \"first\" -> \"second\" failed.\n";
		return EXIT_FAILURE;
	}

	std::cout << "WinSock successfully initialized.\n";
	std::cout << "Socket ownership transfer \"first\" -> \"second\" passed.\n";

	TcpServer server;

	if (!server.start(5050U)) {
		std::cerr << "Unable to start the server TCP on port 5050.\n";
		return EXIT_FAILURE;
	}

	std::cout << "SentinelGrid TCP server listening on: 127.0.0.1:5050.\n";
	
	std::cout << "Waiting for Agent connection...\n";

	auto client = server.acceptClient();
	if (!client.isValid()) {
		std::cerr << "Unable to accept Agent connection.\n";
		return EXIT_FAILURE;
	}

	std::cout << "Agent connection accepted.\n";

	server.stop();

	if (server.isRunning()) {
		std::cerr << "Server did not stop correctly.\n";
		return EXIT_FAILURE;
	}

	std::cout << "Server stopped.\n";

	return EXIT_SUCCESS;
}