#include <cstdlib>
#include <iostream>

#include <winsock_runtime.hpp>
#include <unique_socket.hpp>

int main() {
	using sentinelgrid::engine::network::WinsockRuntime;
	using sentinelgrid::engine::network::UniqueSocket;

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

	return EXIT_SUCCESS;
}