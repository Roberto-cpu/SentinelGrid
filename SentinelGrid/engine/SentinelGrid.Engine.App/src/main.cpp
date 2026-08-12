#include <cstdlib>
#include <iostream>

#include <winsock_runtime.hpp>

int main() {
	using sentinelgrid::engine::network::WinsockRuntime;

	std::cout << "SentinelGrid Engine start.\n\n";

	WinsockRuntime winsock;

	if (!winsock.isReady()) {
		std::cout << "WinSock initialization failed.\n Errcode: " 
			<< winsock.errorCode() << "\n";
		return EXIT_FAILURE;
	}

	std::cout << "WinSock successfully initialized.\n";

	return EXIT_SUCCESS;
}