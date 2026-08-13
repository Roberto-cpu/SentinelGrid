#include <cstdlib>
#include <iostream>
#include <array>

#include <network/winsock_runtime.hpp>
#include <network/tcp_server.hpp>
#include <network/unique_socket.hpp>
#include <network/socket_io.hpp>
#include <packet_decoder.hpp>

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

	while (true) {
		std::array<std::uint8_t, sentinelgrid::engine::EventPacketSize> packet{};
		const auto receiveRes = sentinelgrid::engine::network::receiveExactly(client, packet);

	
		if (receiveRes.status == sentinelgrid::engine::network::ReceiveStatus::peer_closed && receiveRes.receivedBytes == 0) {
			std::cerr << "The Agent has closed the connection\n";
			break;
		}

		if (receiveRes.status == sentinelgrid::engine::network::ReceiveStatus::peer_closed && receiveRes.receivedBytes > 0) {
			std::cerr << "Unexpected closed connection.\n";
			break;
		}

		if (receiveRes.status == sentinelgrid::engine::network::ReceiveStatus::socket_error) {
			std::cerr << "Socket Crashed.\n" <<
				"Bytes received: " << receiveRes.receivedBytes << ".\n" <<
				"Error code: " << receiveRes.errorCode << "\n";
			break;
		}

		const auto decodeRes = sentinelgrid::engine::decodeEventPacket(packet);
		if (const auto* event = std::get_if<sentinelgrid::engine::SecurityEvent>(&decodeRes)) {
			std::cout << "Agent ID: " << event->agent_id
				<< ", Sequence Number: " << event->sequence_number
				<< ", Event Type: " << sentinelgrid::engine::eventTypeToString(event->type) << "\n";
		}
		else {
			const auto error = std::get<sentinelgrid::engine::DecodeError>(decodeRes);
			std::cerr << "Decoding Error: " << sentinelgrid::engine::decodeErrorToString(error) << "\n";
			break;
		}
	}

	server.stop();

	if (server.isRunning()) {
		std::cerr << "Server did not stop correctly.\n";
		return EXIT_FAILURE;
	}

	std::cout << "Server stopped.\n";

	return EXIT_SUCCESS;
}