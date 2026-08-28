#include <cstdlib>
#include <iostream>
#include <array>
#include <variant>
#include <cstddef>

#include <agent_session.hpp>
#include <network/winsock_runtime.hpp>
#include <network/tcp_server.hpp>
#include <network/unique_socket.hpp>
#include <network/socket_io.hpp>
#include <codecs/packet_decoder.hpp>
#include <security/agent_key_registry.hpp>


namespace sentinelgrid::engine::app {

	SessionResult runSessionAgent(network::UniqueSocket client, EventQueue& eventQueue,
		const sentinelgrid::engine::security::AgentKeyRegistry& keyRegistry)
	{
		std::size_t receivedEvents{ 0 };
		SessionStatus status{ SessionStatus::cleanDisconnect };
		int socketCode{ 0 };

		while (true) {
			std::array<std::uint8_t, sentinelgrid::engine::AuthenticatedPacketSize> packet{};
			const auto receiveRes = sentinelgrid::engine::network::receiveExactly(client, packet);


			if (receiveRes.status == sentinelgrid::engine::network::ReceiveStatus::peer_closed && receiveRes.receivedBytes == 0) {
				std::cout << "The Agent has closed the connection\n";
				status = SessionStatus::cleanDisconnect;
				break;
			}

			if (receiveRes.status == sentinelgrid::engine::network::ReceiveStatus::peer_closed && receiveRes.receivedBytes > 0) {
				std::cerr << "Unexpected closed connection.\n";
				status = SessionStatus::truncatedPacket;
				break;
			}

			if (receiveRes.status == sentinelgrid::engine::network::ReceiveStatus::socket_error) {
				std::cerr << "Socket Crashed.\n" <<
					"Bytes received: " << receiveRes.receivedBytes << ".\n" <<
					"Error code: " << receiveRes.errorCode << "\n";

				if (receiveRes.status == network::ReceiveStatus::socket_error) {
					status = SessionStatus::socketError;
					socketCode = receiveRes.errorCode;
					break;
				}
			}

			//const auto decodeRes = sentinelgrid::engine::decodeEventPacket(packet);
			const auto decodeRes = sentinelgrid::engine::decodeAuthenticatedEventPacket(packet, keyRegistry);
			if (const auto* event = std::get_if<sentinelgrid::engine::SecurityEvent>(&decodeRes)) {

				if (!eventQueue.push(*event)) {
					std::cerr << "Unable to push the event into the queue.\n";
					status = SessionStatus::queueClosed;
					break;
				}

				receivedEvents++;
			}
			else {
				const auto error = std::get<sentinelgrid::engine::DecodeError>(decodeRes);
				std::cerr << "Decoding Error: " << sentinelgrid::engine::decodeErrorToString(error) << "\n";
				status = SessionStatus::decodingError;
				break;
			}
		}

		return {
			status,
			receivedEvents,
			socketCode
		};
	}
}