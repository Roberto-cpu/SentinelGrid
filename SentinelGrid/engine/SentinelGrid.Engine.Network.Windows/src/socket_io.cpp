#include <cstdint>	
#include <climits>
#include <WinSock2.h>

#include <network/socket_io.hpp>

namespace sentinelgrid::engine::network {

	ReceiveResult receiveExactly(const UniqueSocket& socket, std::span<std::uint8_t> output) noexcept {
		if (!socket.isValid()) {
			return {
				ReceiveStatus::socket_error,
				0U,
				WSAEINVAL
			};
		}

		std::size_t totalReceived = 0;

		while (totalReceived < output.size()) {
			const std::size_t remaining = output.size() - totalReceived;
			const int chunkSize = remaining > static_cast<int>(INT_MAX) ? INT_MAX : static_cast<int>(remaining);
			const int received = ::recv(socket.get(), reinterpret_cast<char*>(output.data() + totalReceived), chunkSize, 0);

			if (received == SOCKET_ERROR) {
				return {
					ReceiveStatus::socket_error,
					totalReceived,
					WSAGetLastError()
				};
			}

			if (received == 0) {
				return {
					ReceiveStatus::peer_closed,
					0U,
					WSAGetLastError()
				};
			}

			totalReceived += received;
		}

		return {
			ReceiveStatus::success,
			totalReceived,
			0
		};
	}
}