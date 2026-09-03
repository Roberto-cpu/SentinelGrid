/**
 * @file socket_io.cpp
 * @brief Implementation of socket I/O functions for Windows platform.
 * 
 * This file contains the implementation of socket I/O functions, including receiving and sending data over sockets in a Windows environment.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>	
#include <climits>
#include <WinSock2.h>
#include <algorithm>

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
					totalReceived,
					0
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

	SendResult sendAll(const UniqueSocket& socket, std::span<const std::uint8_t> data) noexcept {
		if (!socket.isValid()) {
			return {
				SendStatus::socket_error,
				0U,
				WSAEINVAL
			};
		}

		if (data.empty()) {
			return {
				SendStatus::connection_closed,
				0U,
				0
			};
		}

		std::size_t totalSent = 0;
		while (totalSent < data.size()) {
			const std::size_t remaining = data.size() - totalSent;
			const std::size_t chunkSize = std::min<std::size_t>(remaining, static_cast<const std::size_t>(INT_MAX));
			const int requestedBytes = static_cast<int>(chunkSize);

			const int sent = ::send(socket.get(), reinterpret_cast<const char*>(data.data() + totalSent), requestedBytes, 0);
		
			if (sent == SOCKET_ERROR) {
				return {
					SendStatus::socket_error,
					totalSent,
					WSAGetLastError()
				};
			}

			if (sent == 0) {
				return {
					SendStatus::connection_closed,
					totalSent,
					0
				};
			}

			totalSent += sent;
		}

		return {
			SendStatus::success,
			totalSent,
			0
		};
	}
}