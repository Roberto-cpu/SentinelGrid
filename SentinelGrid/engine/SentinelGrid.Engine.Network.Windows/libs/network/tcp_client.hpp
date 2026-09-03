#pragma once

/**
 * @file tcp_client.hpp
 * @brief This header file defines the TcpClient class, which provides a simple TCP client implementation for Windows.
 *
 * The TcpClient class allows for connecting to a TCP server at a specified IPv4 address and port, disconnecting from the server, and checking the connection status.
 * It manages the underlying socket resources and provides error handling through error codes.
 *
 * @note The implementation of the TcpClient class is expected to be provided in a corresponding source file (e.g., tcp_client.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>
#include <string_view>

#include <network/unique_socket.hpp>

namespace sentinelgrid::engine::network {

	/**
	 * @class TcpClient
	 * @brief A simple TCP client implementation for Windows.
	 *
	 * The TcpClient class allows for connecting to a TCP server at a specified IPv4 address and port, disconnecting from the server, and checking the connection status.
	 * It manages the underlying socket resources and provides error handling through error codes.
	 */
	class TcpClient final {
		public:
			
			/**
			 * @brief Connects to a TCP server at the specified IPv4 address and port.
			 * @param ipv4Address The IPv4 address of the server to connect to.
			 * @param port The port number of the server to connect to.
			 * @return true if the connection was successful, false otherwise.
			 */
			[[nodiscard]]
			bool connect(std::string_view ipv4Address, std::uint16_t port) noexcept;

			/**
			 * @brief Disconnects from the currently connected TCP server.
			 */
			void disconnect() noexcept;

			/**
			 * @brief Checks if the TcpClient is currently connected to a server.
			 * @return true if the client is connected, false otherwise.
			 */
			[[nodiscard]]
			bool isConnected() const noexcept;

			/**
			 * @brief Retrieves the underlying UniqueSocket used for the TCP connection.
			 * @return A const reference to the UniqueSocket instance.
			 */
			[[nodiscard]]
			const UniqueSocket& socket() const noexcept;

			/**
			 * @brief Retrieves the last error code encountered by the TcpClient.
			 * @return The last error code.
			 */
			[[nodiscard]]
			int errorCode() const noexcept;

		private:
			UniqueSocket socket_;
			int errCode_{ 0 };
	};
}