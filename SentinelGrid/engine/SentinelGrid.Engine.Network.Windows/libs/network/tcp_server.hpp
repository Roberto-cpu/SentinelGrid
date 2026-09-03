#pragma once

/**
 * @file tcp_server.hpp
 * @brief This header file defines the TcpServer class, which provides a simple TCP server implementation for Windows.
 *
 * The TcpServer class allows for starting a TCP server on a specified port, accepting client connections, and stopping the server.
 * It manages the underlying socket resources and provides error handling through error codes.
 *
 * @note The implementation of the TcpServer class is expected to be provided in a corresponding source file (e.g., tcp_server.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>
#include "unique_socket.hpp"

namespace sentinelgrid::engine::network {

	/**
	 * @class TcpServer
	 * @brief A simple TCP server implementation for Windows.
	 *
	 * The TcpServer class allows for starting a TCP server on a specified port, accepting client connections, and stopping the server.
	 * It manages the underlying socket resources and provides error handling through error codes.
	 */
	class TcpServer final {
		public:

			/**
			 * @brief Starts the TCP server on the specified port.
			 * @param port The port number to listen on.
			 * @return true if the server started successfully, false otherwise.
			 */
			[[nodiscard]]
			bool start(std::uint16_t port) noexcept;

			/**
			 * @brief Accepts a client connection and returns a UniqueSocket representing the connected client.
			 * @return A UniqueSocket representing the accepted client connection.
			 */
			[[nodiscard]]
			UniqueSocket acceptClient() noexcept;

			/**
			 * @brief Stops the TCP server and closes the listening socket.
			 */
			void stop() noexcept;

			/**
			 * @brief Checks if the TCP server is currently running.
			 * @return true if the server is running, false otherwise.
			 */
			[[nodiscard]]
			bool isRunning() const noexcept;

			/**
			 * @brief Retrieves the last error code encountered by the TcpServer.
			 * @return The last error code.
			 */
			[[nodiscard]]
			int errorCode() const noexcept;

		private:
			UniqueSocket listeningSocket_;
			int errCode_ = { 0 };
	};
}