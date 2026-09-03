#pragma once

/**
 * @file socket_io.hpp
 * @brief This header file defines the interface for socket input/output operations, including receiving and sending data over sockets.
 *
 * The functions declared in this file allow for receiving a specified number of bytes from a socket and sending all bytes of data over a socket.
 * It provides structured results for both operations, including status codes and error information.
 *
 * @note The implementation of these functions is expected to be provided in a corresponding source file (e.g., socket_io.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstddef>
#include <cstdint>
#include <span>

#include "unique_socket.hpp"

namespace sentinelgrid::engine::network {
	
	/**
	 * @brief Enumeration representing the status of a receive operation.
	 */
	enum class ReceiveStatus {
		success,
		peer_closed,
		socket_error
	};

	/**
	 * @brief Enumeration representing the status of a send operation.
	 */
	enum class SendStatus {
		success,
		connection_closed,
		socket_error
	};

	/**
	 * @brief Structure representing the result of a receive operation.
	 */
	struct ReceiveResult {
		ReceiveStatus status{};
		std::size_t receivedBytes{};
		int errorCode{};
	};
	
	/**
	 * @brief Structure representing the result of a send operation.
	 */
	struct SendResult {
		SendStatus status{};
		std::size_t sentBytes{};
		int errorCode{};

		/**
		 * @brief Checks if the send operation was successful.
		 * @return true if the send operation was successful, false otherwise.
		 */
		[[nodiscard]]
		bool isSuccess() const noexcept {
			return status == SendStatus::success;
		}
	};

	/**
	 * @brief Receives exactly the specified number of bytes from the given socket and stores them in the output buffer.
	 * @param socket The socket from which to receive data.
	 * @param output The buffer to store the received data.
	 * @return A ReceiveResult structure containing the status, number of bytes received, and any error code.
	 */
	[[nodiscard]]
	ReceiveResult receiveExactly(const UniqueSocket& socket, std::span<std::uint8_t> output) noexcept;

	/**
	 * @brief Sends all bytes of data from the given buffer over the specified socket.
	 * @param socket The socket over which to send data.
	 * @param data The buffer containing the data to send.
	 * @return A SendResult structure containing the status, number of bytes sent, and any error code.
	 */
	[[nodiscard]]
	SendResult sendAll(const UniqueSocket& socket, std::span<const std::uint8_t> data) noexcept;
}