#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "unique_socket.hpp"

namespace sentinelgrid::engine::network {
	enum class ReceiveStatus {
		success,
		peer_closed,
		socket_error
	};

	enum class SendStatus {
		success,
		connection_closed,
		socket_error
	};

	struct ReceiveResult {
		ReceiveStatus status{};
		std::size_t receivedBytes{};
		int errorCode{};
	};
	
	struct SendResult {
		SendStatus status{};
		std::size_t sentBytes{};
		int errorCode{};

		[[nodiscard]]
		bool isSuccess() const noexcept {
			return status == SendStatus::success;
		}
	};

	[[nodiscard]]
	ReceiveResult receiveExactly(const UniqueSocket& socket, std::span<std::uint8_t> output) noexcept;

	[[nodiscard]]
	SendResult sendAll(const UniqueSocket& socket, std::span<const std::uint8_t> data) noexcept;
}