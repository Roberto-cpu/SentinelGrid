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

	struct ReceiveResult {
		ReceiveStatus status{};
		std::size_t receivedBytes{};
		int errorCode{};
	};

	[[nodiscard]]
	ReceiveResult receiveExactly(const UniqueSocket& socket, std::span<std::uint8_t> output) noexcept;
}