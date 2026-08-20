#pragma once
#pragma once

#include <cstdint>
#include <string_view>

#include <network/unique_socket.hpp>

namespace sentinelgrid::engine::network {

	class TcpClient final {
	public:

		[[nodiscard]]
		bool connect(std::string_view ipv4Address, std::uint16_t port) noexcept;

		void disconnect() noexcept;

		[[nodiscard]]
		bool isConnected() const noexcept;

		[[nodiscard]]
		const UniqueSocket& socket() const noexcept;

		[[nodiscard]]
		int errorCode() const noexcept;

	private:
		UniqueSocket socket_;
		int errCode_{ 0 };
	};
}