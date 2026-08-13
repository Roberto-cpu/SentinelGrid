#pragma once

#include <cstdint>
#include "unique_socket.hpp"

namespace sentinelgrid::engine::network {

	class TcpServer final {
		public:
			[[nodiscard]]
			bool start(std::uint16_t port) noexcept;

			[[nodiscard]]
			UniqueSocket acceptClient() noexcept;

			void stop() noexcept;

			[[nodiscard]]
			bool isRunning() const noexcept;

			[[nodiscard]]
			int errorCode() const noexcept;

		private:
			UniqueSocket listeningSocket_;
			int errCode_ = { 0 };
	};
}