#pragma once

#include <WinSock2.h>

namespace sentinelgrid::engine::network {

	class UniqueSocket final {

		public:
			UniqueSocket() noexcept = default;
			explicit UniqueSocket(SOCKET handler) noexcept;

			~UniqueSocket() noexcept;

			UniqueSocket(const UniqueSocket&) = delete;
			UniqueSocket& operator = (const UniqueSocket&) = delete;

			UniqueSocket(UniqueSocket&& other) noexcept;
			UniqueSocket& operator=(UniqueSocket&& other) noexcept;

			[[nodiscard]]
			bool isValid() const noexcept;

			[[nodiscard]]
			SOCKET get() const noexcept;

			[[nodiscard]]
			SOCKET release() noexcept;

			[[nodiscard]]
			void reset(SOCKET newHandle = INVALID_SOCKET) noexcept;

		private:
			SOCKET handler_{ INVALID_SOCKET };
	};
}