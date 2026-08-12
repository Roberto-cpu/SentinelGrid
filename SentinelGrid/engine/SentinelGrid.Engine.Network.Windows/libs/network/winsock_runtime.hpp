#pragma once

namespace sentinelgrid::engine::network {

	class WinsockRuntime final {
		public:
			WinsockRuntime() noexcept;
			~WinsockRuntime() noexcept;

			WinsockRuntime(const WinsockRuntime&) = delete;
			WinsockRuntime& operator = (const WinsockRuntime&&) = delete;

			[[nodiscard]]
			bool isReady() const noexcept;

			[[nodiscard]]
			int errorCode() const noexcept;

		private:
			bool initialized_{ false };
			int errCode_{ 0 };
	};
}