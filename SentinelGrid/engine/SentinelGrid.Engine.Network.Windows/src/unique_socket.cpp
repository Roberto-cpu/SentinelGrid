#include <WinSock2.h>
#include <utility>
#include <network/unique_socket.hpp>

namespace sentinelgrid::engine::network {

	UniqueSocket::UniqueSocket(SOCKET handler) noexcept {
		handler_ = handler;
	}

	UniqueSocket::~UniqueSocket() noexcept  {
		reset();
	}

	bool UniqueSocket::isValid() const noexcept { return (handler_ != INVALID_SOCKET); }

	SOCKET UniqueSocket::get() const noexcept { return handler_; }

	SOCKET UniqueSocket::release() noexcept {
		return std::exchange(handler_, INVALID_SOCKET);
	}

	void UniqueSocket::reset(SOCKET newHandle) noexcept {
		if (handler_ == newHandle)
			return;

		if (isValid())
			::closesocket(handler_);

		handler_ = newHandle;
	}

	UniqueSocket::UniqueSocket(UniqueSocket&& other) noexcept : handler_{ other.release() } {}

	UniqueSocket& UniqueSocket::operator=(UniqueSocket&& other) noexcept {
		if (this != &other)
			reset(other.release());

		return *this;
	}
}