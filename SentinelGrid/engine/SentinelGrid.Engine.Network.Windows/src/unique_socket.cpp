/**
 * @file unique_socket.cpp
 * @brief Implementation of the UniqueSocket class for managing socket resources.
 * 
 * This file contains the implementation of the UniqueSocket class, 
 * which is responsible for managing the lifetime of a socket resource in a RAII manner.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

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