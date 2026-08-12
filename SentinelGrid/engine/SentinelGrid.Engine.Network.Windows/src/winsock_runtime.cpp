#include <WinSock2.h>

#include <network/winsock_runtime.hpp>

namespace sentinelgrid::engine::network {
	WinsockRuntime::WinsockRuntime() noexcept {
		WSADATA wsaData{};

		errCode_ = WSAStartup(MAKEWORD(2, 2), &wsaData);
		initialized_ = (errCode_ == 0);
	}

	WinsockRuntime::~WinsockRuntime() noexcept {
		if (initialized_)
			WSACleanup();
	}

	bool WinsockRuntime::isReady() const noexcept { return initialized_; }

	int WinsockRuntime::errorCode() const noexcept { return errCode_; }
}