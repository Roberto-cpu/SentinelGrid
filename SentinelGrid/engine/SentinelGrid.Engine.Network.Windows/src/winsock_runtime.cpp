/*
 * @file winsock_runtime.cpp
 * @brief Implementation of the WinsockRuntime class for managing Winsock initialization and cleanup.
 * 
 * This file contains the implementation of the WinsockRuntime class, 
 * which is responsible for initializing and cleaning up the Winsock library in a Windows environment.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

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