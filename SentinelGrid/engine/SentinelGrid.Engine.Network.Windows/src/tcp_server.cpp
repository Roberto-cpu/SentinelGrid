#include <utility>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <network/tcp_server.hpp>

namespace sentinelgrid::engine::network {

	bool TcpServer::start(std::uint16_t port) noexcept {
		if (isRunning()) {
			errCode_ = WSAEALREADY;
			return false;
		}

		if (port == 0) {
			errCode_ = WSAEINVAL;
			return false;
		}

		UniqueSocket candidate{ ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
		
		if (!candidate.isValid()) {
			errCode_ = WSAGetLastError();
			return false;
		}

		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		
		const int bindRes = bind(candidate.get(), reinterpret_cast<const sockaddr*>(&address), static_cast<int>(sizeof address));

		if (bindRes == SOCKET_ERROR) {
			errCode_ = WSAGetLastError();
			return false;
		}

		const int listenRes = ::listen(candidate.get(), SOMAXCONN);

		if (listenRes == SOCKET_ERROR) {
			errCode_ = WSAGetLastError();
			return false;
		}

		listeningSocket_ = std::move(candidate);
		errCode_ = 0;
		return true;
	}

	UniqueSocket TcpServer::acceptClient() noexcept {
		if (!isRunning()) {
			errCode_ = WSAENOTSOCK;
			return UniqueSocket{};
		}

		const SOCKET clientHandle = ::accept(listeningSocket_.get(), nullptr, nullptr);
		if (clientHandle == INVALID_SOCKET) {
			errCode_ = WSAGetLastError();
			return UniqueSocket{};
		}

		errCode_ = 0;
		return UniqueSocket{ clientHandle };
	}

	void TcpServer::stop() noexcept {
		listeningSocket_.reset();
		errCode_ = 0;
	}

	bool TcpServer::isRunning() const noexcept { return listeningSocket_.isValid(); }

	int TcpServer::errorCode() const noexcept { return errCode_; }

}