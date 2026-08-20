#include <string>
#include <string_view>
#include <WS2tcpip.h>
#include <WinSock2.h>

#include <network/tcp_client.hpp>

namespace sentinelgrid::engine::network {
	
	bool TcpClient::connect(std::string_view ipv4Address, std::uint16_t port) noexcept {
		
		if (ipv4Address.empty() || port == 0) {
			errCode_ = WSAEINVAL;
			return false;
		}

		if (isConnected()) {
			errCode_ = WSAEISCONN;
			return false;
		}

		UniqueSocket candidate{ ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };

		if (!candidate.isValid()) {
			errCode_ = WSAGetLastError();
			return false;
		}

		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);

		const std::string addressText{ ipv4Address };
		const int conversionRes = ::inet_pton(AF_INET, addressText.c_str(), &addr.sin_addr);

		if (conversionRes == 0) {
			errCode_ = WSAEINVAL;
			return false;
		}

		if (conversionRes == SOCKET_ERROR) {
			errCode_ = WSAGetLastError();
			return false;
		}
		
		int connRes = ::connect(candidate.get(), (struct sockaddr*)&addr, sizeof(addr));
		if (connRes == SOCKET_ERROR) {
			errCode_ = WSAGetLastError();
			return false;
		}

		socket_ = std::move(candidate);
		errCode_ = 0;
		return true;
	}

	void TcpClient::disconnect() noexcept {
		socket_.reset();
		errCode_ = 0;
	}

	bool TcpClient::isConnected() const noexcept { return socket_.isValid(); }

	const UniqueSocket& TcpClient::socket() const noexcept { return socket_; }

	int TcpClient::errorCode() const noexcept { return errCode_; }
}