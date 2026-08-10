#include <stdio.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "../../include/agent/sockets/tcp_client.h"

void initTcpClient(TcpClient* client) {
	if (client == NULL)
		return;

	client->socket_handle = INVALID_SOCKET;
	client->win_sock_init = 0;
}

int tcpClientConnect(TcpClient* client, const char* ipv4Address, uint16_t port) {
	if (client == NULL || ipv4Address == NULL)
		return 0;

	if (port == 0)
		return 0;

	WSADATA wsaData = { 0 };

	int wsaStartup = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (wsaStartup != 0) {
		printf("WSAStartup failed with status: %d\n", wsaStartup);
		return 0;
	}

	client->win_sock_init = 1;
	
	client->socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (client->socket_handle == INVALID_SOCKET) {
		printf("Unable to create the socket.\n");
		return 0;
	}

	struct sockaddr_in server_addr = { 0 };
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	int addrRes = InetPtonA(AF_INET, ipv4Address, &server_addr.sin_addr);

	if (addrRes != 1) {
		printf("Invalid IPv4 Address: %s.\n", ipv4Address);

		tcpClientClose(client);
		return 0;
	}

	int connRes = connect(client->socket_handle, (const struct sockaddr*)&server_addr, sizeof server_addr);
	if (connRes == SOCKET_ERROR) {
		printf("Unable to open a connectio to %s:%u\n WinSockError: %d\n", ipv4Address, (unsigned int)port, WSAGetLastError());

		tcpClientClose(client);
		return 0;
	}

	return 1;
}

int tcpClientSendAll(TcpClient* client, const uint8_t* data, size_t dataSize) {

	if (client == NULL || data == NULL)
		return 0;

	if (dataSize == 0)
		return 0;

	if (!client->win_sock_init || client->socket_handle == INVALID_SOCKET)
		return 0;

	size_t totalByteSent = 0;

	while (totalByteSent < dataSize) {
		size_t remaining = dataSize - totalByteSent;

		int chunkSize = remaining > INT_MAX ? INT_MAX : (int)remaining;

		int sendRes = send(client->socket_handle, (const char*)(data + totalByteSent), chunkSize, 0);
		
		if (sendRes == SOCKET_ERROR) {
			printf("Error while sending data.\n WinError: %d\n", WSAGetLastError());

			tcpClientClose(client);
			return 0;
		}

		if (sendRes == 0) {
			printf("Connection closed while sending data.\n");
			return 0;
		}

		totalByteSent += (size_t)sendRes;
	}

	return 1;
}

void tcpClientClose(TcpClient* client) {
	if (client == NULL)
		return;

	if (client->socket_handle != INVALID_SOCKET) {
		closesocket(client->socket_handle);
		client->socket_handle = INVALID_SOCKET;
	}

	if (client->win_sock_init) {
		WSACleanup();
		client->win_sock_init = 0;
	}
}