#pragma once

/*
 * @file tcp_client.h
 * @brief Header file for TCP client socket operations.
 *
 * This header file defines the structure and function prototypes for managing a TCP client connection,
 * including initialization, connection, data transmission, and closure of the socket.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <WinSock2.h>

/*
 * @brief Denifes the TCP client connection instance properties
 * @param socket_handle: the socket instance on which it communicates
 * @param win_sock_init: the socket opening status
 */
typedef struct {
	SOCKET socket_handle;
	int win_sock_init;
} TcpClient;

/*
* @brief Initializes the client, by defining its structure
* @param client: the object to initialize
*/
void initTcpClient(TcpClient* client);

/*
* @brief Connects the  client to a specified host.
* @param client: the instance to connect
* @param ipv4Address: the remote host IPv4 Address
* @param port: the remote host's port
* @returns 1 if the connection is established; 0 otherwise
*/
int tcpClientConnect(TcpClient* client, const char* ipv4Address, uint16_t port);

/*
* @brief Sends the event data through the opened connection
* @param client: the socket instance
* @param data: the event's data to send
* @param dataSize: the bytes array dimension
* @returns 1 if the data are correctly sent; 0 otherwise
*/
int tcpClientSendAll(TcpClient* client, const uint8_t* data, size_t dataSize);

/*
* @brief Closes the socket
* @param client: the  socket instance to close
*/
void tcpClientClose(TcpClient* client);

#endif // !TCP_CLIENT_H
