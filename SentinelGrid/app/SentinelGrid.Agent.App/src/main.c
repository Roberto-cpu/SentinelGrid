/**
 * @file main.c
 * @brief Main entry point for the SentinelGrid Agent application.
 *
 * This file contains the main function that initializes the agent, connects to the engine, and sends security event packets.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <stdio.h>

#include <agent/codecs/security_event.h>
#include <agent/codecs/event_codec.h>
#include <agent/codecs/buffer_codec.h>
#include <agent/protocols/packet_codec.h>
#include <agent/sockets/tcp_client.h>
#include <utilities/agent_options.h>

int main(int argc, char* argv[]) {
	AgentOptions options = { 0 };

	if (!parseAgentOptions(argc, argv, &options)) {
		fprintf(
			stderr,
			"Usage: %s <agent-id>\n",
			argc > 0 ? argv[0] : "SentinelGrid.Agent.App"
		);
		return EXIT_FAILURE;
	}

	printf("SentinelGrid agent %d started\n", options.agent_id);

	SecurityEvent login_failed1 = {
		options.agent_id,
		1ULL,
		EVENT_LOGIN_FAILED
	};
	
	SecurityEvent login_failed2 = {
		options.agent_id,
		2ULL,
		EVENT_LOGIN_FAILED
	};
	
	SecurityEvent login_failed3 = {
		options.agent_id,
		3ULL,
		EVENT_LOGIN_FAILED
	};

	uint8_t packet_h[EVENT_PACKET_SIZE] = { 0 };
	uint8_t packet_l[EVENT_PACKET_SIZE] = { 0 };
	uint8_t packet_s[EVENT_PACKET_SIZE] = { 0 };
	
	TcpClient client = { 0 };
	initTcpClient(&client);

	if (!tcpClientConnect(&client, "127.0.0.1", 5050U)) {
		printf("Unable to connect to the engine.\n");
		tcpClientClose(&client);
		return EXIT_FAILURE;
	}

	if (!encodeEventPacket(&login_failed1, packet_h, sizeof packet_h)) {
		printf("Unable to encode event packet.\n");
		return EXIT_FAILURE;
	}

	if (!tcpClientSendAll(&client, packet_h, sizeof packet_h)) {
		printf("Unable to send the packet.\n");
		tcpClientClose(&client);
		return EXIT_FAILURE;
	}

	printf("Heartbeat packet correctly sent.\n");

	if (!encodeEventPacket(&login_failed2, packet_l, sizeof packet_l)) {
		printf("Unable to encode event packet.\n");
		return EXIT_FAILURE;
	}

	if (!tcpClientSendAll(&client, packet_l, sizeof packet_l)) {
		printf("Unable to send the packet.\n");
		tcpClientClose(&client);
		return EXIT_FAILURE;
	}

	printf("Login failed packet correctly sent.\n");

	if (!encodeEventPacket(&login_failed3, packet_s, sizeof packet_s)) {
		printf("Unable to encode event packet.\n");
		return EXIT_FAILURE;
	}

	if (!tcpClientSendAll(&client, packet_s, sizeof packet_s)) {
		printf("Unable to send the packet.\n");
		tcpClientClose(&client);
		return EXIT_FAILURE;
	}

	printf("Service stop packet correctly sent.\n");

	tcpClientClose(&client);
	return EXIT_SUCCESS;
}