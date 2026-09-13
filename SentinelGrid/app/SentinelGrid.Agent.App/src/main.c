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
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

#include <agent/codecs/security_event.h>
#include <agent/codecs/event_codec.h>
#include <agent/codecs/buffer_codec.h>
#include <agent/protocols/packet_codec.h>
#include <agent/sockets/tcp_client.h>
#include <utilities/agent_options.h>
#include <windows_agent_key_store.h>
#include <windows_agent_sequence_store.h>

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

	int exitCode = EXIT_FAILURE;

	uint8_t agentKey[SENTINELGRID_AGENT_KEY_SIZE] = { 0 };
	wchar_t credentialTarget[64] = { 0 };

	const int targetLength = swprintf(
		credentialTarget,
		sizeof credentialTarget / sizeof credentialTarget[0],
		L"SentinelGrid/Agent/%u",
		(unsigned int)options.agent_id
	);

	if (targetLength < 0) {
		fprintf(
			stderr,
			"Unable to construct credential target.\n"
		);

		goto cleanup;
	}

	TcpClient client = { 0 };
	initTcpClient(&client);

	printf("SentinelGrid agent %d started\n", options.agent_id);
	
	const AgentKeyLoadResult loadResult = loadAgentKey(credentialTarget, agentKey, sizeof agentKey);

	if (loadResult.status != AGENT_KEY_LOAD_SUCCESS) {
		fprintf(
			stderr,
			"Unable to load agent key for agent %d. Error code: %d\n",
			(unsigned int)options.agent_id,
			(unsigned int)loadResult.native_error_code
		);
		goto cleanup;
	}

	if (!tcpClientConnect(&client, "127.0.0.1", 5050U)) {
		fprintf(
			stderr,
			"Unable to connect to the engine.\n"
		);
		
		goto cleanup;
	}

	const uint32_t keyId = options.agent_id;
	for (size_t i = 0; i < 3U; i++) {
		
		uint64_t sequence = 0U;

		const AgentSequenceResult sequenceRes = reserveNextAgentSequence(options.agent_id, &sequence);

		if (sequenceRes.status != AGENT_SEQUENCE_SUCCESS) {
			fprintf(
				stderr,
				"[-] Unable to reserver sequence number. Error: %u",
				(unsigned int)sequenceRes.native_error_code
			);

			goto cleanup;
		}

		const SecurityEvent event = {
			options.agent_id,
			sequence,
			EVENT_LOGIN_FAILED
		};

		uint8_t packet[AUTHENTICATED_PACKET_SIZE] = { 0 };

		if (!encodeAuthenticatedEvent(&event, keyId, agentKey, sizeof agentKey, packet)) {
			fprintf(
				stderr,
				"Unable to encode authenticated packet.\n"
			);

			goto cleanup;
		}

		if (!tcpClientSendAll(&client, packet, sizeof packet)) {
			fprintf(
				stderr,
				"Unable to send encoded authenticated packet.\n"
			);

			goto cleanup;
		}

		printf(
			"Authenticated packet { type=%u; sequence=%llu } correctly sent.\n", 
			(unsigned int)event.type, 
			(unsigned long long)event.sequence_number
		);
	}

	printf("Service stop packet correctly sent.\n");
	exitCode = EXIT_SUCCESS;

cleanup:
	tcpClientClose(&client);
	secureEraseAngetKey(agentKey, sizeof agentKey);

	return exitCode;
}