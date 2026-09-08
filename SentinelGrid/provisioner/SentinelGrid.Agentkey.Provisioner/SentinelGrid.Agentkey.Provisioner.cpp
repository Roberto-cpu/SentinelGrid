/*
 * @file SentinelGrid.Agentkey.Provisioner.cpp
 * @brief This file contains the main entry point for the SentinelGrid Agent Key Provisioner application.
 * 
 * This application is responsible for generating and storing agent keys in the Windows Credential Manager.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <stdexcept>

#include <security/agent_key_registry.hpp>
#include <security/windows_credential_store.hpp>

using namespace sentinelgrid::engine::security;

namespace {

    /**
	 * @brief A secure wrapper for the AgentKey structure that ensures sensitive data is erased from memory upon destruction.
    */
    struct SecureAgentKey final {
        
        AgentKey value{};
        
		/**
		 * @brief Default constructor for SecureAgentKey.
		 * Initializes the AgentKey structure to its default state.
        */
        SecureAgentKey() = default;

		/**
		 * @brief Destructor for SecureAgentKey.
         */
        ~SecureAgentKey() noexcept { secureErase(value); }

        /**
		 * @brief Copy constructor for SecureAgentKey.
		 * Deleted to prevent copying of sensitive data.
        */
		SecureAgentKey(const SecureAgentKey&) = delete;

		/**
		 * @brief Assignment operator for SecureAgentKey.
		 * Deleted to prevent assignment of sensitive data.
        */
		SecureAgentKey& operator=(const SecureAgentKey&) = delete;
    };
}

int wmain(int argc, wchar_t* argv[])
{
    std::cout << "Running SentinelGrid Agent Key Provisioner\n";

    if (argc != 2 && argc != 3) {
        std::cerr << "Usage: SentinelGrid.Agentkey.Provisioner.exe <agent-id> [--overwrite]\n";
        std::cerr << "Commands:\n";
        std::cerr << "  agent-id - Identifies the agent for which to generate a key and the key ID\n";
        std::cerr << "  --overwrite - Optional flag to overwrite existing key ID if it exists\n";

        return EXIT_FAILURE;
    }

    std::uint32_t agentId{ 0U };
	std::size_t parsed{ 0U };

    try {
		const std::wstring agentIdStr{ argv[1] };
		const std::uint32_t parsedId = std::stoul(agentIdStr, &parsed, 10);

		if (parsed != agentIdStr.size() || parsed == 0UL || parsed > UINT32_MAX) {
			std::cerr << "Invalid agent ID provided. Agent ID must be a positive integer.\n";
			return EXIT_FAILURE;
		}

		agentId = static_cast<std::uint32_t>(parsedId);
    }
    catch (std::invalid_argument& e) {
        std::cerr << "Invalid agent ID provided. Agent ID must be a positive integer.\n";
        return EXIT_FAILURE;

    }
    catch (std::out_of_range& e) {
        std::cerr << "Invalid agent ID provided. Agent ID is out of range.\n";
        return EXIT_FAILURE;
    }

    bool overwrite{ false };

	if (argc == 3) {
		const std::wstring overwriteArg{ argv[2] };
		if (overwriteArg != L"--overwrite") {
		    std::cerr << "Invalid argument provided. Only '--overwrite' is accepted as the second argument.\n";
			return EXIT_FAILURE;
		}

        overwrite = true;
	}

	const std::wstring agentIdStr{ std::to_wstring(agentId) };

    const std::wstring target{ L"SentinelGrid/Agent/" + agentIdStr };
    const std::wstring username{ L"Agent/" + agentIdStr };

    std::cout << "Creating authentication key.\n";

    SecureAgentKey generatedKey;

    const auto generationRes = generateAgentKey(generatedKey.value);
    if (!generationRes.isSuccess()) {
        std::cerr << "Unable to generate agent key for: " << generationRes.errorCode << "\n";
        return EXIT_FAILURE;
    }

    const auto writeRes = storeAgentKey(target, username, generatedKey.value, CredentialPersistence::local_machine, overwrite);
    
    if (!writeRes.isSuccess()) {
        std::cerr << "Unable to store generated agent key for: " << writeRes.errorCode <<"\n";
        return EXIT_FAILURE;
    }

    std::cout << "Generated agent key successfully stored in Windows Credential Manager.\n";
    return EXIT_SUCCESS;
}