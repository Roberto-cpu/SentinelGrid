/*
 * @file SentinelGrid.Agentkey.Provisioner.cpp
 * #brief This file contains the main entry point for the SentinelGrid Agent Key Provisioner application.
 * 
 * This application is responsible for generating and storing agent keys in the Windows Credential Manager.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <iostream>
#include <security/agent_key_registry.hpp>
#include <security/windows_credential_store.hpp>

using namespace sentinelgrid::engine::security;

int main()
{
    std::cout << "Creating authentication key.\n";

    AgentKey generatedKey{};

    const auto generationRes = generateAgentKey(generatedKey);
    if (!generationRes.isSuccess()) {
        std::cerr << "Unable to generate agent key for: " << generationRes.errorCode << "\n";
        return EXIT_FAILURE;
    }

    const auto writeRes = storeAgentKey(L"SentinelGrid/Agent/1", L"Agent/1", generatedKey, CredentialPersistence::local_machine);
    secureErase(generatedKey);
    
    if (!writeRes.isSuccess()) {
        std::cerr << "Unalbe to store generated agent key for: " << writeRes.errorCode <<"\n";
        return EXIT_FAILURE;
    }

    std::cout << "Generated agent key successfully stored in Windows Credentials Manager.\n";
    return EXIT_SUCCESS;
}