#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

/**
 * @file windows_credential_store.hpp
 * @brief This file contains the declarations for managing agent credentials in the Windows Credentials Manager.
 * 
 * This header provides the interface for generating, storing, and loading agent keys securely using the Windows Credential Manager API.
 * 
 * @note The implementation of these functions is expected to be provided in a corresponding source file (e.g., windows_credential_store.cpp).
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>
#include <string>

#include <security/agent_key_registry.hpp>

namespace sentinelgrid::engine::security {
	
	/*
	 * @brief: This enumeration defines the persistence options for storing credentials in the Windows Credentials Manager.
	 */
	enum class CredentialPersistence {
		session,
		local_machine
	};

	/*
	 * @brief: This enumeration defines the status codes for credential write operations.
	 */
	enum class CredentialWriteStatus {
		success,
		invalid_input,
		already_exists,
		access_denied,
		generation_failed,
		platform_failure
	};
	
	/*
	 * @brief: This enumeration defines the status codes for credential load operations.
	 */
	enum class CredentialLoadStatus {
		success,
		invalid_input,
		not_found,
		access_denied,
		invalid_key_size,
		platform_failure
	};

	/*
	 * @brief: This structure holds the result of a credential write operation.
	 */
	struct CredentialWriteResult {
		CredentialWriteStatus status;
		std::uint32_t errorCode;

		[[nodiscard]]
		bool isSuccess() const noexcept { return status == CredentialWriteStatus::success; }
	};

	/*
	 * @brief: This structure holds the result of a credential load operation.
	 */
	struct CredentialLoadResult {
		
		CredentialLoadStatus status;
		std::uint32_t nativeErrorCode;

		[[nodiscard]]
		bool isSuccess() const noexcept { return status == CredentialLoadStatus::success; }
	};

	/*
	 * @brief: Generates a new agent key and stores it in the provided destination.
	 * @param destination: A reference to an AgentKey object where the generated key will be stored.
	 * @return A CredentialWriteResult indicating the success or failure of the operation.
	 */
	[[nodiscard]]
	CredentialWriteResult generateAgentKey(AgentKey& destination) noexcept;
	
	/*
	 * @brief: Stores an agent key in the Windows Credentials Manager.
	 * @param target: The target identifier for the credential.
	 * @param username: The username associated with the credential.
	 * @param key: A span containing the key data to store.
	 * @param persistence: The persistence option for the credential.
	 * @param allowOverwrite: Whether to allow overwriting an existing credential.
	 * @return A CredentialWriteResult indicating the success or failure of the operation.
	 */
	[[nodiscard]]
	CredentialWriteResult storeAgentKey(
		const std::wstring& target,
		const std::wstring& username,
		std::span<const std::uint8_t> key,
		CredentialPersistence persistence,
		bool allowOverwrite = false
	) noexcept;

	/**
	 * @brief: Loads an agent key from the Windows Credentials Manager.
	 * @param credentialTarget: The target identifier for the credential.
	 * @param destination: A reference to an AgentKey object where the loaded key will be stored.
	 * @return A CredentialLoadResult indicating the success or failure of the operation.
	 */
	[[nodiscard]]
	CredentialLoadResult loadAgentKey(const std::wstring& credentialTarget, AgentKey& destination) noexcept;
	
	/*
	 * @brief: Securely erases the contents of an agent key.
	 * @param agent: A reference to the AgentKey object to erase.
	 */
	void secureErase(AgentKey& agent) noexcept;
}