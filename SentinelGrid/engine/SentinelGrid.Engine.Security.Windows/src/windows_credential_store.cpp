/**
 * @file windows_credential_store.cpp
 * @brief This file contains the implementation for managing agent credentials in the Windows Credentials Manager.
 * 
 * This implementation provides functions to generate, store, and load agent keys securely using the Windows Credential Manager API.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <wincred.h>
#include <cstdint>
#include <string>
#include <algorithm>
#include <memory>
#include <bcrypt.h>

#include <security/windows_credential_store.hpp>

namespace sentinelgrid::engine::security {

	struct CredentialDeleter {
		void operator()(CREDENTIALW* credential) const noexcept {
			if (credential == nullptr)
				return;

			if (credential->CredentialBlob != nullptr && credential->CredentialBlobSize > 0U) {
				SecureZeroMemory(
					credential->CredentialBlob,
					credential->CredentialBlobSize
				);
			}

			CredFree(credential);
		}
	};

	using UniqueCredential = std::unique_ptr<CREDENTIALW, CredentialDeleter>;

	void secureErase(AgentKey& agent) noexcept { SecureZeroMemory(agent.data(), agent.size()); }

	CredentialWriteResult generateAgentKey(AgentKey& destination) noexcept {
		secureErase(destination);

		const auto status = BCryptGenRandom(
			nullptr, destination.data(), static_cast<ULONG>(destination.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG
		);

		if (!BCRYPT_SUCCESS(status)) {
			secureErase(destination);
			return {
				CredentialWriteStatus::generation_failed,
				static_cast<std::uint32_t>(status)
			};
		}
		
		return {
			CredentialWriteStatus::success,
			ERROR_SUCCESS
		};
	}

	CredentialWriteResult storeAgentKey(
		const std::wstring& target,
		const std::wstring& username,
		std::span<const std::uint8_t> key,
		CredentialPersistence persistence,
		bool allowOverwrite
	) noexcept
	{
		if (target.empty() || key.size() != AgentKeySize) {
			return {
				CredentialWriteStatus::invalid_input,
				ERROR_INVALID_PARAMETER
			};
		}

		DWORD nativePersistence{};

		switch (persistence) {
			case CredentialPersistence::session:
				nativePersistence = CRED_PERSIST_SESSION;
				break;
			case CredentialPersistence::local_machine:
				nativePersistence = CRED_PERSIST_LOCAL_MACHINE;
				break;
			default:
				return {
					CredentialWriteStatus::invalid_input,
					ERROR_INVALID_PARAMETER
				};
		}

		PCREDENTIALW pcredential = nullptr;
		if (CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcredential)) {
			
			CredFree(pcredential);
			pcredential = nullptr;

			if (!allowOverwrite) {
				CredFree(pcredential);
				return {
					CredentialWriteStatus::already_exists,
					ERROR_ALREADY_EXISTS
				};
			}
		}
		else {
			DWORD readErr = GetLastError();

			if (readErr != ERROR_NOT_FOUND) {

				return {
					readErr == ERROR_ACCESS_DENIED ? CredentialWriteStatus::access_denied : CredentialWriteStatus::platform_failure,
					readErr
				};
			}
		}
		
		CREDENTIALW credential{};

		credential.TargetName = const_cast<LPWSTR>(target.c_str());
		credential.UserName = const_cast<LPWSTR>(username.c_str());
	
		credential.CredentialBlob = const_cast<LPBYTE>(key.data());
		credential.CredentialBlobSize = static_cast<DWORD>(key.size());

		credential.Type = CRED_TYPE_GENERIC;
		credential.Persist = nativePersistence;

		bool success = CredWriteW(&credential, 0);
		
		if (!success) {
			const DWORD writeErr = GetLastError();

			if (writeErr == ERROR_ACCESS_DENIED) {
				return {
					CredentialWriteStatus::access_denied,
					writeErr
				};
			}

			return {
				CredentialWriteStatus::platform_failure,
				writeErr
			};
		}

		return {
			CredentialWriteStatus::success,
			ERROR_SUCCESS
		};
	}

	CredentialLoadResult loadAgentKey(const std::wstring& credentialTarget, AgentKey& destination) noexcept {

		secureErase(destination);

		if (credentialTarget.empty()) {
			return CredentialLoadResult{
				CredentialLoadStatus::invalid_input,
				ERROR_INVALID_PARAMETER
			};
		}
		
		PCREDENTIALW rawCredential = nullptr;
		bool readRes = CredReadW(credentialTarget.c_str(), CRED_TYPE_GENERIC, 0U, &rawCredential);

		if (readRes == false) {
			const DWORD errCode = GetLastError();

			if (errCode == ERROR_NOT_FOUND) {
				return {
					CredentialLoadStatus::not_found,
					errCode
				};
			}

			if (errCode == ERROR_ACCESS_DENIED) {
				return {
					CredentialLoadStatus::access_denied,
					errCode
				};
			}

			return {
				CredentialLoadStatus::platform_failure,
				errCode
			};
		}

		UniqueCredential credential{ rawCredential };

		if (credential->CredentialBlob == nullptr) {
			return {
				CredentialLoadStatus::platform_failure,
				ERROR_INVALID_DATA
			};
		}

		if (credential->CredentialBlobSize != static_cast<DWORD>(AgentKeySize)) {
			return {
				CredentialLoadStatus::invalid_key_size,
				ERROR_INVALID_DATA
			};
		}

		std::copy_n(credential->CredentialBlob, AgentKeySize, destination.begin());
		return {
			CredentialLoadStatus::success,
			ERROR_SUCCESS
		};
	}
}