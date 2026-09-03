/**
 * @file hmac_sha256_verifier.cpp
 * @brief This file contains the implementation for verifying HMAC-SHA256 signatures.
 *
 * This implementation provides functions to compute and verify HMAC-SHA256 signatures using the Windows Cryptography API: Next Generation (CNG).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <bcrypt.h>

#include <iostream>
#include <span>
#include <limits>
#include <array>
#include <cstdint>

#include <security/hmac_sha256_verifier.hpp>

namespace sentinelgrid::engine::security {

	HmacVerificationResult verifyHmacSha256(
		std::span<const std::uint8_t> key,
		std::span<const std::uint8_t> authenticatedData,
		std::span<const std::uint8_t> receivedMac
	) noexcept
	{
		if (key.empty())
			return HmacVerificationResult::invalid_input;

		if (authenticatedData.size() != authenticatedDataSize || receivedMac.size() != hmacSha256Size)
			return HmacVerificationResult::invalid_input;

		std::array<uint8_t, hmacSha256Size> calculatedMac{};

		if (!computeHmacSha256(key, authenticatedData, calculatedMac))
			return HmacVerificationResult::calculation_failed;

		const bool matches = fixedTimeEquals(calculatedMac, receivedMac);

		SecureZeroMemory(
			calculatedMac.data(),
			calculatedMac.size()
		);

		return !matches ? HmacVerificationResult::mismatch : HmacVerificationResult::valid;
	}

	bool computeHmacSha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> authenticatedData, std::array<std::uint8_t, hmacSha256Size>& output) noexcept {

		if (key.empty())
			return false;

		constexpr std::size_t maxulong = static_cast<std::size_t>((std::numeric_limits<ULONG>::max)());
		if (key.size() > maxulong || authenticatedData.size() > maxulong)
			return false;

		BCRYPT_ALG_HANDLE hAlg = nullptr;
		NTSTATUS status = 0;

		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
		if (!BCRYPT_SUCCESS(status))
			return false;

		status = BCryptHash(hAlg, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()),
			const_cast<PUCHAR>(authenticatedData.data()), static_cast<ULONG>(authenticatedData.size()),
			output.data(), static_cast<ULONG>(output.size()));

		BCryptCloseAlgorithmProvider(&hAlg, 0);

		if (!BCRYPT_SUCCESS(status)) {
			SecureZeroMemory(
				output.data(),
				output.size()
			);
			return false;
		}

		return true;
	}

	bool fixedTimeEquals(
		const std::array<std::uint8_t, hmacSha256Size>& calculated,
		std::span<const std::uint8_t> received)  noexcept
	{
		volatile std::uint32_t difference = 0U;

		for (std::size_t i = 0; i < calculated.size(); ++i)
		{
			difference =
				difference |
				static_cast<std::uint32_t>(
					calculated[i] ^ received[i]);
		}

		return difference == 0U;
	}
}