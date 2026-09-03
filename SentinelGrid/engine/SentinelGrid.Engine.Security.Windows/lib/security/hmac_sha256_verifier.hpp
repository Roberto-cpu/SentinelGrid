#pragma once

/**
 * @file hmac_sha256_verifier.hpp
 * @brief This header file defines the interface for HMAC-SHA256 verification and computation.
 *
 * The functions declared in this file allow for the verification of HMAC-SHA256 signatures and the computation of HMAC-SHA256 signatures
 * for given authenticated data using a specified key. Additionally, it provides a utility function for constant-time comparison of byte arrays.
 *
 * @note The implementation of these functions is expected to be provided in a corresponding source file (e.g., hmac_sha256_verifier.cpp).
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstdint>
#include <span>
#include <array>

namespace sentinelgrid::engine::security {

	constexpr std::size_t authenticatedDataSize = 28U;
	constexpr std::size_t hmacSha256Size = 32U;

	/**
	 * @brief This enumeration defines the possible results of HMAC-SHA256 verification.
	 */
	enum class HmacVerificationResult {
		valid,
		invalid_input,
		calculation_failed,
		mismatch
	};
	
	/**
	 * @brief Computes the HMAC-SHA256 signature for the given authenticated data using the provided key.
	 *
	 * @param key The key used for HMAC computation.
	 * @param authenticatedData The data to be authenticated.
	 * @param output The output buffer where the computed HMAC will be stored.
	 * @return true if the computation was successful, false otherwise.
	 */
	[[nodiscard]]
	HmacVerificationResult verifyHmacSha256(
		std::span<const std::uint8_t> key,
		std::span<const std::uint8_t> authenticatedData,
		std::span<const std::uint8_t> receivedMac) noexcept;

	/**
	 * @brief Computes the HMAC-SHA256 signature for the given authenticated data using the provided key.
	 *
	 * @param key The key used for HMAC computation.
	 * @param authenticatedData The data to be authenticated.
	 * @param output The output buffer where the computed HMAC will be stored.
	 * @return true if the computation was successful, false otherwise.
	 */
	[[nodiscard]]
	bool computeHmacSha256(
		std::span<const std::uint8_t> key,
		std::span<const std::uint8_t> authenticatedData,
		std::array<std::uint8_t, hmacSha256Size>& output) noexcept;


	/**
	 * @brief Compares two byte arrays for equality in constant time.
	 *
	 * @param calculated The first array to compare.
	 * @param received The second array to compare.
	 * @return true if the arrays are equal, false otherwise.
	 */
	[[nodiscard]]
	bool fixedTimeEquals(
		const std::array<std::uint8_t, hmacSha256Size>& calculated,
		std::span<const std::uint8_t> received)  noexcept;
}