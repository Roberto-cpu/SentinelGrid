#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace sentinelgrid::engine::security {

	constexpr std::size_t authenticatedDataSize = 28U;
	constexpr std::size_t hmacSha256Size = 32U;

	enum class HmacVerificationResult {
		valid,
		invalid_input,
		calculation_failed,
		mismatch
	};

	[[nodiscard]]
	HmacVerificationResult verifyHmacSha256(
		std::span<const std::uint8_t> key,
		std::span<const std::uint8_t> authenticatedData,
		std::span<const std::uint8_t> receivedMac) noexcept;

	[[nodiscard]]
	bool computeHmacSha256(
		std::span<const std::uint8_t> key,
		std::span<const std::uint8_t> authenticatedData,
		std::array<std::uint8_t, hmacSha256Size>& output) noexcept;

	[[nodiscard]]
	bool fixedTimeEquals(
		const std::array<std::uint8_t, hmacSha256Size>& calculated,
		std::span<const std::uint8_t> received)  noexcept;
}