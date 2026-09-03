/**
 * @file security.c
 * @brief Implementation of security functions for the SentinelGrid Agent.
 *
 * This file contains the implementation of security-related functions, including HMAC SHA-256 calculation.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <stddef.h>
#include <stdint.h>
#include <Windows.h>
#include <bcrypt.h>
#include <limits.h>

#include <security/security.h>

int calculateHMacSha256(const uint8_t* key, size_t keyLength, const uint8_t* data, size_t dataLength, uint8_t output[HMAC_SHA256_SIZE]) 
{
	BCRYPT_ALG_HANDLE algo = NULL;
	NTSTATUS status;

	if (key == NULL || data == NULL || output == NULL)
		return 0;

	if (keyLength == 0 || dataLength == 0 ||
		keyLength > LONG_MAX || dataLength > LONG_MAX)
		return 0;

	SecureZeroMemory(output, HMAC_SHA256_SIZE);
	status = BCryptOpenAlgorithmProvider(&algo, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);

	if (!BCRYPT_SUCCESS(status))
		return 0;

	status = BCryptHash(algo, (PUCHAR)key, (ULONG)keyLength, (PUCHAR)data, (ULONG)dataLength, output, HMAC_SHA256_SIZE);
	if (!BCRYPT_SUCCESS(status)) {
		SecureZeroMemory(output, HMAC_SHA256_SIZE);
		return 0;
	}

	return 1;
}