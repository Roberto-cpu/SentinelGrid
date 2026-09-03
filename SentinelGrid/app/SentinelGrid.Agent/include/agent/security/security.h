#pragma once

/**
 * @file security.h
 * @brief This header file defines the interface for security-related functions, including HMAC SHA256 encryption.
 *
 * The functions in this header file provide functionality to calculate HMAC SHA256 encryption for securing data.
 *
 * @note The implementation of the security functions is expected to be provided in a corresponding source file (e.g., security.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <stddef.h>
#include <stdint.h>

#define HMAC_SHA256_SIZE 32U

/*
* @brief Calculates the HMAC SHA256 encryption to secure the given data
* @param key: the encryption key
* @param keyLength: the size of the key
* @param data: the bytes to encrypt
* @param dataLength: the buffer dimension
* @param output: the memory address in which store the encrypted bytes
*/
int calculateHMacSha256(const uint8_t* key, size_t keyLength, const uint8_t* data, size_t dataLength, uint8_t output[HMAC_SHA256_SIZE]);

#endif // !SECURITY_H
