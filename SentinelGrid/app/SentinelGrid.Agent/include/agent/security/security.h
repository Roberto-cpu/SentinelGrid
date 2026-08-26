#pragma once
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
