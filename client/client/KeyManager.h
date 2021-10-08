#pragma once
#include <array>
#include <aes.h>
#include <rsa.h>
#include <osrng.h>
#include <aes.h>
#include <base64.h>
#include <modes.h>


class KeyManagerException : public std::exception {
};


class SymmetricKeyEncryptor {
private:
	CryptoPP::byte _key[16];
public:
	SymmetricKeyEncryptor();
	SymmetricKeyEncryptor(std::array<char, 16> key);
	std::string ECBMode_Encrypt(std::string text);
	std::string ECBMode_Decrypt(std::string cipher);
	std::array<CryptoPP::byte,16>* GetKey();
};


class KeyManager {
private:
	CryptoPP::RSA::PublicKey _public_key;
	CryptoPP::RSA::PrivateKey _private_key;
public:
	KeyManager();
	KeyManager(std::string encoded);
	std::string* GetPublicKey();
	std::string* GetEncodedPrivateKey();
	SymmetricKeyEncryptor* DecryptSymmetricKey(std::string enc);
};


class PublicKeyManager {
private:
	CryptoPP::RSA::PublicKey _public_key;
public:
	PublicKeyManager(std::string encoded);
	std::string* EncryptSymmetricKey(SymmetricKeyEncryptor key);
};