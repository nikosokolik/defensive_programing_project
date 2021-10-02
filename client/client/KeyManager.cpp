#include <iostream>
#include "KeyManager.h"


KeyManager::KeyManager() {
	_private_key = CryptoPP::RSA::PrivateKey();
	CryptoPP::AutoSeededRandomPool  prng;
	_private_key.GenerateRandomWithKeySize(prng, 1024);
    _public_key = CryptoPP::RSA::PublicKey (_private_key);
}


KeyManager::KeyManager(std::string encoded) {
    CryptoPP::Base64Decoder encoder(new CryptoPP::StringSource(encoded, true, new CryptoPP::Base64Decoder));
    _private_key.BERDecode(encoder);
	CryptoPP::RSA::PublicKey _public_key(_private_key);
}


std::string* KeyManager::GetEncodedPrivateKey() {
	/* User must free */
	std::string* encoded = new std::string();
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(*encoded));
	_private_key.DEREncode(encoder);
    encoder.MessageEnd();
    return encoded;
}

std::string* KeyManager::GetPublicKey() {
	/* User must free */
    std::string key;
	CryptoPP::StringSink stringSource(key);
	_public_key.BEREncode(stringSource.Ref());
	return new std::string(key);
}


SymmetricKeyEncryptor::SymmetricKeyEncryptor(std::array<char, 128> key) {
    std::copy_n(key.begin(), key.size(), std::begin(_key));
}


SymmetricKeyEncryptor::SymmetricKeyEncryptor() {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    std::copy_n(key.begin(), key.size(), std::begin(_key));
}


std::string SymmetricKeyEncryptor::ECBMode_Encrypt(std::string text) {
    std::string cipher = "";
    //Encryption
    try
    {
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(_key, 128, iv);
        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        CryptoPP::StringSource s(text, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(cipher))); // StringSource
    }
    catch (const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    return cipher;
}


std::string SymmetricKeyEncryptor::ECBMode_Decrypt(std::string cipher) {
    std::string recovered = "";
    //Decryption
    try
    {
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption dec;
        dec.SetKeyWithIV(_key, 128, iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(recovered))); // StringSource
    }
    catch (const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    return recovered;
}

std::array<CryptoPP::byte, 128>* SymmetricKeyEncryptor::GetKey() {
    std::array<CryptoPP::byte, 128>* retval = new std::array<CryptoPP::byte, 128>();
    std::copy_n(retval->begin(), retval->size(), std::begin(_key));
    return retval;
}


SymmetricKeyEncryptor* KeyManager::DecryptSymmetricKey(std::string enc) {
    std::string decrypted;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(_private_key);
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::StringSink s = CryptoPP::StringSink(decrypted);
    CryptoPP::PK_DecryptorFilter* decryptor = new CryptoPP::PK_DecryptorFilter(prng, d, &s);
    CryptoPP::StringSource(enc, true, decryptor);
    if (decrypted.size() != 128) {
        throw KeyManagerException();
    }
    std::array<char, 128> key;
    std::copy_n(decrypted.begin(), decrypted.length(), key.begin());
    delete decryptor;
    return new SymmetricKeyEncryptor(key);
}


std::string* PublicKeyManager::EncryptSymmetricKey(SymmetricKeyEncryptor key) {
    std::string* encrypted = new std::string();
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(_public_key);
    CryptoPP::RandomPool prng;
    std::array<CryptoPP::byte, 128>* key_data = key.GetKey();
    std::string string_key_data = std::string(key_data->begin(), key_data->end());
    CryptoPP::StringSource(string_key_data, true,
        new CryptoPP::PK_EncryptorFilter(prng, e,
            new CryptoPP::StringSink(*encrypted)));
    delete key_data;
    return encrypted;
}


PublicKeyManager::PublicKeyManager(std::string encoded) {
    CryptoPP::ArraySource s(encoded.c_str(), encoded.length());
    _public_key.Load(s);
}