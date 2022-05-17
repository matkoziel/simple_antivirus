//
// Created by kozzi on 3/9/22.
//

#include "../headers/crypto_functions.h"

#include <iostream>

#include <crypto++/aes.h>
#include <cryptopp/files.h>
#include <crypto++/filters.h>
#include <cryptopp/hex.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#include "../headers/main.h"

struct QuarantineData;

// CryptoPP lib
// Calculates md5 sum of given file
std::string MD5FileCryptoPP(const std::string& path) {
    CryptoPP::Weak1::MD5 md5;
    std::string out;
    CryptoPP::FileSource fs(path.c_str(), true,                                             // Loads file in 4096B chunks
                            new CryptoPP::HashFilter(md5,
                                                     new CryptoPP::HexEncoder(
                                                             new CryptoPP::StringSink(out),
                                                                              false )));           // Result is hex string in lowercase
    return out;
}

// CryptoPP lib
// Encrypts given file with AES128
QuarantineData EncryptFile(QuarantineData& cryptoData, std::vector<std::string>& database) {
    CryptoPP::AutoSeededRandomPool rng{};
    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key{};
    rng.GenerateBlock(reinterpret_cast<byte *>(key.data()), key.size());    // Generates random key

    std::array<std::byte, CryptoPP::AES::BLOCKSIZE> iv{};
    rng.GenerateBlock(reinterpret_cast<byte *>(iv.data()), iv.size());      // Generates random iv
    cryptoData.ivString = AESBytesToString(iv);
    cryptoData.keyString = AESBytesToString(key);                                   // Saves bytes as string to temporary struct
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cipher{};
    cipher.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                        reinterpret_cast<const byte *>(iv.data()));

    AddToQuarantineDatabase(cryptoData, database);

    std::ifstream in{cryptoData.prevName, std::ios::binary};
    std::ofstream out{cryptoData.inQuarantineName, std::ios::binary};
    try {
        CryptoPP::FileSource{in, true,
                             new CryptoPP::StreamTransformationFilter{cipher,
                                                                      new CryptoPP::FileSink{out}}};    // Saves encrypted file as out
    }
    catch(const CryptoPP::Exception& exception) {
        std::cout << "Failed encrypting file\n";
    }
    return cryptoData;
}

// CryptoPP lib
// Decrypts given file with given key and iv
void DecryptFile(QuarantineData& cryptoData) {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cipher{};
    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key = AESHexStringToBytes(cryptoData.keyString);
    std::array<std::byte, CryptoPP::AES::BLOCKSIZE> iv = AESHexStringToBytes(cryptoData.ivString);                // Loads key and iv from struct

    cipher.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                        reinterpret_cast<const byte *>(iv.data()));

    std::ifstream in{cryptoData.inQuarantineName, std::ios::binary};
    std::ofstream out{cryptoData.prevName, std::ios::binary};

    try {
        CryptoPP::FileSource{in, true,
                             new CryptoPP::StreamTransformationFilter{cipher,
                                                                      new CryptoPP::FileSink{out}}};    // Saves decrypted file as out
    }
    catch(const CryptoPP::Exception& exception) {
        std::cout << "Failed decrypting file\n";
    }
}








