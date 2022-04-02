//
// Created by kozzi on 3/9/22.
//

#include <iostream>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/modes.h>
#include <iomanip>
#include <fstream>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <array>

#ifndef ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H
#define ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H

struct AESCryptoData {
    std::string prevName;
    std::string inQuarantineName;
    std::string hash;
    std::string keyString;
    std::string ivString;
    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key;
    std::array<std::byte, CryptoPP::AES::BLOCKSIZE> iv;
};

std::string md5(const std::string& str);

std::string md5File(const char *fileName);

AESCryptoData encryptFile(AESCryptoData& cryptoData);

void decryptFile(AESCryptoData& cryptoData);

std::string md5FileCryptoPP(const std::string& path);

//template<int T>
std::array<std::byte, 16> AESHexStringToBytes(const std::string& in);

std::string AESBytesToString(const std::array<std::byte, 16>& in);

#endif //ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H
