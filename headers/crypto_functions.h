//
// Created by kozzi on 3/9/22.
//

#include <ctime>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#ifndef ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H
#define ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H

struct AESCryptoData {
    std::string prevName;
    std::string inQuarantineName;
    std::string keyString;
    std::string ivString;
    std::filesystem::perms perms;
    std::string date;
};

std::string md5FileCryptoPP(const std::string& path);

std::string AESBytesToString(const std::array<std::byte, 16>& in);

std::array<std::byte, 16> AESHexStringToBytes(const std::string& in);

AESCryptoData encryptFile(AESCryptoData& cryptoData,std::vector<std::string>& database);

void decryptFile(AESCryptoData& cryptoData);

#endif //ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H
