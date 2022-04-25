//
// Created by kozzi on 3/9/22.
//

#ifndef SIMPLE_ANTIVIRUS_CRYPTO_FUNCTIONS_H
#define SIMPLE_ANTIVIRUS_CRYPTO_FUNCTIONS_H

#include <ctime>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "../headers/data_functions.h"

std::string MD5FileCryptoPP(const std::string& path);

QuarantineData EncryptFile(QuarantineData& cryptoData, std::vector<std::string>& database);

void DecryptFile(QuarantineData& cryptoData);

#endif //SIMPLE_ANTIVIRUS_CRYPTO_FUNCTIONS_H
