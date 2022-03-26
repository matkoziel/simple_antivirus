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

std::string md5(const std::string& str);

std::string md5File(const char *fileName);

void encryptFile(const std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> &key, const std::array<std::byte, CryptoPP::AES::BLOCKSIZE> &iv,
                 const std::string &filename_in, const std::string &filename_out);

void decryptFile(const std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> &key, const std::array<std::byte, CryptoPP::AES::BLOCKSIZE> &iv,
                 const std::string &filename_in, const std::string &filename_out);

std::string md5FileCryptoPP(const std::string& path);

#endif //ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H
