//
// Created by kozzi on 3/9/22.
//

#include "crypto_functions.h"

#include <openssl/md5.h>
#include <openssl/blowfish.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <random>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/modes.h>
#include <iomanip>
#include <fstream>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>

#define DEFAULT_INPUT_DATA_SIZE 1024

std::string md5(const std::string& str) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, str.c_str(), str.size());
    MD5_Final(hash, &md5);
    std::stringstream ss;
    for (unsigned char hex: hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hex;
    }
    return ss.str();
}

std::string md5File(const char *fileName) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    FILE *inputFile = fopen (fileName, "rb");
    std::string result;
    if (!inputFile) {
        std::cerr << "Error, file: "<<fileName<<" doesn't exist";
    }
    else {
        int bytes;
        unsigned char data[DEFAULT_INPUT_DATA_SIZE];
        MD5_CTX md5;
        MD5_Init(&md5);
        while (inputFile && (bytes = fread(data,1,DEFAULT_INPUT_DATA_SIZE,inputFile)) != 0) {
            MD5_Update(&md5, data, bytes);
        }
        MD5_Final(hash, &md5);
        fclose(inputFile);
    }
    std::stringstream temp;
    for (unsigned char hex : hash){
        temp << std::hex << std::setw(2) << std::setfill('0') << (int) hex;
    }
    return temp.str();
}

void encryptFile(const std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> &key, const std::array<std::byte, CryptoPP::AES::BLOCKSIZE> &iv,
             const std::string &filename_in, const std::string &filename_out) {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cipher{};
    cipher.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                        reinterpret_cast<const byte *>(iv.data()));

    std::ifstream in{filename_in, std::ios::binary};
    std::ofstream out{filename_out, std::ios::binary};

    CryptoPP::FileSource{in, /*pumpAll=*/true,
                         new CryptoPP::StreamTransformationFilter{
                                 cipher, new CryptoPP::FileSink{out}}};
}

void decryptFile(const std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> &key, const std::array<std::byte, CryptoPP::AES::BLOCKSIZE> &iv,
             const std::string &filename_in, const std::string &filename_out) {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cipher{};
    cipher.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                        reinterpret_cast<const byte *>(iv.data()));

    std::ifstream in{filename_in, std::ios::binary};
    std::ofstream out{filename_out, std::ios::binary};

    CryptoPP::FileSource fileSource{in, /*pumpAll=*/true,
                         new CryptoPP::StreamTransformationFilter{
                                 cipher, new CryptoPP::FileSink{out}}};
}

std::string md5FileCryptoPP(const std::string& path) {
    CryptoPP::MD5 md5;
    std::string out;
    CryptoPP::FileSource fs( path.c_str(), true /* PumpAll */,
                   new CryptoPP::HashFilter( md5,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink( out),false /*UCase*/) // HexEncoder) // HashFilter
    )); // FileSource
    return out;
}








