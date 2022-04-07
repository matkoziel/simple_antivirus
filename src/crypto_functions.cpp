//
// Created by kozzi on 3/9/22.
//

#include "../headers/crypto_functions.h"
#include "../headers/file_management.h"
#include "../headers/main.h"

#include <openssl/md5.h>

#include <iostream>
#include <iomanip>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>

#define DEFAULT_INPUT_DATA_SIZE 1024

struct AESCryptoData;

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

std::string md5FileCryptoPP(const std::string& path) {
    CryptoPP::MD5 md5;
    std::string out;
    try {
        CryptoPP::FileSource fs(path.c_str(), true /* PumpAll */,
                                new CryptoPP::HashFilter(md5,
                                                         new CryptoPP::HexEncoder(new CryptoPP::StringSink(out),
                                                                                  false /*UCase*/) // HexEncoder) // HashFilter
                                ));// FileSource
    }
    catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
    }
    return out;
}

std::string AESBytesToString(const std::array<std::byte, 16>& in) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (std::byte byte : in){
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::array<std::byte, 16> AESHexStringToBytes(const std::string& in) {
    std::array<std::byte, 16> out{};
    std::stringstream converter;
    for(int i = 0; i < out.size(); i++){
        converter << std::hex << in.substr(2*i,2);
        int byte;
        converter >> byte;
        out[i] = static_cast<std::byte>(byte & 0xFF);
        converter.str(std::string());
        converter.clear();
    }
    return out;
}

AESCryptoData encryptFile(AESCryptoData& cryptoData,std::vector<std::string>& database) {
    CryptoPP::AutoSeededRandomPool rng{};
    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key{};
    rng.GenerateBlock(reinterpret_cast<byte *>(key.data()), key.size());

    std::array<std::byte, CryptoPP::AES::BLOCKSIZE> iv{};
    rng.GenerateBlock(reinterpret_cast<byte *>(iv.data()), iv.size());
    cryptoData.ivString = AESBytesToString(iv);
    cryptoData.keyString = AESBytesToString(key);
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cipher{};
    cipher.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                        reinterpret_cast<const byte *>(iv.data()));

    addToQuarantineDatabase(cryptoData,database);

    std::ifstream in{cryptoData.prevName, std::ios::binary};
    std::ofstream out{cryptoData.inQuarantineName, std::ios::binary};
    CryptoPP::FileSource{in, /*pumpAll=*/true,
                         new CryptoPP::StreamTransformationFilter{
                                 cipher, new CryptoPP::FileSink{out}}};

    return cryptoData;
}

void decryptFile(AESCryptoData& cryptoData) {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cipher{};
    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key = AESHexStringToBytes(cryptoData.keyString);
    std::array<std::byte, CryptoPP::AES::BLOCKSIZE> iv = AESHexStringToBytes(cryptoData.ivString);

    cipher.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                        reinterpret_cast<const byte *>(iv.data()));

    std::ifstream in{cryptoData.inQuarantineName, std::ios::binary};
    std::ofstream out{cryptoData.prevName, std::ios::binary};

    CryptoPP::FileSource {in, /*pumpAll=*/true,
                         new CryptoPP::StreamTransformationFilter{
                                 cipher, new CryptoPP::FileSink{out}}};
}









