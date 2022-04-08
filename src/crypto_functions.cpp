//
// Created by kozzi on 3/9/22.
//

#include "../headers/crypto_functions.h"

#include <iomanip>
#include <iostream>

#include <crypto++/aes.h>
#include <cryptopp/files.h>
#include <crypto++/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#include "../headers/file_management.h"
#include "../headers/main.h"

struct AESCryptoData;

std::string md5FileCryptoPP(const std::string& path) {
    CryptoPP::MD5 md5;
    std::string out;
    try {
        CryptoPP::FileSource fs(path.c_str(), true,
                                new CryptoPP::HashFilter(md5,
                                                         new CryptoPP::HexEncoder(
                                                                 new CryptoPP::StringSink(out),
                                                                                  false )));
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
    try {
        CryptoPP::FileSource{in, true,
                             new CryptoPP::StreamTransformationFilter{cipher,
                                                                      new CryptoPP::FileSink{out}}};
    }
    catch(const CryptoPP::Exception& exception) {
        std::cout << "Failed encrypting file\n";
    }
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

    try {
        CryptoPP::FileSource{in, true,
                             new CryptoPP::StreamTransformationFilter{cipher,
                                                                      new CryptoPP::FileSink{out}}};
    }
    catch(const CryptoPP::Exception& exception) {
        std::cout << "Failed decrypting file\n";
    }
}








