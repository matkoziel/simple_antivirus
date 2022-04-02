#include "../headers/file_management.h"
#include "../headers/crypto_functions.h"

#include <iostream>
#include <crypto++/osrng.h>
#include <filesystem>


extern const std::string quarantineDir;

//using aes_key_t = std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
//using aes_iv_t = std::array<std::byte, CryptoPP::AES::BLOCKSIZE>;



int main() {

    scanAllFilesInDirectory("/dev");
//    std::filesystem::path directoryIteratorPath("/etc/ssl/private/ssl-cert-snakeoil.key");
//    std::cout <<is_empty(directoryIteratorPath) << "\n";

//    AESCryptoData aes{};
//    aes.prevName = "/home/kozzi/CLionProjects/simple_antivirus/data/plain.txt";
//    aes.inQuarantineName = "/home/kozzi/CLionProjects/simple_antivirus/data/cyphertext.txt";
//    CryptoPP::AutoSeededRandomPool rng{};
//    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key{};
//    rng.GenerateBlock(reinterpret_cast<byte *>(key.data()), key.size());
//    auto keyString = AESBytesToString(key);
//    std::cout << keyString << "\n";
//    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> keyRestored = AESHexStringToBytes(keyString);
//    std::cout << (key==keyRestored) <<"\n";
//    aes.key = key;
//    std::array<std::byte, CryptoPP::AES::BLOCKSIZE> iv{};
//    rng.GenerateBlock(reinterpret_cast<byte *>(iv.data()), iv.size());
//    aes.iv = iv;

//    encryptFile(aes);
//    decryptFile(aes);


    return 0;
}


//TODO: Linki(done), pliki specjalne (partialy done) - done
//TODO: CLI
//TODO: Duże pliki (kcore) - done

