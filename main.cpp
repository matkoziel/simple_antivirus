#include "file_management.h"
#include "crypto_functions.h"

#include <iostream>
#include <vector>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <queue>
#include <random>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/modes.h>
#include <iomanip>
#include <fstream>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#include <fstream>
#include <iostream>


extern const std::string quarantineDir;

//using aes_key_t = std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
//using aes_iv_t = std::array<std::byte, CryptoPP::AES::BLOCKSIZE>;


int main() {

//    CryptoPP::AutoSeededRandomPool rng{};
//
//    // Generate a random key
//    std::array<std::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key{};
//    rng.GenerateBlock(reinterpret_cast<byte *>(key.data()), key.size());
//
//    // Generate a random IV
//    std::array<std::byte, CryptoPP::AES::BLOCKSIZE> iv{};
//    rng.GenerateBlock(reinterpret_cast<byte *>(iv.data()), iv.size());
//
//    // encrypt
//    encryptFile(key, iv, "/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/input_file", "/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/output_file");
//
//    // decrypt
//    decryptFile(key, iv, "/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/output_file", "/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/decrypted_file");
//    scanAllFilesInDirectory("/");

    std::string path = "/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/1GB.zip";
    std::cout << path << "\n";
    std::string hash = md5FileCryptoPP(path);
    std::cout << hash << "\n";
//    std::filesystem::path directoryIteratorPath = "/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/link2";
//    std::cout << std::filesystem::canonical(directoryIteratorPath.parent_path().append(directoryIteratorPath.filename().u8string())) << "\n";
    return 0;
}


//TODO: Linki(done), pliki specjalne (partialy done)
//TODO: CLI
//TODO: Duże pliki (kcore)

