#include "../headers/file_management.h"
#include "../headers/crypto_functions.h"

#include <iostream>
#include <crypto++/osrng.h>
#include <filesystem>


extern const std::string quarantineDir;

int main() {

//    scanAllFilesInDirectory("/etc");
    scan("1231231");
//    std::cout << checkFileSystem("/etc/brlapi.key");
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
//    std::string path = "/etc/ssl/private/ssl-cert-snakeoil.key";
//    std::cout << std::filesystem::is_directory(path) <<"\n";

    return 0;
}

//TODO: Skanowanie /proc coś wywala czasami
//TODO: CLI
//TODO: Zrobienie tabelki w folderze kwarantanny
//TODO: Przy przenoszeniu do kwarantanny zapisać do tabelki:nazwę teraz, nazwę przed, klucz, iv, wcześniejsze uprawnienia
//TODO: Zrobić przywacanie z kwarantanny na podstawie wcześniejszej nazwy
//TODO: Zmienić opisy przy skanowaniu na sensowne

