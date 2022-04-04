#include "../headers/file_management.h"
#include "../headers/crypto_functions.h"

#include <iostream>
#include <crypto++/osrng.h>
#include <filesystem>


extern const std::string quarantineDir;

int main() {

    std::unordered_set<std::string> hashDatabase = readDatabaseToUnorderedSet("/home/kozzi/CLionProjects/simple_antivirus/data/database.csv");
    std::unordered_set<std::string> quarantineDatabase = readDatabaseToUnorderedSet("/home/kozzi/CLionProjects/simple_antivirus/data/quarantine_database.csv");
//    findInQuarantine("/home/kozzi/CLionProjects/simple_antivirus/data/plain.txt",quarantineDatabase);
    std::filesystem::path path("/home/kozzi/CLionProjects/simple_antivirus/data/plain.txt");
    auto perms = status(path).permissions();
    std::cout << static_cast<int>(perms);
//    addToQuarantineDatabase(aes,"/home/kozzi/CLionProjects/simple_antivirus/data/quarantine_database.csv");
//    AESCryptoData aesRead = findInQuarantine("123",quarantineDatabase);
//    std::string temp ="/home/kozzi/CLionProjects/simple_antivirus/data/plain.txt,/home/kozzi/CLionProjects/simple_antivirus/data/cyphertext.txt,1,2";
//    std::string res = "/home/kozzi/CLionProjects/simple_antivirus/data/plain.txt";
//    int start=0;
//    int delimiter = temp.find_first_of(',');
//    std::string readPrevName = temp.substr(start,delimiter);
//    std::cout << temp << "\n";
//    std::cout<< readPrevName << "\n";
//    std::cout<< (readPrevName==res) << "\n";
//    scan("1231231");

//    encryptFile(aes);
//    decryptFile(aes);

    return 0;
}

//TODO: Skanowanie /proc coś wywala czasami
//TODO: CLI
//TODO: Zrobienie tabelki w folderze kwarantanny
//TODO: Przy przenoszeniu do kwarantanny zapisać do tabelki:nazwę teraz, nazwę przed, klucz, iv, wcześniejsze uprawnienia
//TODO: Zrobić przywacanie z kwarantanny na podstawie wcześniejszej nazwy
//TODO: Zmienić opisy przy skanowaniu na sensowne
//TODO: Fix znajdowanie w tablicy w kwarantannie, bo jak się poda wartośc której tam nie ma to się dzieją dziwne rzeczy

