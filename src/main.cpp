#include "../headers/file_management.h"
#include "../headers/crypto_functions.h"
#include "../headers/main.h"
#include "../headers/CLI11.hpp"

#include <iostream>


std::string quarantineDir;
std::string quarantineDatabase;

int main(int argc, char **argv) {
    quarantineDatabase="/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/quarantine_database.csv";
    quarantineDir="/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data";
    std::unordered_set<std::string> hashDatabase = readDatabaseToUnorderedSet("/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/database.csv");
    std::unordered_set<std::string> quarantineDatabaseDB = readDatabaseToUnorderedSet("/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/quarantine_database.csv");
    scan("/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data",hashDatabase,quarantineDatabaseDB);

//    quarantineAFile("/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/plain.txt",quarantineDatabaseDB);
    restoreFromQuarantine("/home/kozzi/CLionProjects/BSO/Antywirus/simple_antivirus/data/plain.txt",quarantineDatabaseDB);
//    CLI::App app{"Simple antivirus"};
//
//    CLI11_PARSE(app, argc, argv);

    return 0;
}

//TODO: Skanowanie /proc coś wywala czasami
//TODO: CLI
//TODO: Zmienić opisy przy skanowaniu na sensowne
//TODO: Testowanie

