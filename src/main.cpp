#include "../headers/file_management.h"
#include "../headers/crypto_functions.h"
#include "../headers/main.h"
#include "../headers/CLI11.hpp"

#include <iostream>

std::string quarantineDir;
std::string quarantineDatabase;

int main(int argc, char **argv) {

    quarantineDir= getenv("HOME");
    quarantineDir=quarantineDir.append("/.quarantine");
    quarantineDatabase=quarantineDir +"/.quarantine_database.csv";

    CLI::App app{"Simple antivirus"};

    auto scanOpt=app.add_subcommand("scan", "Scan given path");
    auto restoreOpt=app.add_subcommand("restore", "Restore file from quarantine");

    std::string scanFileName{};
    scanOpt -> add_option("--path",scanFileName,"Path to file/directory we want to scan")
    ->required()
    ->check(CLI::ExistingPath);

    std::string hashDatabaseStr{};
    auto d = scanOpt -> add_option("--d",hashDatabaseStr,"Path to hash database")
            ->required()
            ->check(CLI::ExistingPath);

    std::string restoreFileName{};
    restoreOpt -> add_option("--path",restoreFileName,"Path to file we want to restore");

    CLI11_PARSE(app, argc, argv)
    if(!(*scanOpt || *restoreOpt)){
        std::cout << "Subcommand is obligatory, type --help for more information\n";
    }
    if(*scanOpt){
        if(*d){
            if (std::filesystem::exists(quarantineDir)) {
                if(!std::filesystem::exists(quarantineDatabase)){
                    std::ofstream file(quarantineDatabase,std::ios::out);
                    file.close();
                }
                std::unordered_set<std::string> hashDatabase = readDatabaseToUnorderedSet(hashDatabaseStr);
                std::vector<std::string> quarantineDatabaseDB = readQuarantineDatabase(quarantineDatabase);
                scan(scanFileName, hashDatabase, quarantineDatabaseDB);
            }
            else {
                std::filesystem::create_directory(quarantineDir);
                std::filesystem::permissions(quarantineDir, std::filesystem::perms::owner_all |
                                                            std::filesystem::perms::group_write |
                                                            std::filesystem::perms::group_read |
                                                            std::filesystem::perms::others_write |
                                                            std::filesystem::perms::others_read,
                                             std::filesystem::perm_options::replace);
                if (std::filesystem::is_directory(quarantineDir)) {
                    if(!std::filesystem::exists(quarantineDatabase)){
                        std::ofstream file(quarantineDatabase,std::ios::out);
                        file.close();
                    }
                    std::cout << "Successfully created quarantine directory in :" << quarantineDir << "\n";
                    std::unordered_set<std::string> hashDatabase = readDatabaseToUnorderedSet(hashDatabaseStr);
                    std::vector<std::string> quarantineDatabaseDB = readQuarantineDatabase(quarantineDatabase);
                    scan(scanFileName, hashDatabase, quarantineDatabaseDB);
                } else {
                    std::cerr << "Unable to create a quarantine directory in :" << quarantineDir << "\n";
                    return EXIT_FAILURE;
                }
            }
        }
    }
    if(*restoreOpt){
        std::vector<std::string> quarantineDatabaseDB = readQuarantineDatabase(quarantineDatabase);
        if(!restoreFromQuarantine(restoreFileName,quarantineDatabaseDB)){
            std::cerr << "No such file in quarantine database\n";
            return EXIT_FAILURE;
        }
        else {
            std::cout << "Successfully restored file: " << restoreFileName <<" from quarantine\n";
        }
    }
    return 0;
}

//TODO: Skanowanie /proc coś wywala czasami
//TODO: Zmienić opisy przy skanowaniu na sensowne
//TODO: Testowanie
//TODO: Zamiana stringow w tablice uint64 i dopisanie funkcji hashujacej


