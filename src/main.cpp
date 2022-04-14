//
// Created by kozzi on 3/9/22.
//

#include "../headers/main.h"

#include <csignal>

#include <iostream>

#include "../libs/CLI11.hpp"

#include "../headers/crypto_functions.h"
#include "../headers/file_functions.h"
#include "../headers/scan.h"

std::string quarantineDir;
std::string quarantineDatabase;

void terminateProgram(int inputSignal){
    char input;
    signal(inputSignal,SIG_IGN);
    std::cout << "\nDo you really want to quit? [Y/N]\n";
    std::cin.read(&input,sizeof(char));
    if(input=='y'||input=='Y'||input=='T'||input=='t'){
        throw std::runtime_error("EXIT!");
    }
    else{
        signal(SIGINT,terminateProgram);
    }
}

int main(int argc, char **argv) {
    
    quarantineDir= getenv("HOME");
    quarantineDir=quarantineDir.append("/.quarantine");
    quarantineDatabase=quarantineDir +"/.quarantine_database.csv";
    std::vector<std::string> quarantineDatabaseDB{};
    try{
        signal(SIGINT,terminateProgram);
        CLI::App app{"Simple antivirus"};

        auto scanOpt=app.add_subcommand("scan", "Scan given path");
        auto restoreOpt=app.add_subcommand("restore", "Restore file from quarantine");
        auto showOpt = app.add_subcommand("show", "Show quarantined files");

        std::string scanFileName{};
        scanOpt -> add_option("--path",scanFileName,"Path to file/directory we want to scan")
                ->required()
                ->check(CLI::ExistingPath);

        std::string hashDatabaseStr{};
        auto d = scanOpt -> add_option("--d",hashDatabaseStr,"Path to hash database")
                ->check(CLI::ExistingPath);

        std::string restoreFileName{};
        restoreOpt -> add_option("--path",restoreFileName,"Path to file we want to restore");

        CLI11_PARSE(app, argc, argv)
        if(!(*scanOpt || *restoreOpt || *showOpt)){
            std::cout << "Subcommand is obligatory, type --help for more information\n";
        }
        if(*scanOpt){
            if(!*d) {
                hashDatabaseStr="../data/example_database.csv";
            }
            std::unordered_set<std::string> hashDatabase{};
            bool quarantineDirExist{};
            bool quarantineDatabaseExist{};
            makeQuarantineDatabaseAvailable();
            try{
                quarantineDirExist = std::filesystem::exists(quarantineDir);
                quarantineDatabaseExist =std::filesystem::exists(quarantineDatabase);
            }catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Permission denied: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                return EXIT_FAILURE;
            }
            if (quarantineDirExist) {
                if (!quarantineDatabaseExist){
                    try {
                        std::ofstream file(quarantineDatabase, std::ios::out);
                        file.close();
                    } catch (std::filesystem::filesystem_error const &ex) {
                        std::cerr << "Cannot create database in: " << quarantineDatabase << "\n";
                        return EXIT_FAILURE;
                    }
                }
                try {
                    hashDatabase = readDatabaseToUnorderedSet(hashDatabaseStr);
                    quarantineDatabaseDB = readQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load databases from: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                makeQuarantineDatabaseUnavailable();
                try {
                    std::filesystem::path scanPath (scanFileName);
                    std::string pathString = std::filesystem::canonical(
                            scanPath.parent_path().append(
                                    scanPath.filename().u8string()));
                    scan(pathString, hashDatabase, quarantineDatabaseDB);
                }
                catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot create canonical path of: "<< scanFileName<< "\n";
                    return EXIT_FAILURE;
                }
            }
            else {
                try {
                    std::filesystem::create_directory(quarantineDir);
                    std::filesystem::permissions(quarantineDir, std::filesystem::perms::owner_all |
                                                                std::filesystem::perms::group_write |
                                                                std::filesystem::perms::group_read |
                                                                std::filesystem::perms::others_write |
                                                                std::filesystem::perms::others_read,
                                                 std::filesystem::perm_options::replace);
                }catch(std::filesystem::filesystem_error const& ex){
                    std::cerr << "Cannot create directory in: "<< scanFileName<< "\n";
                    return EXIT_FAILURE;
                }
                makeQuarantineDatabaseAvailable();
                try{
                    quarantineDirExist = std::filesystem::exists(quarantineDir);
                    quarantineDatabaseExist =std::filesystem::exists(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Permission denied: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                if (quarantineDirExist) {
                    if(!quarantineDatabaseExist){
                        std::ofstream file(quarantineDatabase,std::ios::out);
                        file.close();
                    }
                    std::cout << "Successfully created quarantine directory in :" << quarantineDir << "\n";
                    try {
                        hashDatabase = readDatabaseToUnorderedSet(hashDatabaseStr);
                        quarantineDatabaseDB = readQuarantineDatabase(quarantineDatabase);
                    }catch(std::filesystem::filesystem_error const& ex) {
                        std::cerr << "Cannot load databases from: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                        return EXIT_FAILURE;
                    }
                    makeQuarantineDatabaseUnavailable();
                    try {
                        std::filesystem::path scanPath (scanFileName);
                        std::string pathString = std::filesystem::canonical(
                                scanPath.parent_path().append(
                                        scanPath.filename().u8string()));
                        scan(pathString, hashDatabase, quarantineDatabaseDB);
                    }
                    catch(std::filesystem::filesystem_error const& ex) {
                        std::cerr << "Cannot create canonical path of: "<< scanFileName<< "\n";
                        return EXIT_FAILURE;
                    }
                } else {
                    std::cerr << "Unable to create a quarantine directory in :" << quarantineDir << "\n";
                    return EXIT_FAILURE;
                }
            }
        }
        if(*restoreOpt){
            makeQuarantineDatabaseAvailable();
            try {
                quarantineDatabaseDB = readQuarantineDatabase(quarantineDatabase);
            }catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Cannot load databases from: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                return EXIT_FAILURE;
            }
            makeQuarantineDatabaseUnavailable();
            try {
                std::filesystem::path restorePath (restoreFileName);
                std::string fileName = restorePath.filename();
                std::string fullDirectoryPath = std::filesystem::canonical(
                        restorePath.parent_path());
                std::string pathString = fullDirectoryPath + "/" + fileName;
                if(!restoreFromQuarantine(pathString,quarantineDatabaseDB)){
                    std::cerr << "No such file in quarantine database\n";
                    return EXIT_FAILURE;
                }
                else {
                    std::cout << "Successfully restored file: " << restoreFileName <<" from quarantine\n";
                }
            }
            catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Cannot create canonical path of: "<< restoreFileName<< "\n";
                std::cout << ex.what() << "\n";
                return EXIT_FAILURE;
            }
        }
        if(*showOpt){
            bool quarantineDirExist{};
            bool quarantineDatabaseExist{};
            makeQuarantineDatabaseAvailable();
            try{
                quarantineDirExist = std::filesystem::exists(quarantineDir);
                quarantineDatabaseExist =std::filesystem::exists(quarantineDatabase);
            }catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Permission denied: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                return EXIT_FAILURE;
            }
            if (quarantineDirExist && quarantineDatabaseExist) {
                try {
                    quarantineDatabaseDB = readQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load database from: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                printQuarantineDatabase(quarantineDatabaseDB);
                makeQuarantineDatabaseUnavailable();
            }
            else {
                std::cerr << "Quarantine database: " << quarantineDatabase << " does not exist!";
                return EXIT_FAILURE;
            }
        }
    }
    catch (std::runtime_error const &ex){
        if(!quarantineDatabaseDB.empty()){
            saveToQuarantineDatabase(quarantineDatabaseDB);
        }
        makeQuarantineDatabaseUnavailable();
        return EXIT_SUCCESS;
    }
    return EXIT_SUCCESS;
}

//TODO: Testowanie
//TODO: Czyszczenie linii


