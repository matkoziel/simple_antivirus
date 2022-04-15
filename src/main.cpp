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
std::vector<std::string> quarantineDatabaseDB;

// Safe program termination
void TerminateProgram(int inputSignal){
    char input;
    signal(inputSignal,SIG_IGN);
    std::cout << "\nDo you really want to quit? [Y/N]\n";
    std::cin.read(&input,sizeof(char));
    if(input=='y'||input=='Y'||input=='T'||input=='t'){
        if(!quarantineDatabaseDB.empty()){
            MakeQuarantineDatabaseAvailable();
            SaveToQuarantineDatabase(quarantineDatabaseDB);
        }
        MakeQuarantineDatabaseUnavailable();
        throw std::runtime_error("EXIT!");
    }
    else{
        signal(SIGINT, TerminateProgram);
    }
}

int main(int argc, char **argv) {
    
    quarantineDir= getenv("HOME");
    quarantineDir=quarantineDir.append("/.quarantine");
    quarantineDatabase=quarantineDir +"/.quarantine_database.csv";
    quarantineDatabaseDB={};
    try{
        signal(SIGINT, TerminateProgram);
        CLI::App app{"Simple antivirus"};

        auto scanOpt=app.add_subcommand("scan", "Scan given path");
        auto restoreOpt=app.add_subcommand("restore", "Restore file from quarantine");
        auto showOpt = app.add_subcommand("show", "Show quarantined files");

        std::string scanFileName{};
        scanOpt -> add_option("--path",scanFileName,"Path to file/directory we want to Scan")
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
                hashDatabaseStr="data/example_database.csv";
                try{
                    std::filesystem::exists(hashDatabaseStr);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
            }
            std::unordered_set<std::string> hashDatabase{};
            bool quarantineDirExist{};
            bool quarantineDatabaseExist{};
            MakeQuarantineDatabaseAvailable();                                                  // Opening database
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
                        std::ofstream file(quarantineDatabase, std::ios::out);      // Creates database file
                        file.close();
                    } catch (std::filesystem::filesystem_error const &ex) {
                        std::cerr << "Cannot create database in: " << quarantineDatabase << "\n";
                        return EXIT_FAILURE;
                    }
                }
                try {
                    hashDatabase = ReadDatabaseToUnorderedSet(hashDatabaseStr);
                    quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load databases from: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                MakeQuarantineDatabaseUnavailable();                    // Closes quarantine database
                try {
                    std::filesystem::path scanPath (scanFileName);
                    std::string pathString = std::filesystem::canonical(
                            scanPath.parent_path().append(
                                    scanPath.filename().u8string()));   // Creates fullpath name of file
                    Scan(pathString, hashDatabase, quarantineDatabaseDB);
                }
                catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot create canonical path of: "<< scanFileName<< "\n";
                    return EXIT_FAILURE;
                }
            }
            else {
                try {
                    std::filesystem::create_directory(quarantineDir);                       // Creates quarantine directory
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
                MakeQuarantineDatabaseAvailable();
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
                        hashDatabase = ReadDatabaseToUnorderedSet(hashDatabaseStr);
                        quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
                    }catch(std::filesystem::filesystem_error const& ex) {
                        std::cerr << "Cannot load databases from: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                        return EXIT_FAILURE;
                    }
                    MakeQuarantineDatabaseUnavailable();
                    try {
                        std::filesystem::path scanPath (scanFileName);
                        std::string pathString = std::filesystem::canonical(
                                scanPath.parent_path().append(
                                        scanPath.filename().u8string()));
                        Scan(pathString, hashDatabase, quarantineDatabaseDB);
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
            MakeQuarantineDatabaseAvailable();
            try {
                quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
            }catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Cannot load databases from: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                return EXIT_FAILURE;
            }
            MakeQuarantineDatabaseUnavailable();
            try {
                std::filesystem::path restorePath (restoreFileName);
                std::string fileName = restorePath.filename();
                std::string fullDirectoryPath = std::filesystem::canonical(
                        restorePath.parent_path());
                std::string pathString = fullDirectoryPath + "/" + fileName;        // Creating full path name of given file
                if(!RestoreFromQuarantine(pathString, quarantineDatabaseDB)){
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
            MakeQuarantineDatabaseAvailable();
            try{
                quarantineDirExist = std::filesystem::exists(quarantineDir);
                quarantineDatabaseExist =std::filesystem::exists(quarantineDatabase);
            }catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Permission denied: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                return EXIT_FAILURE;
            }
            if (quarantineDirExist && quarantineDatabaseExist) {
                try {
                    quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load database from: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                PrintQuarantineDatabase(quarantineDatabaseDB);
                MakeQuarantineDatabaseUnavailable();
            }
            else {
                std::cerr << "Quarantine database: " << quarantineDatabase << " does not exist!";
                return EXIT_FAILURE;
            }
        }
    }
    catch (std::runtime_error const &ex) {
        return EXIT_SUCCESS;
    }
}



