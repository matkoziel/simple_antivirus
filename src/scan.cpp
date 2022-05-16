//
// Created by kozzi on 14.04.2022.
//

#include "../headers/scan.h"

#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

#include <cryptopp/files.h>

#include "../headers/file_functions.h"
#include "../headers/main.h"

// Analyze given hash of given path with hashDatabaseDB database and gives feedback
void AnalyzingFile(const std::string& pathString, std::vector<std::string>& quarantinedList) {
    if(pathString.empty()) return;
    std::string hash{};
    std::cout << "Analyzing: " << pathString;
    try {
        hash = MD5FileCryptoPP(pathString);
    }
    catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
    }
    catch (CryptoPP::FileStore::ReadErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
    }
    std::cout << ", hash : " << hash << "\n";
    if (CheckFile(hash, hashDatabaseDB)) {
        std::cout << "Found potentially malicious file: " << pathString << "\n";
        quarantinedList.push_back(pathString);
        QuarantineAFile(pathString, quarantineDatabaseDB);                            // Quarantines a file
        try {
            std::filesystem::remove(pathString);                                    // Removes malicious file that was quarantined before
        }
        catch (std::filesystem::filesystem_error const &ex) {
            std::cerr << ex.code().message() << ": " << pathString << "\n";
        }
    }
}
// Analyze given hash of given path with hashDatabaseDB database and gives feedback
void AnalyzingFileWithoutFeedback(const std::string& pathString) {
    if(pathString.empty()) return;
    std::string hash{};
    try {
        hash = MD5FileCryptoPP(pathString);
        std::cout << "Analyzing: " << pathString<< ", hash : " << hash << "\n";
    }
    catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
    }
    catch (CryptoPP::FileStore::ReadErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
    }
    if (CheckFile(hash, hashDatabaseDB)) {
        std::cout << "Found potentially malicious file: " << pathString << "\n";
        QuarantineAFile(pathString, quarantineDatabaseDB);                            // Quarantines a file
        try {
            std::filesystem::remove(pathString);                                    // Removes malicious file that was quarantined before
        }
        catch (std::filesystem::filesystem_error const &ex) {
            std::cerr << ex.code().message() << ": " << pathString << "\n";
        }
    }
}

// Scanning directory tree
void ScanAllFilesInDirectory(const std::string& path) {
    int nonRegularFiles=0;
    int symlinks=0;
    long long regularFiles=0;
    int permissionDenied=0;
    std::vector<std::string> quarantined{};
    for (const std::filesystem::path &directoryIteratorPath : std::filesystem::recursive_directory_iterator(path,std::filesystem::directory_options::skip_permission_denied)) {
        bool boolPermissionDenied;
        try{
            boolPermissionDenied=std::filesystem::exists(directoryIteratorPath);    // Check if permission denied
        }
        catch (std::filesystem::filesystem_error const& ex){
            boolPermissionDenied = false;
        }
        if(boolPermissionDenied) {
            if ((CheckFileSystem(directoryIteratorPath))) {                       // Checks filesystem
                if (std::filesystem::status(directoryIteratorPath).type() == std::filesystem::file_type::regular) {  // Checks if file is regular
                    if (std::filesystem::is_symlink(directoryIteratorPath)) {       // Checks if is symlink
                        std::string pathString{};
                        try {
                            pathString = std::filesystem::canonical(                    // Generates absolute path of resolved symlink
                                    directoryIteratorPath.parent_path().append(
                                            directoryIteratorPath.filename().u8string()));
                        }
                        catch (std::filesystem::filesystem_error const &ex) {
                            continue;
                        }
                        try{
                            boolPermissionDenied=std::filesystem::exists(pathString);   // Checks if resolves symlink is available
                        }
                        catch (std::filesystem::filesystem_error const& ex){
                            boolPermissionDenied = false;
                        }
                        if(boolPermissionDenied) {
                            if (std::filesystem::status(pathString).type() == std::filesystem::file_type::regular) {    // Checks if resolved symlink is regular
                                if (!std::filesystem::is_empty(pathString)) {                                           // Checks if resolved symlink is empty
                                    AnalyzingFile(pathString, quarantined);
                                    symlinks++;
                                }
                            } else {
                                nonRegularFiles++;
                            }
                        }
                        else{
                            permissionDenied++;
                        }
                    } else {
                        std::string pathString=directoryIteratorPath.string();
                        if (!std::filesystem::is_empty(pathString)) {                           // Checks if file is not empty
                            AnalyzingFile(pathString, quarantined);
                            regularFiles++;
                        }
                    }
                } else {
                    nonRegularFiles++;
                }
            } else {
                nonRegularFiles++;
            }
        } else {
            permissionDenied++;
        }
    }
    std::cout << "\nScanned: \n";
    std::cout << "Regular files: " << regularFiles << "\n";
    std::cout << "Permission denied: " << permissionDenied << "\n";
    std::cout << "Non regular files: " << nonRegularFiles << "\n";
    std::cout << "Symlinks: " << symlinks << "\n";
    if(quarantined.empty()){
        std::cout << "No malicious files were found\n";
    }
    else{
        for(const std::string& file: quarantined){
            std::cout << "Found malicious file: "<< file <<" and was moved to quarantine\n";
        }
        std::cout << "Type ./simple_antivirus show for more details\n";
    }
}

// Checks if given path is directory or file, then analyzes.
void Scan(const std::string& path){
    std::cout << "Work in progress...\n";
    std::vector<std::string> quarantined{};
    bool isDirectory;
    try{
         isDirectory = std::filesystem::is_directory(path);
    }
    catch (std::filesystem::filesystem_error const &ex) {
        std::cerr << "Permission denied\n";
        return;
    }
    if(isDirectory){
        ScanAllFilesInDirectory(path);
    }
    else {
        const std::filesystem::path &directoryIteratorPath(path);
        if ((CheckFileSystem(directoryIteratorPath))) {
            if (std::filesystem::status(directoryIteratorPath).type() == std::filesystem::file_type::regular) {
                if (std::filesystem::is_symlink(directoryIteratorPath)) {
                    std::string pathString{};
                    try {
                        pathString = std::filesystem::canonical(
                                directoryIteratorPath.parent_path().append(
                                        directoryIteratorPath.filename().u8string()));
                    }
                    catch(std::filesystem::filesystem_error const& ex) {
                        std::cerr << "Cannot create canonical path of: "<< path<< "\n";
                        return;
                    }
                    if (std::filesystem::status(pathString).type() == std::filesystem::file_type::regular) {
                        if (!std::filesystem::is_empty(pathString)) {
                            AnalyzingFileWithoutFeedback(pathString);
                        }
                    } else {
                        std::cout << "Resolved symlink "<<pathString<<"is not regular file\n";
                    }

                } else {
                    std::string pathString{directoryIteratorPath.string()};
                    if (!std::filesystem::is_empty(pathString)) {
                        AnalyzingFileWithoutFeedback(pathString);
                    }
                }
            } else {
                std::cout << "File: "<< directoryIteratorPath <<" is not a regular file\n";
            }
        } else std::cout << "File: "<< directoryIteratorPath << " cannot be read due to filesystem problems\n";
        if(quarantined.empty()){
            std::cout << "No malicious files were found\n";
        }
        else{
            std::cout << "Found malicious file: "<< quarantined[0] <<" and was moved to quarantine\n";
            std::cout << "Type ./simple_antivirus show for more details\n";
        }
    }
}