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


void analyzingFile(const std::string& pathString, std::unordered_set<std::string>& hashes, std::vector<std::string>& quarantineDB) {
    std::string hash{};
    std::cout << "Analyzing: " << pathString;
    try {
        hash = md5FileCryptoPP(pathString);
    }
    catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
    }
//    std::cout << ", hash : " << hash << "\n";
    std:: cout << ", hash : " << hash <<"\t\r" << std::flush;

    if (checkFile(hash, hashes)) {
        std::cout << "Found potentially malicious file: " << pathString << "\n";
        quarantineAFile(pathString, quarantineDB);
        try {
            std::filesystem::remove(pathString);
        }
        catch (std::filesystem::filesystem_error const &ex) {
            std::cerr << ex.code().message() << ": " << pathString << "\n";
        }
    }
}
void scanAllFilesInDirectory(const std::string& path, std::unordered_set<std::string>& hashes,std::vector<std::string>& quarantineDB) {
    int nonRegularFiles=0;
    int symlinks=0;
    long long regularFiles=0;
    for (const std::filesystem::path &directoryIteratorPath : std::filesystem::recursive_directory_iterator(path,std::filesystem::directory_options::skip_permission_denied)) {
        if ((checkFileSystem(directoryIteratorPath))) {
            if (std::filesystem::status(directoryIteratorPath).type() == std::filesystem::file_type::regular) {
                if (std::filesystem::is_symlink(directoryIteratorPath)) {
                    std::string pathString{};
                    try {
                        pathString = std::filesystem::canonical(
                                directoryIteratorPath.parent_path().append(
                                        directoryIteratorPath.filename().u8string()));
                    }
                    catch(std::filesystem::filesystem_error const& ex) {
//                            std::cerr << "Cannot create canonical path of: "<< directoryIteratorPath<< "\n";
                        continue;
                    }
                    if (std::filesystem::status(pathString).type() == std::filesystem::file_type::regular) {
                        if (!std::filesystem::is_empty(pathString)) {
                            analyzingFile(pathString, hashes,quarantineDB);
                            symlinks++;
                        }
                    } else {
//                            std::cout << "Resolved symlink "<<pathString<<"is not regular file\n";
                        nonRegularFiles++;
                    }

                } else {
                    std::string pathString{directoryIteratorPath.u8string()};
                    if (!std::filesystem::is_empty(pathString)) {
                        analyzingFile(pathString, hashes,quarantineDB);
                        regularFiles++;
                    }
                }
            } else {
//                    std::cout << "File: "<< directoryIteratorPath <<" is not a regular file\n";
                nonRegularFiles++;
            }
        } else {
            nonRegularFiles++;
        }
    }
    std::cout << "\nScanned: \n";
    std::cout << "Regular files: " << regularFiles << "\n";
    std::cout << "Non regular files: " << nonRegularFiles << "\n";
    std::cout << "Symlinks: " << symlinks << "\n";
}

void scan(const std::string& path, std::unordered_set<std::string>& hashes,std::vector<std::string>& quarantineDB){
    std::cout << "Work in progress...\n";
    bool isDirectory = std::filesystem::is_directory(path);
    if(isDirectory){
        scanAllFilesInDirectory(path,hashes,quarantineDB);
    }
    else {
        const std::filesystem::path &directoryIteratorPath(path);
        if ((checkFileSystem(directoryIteratorPath))) {
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
                            analyzingFile(pathString, hashes,quarantineDB);
                        }
                    } else {
                        std::cout << "Resolved symlink "<<pathString<<"is not regular file\n";
                    }

                } else {
                    std::string pathString{directoryIteratorPath.u8string()};
                    if (!std::filesystem::is_empty(pathString)) {
                        analyzingFile(pathString, hashes,quarantineDB);
                    }
                }
            } else {
                std::cout << "File: "<< directoryIteratorPath <<" is not a regular file\n";
            }
        } else std::cout << "File: "<< directoryIteratorPath << " cannot be read due to filesystem problems\n";
    }
}