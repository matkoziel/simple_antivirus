//
// Created by kozzi on 3/9/22.
//

#include "../headers/file_management.h"
#include "../headers/crypto_functions.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <unordered_set>
#include <queue>
#include <cstring>

#include<stdio.h>
#include<sys/stat.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/vfs.h>


#define DATABASE_PATH "/home/kozzi/CLionProjects/simple_antivirus/data/database.csv"

extern const std::string quarantineDir = strcat(getenv("HOME"), "/.quarantine");

bool findInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet) {
    return unorderedSet.find(value) != unorderedSet.end();
}

std::string renameFileToAvoidConflicts(const std::string& path) {
    std::string temp = path;
    temp.append("_0");
    while(std::filesystem::exists(temp)) {
        int index = temp.find_last_of("_");
        int newNumber = std::stoi(temp.substr(index+1,temp.size()));
        temp = temp.substr(0,index+1).append(std::to_string(newNumber+1));
    }
    return temp;
}

bool moveFile(const std::string& from, const std::string& to) {
    if(!std::filesystem::exists(from)) {
        std::cerr << "No such file! : " << from << "\n";
        return false;
    }
    else {
        std::filesystem::rename(from,to);
        if(!std::filesystem::exists(from)) {
            return true;
        }
        else {
            std::cerr << "Error occurred, could not move file : " << from <<" to: " << to << "\n";
            return false;
        }
    }
}

void appendToDatabase(const std::string& input, const std::string& path) {
    const char separator = '\n';
    std::ofstream outputFile;
    outputFile.open(path, std::ios_base::app);
    if (!outputFile) {
        std::cerr << "Error, cannot load database from: " << path << "\n";
    }
    else {
        outputFile << input + separator;
    }
    outputFile.close();
}

std::unordered_set<std::string> readDatabaseToUnorderedSet(const std::string& path) {
    std::unordered_set<std::string> output;
    std::ifstream inputFile(path,std::ios::out);
    if (!inputFile) {
        std::cerr << "Error, cannot load database from: " << path << "\n";
    }
    else {
        std::string temp;
        while(getline(inputFile, temp)) {
            output.insert(temp);
        }
    }
    inputFile.close();
    return output;
}

void moveAndRemovePermissions(const std::string& path) {
    std::string fullPath;
    fullPath.append(quarantineDir);
    fullPath.append("/");
    fullPath.append("malicious_file");
//    fullPath.append(std::filesystem::path(path).filename());
    fullPath = renameFileToAvoidConflicts(fullPath);
    if(moveFile(path,fullPath)) {
        std::filesystem::permissions(fullPath,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                              std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                              std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
        std::cout << "File " << path << " moved to: " << fullPath << "\n";
    }
    else {
//        std::cerr << "Error occurred, could not move file : " << path <<" to: " << fullPath << "\n";
    }
}

void quarantineAFile(const std::string& path) {

    if (std::filesystem::is_directory(quarantineDir)) {
        moveAndRemovePermissions(path);
    }
    else {
        std::filesystem::create_directory(quarantineDir);
        std::filesystem::permissions(quarantineDir,std::filesystem::perms::owner_all |
                                                   std::filesystem::perms::group_write | std::filesystem::perms::group_read |
                                                   std::filesystem::perms::others_write | std::filesystem::perms::others_read
                ,std::filesystem::perm_options::replace);
        if(std::filesystem::is_directory(quarantineDir)) {
            std::cout << "Successfully created quarantine directory in :"<< quarantineDir << "\n";
            moveAndRemovePermissions(path);
        }
        else {
            std::cout << "Unable to create a quarantine directory in :"<< quarantineDir << "\n";
        }

    }
}

void followMaliciousSymlink (const std::string& path) {
    std::queue<std::string> fifo;
    std::string tempFile = path;
    fifo.push(tempFile);
    do {
        fifo.push(tempFile);
        tempFile = std::filesystem::read_symlink(tempFile);
    }
    while (std::filesystem::is_symlink(tempFile));
    fifo.push(tempFile);
    while (fifo.size() > 1) {
        std::filesystem::remove(fifo.front());
        fifo.pop();
    }
    quarantineAFile(fifo.front());
    fifo.pop();
}

bool checkFile(const std::string& hash, const std::unordered_set<std::string>& hashes) {
    return findInUnorderedSet(hash, hashes);
}

void analyzingFile(const std::string& pathString, const std::unordered_set<std::string>& hashes) {
    try {
        std::string hash = md5FileCryptoPP(pathString);
        std::cout << "Analyzing: " << pathString;
        std:: cout << ", hash : " << hash << "\n";
//        std:: cout << ", hash : " << hash << "\t\r" << std::flush;
        if (checkFile(hash, hashes)) {
            std::cout << "Found potentially malicious file: " << pathString << "\n";
//        quarantineAFile(pathString);
        }
    }catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
    }

}

int checkFileSystem(const std::string& path) {
    struct statfs sb{};
    if ((statfs(path.c_str(), &sb)) == 0) {
        if (sb.f_type == 40864) return -1;
        else return 1;
    } else return -1;
}

AESCryptoData findInQuarantine(const std::string& prevPath, const std::unordered_set<std::string>& quarantineDatabase){
    AESCryptoData aes{};
    std::array<std::string,4> quarantineData{};
    for (std::string line : quarantineDatabase){
        int start = 0;
        int delimiter = line.find_first_of(",");
        std::string temp = prevPath.substr(start,delimiter);
        if (temp == prevPath){
            quarantineData[0]=temp;
            for (int i = 1; i<4; i++){
                line = line.erase(start,delimiter+1);
                delimiter = line.find_first_of(",");
                quarantineData[i]=line.substr(start,delimiter);
                std::cout << quarantineData[i]<<"\n";
            }
            break;
        }
    }
    aes.prevName=quarantineData[0];
    aes.inQuarantineName=quarantineData[1];
    aes.keyString=quarantineData[2];
    aes.ivString=quarantineData[3];
    return aes;
}

void addToQuarantineDatabase(const AESCryptoData& aes, const std::string& databasePath) {
    std::stringstream ss;
    ss<< aes.prevName << "," << aes.inQuarantineName << "," << aes.keyString << "," <<aes.ivString;
    appendToDatabase(ss.str(),databasePath);
}

void restoreFromQuarantine(){}







void scanAllFilesInDirectory(const std::string& path) {
    std::unordered_set<std::string> hashes = readDatabaseToUnorderedSet(DATABASE_PATH);
    int nonRegularFiles=0;
    int symlinks=0;
    long long regularFiles=0;
        for (const std::filesystem::path &directoryIteratorPath : std::filesystem::recursive_directory_iterator(path,std::filesystem::directory_options::skip_permission_denied)) {
            if ((checkFileSystem(directoryIteratorPath) == 1) && exists(directoryIteratorPath)) {
                if (std::filesystem::status(directoryIteratorPath).type() == std::filesystem::file_type::regular) {
                    if (std::filesystem::is_symlink(directoryIteratorPath)) {
                        std::string pathString = std::filesystem::canonical(
                                directoryIteratorPath.parent_path().append(
                                        directoryIteratorPath.filename().u8string()));
                        if (std::filesystem::status(pathString).type() == std::filesystem::file_type::regular) {
                            if (!std::filesystem::is_empty(pathString)) {
                                analyzingFile(pathString, hashes);
                                symlinks++;
                            }
                        } else {
                            nonRegularFiles++;
                        }

                    } else {
                        std::string pathString{directoryIteratorPath.u8string()};
                        if (!std::filesystem::is_empty(pathString)) {
                            analyzingFile(pathString, hashes);
                            regularFiles++;
                        }
                    }
                } else {
                    nonRegularFiles++;
                }
            } else nonRegularFiles++;
        }
        std::cout << "Scanned: \n";
        std::cout << "Regular files: " << regularFiles << "\n";
        std::cout << "Non regular files: " << nonRegularFiles << "\n";
        std::cout << "Symlinks: " << symlinks << "\n";
}

void scan(const std::string& path){
    try {
        bool isDirectory = std::filesystem::is_directory(path);
        if(isDirectory){
            scanAllFilesInDirectory(path);
        }
        else {
            std::unordered_set<std::string> hashes = readDatabaseToUnorderedSet(DATABASE_PATH);
            const std::filesystem::path &directoryIteratorPath(path);
            if ((checkFileSystem(directoryIteratorPath) == 1) && exists(directoryIteratorPath)) {
                if (std::filesystem::status(directoryIteratorPath).type() == std::filesystem::file_type::regular) {
                    if (std::filesystem::is_symlink(directoryIteratorPath)) {
                        std::string pathString = std::filesystem::canonical(
                                directoryIteratorPath.parent_path().append(
                                        directoryIteratorPath.filename().u8string()));
                        if (std::filesystem::status(pathString).type() == std::filesystem::file_type::regular) {
                            if (!std::filesystem::is_empty(pathString)) {
                                analyzingFile(pathString, hashes);
                            }
                        } else {
                            std::cout << "Failed\n";
                        }

                    } else {
                        std::string pathString{directoryIteratorPath.u8string()};
                        if (!std::filesystem::is_empty(pathString)) {
                            analyzingFile(pathString, hashes);
                        }
                    }
                } else {
                    std::cout << "Failed\n";
                }
            } else std::cout << "Failed\n";
        }
    }
    catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << ex.code().message() <<": "<< path<< "\n";
    }
}


