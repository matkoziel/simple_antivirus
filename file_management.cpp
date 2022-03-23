//
// Created by kozzi on 3/9/22.
//

#include "file_management.h"
#include "crypto_functions.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <unordered_set>
#include <queue>
#include <cstring>

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

void appendToHashDatabase(const std::string& input, const std::string& path) {
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
            std::cout << "Successfully created quarantine directoryin :"<< quarantineDir << "\n";
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

void scanPath(const std::string& path) {
    std::vector<std::string> files = getAllFilesInDirectory(path);
    std::unordered_set<std::string> hashes = readDatabaseToUnorderedSet(DATABASE_PATH);
    auto itr = std::find(files.begin(), files.end(), quarantineDir);
    if (itr != files.end()) files.erase(itr);
    std::cout << "Total files: " << files.size() << "\n";
    for (const std::string& file : files) {
//        std::cout << "Scanning: " << file << "\n";
        char *filePointer = const_cast<char*>(file.c_str());
        std::string fileHash = md5File(filePointer);
        if (findInUnorderedSet(fileHash, hashes)) {
            std::cout << "File "<< file << " is in hash database, potential virus!!!!\n";
            if (std::filesystem::is_symlink(file)) {
                followMaliciousSymlink(file);
            }
            else {
                quarantineAFile(file);
            }
        }
    }
}

std::vector<std::string> getAllFilesInDirectory(const std::string& path) {
    std::vector<std::string> result;
    int nonRegularFiles=0;
    int symlinks=0;
    long long regularFiles=0;
    for (const std::filesystem::path& dir : std::filesystem::recursive_directory_iterator(path,std::filesystem::directory_options::skip_permission_denied)) {
        if(std::filesystem::status(dir).type() == std::filesystem::file_type::regular) {
            if(std::filesystem::is_symlink(dir)) {
                std::string pathString = std::filesystem::canonical(dir.parent_path().append(dir.filename().u8string()));
                std::cout << "Analyzing: " << pathString;
                char *filePointer = const_cast<char*>(pathString.c_str());
                std:: cout << ", hash : "<<md5File(filePointer)<<"\t\r" << std::flush;
//            result.push_back(pathString);
                symlinks++;
            }
            else {
                std::string pathString{dir.u8string()};
                std::cout << "Analyzing: " << pathString;
                char *filePointer = const_cast<char*>(pathString.c_str());
                std:: cout << ", hash : "<<md5File(filePointer)<<"\t\r" << std::flush;
//            result.push_back(pathString);
                regularFiles++;
            }
        }
        else {
            nonRegularFiles++;
        }
    }
    std::cout << "Regular files: "<< regularFiles << "\n";
    std::cout << "Non regular files: "<< nonRegularFiles << "\n";
    std::cout << "Symlinks: "<< symlinks << "\n";
    return result;
}
