#include "file_management.h"
#include "crypto_functions.h"

#include <iostream>
#include <vector>
#include <filesystem>
#include <cstring>
#include <algorithm>

#define DATABASE_PATH "/home/kozzi/CLionProjects/simple_antivirus/data/database.csv"

const static std::string quarantineDir = strcat(getenv("HOME"), "/.quarantine");

void moveAndRemovePermissions(const std::string& path) {
    std::string fullPath;
    fullPath.append(quarantineDir);
    fullPath.append("/");
    fullPath.append(std::filesystem::path(path).filename());
    if(moveFile(path,fullPath)) {
        std::filesystem::permissions(fullPath,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                              std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                              std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
        std::cout << "File " << path << " moved to: " << fullPath << "\n";
    }
    else {
        std::cerr << "Error occurred, could not move file\n";
    }
}

void quarantineAFile(const std::string& path) {

    if (std::filesystem::is_directory(quarantineDir)) {
        std::cout << "Quarantine directory exists\n";
        moveAndRemovePermissions(path);
    }
    else {
        std::filesystem::create_directory(quarantineDir);
        std::filesystem::permissions(quarantineDir,std::filesystem::perms::owner_all |
                                                    std::filesystem::perms::group_write | std::filesystem::perms::group_read |
                                                    std::filesystem::perms::others_write | std::filesystem::perms::others_read
                                                    ,std::filesystem::perm_options::replace);
        if(std::filesystem::is_directory(quarantineDir)) {
            std::cout << "Successfully created quarantine directory\n";
            moveAndRemovePermissions(path);
        }
        else {
            std::cout << "Unable to create a quarantine directory\n";
        }

    }
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
            quarantineAFile(file);
        }
    }
}

int main() {
//    std::cout << quarantineDir << "\n";
    scanPath("/home/kozzi");
//    std::vector<std::string> tempVec;
//    tempVec.push_back(quarantineDir);

    return 0;
}
