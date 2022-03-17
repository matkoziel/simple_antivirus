#include "file_management.h"
#include "crypto_functions.h"

#include <iostream>
#include <vector>
#include <filesystem>

#define DATABASE_PATH "/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data/database.csv"
#define QUARANTINE_DIR "/home/.quarantine"

void moveAndRemovePermissions(const std::string& path) {
    std::string fullPath;
    fullPath.append(QUARANTINE_DIR);
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

    if (std::filesystem::is_directory(QUARANTINE_DIR)) {
        std::cout << "Quarantine directory exists\n";
        moveAndRemovePermissions(path);
    }
    else {
        std::filesystem::create_directory(QUARANTINE_DIR);
        std::filesystem::permissions(QUARANTINE_DIR,std::filesystem::perms::owner_all |
                                                    std::filesystem::perms::group_write | std::filesystem::perms::group_read |
                                                    std::filesystem::perms::others_write | std::filesystem::perms::others_read
                                                    ,std::filesystem::perm_options::replace);
        if(std::filesystem::is_directory(QUARANTINE_DIR)) {
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
    for (const std::string& file : files) {
        char *filePointer = const_cast<char*>(file.c_str());
        std::string fileHash = md5File(filePointer);
        unsigned long count = hashes.count(fileHash);
        if (count > 0) {
            std::cout << "File "<< file << " is in hash database, potential virus!!!!\n";
            quarantineAFile(file);
        }
    }
}

int main() {
    scanPath("/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data");
    return 0;
}
