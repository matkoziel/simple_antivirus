#include "file_management.h"
#include "crypto_functions.h"

#include <iostream>
#include <vector>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <queue>

#define DATABASE_PATH "/home/kozzi/CLionProjects/simple_antivirus/data/database.csv"

const static std::string quarantineDir = strcat(getenv("HOME"), "/.quarantine");

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

int main() {
//    std::cout << quarantineDir << "\n";
//    scanPath("/home/kozzi");
//    std::vector<std::string> tempVec;
//    tempVec.push_back(quarantineDir);
//    for (auto a : getAllFilesInDirectory("/home/kozzi/CLionProjects/simple_antivirus/data")){
//        std::cout << a << "\n";
//    }
    std::vector<std::string> temp = getAllFilesInDirectory("/usr");
//    for (std::string b : temp ){
//        std::cout << b << "\n";
//    }
    return 0;
}

//TODO: Linki(done), pliki specjalne (partialy done)
//TODO: CLI
//TODO: Duże pliki (kcore)

