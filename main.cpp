#include "file_management.h"
#include "crypto_functions.h"


#include <iostream>
#include <vector>
#include <filesystem>

#define DATABASE_PATH "/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data/database.csv"
#define QUARANTINE_DIR "/.quarantine"

const std::string homeDir= getenv("HOME");

void scanPath(const std::string& path){
    std::vector<std::string> files = getAllFilesInDirectory(path);
    std::vector<std::string> hashes = readDatabase(DATABASE_PATH);
    for (const std::string& file : files){
        char *filePointer = const_cast<char*>(file.c_str());
        std::string fileHash = sha256File(filePointer);
//        appendToFile(fileHash, DATABASE_PATH);
        for(const std::string& hash : hashes){
            if(fileHash == hash){
                std::cout << "File in hash database, potential virus\n";
            }
        }
    }
}

void moveAndRemovePermissions(const std::string& path)
{
    std::string fullPath;
    fullPath.append(homeDir);
    fullPath.append(QUARANTINE_DIR);
    fullPath.append("/");
    fullPath.append(std::filesystem::path(path).filename());
    std::cout << "Moved to: " << fullPath << "\n";
    if(moveFile(path,fullPath)){
        std::filesystem::permissions(fullPath,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                              std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                              std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
    }
    else{
        std::cerr << "Error occurred, could not move file\n";
    }
}

void quarantineAFile(const std::string& path)
{
    //TODO: Check if directory exists, if not, create one (should be hidden)
    std::string quarantinePath = homeDir;
    quarantinePath.append(QUARANTINE_DIR);
    if (std::filesystem::is_directory(quarantinePath))
    {
        std::cout << "Directory exists\n";
        moveAndRemovePermissions(path);
    }
    else
    {
        std::filesystem::create_directory(quarantinePath);
        std::filesystem::permissions(quarantinePath,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                              std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                              std::filesystem::perms::others_read | std::filesystem::perms::others_write,
                                              std::filesystem::perm_options::replace);
        if(std::filesystem::is_directory(quarantinePath))
        {
            std::cout << "Successfully created quarantine directory\n";
            moveAndRemovePermissions(path);
        }
        else std::cout << "Unable to create a quarantine directory\n";

    }

    //TODO: Move a file to this directory
    //TODO: Remove execute privileges for everyone
}

int main()
{
//    scanPath("/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data");
//    moveFile("/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data/test_data_moved.txt","/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/test_data_moved.txt");
//    std::string fullPath;
//    fullPath.append(QUARANTINE_PATH);
//    fullPath.append("/");
//    fullPath.append(std::filesystem::path("/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data/test_data_moved.txt").filename());
//    std::cout << fullPath << "\n";
    quarantineAFile("/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data/test.py");


    return 0;
}
