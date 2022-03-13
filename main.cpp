#include "file_management.h"
#include "crypto_functions.h"

#include <openssl/sha.h>

#include <iostream>
#include <vector>
#include <sys/stat.h>

#define DATABASE_PATH "/home/kozzi/CLionProjects/simple_antivirus/data/database.csv"

void scanPath(const std::string& path){
    std::vector<std::string> files = getAllFilesInDirectory(path);
    std::vector<std::string> hashes = readDatabase(DATABASE_PATH);
    for (const std::string& file : files){
        char *filePointer = const_cast<char*>(file.c_str());
        std::string fileHash = sha256File(filePointer);
        appendToFile(fileHash, DATABASE_PATH);
        for(const std::string& hash : hashes){
            if(fileHash == hash){
                std::cout << "File in hash database, potential virus\n";
            }
        }
    }
}
void quarantineAFile(const std::string& path)
{
    //TODO: Check if directory exists, if not, create one (should be hidden)
    //TODO: Move a file to this directory
    //TODO: Remove execute privileges for everyone
}
int main()
{
    scanPath("/home/kozzi/CLionProjects/simple_antivirus/data");

    return 0;
}
