#include "file_management.h"
#include "crypto_functions.h"

#include <iostream>
#include <vector>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <queue>

extern const std::string quarantineDir;

int main() {
//    std::cout << quarantineDir << "\n";
//    scanPath("/home/kozzi");
//    std::vector<std::string> tempVec;
//    tempVec.push_back(quarantineDir);
//    for (auto a : getAllFilesInDirectory("/home/kozzi/CLionProjects/simple_antivirus/data")){
//        std::cout << a << "\n";
//    }
    std::vector<std::string> temp = getAllFilesInDirectory("/usr/bin");
//    for (std::string b : temp ){
//        std::cout << b << ": " << std::filesystem::file_size(b) <<"\n";
//    }
//    std::filesystem::path symlink = std::filesystem::path("/home/kozzi/CLionProjects/BSO/simple_antivirus/link1");
//    std::filesystem::path temp = std::filesystem::read_symlink(symlink);
//    std::cout << std::filesystem::is_symlink(symlink) << "\n";
//    std::cout << symlink.parent_path() << "\n";
    std::cout << quarantineDir << "\n";
//    std::cout << symlink.parent_path().append(temp.string()) << "\n";
//    std::cout << std::filesystem::canonical(symlink.parent_path().append(temp.string())) << "\n";
    return 0;
}

//TODO: Linki(done), pliki specjalne (partialy done)
//TODO: CLI
//TODO: Duże pliki (kcore)

