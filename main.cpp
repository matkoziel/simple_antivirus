#include "file_management.h"
#include "crypto_functions.h"

#include <openssl/sha.h>

#include <iostream>
#include <vector>

int main()
{
//     std::vector<unsigned char> res = readFileBinary("/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data/bmp_test.bmp");
//     for (unsigned char re : res)
//     {
//         std::cout << std::hex << (re & 0xFF) << " ";
//     }
//    std::string resString = readFileToString("/home/kozzi/Projects/BSO/Antywirus/AntywirusCLion/data/test_data.txt");
//    std::cout << resString << "\n";
    // appendToFile("Dane testowe 1", "/home/kozzi/Studia/SEM4/BSO/Projekt/Antywirus/data/database.csv");
    // appendToFile("Dane testowe 2", "/home/kozzi/Studia/SEM4/BSO/Projekt/Antywirus/data/database.csv");
//    std::vector<std::string> res = getAllFilesInDirectory("/home/kozzi/Projects/BSO/Antywirus");
//    for (std::string a : res)
//    {
//        std::cout << a <<""<< typeid(a).name()<< "\n";
//    };
//    std::string something = "Chuj123";
//    std::string resHash = sha256(something);
//    std::cout << resHash <<"\n";
    unsigned char *res = sha256File("/home/kozzi/CLionProjects/BSO/Antywirus_Mateusz_Koziel/data/bmp_test.bmp");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        std::cout << res[i] << "\n";
    }
    return 0;
}
