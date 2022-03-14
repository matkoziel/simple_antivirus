//
// Created by kozzi on 3/9/22.
//

#include "crypto_functions.h"

#include <openssl/sha.h>

#include <iostream>
#include <iomanip>
#include <fstream>

#define DEFAULT_INPUT_DATA_SIZE 1024*1024

std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (unsigned char i: hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) i;
    }
    return ss.str();
}

std::string sha256File(const char *fileName)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    FILE *inputFile = fopen (fileName, "rb");
    std::string result;
    if (!inputFile)
    {
        std::cerr << "Wystapił błąd, podany plik nie istnieje\n";
    }
    else
    {
        int bytes;
        unsigned char data[DEFAULT_INPUT_DATA_SIZE];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        while ((bytes = fread(data,1,DEFAULT_INPUT_DATA_SIZE,inputFile)) != 0) {
            SHA256_Update(&sha256, data, bytes);
        }
        SHA256_Final(hash, &sha256);
        fclose(inputFile);
    }
    std::stringstream temp;
    for (unsigned char hex : hash){
        temp << std::hex << std::setw(2) << std::setfill('0') << (int) hex;
    }
    return temp.str();
}








