//
// Created by kozzi on 3/9/22.
//

#include "crypto_functions.h"

#include <openssl/md5.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>

#define DEFAULT_INPUT_DATA_SIZE 1024

std::string md5(const std::string& str) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, str.c_str(), str.size());
    MD5_Final(hash, &md5);
    std::stringstream ss;
    for (unsigned char hex: hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hex;
    }
    return ss.str();
}

std::string md5File(const char *fileName) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    FILE *inputFile = fopen (fileName, "rb");
    std::string result;
    if (!inputFile) {
        std::cerr << "Error, file: "<<fileName<<" doesn't exist";
    }
    else {
        int bytes;
        unsigned char data[DEFAULT_INPUT_DATA_SIZE];
        MD5_CTX md5;
        MD5_Init(&md5);
        while (inputFile && (bytes = fread(data,1,DEFAULT_INPUT_DATA_SIZE,inputFile)) != 0) {
            MD5_Update(&md5, data, bytes);
        }
        MD5_Final(hash, &md5);
        fclose(inputFile);
    }
    std::stringstream temp;
    for (unsigned char hex : hash){
        temp << std::hex << std::setw(2) << std::setfill('0') << (int) hex;
    }
    return temp.str();
}








