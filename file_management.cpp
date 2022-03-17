//
// Created by kozzi on 3/9/22.
//

#include "file_management.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <unordered_set>

bool findInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet) {
    return unorderedSet.find(value) != unorderedSet.end();
}

std::string readFileToString(const std::string& path) {
    std::string output;
    std::ifstream inputFile(path);
    if (!inputFile) {
//        std::cerr << "Wysta\n";
    }
    else {
        output.assign((std::istreambuf_iterator<char>(inputFile)),std::istreambuf_iterator<char>());
    }
    inputFile.close();
    return output;
}

std::vector<std::string> readDatabase(const std::string& path) {
    std::vector<std::string> output;
    std::ifstream inputFile(path,std::ios::out);
    if (!inputFile) {
        std::cerr << "Error, cannot load database\n";
    }
    else {
        std::string temp;
        while(getline(inputFile, temp)) {
            output.push_back(temp);
        }
    }
    inputFile.close();
    return output;
}

std::vector<unsigned char> readFileBinary(const std::string& path) {
    std::vector<unsigned char> output;
    std::ifstream inputFile(path, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error, file does not exist\n";
    }
    else {
        output.assign((std::istreambuf_iterator<char>(inputFile)),std::istreambuf_iterator<char>());
    }
    inputFile.close();
    return output;
}

bool moveFile(const std::string& from, const std::string& to) {
    if(!std::filesystem::exists(from)) {
        std::cerr << "No such file!\n";
        return false;
    }
    else {
        std::filesystem::rename(from,to);
        if(!std::filesystem::exists(from)) {
            return true;
        }
        else {
            std::cerr << "Failed moving file\n";
            return false;
        }
    }
}

void appendToHashDatabase(const std::string& input, const std::string& path) {
    const char separator = '\n';
    std::ofstream outputFile;
    outputFile.open(path, std::ios_base::app);
    if (!outputFile) {
        std::cerr << "Cannot find database file!\n";
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
        std::cerr << "Error, cannot load database\n";
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

std::vector<std::string> getAllFilesInDirectory(const std::string& path) {
    std::vector<std::string> result;
    for (const std::filesystem::path& dir : std::filesystem::recursive_directory_iterator(path)) {
        std::string path_string{dir.u8string()};
        result.push_back(path_string);
    }
    return result;
}
