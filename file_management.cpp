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

std::string renameFileToAvoidConflicts(const std::string& path) {
    std::string temp = path;
    temp.append("_0");
    while(std::filesystem::exists(temp)) {
        int index = temp.find_last_of("_");
        int newNumber = std::stoi(temp.substr(index+1,temp.size()));
        temp = temp.substr(0,index+1).append(std::to_string(newNumber+1));
    }
    return temp;
}

std::string readFileToString(const std::string& path) {
    std::string output;
    std::ifstream inputFile(path);
    if (!inputFile) {
        std::cerr << "Error, cannot open file\n";
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
        std::cerr << "No such file! : " << from << "\n";
        return false;
    }
    else {
        std::filesystem::rename(from,to);
        if(!std::filesystem::exists(from)) {
            return true;
        }
        else {
            std::cerr << "Error occurred, could not move file : " << from <<" to: " << to << "\n";
            return false;
        }
    }
}

void appendToHashDatabase(const std::string& input, const std::string& path) {
    const char separator = '\n';
    std::ofstream outputFile;
    outputFile.open(path, std::ios_base::app);
    if (!outputFile) {
        std::cerr << "Error, cannot load database from: " << path << "\n";
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
        std::cerr << "Error, cannot load database from: " << path << "\n";
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
    int nonRegularFiles=0;
    for (const std::filesystem::path& dir : std::filesystem::recursive_directory_iterator(path
//                                                                                          ,| std::filesystem::directory_options::skip_permission_denied
          )) {
        if((std::filesystem::status(dir).type() == std::filesystem::file_type::regular)
//        || (std::filesystem::status(dir).type() == std::filesystem::file_type::symlink)
        ) {
            std::string path_string{dir.u8string()};
            result.push_back(path_string);
        }
        else {
            nonRegularFiles++;
        }
    }
    std::cout << nonRegularFiles << "\n";
    return result;
}
