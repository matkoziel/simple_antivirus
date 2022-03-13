//
// Created by kozzi on 3/9/22.
//

#include <iostream>
#include <vector>

#ifndef FILE_MANAGEMENT_H
#define FILE_MANAGEMENT_H

std::string readFileToString(const std::string& path);

void appendToFile(const std::string& input, const std::string& path);

std::string removeSpaces(const std::string& input);

std::vector<std::string> getAllFilesInDirectory(const std::string& path);

std::vector<unsigned char> readFileBinary(const std::string& path);

std::vector<std::string> readDatabase(const std::string& path);

#endif //FILE_MANAGEMENT_H
