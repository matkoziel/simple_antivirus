//
// Created by kozzi on 3/9/22.
//

#include <iostream>
#include <vector>
#include <unordered_set>

#ifndef FILE_MANAGEMENT_H
#define FILE_MANAGEMENT_H

std::string readFileToString(const std::string& path);

void appendToHashDatabase(const std::string& input, const std::string& path);

std::vector<std::string> getAllFilesInDirectory(const std::string& path);

std::vector<unsigned char> readFileBinary(const std::string& path);

std::vector<std::string> readDatabase(const std::string& path);

bool moveFile(const std::string& from, const std::string& to);

std::unordered_set<std::string> readDatabaseToUnorderedSet(const std::string& path);

bool findInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet);

std::string renameFileToAvoidConflicts(const std::string& path);


#endif //FILE_MANAGEMENT_H
