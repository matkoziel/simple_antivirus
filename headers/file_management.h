//
// Created by kozzi on 3/9/22.
//

#include <iostream>
#include <vector>
#include <unordered_set>
#include "crypto_functions.h"

#ifndef FILE_MANAGEMENT_H
#define FILE_MANAGEMENT_H


bool findInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet);

std::string renameFileToAvoidConflicts();

bool moveFile(const std::string& from, const std::string& to);

void saveToDatabase(const std::unordered_set<std::string>& database);

void appendToDatabase(const std::string& input, std::unordered_set<std::string>& database);

std::unordered_set<std::string> readDatabaseToUnorderedSet(const std::string& path);

void removeExecutePermissions(const std::string& path);

void analyzingFile(const std::string& pathString, std::unordered_set<std::string>& hashes, std::unordered_set<std::string>& quarantineDB);

bool checkFile(const std::string& hash, const std::unordered_set<std::string>& hashes);

int checkFileSystem(const std::string& path);

AESCryptoData findInQuarantine(const std::string& prevPath, const std::unordered_set<std::string>& quarantineDb);

void addToQuarantineDatabase(const AESCryptoData& aes, std::unordered_set<std::string>& database);

bool restoreFromQuarantine(const std::string& path, const std::unordered_set<std::string>& quarantineDb);

void scanAllFilesInDirectory(const std::string& path, std::unordered_set<std::string>& hashes,std::unordered_set<std::string>& quarantineDB);

void scan(const std::string& path, std::unordered_set<std::string>& hashes,std::unordered_set<std::string>& quarantineDB);

#endif //FILE_MANAGEMENT_H
