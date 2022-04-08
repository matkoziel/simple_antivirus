//
// Created by kozzi on 3/9/22.
//

#include <iostream>
#include <unordered_set>
#include <vector>

#include "crypto_functions.h"

#ifndef FILE_MANAGEMENT_H
#define FILE_MANAGEMENT_H


bool findInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet);

std::string renameFileToAvoidConflicts();

void appendToQuarantineDatabase(const std::string& input, std::vector<std::string>& database);

std::unordered_set<std::string> readDatabaseToUnorderedSet(const std::string& path);

std::vector<std::string> readQuarantineDatabase(const std::string& path);

void removeExecutePermissions(const std::string& path);

bool checkFile(const std::string& hash, const std::unordered_set<std::string>& hashes);

bool checkFileSystem(const std::string& path);

AESCryptoData findInQuarantine(const std::string& prevPath, const std::vector<std::string>& quarantineDb);

void addToQuarantineDatabase(const AESCryptoData& aes, std::vector<std::string>& database);

bool restoreFromQuarantine(const std::string& path, std::vector<std::string>& quarantineDb);

void scan(const std::string& path, std::unordered_set<std::string>& hashes,std::vector<std::string>& quarantineDB);

#endif //FILE_MANAGEMENT_H
