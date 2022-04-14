//
// Created by kozzi on 3/9/22.
//

#ifndef SIMPLE_ANTIVIRUS_FILE_FUNCTIONS_H
#define SIMPLE_ANTIVIRUS_FILE_FUNCTIONS_H

#include <iostream>
#include <unordered_set>
#include <vector>

#include "crypto_functions.h"


void makeQuarantineDatabaseAvailable();

void makeQuarantineDatabaseUnavailable();

std::string renameFileToAvoidConflicts();

std::unordered_set<std::string> readDatabaseToUnorderedSet(const std::string& path);

std::vector<std::string> readQuarantineDatabase(const std::string& path);

AESCryptoData quarantineAFile(const std::string& path, std::vector<std::string>& database);

void removeExecutePermissions(const std::string& path);

bool checkFile(const std::string& hash, const std::unordered_set<std::string>& hashes);

bool checkFileSystem(const std::string& path);

bool restoreFromQuarantine(const std::string& path, std::vector<std::string>& quarantineDb);

void printQuarantineDatabase(const std::vector<std::string>& database);

void saveToQuarantineDatabase(const std::vector<std::string>& database);

#endif //SIMPLE_ANTIVIRUS_FILE_FUNCTIONS_H
