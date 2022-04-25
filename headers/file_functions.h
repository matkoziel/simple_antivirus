//
// Created by kozzi on 3/9/22.
//

#ifndef SIMPLE_ANTIVIRUS_FILE_FUNCTIONS_H
#define SIMPLE_ANTIVIRUS_FILE_FUNCTIONS_H

#include <iostream>
#include <unordered_set>
#include <vector>

#include "crypto_functions.h"


void MakeQuarantineDatabaseAvailable();

void MakeQuarantineDatabaseUnavailable();

std::string RenameFileToAvoidConflicts();

std::unordered_set<std::string> ReadDatabaseToUnorderedSet(const std::string& path);

std::vector<std::string> ReadQuarantineDatabase(const std::string& path);

QuarantineData QuarantineAFile(const std::string& path, std::vector<std::string>& database);

void RemoveExecutePermissions(const std::string& path);

bool CheckFile(const std::string& hash, const std::unordered_set<std::string>& hashes);

bool CheckFileSystem(const std::string& path);

bool RestoreFromQuarantine(const std::string& path, std::vector<std::string>& quarantineDb);

void PrintQuarantineDatabase(const std::vector<std::string>& database);

void SaveToQuarantineDatabase(const std::vector<std::string>& database);

#endif //SIMPLE_ANTIVIRUS_FILE_FUNCTIONS_H
