//
// Created by kozzi on 4/5/22.
//

#ifndef SIMPLE_ANTIVIRUS_MAIN_H
#define SIMPLE_ANTIVIRUS_MAIN_H

#include <atomic>
#include <string>
#include <vector>
#include <unordered_set>


extern std::string quarantineDir;
extern std::string quarantineDatabase;
extern std::vector<std::string> quarantineDatabaseDB;
extern std::unordered_set<std::string> hashDatabaseDB;
extern std::atomic<bool> loop;

#endif //SIMPLE_ANTIVIRUS_MAIN_H
