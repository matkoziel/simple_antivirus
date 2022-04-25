//
// Created by kozzi on 14.04.2022.
//

#ifndef SIMPLE_ANTIVIRUS_DATA_FUNCTIONS_H
#define SIMPLE_ANTIVIRUS_DATA_FUNCTIONS_H

#include <array>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

// Structure containing one row of quarantine database:
//      -prevName- full path of file before moving to quarantine
//      -inQuarantineName- full path of file in quarantine
//      -keyString- AES128 key in hex
//      -ivString- AES128 iv in hex
//      -perms- permissions before moving to quarantine
//      -date- date of moving to quarantine
struct QuarantineData {
    std::string prevName;
    std::string inQuarantineName;
    std::string keyString;
    std::string ivString;
    std::filesystem::perms perms;
    std::string date;
};

std::string AESBytesToString(const std::array<std::byte, 16>& in);

std::array<std::byte, 16> AESHexStringToBytes(const std::string& in);

bool FindInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet);

void AppendToQuarantineDatabase(const std::string& input, std::vector<std::string>& database);

QuarantineData FindInQuarantine(const std::string& prevPath, const std::vector<std::string>& quarantineDb);

void AddToQuarantineDatabase(const QuarantineData& qDB, std::vector<std::string>& database);


#endif //SIMPLE_ANTIVIRUS_DATA_FUNCTIONS_H
