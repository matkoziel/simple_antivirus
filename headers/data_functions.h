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

struct AESCryptoData {
    std::string prevName;
    std::string inQuarantineName;
    std::string keyString;
    std::string ivString;
    std::filesystem::perms perms;
    std::string date;
};

std::string AESBytesToString(const std::array<std::byte, 16>& in);

std::array<std::byte, 16> AESHexStringToBytes(const std::string& in);

bool findInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet);

void appendToQuarantineDatabase(const std::string& input, std::vector<std::string>& database);

AESCryptoData findInQuarantine(const std::string& prevPath, const std::vector<std::string>& quarantineDb);

void addToQuarantineDatabase(const AESCryptoData& aes, std::vector<std::string>& database);


#endif //SIMPLE_ANTIVIRUS_DATA_FUNCTIONS_H
