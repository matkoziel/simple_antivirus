//
// Created by kozzi on 14.04.2022.
//

#include "../headers/data_functions.h"

#include <array>
#include <iomanip>
#include <string>
#include <sstream>

#include "../headers/file_functions.h"

// Finds given value in unordered set, time complexity- O(n) in worst case, compares hashed value with hashed values in unordered set.
// Return true if value is in given structure
bool FindInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet) {
    return unorderedSet.find(value) != unorderedSet.end();
}

// Appends given input at the beginning of given vector
void AppendToQuarantineDatabase(const std::string& input, std::vector<std::string>& database) {
    database.insert(database.begin(),input);
    SaveToQuarantineDatabase(database);
}

// Changes QuarantineData to csv line and appends csv line to vrctor
void AddToQuarantineDatabase(const QuarantineData& qDB, std::vector<std::string>& database) {
    std::stringstream ss;
    ss << qDB.prevName << "," << qDB.inQuarantineName << "," << qDB.keyString << "," << qDB.ivString << "," << static_cast<int>(qDB.perms) << "," << qDB.date;
    AppendToQuarantineDatabase(ss.str(), database);
}

// Changes byte array to hex string
std::string AESBytesToString(const std::array<std::byte, 16>& in) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (std::byte byte : in){
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Changes hex string to array of bytes
std::array<std::byte, 16> AESHexStringToBytes(const std::string& in) {
    std::array<std::byte, 16> out{};
    std::stringstream converter;
    for(int i = 0; i < out.size(); i++){
        converter << std::hex << in.substr(2*i,2);
        int byte;
        converter >> byte;
        out[i] = static_cast<std::byte>(byte & 0xFF);
        converter.str(std::string());
        converter.clear();
    }
    return out;
}