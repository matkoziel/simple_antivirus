//
// Created by kozzi on 3/9/22.
//

#include "../headers/file_functions.h"

#include <sys/vfs.h>
#include <ctime>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unordered_set>

#include "../headers/main.h"


void makeQuarantineDatabaseAvailable(){
    try{
        std::filesystem::permissions(quarantineDatabase,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                                        std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                                        std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
    }
    catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << "Cannot open quarantine database in: " << quarantineDatabase << "\n";
    }
}

void makeQuarantineDatabaseUnavailable(){
    try{
        std::filesystem::permissions(quarantineDatabase,std::filesystem::perms::owner_read |
                                                        std::filesystem::perms::group_read |
                                                        std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
    }
    catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << "Cannot close quarantine database in: " << quarantineDatabase << "\n";
    }
}

std::string renameFileToAvoidConflicts() {
    std::string temp;
    temp.append(quarantineDir);
    temp.append("/malicious_file");
    temp.append("_0");
    while(std::filesystem::exists(temp)) {
        int index = temp.find_last_of('_');
        int newNumber = std::stoi(temp.substr(index+1,temp.size()));
        temp = temp.substr(0,index+1).append(std::to_string(newNumber+1));
    }
    return temp;
}

void saveToQuarantineDatabase(const std::vector<std::string>& database) {
    std::ofstream outputFile;
    makeQuarantineDatabaseAvailable();
    outputFile.open(quarantineDatabase, std::ios_base::out);
    for (const std::string& line : database){
        outputFile << line +"\n";
    }
    outputFile.close();
    makeQuarantineDatabaseUnavailable();
}

std::vector<std::string> readQuarantineDatabase(const std::string& path){
    std::vector<std::string> out{};
    std::ifstream inputFile(path,std::ios::out);
    if (!inputFile) {
        std::cerr << "Error, cannot load database from: " << path << "\n";
    }
    else {
        std::string temp;
        while(getline(inputFile, temp)) {
            out.push_back(temp);
        }
    }
    inputFile.close();
    return out;
}

std::unordered_set<std::string> readDatabaseToUnorderedSet(const std::string& path) {
    std::unordered_set<std::string> output;
    std::ifstream inputFile(path,std::ios::out);
    if (!inputFile) {
        std::string ex= "Error, cannot load database from: " + path + "\n";
        throw std::filesystem::filesystem_error(ex, std::error_code());
    }
    else {
        std::string temp;
        while(getline(inputFile, temp)) {
            output.insert(temp);
        }
    }
    inputFile.close();
    return output;
}

void removeExecutePermissions(const std::string& path) {
    if(exists(std::filesystem::path(path))){
        std::filesystem::permissions(path,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                          std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                          std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
        std::cout << "File " << path << " moved to: " << path << "\n";
    }
    else {
        std::cerr << "Error occurred, no such file: " << path << "\n";
    }
}

AESCryptoData quarantineAFile(const std::string& path, std::vector<std::string>& database) {
    AESCryptoData aes{};
    std::string movedTo = renameFileToAvoidConflicts();
    aes.prevName=path;
    aes.inQuarantineName = movedTo;
    aes.perms = status(std::filesystem::path(path)).permissions();
    time_t now = time(nullptr);
    tm* currTm;
    currTm = localtime(&now);
    char *date = new char[50];
    strftime(date, 50, "%D %T", currTm);
    std::string dateStr = date;
    aes.date = dateStr;
    delete[](date);
    encryptFile(aes,database);
    removeExecutePermissions(aes.inQuarantineName);
    return aes;
}

bool checkFile(const std::string& hash, const std::unordered_set<std::string>& hashes) {
    return findInUnorderedSet(hash, hashes);
}

bool checkFileSystem(const std::string& path) {
    struct statfs sb{};
    if ((statfs(path.c_str(), &sb)) == 0) {
        if (sb.f_type == 61267) return true;
        else return false;
    }
    else return false;
}

AESCryptoData findInQuarantine(const std::string& prevPath, const std::vector<std::string>& quarantineDb){
    AESCryptoData aes{};
    std::array<std::string,6> quarantineData{};
    for (std::string line : quarantineDb){
        int start = 0;
        int delimiter = line.find_first_of(',');
        std::string temp = line.substr(start,delimiter);
        if (temp == prevPath){
            quarantineData[0]=temp;
            for (int i = 1; i<6; i++){
                line = line.erase(start,delimiter+1);
                delimiter = line.find_first_of(',');
                quarantineData[i]=line.substr(start,delimiter);
            }
            break;
        }
    }
    if(quarantineData[0].empty()) return aes;
    aes.prevName=quarantineData[0];
    aes.inQuarantineName=quarantineData[1];
    aes.keyString=quarantineData[2];
    aes.ivString=quarantineData[3];
    aes.perms= static_cast<std::filesystem::perms>(std::stoi(quarantineData[4]));
    aes.date = quarantineData[5];
    return aes;
}

bool restoreFromQuarantine(const std::string& path,std::vector<std::string>& quarantineDb){
    AESCryptoData aes = findInQuarantine(path,quarantineDb);
    if(aes.prevName.empty()){
        return false;
    }
    decryptFile(aes);
    try{
        std::filesystem::remove(aes.inQuarantineName);
    }catch(std::filesystem::filesystem_error const& ex){
        return false;
    }

    std::string toRemove{};
    for (const std::string& line : quarantineDb){
        int delimiter = line.find_first_of(',');
        std::string temp = line.substr(0,delimiter);
        if (temp == aes.prevName){
            toRemove=line;
            break;
        }
    }
    if(!toRemove.empty()){
        auto position = std::find(quarantineDb.begin(), quarantineDb.end(), toRemove);
        quarantineDb.erase(position);
        std::filesystem::remove(aes.inQuarantineName);
        saveToQuarantineDatabase(quarantineDb);
        return true;
    }
    else
        return false;
}


std::string prepareQuarantineLine(std::string& line){
    std::array<std::string,6> quarantineData{};
    int start = 0;
    int delimiter;
    for (int i = 0; i<6; i++){
        delimiter = line.find_first_of(',');
        quarantineData[i]=line.substr(start,delimiter);
        line = line.erase(start,delimiter+1);
    }
    std::stringstream ss{};
    ss<< "Quarantined file: " << quarantineData[0] << " as: " << quarantineData[1] << ", date: " << quarantineData[5];
    return ss.str();
}

void printQuarantineDatabase(const std::vector<std::string>& database){
    for (std::string line : database){
        std::cout << prepareQuarantineLine(line) << "\n";
    }
}




