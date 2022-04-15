//
// Created by kozzi on 3/9/22.
//

#include "../headers/file_functions.h"

#include <sys/vfs.h>

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <unordered_set>

#include <cryptopp/files.h>

#include "../headers/main.h"

// Changes permissions quarantine database, and allows to read and write
void MakeQuarantineDatabaseAvailable(){
    try{
        std::filesystem::permissions(quarantineDatabase,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                                        std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                                        std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
    }
    catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << "Cannot open quarantine database in: " << quarantineDatabase << "\n";
    }
}

// Changes permissions of quarantine database to 000
void MakeQuarantineDatabaseUnavailable(){
    try{
        std::filesystem::permissions(quarantineDatabase,std::filesystem::perms::none,std::filesystem::perm_options::replace);
    }
    catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << "Cannot close quarantine database in: " << quarantineDatabase << "\n";
    }
}

// Renames file to unique quarantine filename
std::string RenameFileToAvoidConflicts() {
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

// Saves file line by line
void SaveToQuarantineDatabase(const std::vector<std::string>& database) {
    std::ofstream outputFile;
    MakeQuarantineDatabaseAvailable();
    outputFile.open(quarantineDatabase, std::ios_base::out);
    for (const std::string& line : database){
        outputFile << line +"\n";
    }
    outputFile.close();
    MakeQuarantineDatabaseUnavailable();
}

// Reads quarantine database to vector
std::vector<std::string> ReadQuarantineDatabase(const std::string& path){
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

// Reads given database of hashes to unordered set
std::unordered_set<std::string> ReadDatabaseToUnorderedSet(const std::string& path) {
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

// Changes permissions of given file to 664
void RemoveExecutePermissions(const std::string& path) {
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

// Quarantine realisation
QuarantineData QuarantineAFile(const std::string& path, std::vector<std::string>& database) {
    QuarantineData qDB{};
    std::string movedTo = RenameFileToAvoidConflicts();
    qDB.prevName=path;
    qDB.inQuarantineName = movedTo;
    qDB.perms = status(std::filesystem::path(path)).permissions();
    time_t now = time(nullptr);
    tm* currTm;
    currTm = localtime(&now);                                           // Gets current date and time
    char *date = new char[50];
    strftime(date, 50, "%D %T", currTm);                 // Date formatting
    std::string dateStr = date;
    qDB.date = dateStr;
    delete[](date);
    try{
        EncryptFile(qDB, database);                                     // Encryption
    }catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed encrypting file, "<<ex.GetWhat()<<"\n";
    }
    catch (CryptoPP::FileStore::ReadErr const & ex){
        std::cerr << "Failed encrypting file, "<<ex.GetWhat()<<"\n";
    }
    RemoveExecutePermissions(qDB.inQuarantineName);                      // Removes execute permissions
    return qDB;
}

// Checks if given hash is in hash database
bool CheckFile(const std::string& hash, const std::unordered_set<std::string>& hashes) {
    return FindInUnorderedSet(hash, hashes);
}

// Checks if given path filesystem is EXT4
bool CheckFileSystem(const std::string& path) {
    struct statfs sb{};
    if ((statfs(path.c_str(), &sb)) == 0) {
        if (sb.f_type == 61267) return true;
        else return false;
    }
    else return false;
}

// Finds given filename in quarantine database
QuarantineData FindInQuarantine(const std::string& prevPath, const std::vector<std::string>& quarantineDb){
    QuarantineData qDB{};
    std::array<std::string,6> quarantineData{};
    for (std::string line : quarantineDb){                              // Iterates through quarantine database
        int start = 0;
        int delimiter = line.find_first_of(',');
        std::string temp = line.substr(start,delimiter);
        if (temp == prevPath){                                          // If previous filename in database equals given filename generates QuarantineData
            quarantineData[0]=temp;
            for (int i = 1; i<6; i++){
                line = line.erase(start,delimiter+1);
                delimiter = line.find_first_of(',');
                quarantineData[i]=line.substr(start,delimiter);
            }
            break;
        }
    }
    if(quarantineData[0].empty()) return qDB;
    qDB.prevName=quarantineData[0];
    qDB.inQuarantineName=quarantineData[1];
    qDB.keyString=quarantineData[2];
    qDB.ivString=quarantineData[3];
    qDB.perms= static_cast<std::filesystem::perms>(std::stoi(quarantineData[4]));
    qDB.date = quarantineData[5];
    return qDB;
}

// Restores given file from quarantine, returns if it was successful
bool RestoreFromQuarantine(const std::string& path, std::vector<std::string>& quarantineDb){
    QuarantineData qDB = FindInQuarantine(path, quarantineDb);
    if(qDB.prevName.empty()){
        return false;
    }
    try {
        DecryptFile(qDB);
    }catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed decrypting file, "<<ex.GetWhat()<<"\n";
        return false;
    }
    catch (CryptoPP::FileStore::ReadErr const & ex){
        std::cerr << "Failed decrypting file, "<<ex.GetWhat()<<"\n";
        return false;
    }
    try{
        std::filesystem::remove(qDB.inQuarantineName);
    }catch(std::filesystem::filesystem_error const& ex){
        return false;
    }

    std::string toRemove{};
    for (const std::string& line : quarantineDb){
        int delimiter = line.find_first_of(',');
        std::string temp = line.substr(0,delimiter);
        if (temp == qDB.prevName){
            toRemove=line;
            break;
        }
    }
    if(!toRemove.empty()){                                  // If found given filename in database, removes it to avoid further conflicts
        auto position = std::find(quarantineDb.begin(), quarantineDb.end(), toRemove);
        quarantineDb.erase(position);
        std::filesystem::remove(qDB.inQuarantineName);
        SaveToQuarantineDatabase(quarantineDb);
        return true;
    }
    else
        return false;
}

// Output prepared for user
std::string PrepareQuarantineLine(std::string& line){
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

void PrintQuarantineDatabase(const std::vector<std::string>& database){
    for (std::string line : database){
        std::cout << PrepareQuarantineLine(line) << "\n";
    }
}




